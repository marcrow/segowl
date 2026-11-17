"""Tests for the Automations engine: parser, evaluation, tag/exclude actions."""

import os
import shutil
from pathlib import Path

import pytest

from segowl.automations import (
    Automation,
    AutomationResult,
    ParseError,
    extract_observations,
    is_portable,
    load_automations,
    parse_condition,
    run_automations,
    save_automations,
)
from segowl.inventory import load_inventory
from segowl.nmap import HostRecord, Scan

MISSION = Path(__file__).parent / "fixtures" / "mission"


# ---------------------------------------------------------------- parser: valid conditions


@pytest.mark.parametrize(
    "cond",
    [
        "port = 80",
        "port != 443",
        "state = closed",
        "protocol = tcp",
        "zone = Admin",
        'zone = "Server Room"',
        "machine = FW-01",
        "tag = windows",
        "port = 80 or port = 443",
        "port = 80 and state = open",
        "(port = 80 or port = 443) and state = open",
        "state = closed and zone = Admin",
        "port = 22 and state = closed and machine = FW-01",
    ],
)
def test_valid_conditions_parse(cond):
    pred, fields = parse_condition(cond)
    assert callable(pred)
    assert fields <= {"port", "state", "protocol", "zone", "machine", "tag"}


# ---------------------------------------------------------------- parser: rejection


@pytest.mark.parametrize(
    "cond",
    [
        "",
        "; drop table",
        "__import__('os')",
        "unknown = foo",
        "port = abc",
        "port = 0",
        "port = 99999",
        "state = invalid",
        "protocol = sctp",
        "(((((port = 1 and port = 2) and port = 3) and port = 4) and port = 5) and port = 6)",  # depth > 4
        "a" * 501,
    ],
)
def test_invalid_conditions_rejected(cond):
    with pytest.raises(ParseError):
        parse_condition(cond)


# ---------------------------------------------------------------- parser: evaluation


def _obs(**kw):
    return {"port": 0, "state": "", "protocol": "tcp", "zone": "", "machine": "", "tag": [], **kw}


def test_port_80_matches():
    pred, _ = parse_condition("port = 80")
    assert pred(_obs(port=80))
    assert not pred(_obs(port=443))


def test_port_80_or_443():
    pred, _ = parse_condition("port = 80 or port = 443")
    assert pred(_obs(port=80))
    assert pred(_obs(port=443))
    assert not pred(_obs(port=22))


def test_port_80_and_443_always_false():
    pred, _ = parse_condition("port = 80 and port = 443")
    assert not pred(_obs(port=80))
    assert not pred(_obs(port=443))


def test_state_closed_and_zone():
    pred, _ = parse_condition("state = closed and zone = Admin")
    assert pred(_obs(state="closed", zone="Admin"))
    assert not pred(_obs(state="open", zone="Admin"))
    assert not pred(_obs(state="closed", zone="DMZ"))


def test_tag_match():
    pred, _ = parse_condition("tag = windows")
    assert pred(_obs(tag=["windows", "admin"]))
    assert not pred(_obs(tag=["linux"]))
    assert not pred(_obs(tag=[]))


def test_tag_not_equal():
    pred, _ = parse_condition("tag != windows")
    assert pred(_obs(tag=["linux"]))
    assert pred(_obs(tag=[]))
    assert not pred(_obs(tag=["windows"]))


def test_parenthesised_or():
    pred, _ = parse_condition("(port = 80 or port = 443) and state = open")
    assert pred(_obs(port=80, state="open"))
    assert pred(_obs(port=443, state="open"))
    assert not pred(_obs(port=80, state="closed"))
    assert not pred(_obs(port=22, state="open"))


def test_quoted_value():
    pred, _ = parse_condition('zone = "Server Room"')
    assert pred(_obs(zone="Server Room"))
    assert not pred(_obs(zone="Server"))


# ---------------------------------------------------------------- parser: fields_used and portability


def test_portable():
    _, fields = parse_condition("port = 80 and state = open")
    assert is_portable(fields)


def test_not_portable():
    _, fields = parse_condition("zone = Admin")
    assert not is_portable(fields)


# ---------------------------------------------------------------- automations.ini round-trip


def test_load_save_round_trip(tmp_path):
    ini = tmp_path / "automations.ini"
    autos = [
        Automation("web-servers", "tag", "port = 80 or port = 443", "web_server"),
        Automation("noise", "exclude", "state = closed and zone = Admin"),
    ]
    save_automations(ini, autos)
    loaded = load_automations(ini)
    assert len(loaded) == 2
    assert loaded[0].name == "web-servers"
    assert loaded[0].action == "tag"
    assert loaded[0].tag == "web_server"
    assert loaded[1].action == "exclude"


def test_load_nonexistent():
    assert load_automations("/nonexistent/automations.ini") == []


def test_load_bad_action(tmp_path):
    ini = tmp_path / "automations.ini"
    ini.write_text("[bad]\naction = nope\ncondition = port = 80\n")
    with pytest.raises(ValueError, match="tag or exclude"):
        load_automations(ini)


def test_load_bad_condition(tmp_path):
    ini = tmp_path / "automations.ini"
    ini.write_text("[bad]\naction = exclude\ncondition = unknown = foo\n")
    with pytest.raises(ValueError, match="unknown field"):
        load_automations(ini)


def test_percent_in_condition_does_not_crash(tmp_path):
    ini = tmp_path / "automations.ini"
    ini.write_text('[test]\naction = exclude\ncondition = machine = "srv%01"\n')
    loaded = load_automations(ini)
    assert loaded[0].condition == 'machine = "srv%01"'


# ---------------------------------------------------------------- engine: tag action


def test_tag_automation_derives_tag():
    inv = load_inventory(str(MISSION / "inventory.csv"))
    scans = {"172.31.250.1": [Scan(
        path="x.xml", source="172.31.250.1",
        hosts={
            "172.31.250.10": HostRecord(state="up", ports=[(80, "tcp", "open"), (443, "tcp", "open")]),
            "172.31.250.20": HostRecord(state="up", ports=[(5432, "tcp", "open")]),
        },
    )]}
    autos = [Automation("web", "tag", "port = 80 or port = 443", "web_server")]
    result = run_automations(autos, inv, scans)
    assert "web_server" in result.derived_tags.get("app-01", set())
    assert "web_server" not in result.derived_tags.get("db-01", set())


# ---------------------------------------------------------------- engine: exclude action


def test_exclude_removes_observations():
    inv = load_inventory(str(MISSION / "inventory.csv"))
    scans = {"172.31.250.1": [Scan(
        path="x.xml", source="172.31.250.1",
        hosts={
            "172.31.250.10": HostRecord(state="up", ports=[(22, "tcp", "closed"), (80, "tcp", "open")]),
        },
    )]}
    autos = [Automation("noise", "exclude", "state = closed")]
    result = run_automations(autos, inv, scans)
    assert ("172.31.250.1", "172.31.250.10", 22, "tcp") in result.excluded
    assert ("172.31.250.1", "172.31.250.10", 80, "tcp") not in result.excluded


def test_open_state_exclusion_warns():
    inv = load_inventory(str(MISSION / "inventory.csv"))
    scans = {"172.31.250.1": [Scan(
        path="x.xml", source="172.31.250.1",
        hosts={"172.31.250.10": HostRecord(state="up", ports=[(80, "tcp", "open")])},
    )]}
    autos = [Automation("risky", "exclude", "state = open")]
    result = run_automations(autos, inv, scans)
    assert any("open-port" in w for w in result.warnings)


# ---------------------------------------------------------------- engine: grouped ports


def test_exclude_matches_grouped_ports():
    inv = load_inventory(str(MISSION / "inventory.csv"))
    scans = {"172.31.250.1": [Scan(
        path="x.xml", source="172.31.250.1",
        hosts={
            "172.31.250.10": HostRecord(
                state="up",
                ports=[(80, "tcp", "open")],
                rest=[("tcp", [(1, 1024)], "closed")],
                ignored=[("closed", 1000)],
            ),
        },
    )]}
    autos = [Automation("noise", "exclude", "state = closed")]
    result = run_automations(autos, inv, scans)
    assert ("172.31.250.1", "172.31.250.10", "tcp") in result.excluded_grouped




# ---------------------------------------------------------------- integration: exclusion changes the verdict


def test_exclusion_changes_verdict_in_analysis():
    from segowl.analysis import analyze

    inv = load_inventory(str(MISSION / "inventory.csv"))
    scans = {"172.31.250.1": [Scan(
        path="x.xml", source="172.31.250.1",
        hosts={
            "172.31.250.10": HostRecord(state="up", ports=[(22, "tcp", "closed"), (80, "tcp", "open")]),
            "172.31.250.20": HostRecord(state="up", ports=[(5432, "tcp", "open")]),
        },
    )]}
    # without automations: app-01 is OPEN (port 80)
    a0 = analyze(inv, scans, [])
    assert a0.matrix["172.31.250.1"]["172.31.250.10"].verdict == 3  # OPEN

    # exclude state = open → app-01 drops from OPEN to REACH (port 22 closed still passes)
    autos = [Automation("no-open", "exclude", "state = open")]
    a1 = analyze(inv, scans, [], automations=autos)
    assert a1.matrix["172.31.250.1"]["172.31.250.10"].verdict == 2  # REACH
    assert a1.automation_warnings  # warning about masking open ports


def test_full_exclusion_gives_excluded_verdict():
    from segowl.analysis import analyze
    from segowl.verdict import EXCLUDED

    inv = load_inventory(str(MISSION / "inventory.csv"))
    scans = {"172.31.250.1": [Scan(
        path="x.xml", source="172.31.250.1", pn=True,
        hosts={
            "172.31.250.10": HostRecord(state="up", ports=[(80, "tcp", "open")]),
        },
    )]}
    autos = [Automation("all", "exclude", "port = 80")]
    a = analyze(inv, scans, [], automations=autos, force_pn=True)
    assert a.matrix["172.31.250.1"]["172.31.250.10"].verdict == EXCLUDED


def test_full_exclusion_with_discovery_gives_alive():
    from segowl.analysis import analyze
    from segowl.verdict import ALIVE

    inv = load_inventory(str(MISSION / "inventory.csv"))
    scans = {"172.31.250.1": [Scan(
        path="x.xml", source="172.31.250.1",
        hosts={
            "172.31.250.10": HostRecord(state="up", ports=[(80, "tcp", "open")]),
        },
    )]}
    autos = [Automation("all", "exclude", "port = 80")]
    a = analyze(inv, scans, [], automations=autos)
    # host answered discovery → ALIVE, not EXCLUDED
    assert a.matrix["172.31.250.1"]["172.31.250.10"].verdict == ALIVE


def test_derived_tags_available_in_analysis():
    from segowl.analysis import analyze

    inv = load_inventory(str(MISSION / "inventory.csv"))
    scans = {"172.31.250.1": [Scan(
        path="x.xml", source="172.31.250.1",
        hosts={
            "172.31.250.10": HostRecord(state="up", ports=[(3389, "tcp", "open")]),
        },
    )]}
    autos = [Automation("win", "tag", "port = 3389 and state = open", "windows")]
    a = analyze(inv, scans, [], automations=autos)
    assert "windows" in a.derived_tags.get("app-01", set())


# ---------------------------------------------------------------- app: Automations CRUD


def test_automations_crud_via_mission(tmp_path):
    from segowl.app import Mission
    m = tmp_path / "mission"
    shutil.copytree(MISSION, m)
    mission = Mission(m)
    # initially empty
    d = mission.automations()
    assert d["automations"] == []
    # save two automations
    mission.save_automations({
        "fp": d["fp"],
        "automations": [
            {"name": "web", "action": "tag", "condition": "port = 80 or port = 443", "tag": "web"},
            {"name": "noise", "action": "exclude", "condition": "state = closed"},
        ],
    })
    d = mission.automations()
    assert len(d["automations"]) == 2
    assert d["automations"][0]["name"] == "web"
    # test a condition
    t = mission.test_automation({"condition": "port = 80 or port = 443"})
    assert "matches" in t
    # bad condition
    t = mission.test_automation({"condition": "unknown = x"})
    assert "error" in t


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
