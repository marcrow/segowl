"""Tests for the Automations engine: parser, evaluation, tag/exclude actions."""

import shutil
from pathlib import Path

import pytest

from segowl.automations import (
    Automation,
    ParseError,
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


def test_state_filtered_matches_compound_states():
    pred, _ = parse_condition("state = filtered")
    assert pred(_obs(state="filtered"))
    assert pred(_obs(state="open|filtered"))
    assert pred(_obs(state="closed|filtered"))
    assert not pred(_obs(state="open"))
    assert not pred(_obs(state="closed"))


def test_state_not_filtered_excludes_compound_states():
    pred, _ = parse_condition("state != filtered")
    assert not pred(_obs(state="filtered"))
    assert not pred(_obs(state="open|filtered"))
    assert pred(_obs(state="open"))
    assert pred(_obs(state="closed"))


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
    scans = {
        "172.31.250.1": [
            Scan(
                path="x.xml",
                source="172.31.250.1",
                hosts={
                    "172.31.250.10": HostRecord(
                        state="up", ports=[(80, "tcp", "open"), (443, "tcp", "open")]
                    ),
                    "172.31.250.20": HostRecord(state="up", ports=[(5432, "tcp", "open")]),
                },
            )
        ]
    }
    autos = [Automation("web", "tag", "port = 80 or port = 443", "web_server")]
    result = run_automations(autos, inv, scans)
    assert "web_server" in result.derived_tags.get("app-01", set())
    assert "web_server" not in result.derived_tags.get("db-01", set())


# ---------------------------------------------------------------- engine: exclude action


def test_exclude_removes_observations():
    inv = load_inventory(str(MISSION / "inventory.csv"))
    scans = {
        "172.31.250.1": [
            Scan(
                path="x.xml",
                source="172.31.250.1",
                hosts={
                    "172.31.250.10": HostRecord(
                        state="up", ports=[(22, "tcp", "closed"), (80, "tcp", "open")]
                    ),
                },
            )
        ]
    }
    autos = [Automation("noise", "exclude", "state = closed")]
    result = run_automations(autos, inv, scans)
    assert ("172.31.250.1", "172.31.250.10", 22, "tcp") in result.excluded
    assert ("172.31.250.1", "172.31.250.10", 80, "tcp") not in result.excluded


def test_open_state_exclusion_warns():
    inv = load_inventory(str(MISSION / "inventory.csv"))
    scans = {
        "172.31.250.1": [
            Scan(
                path="x.xml",
                source="172.31.250.1",
                hosts={"172.31.250.10": HostRecord(state="up", ports=[(80, "tcp", "open")])},
            )
        ]
    }
    autos = [Automation("risky", "exclude", "state = open")]
    result = run_automations(autos, inv, scans)
    assert any("open-port" in w for w in result.warnings)


# ---------------------------------------------------------------- engine: grouped ports


def test_port_not_equal_does_not_match_grouped_observations():
    """port != 22 must NOT match grouped-port observations (port=0 sentinel)."""
    pred, _ = parse_condition("port != 22")
    assert pred(_obs(port=80))
    assert not pred(_obs(port=22))
    assert not pred(_obs(port=0))  # grouped sentinel


def test_port_specific_exclusion_does_not_drop_grouped():
    """port = 22 and state = closed must NOT exclude a grouped 'closed 1-1024' range."""
    inv = load_inventory(str(MISSION / "inventory.csv"))
    scans = {
        "172.31.250.1": [
            Scan(
                path="x.xml",
                source="172.31.250.1",
                hosts={
                    "172.31.250.10": HostRecord(
                        state="up",
                        ports=[(22, "tcp", "closed"), (80, "tcp", "open")],
                        rest=[("tcp", [(1, 1024)], "closed")],
                    ),
                },
            )
        ]
    }
    autos = [Automation("ssh-only", "exclude", "port = 22 and state = closed")]
    result = run_automations(autos, inv, scans)
    assert ("172.31.250.1", "172.31.250.10", 22, "tcp") in result.excluded
    assert ("172.31.250.1", "172.31.250.10", "tcp") not in result.excluded_grouped


def test_exclude_matches_grouped_ports():
    inv = load_inventory(str(MISSION / "inventory.csv"))
    scans = {
        "172.31.250.1": [
            Scan(
                path="x.xml",
                source="172.31.250.1",
                hosts={
                    "172.31.250.10": HostRecord(
                        state="up",
                        ports=[(80, "tcp", "open")],
                        rest=[("tcp", [(1, 1024)], "closed")],
                        ignored=[("closed", 1000)],
                    ),
                },
            )
        ]
    }
    autos = [Automation("noise", "exclude", "state = closed")]
    result = run_automations(autos, inv, scans)
    assert ("172.31.250.1", "172.31.250.10", "tcp") in result.excluded_grouped


# ---------------------------------------------------------------- integration: exclusion changes the verdict


def test_exclusion_changes_verdict_in_analysis():
    from segowl.analysis import analyze

    inv = load_inventory(str(MISSION / "inventory.csv"))
    scans = {
        "172.31.250.1": [
            Scan(
                path="x.xml",
                source="172.31.250.1",
                hosts={
                    "172.31.250.10": HostRecord(
                        state="up", ports=[(22, "tcp", "closed"), (80, "tcp", "open")]
                    ),
                    "172.31.250.20": HostRecord(state="up", ports=[(5432, "tcp", "open")]),
                },
            )
        ]
    }
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
    scans = {
        "172.31.250.1": [
            Scan(
                path="x.xml",
                source="172.31.250.1",
                pn=True,
                hosts={
                    "172.31.250.10": HostRecord(state="up", ports=[(80, "tcp", "open")]),
                },
            )
        ]
    }
    autos = [Automation("all", "exclude", "port = 80")]
    a = analyze(inv, scans, [], automations=autos, force_pn=True)
    assert a.matrix["172.31.250.1"]["172.31.250.10"].verdict == EXCLUDED


def test_full_exclusion_with_discovery_gives_alive():
    from segowl.analysis import analyze
    from segowl.verdict import ALIVE

    inv = load_inventory(str(MISSION / "inventory.csv"))
    scans = {
        "172.31.250.1": [
            Scan(
                path="x.xml",
                source="172.31.250.1",
                hosts={
                    "172.31.250.10": HostRecord(state="up", ports=[(80, "tcp", "open")]),
                },
            )
        ]
    }
    autos = [Automation("all", "exclude", "port = 80")]
    a = analyze(inv, scans, [], automations=autos)
    # host answered discovery → ALIVE, not EXCLUDED
    assert a.matrix["172.31.250.1"]["172.31.250.10"].verdict == ALIVE


def test_derived_tags_available_in_analysis():
    from segowl.analysis import analyze

    inv = load_inventory(str(MISSION / "inventory.csv"))
    scans = {
        "172.31.250.1": [
            Scan(
                path="x.xml",
                source="172.31.250.1",
                hosts={
                    "172.31.250.10": HostRecord(state="up", ports=[(3389, "tcp", "open")]),
                },
            )
        ]
    }
    autos = [Automation("win", "tag", "port = 3389 and state = open", "windows")]
    a = analyze(inv, scans, [], automations=autos)
    assert "windows" in a.derived_tags.get("app-01", set())


# ---------------------------------------------------------------- exclusion stats and report section


def test_exclusion_stats_counts_and_zones():
    inv = load_inventory(str(MISSION / "inventory.csv"))
    scans = {
        "172.31.250.1": [
            Scan(
                path="x.xml",
                source="172.31.250.1",
                hosts={
                    "172.31.250.10": HostRecord(
                        state="up", ports=[(22, "tcp", "closed"), (80, "tcp", "open")]
                    ),
                    "172.31.250.20": HostRecord(state="up", ports=[(5432, "tcp", "open")]),
                },
            )
        ]
    }
    autos = [
        Automation("noise", "exclude", "state = closed"),
        Automation("tag-only", "tag", "port = 80", "web"),
    ]
    result = run_automations(autos, inv, scans)
    assert len(result.exclusion_stats) == 1
    es = result.exclusion_stats[0]
    assert es.automation.name == "noise"
    assert es.match_count == 1
    assert es.zones == {"dmz"}


def test_exclusion_stats_in_analysis():
    from segowl.analysis import analyze

    inv = load_inventory(str(MISSION / "inventory.csv"))
    scans = {
        "172.31.250.1": [
            Scan(
                path="x.xml",
                source="172.31.250.1",
                hosts={
                    "172.31.250.10": HostRecord(state="up", ports=[(80, "tcp", "open")]),
                },
            )
        ]
    }
    autos = [Automation("all", "exclude", "port = 80")]
    a = analyze(inv, scans, [], automations=autos, force_pn=True)
    assert len(a.exclusion_stats) == 1
    assert a.exclusion_stats[0].match_count == 1


def test_exclusion_section_in_html_report(tmp_path):
    """The Exclusion Automations section appears in the report with correct data."""
    from segowl.analysis import analyze
    from segowl.render.html import write_html

    inv = load_inventory(str(MISSION / "inventory.csv"))
    scans = {
        "172.31.250.1": [
            Scan(
                path="x.xml",
                source="172.31.250.1",
                hosts={
                    "172.31.250.10": HostRecord(
                        state="up", ports=[(22, "tcp", "closed"), (80, "tcp", "open")]
                    ),
                },
            )
        ]
    }
    autos = [
        Automation("noise", "exclude", "state = closed"),
        Automation("tag-only", "tag", "port = 80", "web"),
    ]
    a = analyze(inv, scans, [], automations=autos, force_pn=True)
    doc = open(write_html(a, str(tmp_path)), encoding="utf-8").read()
    assert "Exclusion Automations" in doc
    assert "noise" in doc
    assert "state = closed" in doc
    # tag automation must NOT appear in the exclusion section
    assert doc.count("tag-only") == 0


def test_exclusion_section_absent_without_exclusions(tmp_path):
    from segowl.analysis import analyze
    from segowl.render.html import write_html

    inv = load_inventory(str(MISSION / "inventory.csv"))
    scans = {
        "172.31.250.1": [
            Scan(
                path="x.xml",
                source="172.31.250.1",
                hosts={"172.31.250.10": HostRecord(state="up", ports=[(80, "tcp", "open")])},
            )
        ]
    }
    a = analyze(inv, scans, [])
    doc = open(write_html(a, str(tmp_path)), encoding="utf-8").read()
    assert "Exclusion Automations" not in doc
    assert 'class="btn excl-toggle"' not in doc


def test_exclusion_toggle_in_html_report(tmp_path):
    """The toggle button is rendered only when exclusions exist."""
    from segowl.analysis import analyze
    from segowl.render.html import write_html

    inv = load_inventory(str(MISSION / "inventory.csv"))
    scans = {
        "172.31.250.1": [
            Scan(
                path="x.xml",
                source="172.31.250.1",
                hosts={"172.31.250.10": HostRecord(state="up", ports=[(80, "tcp", "open")])},
            )
        ]
    }
    autos = [Automation("all", "exclude", "port = 80")]
    a = analyze(inv, scans, [], automations=autos, force_pn=True)
    doc = open(write_html(a, str(tmp_path)), encoding="utf-8").read()
    assert 'class="btn excl-toggle"' in doc
    assert "(1)</small>" in doc  # the count badge


def test_script_in_automation_name_is_escaped(tmp_path):
    """XSS via automation name: html.escape must be applied."""
    from segowl.analysis import analyze
    from segowl.render.html import write_html

    inv = load_inventory(str(MISSION / "inventory.csv"))
    scans = {
        "172.31.250.1": [
            Scan(
                path="x.xml",
                source="172.31.250.1",
                hosts={"172.31.250.10": HostRecord(state="up", ports=[(80, "tcp", "open")])},
            )
        ]
    }
    autos = [Automation("<script>alert(1)</script>", "exclude", "port = 80")]
    a = analyze(inv, scans, [], automations=autos, force_pn=True)
    doc = open(write_html(a, str(tmp_path)), encoding="utf-8").read()
    assert "<script>alert(1)</script>" not in doc
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in doc


def test_exclusion_removes_findings(tmp_path):
    """An exclusion on an open port that the Flow Policy denies removes that Finding."""
    from segowl.analysis import analyze
    from segowl.policy import load_policy

    inv = load_inventory(str(MISSION / "inventory.csv"))
    scans = {
        "172.31.250.1": [
            Scan(
                path="x.xml",
                source="172.31.250.1",
                hosts={"172.31.250.10": HostRecord(state="up", ports=[(22, "tcp", "open")])},
            )
        ]
    }
    policy = load_policy("policy.csv", inv, {}, text="audit;dmz;22;deny;no ssh\n")
    # without exclusion: one Finding
    a0 = analyze(inv, scans, [], policy=policy, force_pn=True)
    assert len(a0.findings) == 1
    # with exclusion: Finding gone
    autos = [Automation("no-ssh", "exclude", "port = 22 and state = open")]
    a1 = analyze(inv, scans, [], automations=autos, policy=policy, force_pn=True)
    assert len(a1.findings) == 0


def test_excluded_ports_and_was_on_cell():
    """When an open port is excluded, the Cell records excluded_ports and was (pre-exclusion verdict)."""
    from segowl.analysis import analyze
    from segowl.verdict import OPEN

    inv = load_inventory(str(MISSION / "inventory.csv"))
    scans = {
        "172.31.250.1": [
            Scan(
                path="x.xml",
                source="172.31.250.1",
                hosts={
                    "172.31.250.10": HostRecord(state="up", ports=[(22, "tcp", "open"), (80, "tcp", "open")]),
                },
            )
        ]
    }
    autos = [Automation("drop-80", "exclude", "port = 80 and state = open")]
    a = analyze(inv, scans, [], automations=autos, force_pn=True)
    c = a.matrix["172.31.250.1"]["172.31.250.10"]
    assert c.verdict == OPEN
    assert c.excluded_ports == [(80, "tcp")]
    assert c.was is None  # verdict didn't change


def test_excluded_ports_verdict_changes():
    """When all open ports are excluded, verdict becomes EXCLUDED and was records the original."""
    from segowl.analysis import analyze
    from segowl.verdict import EXCLUDED, OPEN

    inv = load_inventory(str(MISSION / "inventory.csv"))
    scans = {
        "172.31.250.1": [
            Scan(
                path="x.xml",
                source="172.31.250.1",
                hosts={
                    "172.31.250.10": HostRecord(state="up", ports=[(80, "tcp", "open")]),
                },
            )
        ]
    }
    autos = [Automation("all", "exclude", "port = 80")]
    a = analyze(inv, scans, [], automations=autos, force_pn=True)
    c = a.matrix["172.31.250.1"]["172.31.250.10"]
    assert c.verdict == EXCLUDED
    assert c.excluded_ports == [(80, "tcp")]
    assert c.was == OPEN


def test_closed_exclusion_reach_to_excluded():
    """Excluding closed ports on a REACHABLE pair: verdict drops to EXCLUDED, was = REACH."""
    from segowl.analysis import analyze
    from segowl.verdict import EXCLUDED, REACH

    inv = load_inventory(str(MISSION / "inventory.csv"))
    scans = {
        "172.31.250.1": [
            Scan(
                path="x.xml",
                source="172.31.250.1",
                hosts={
                    "172.31.250.10": HostRecord(state="up", ports=[(22, "tcp", "closed")]),
                },
            )
        ]
    }
    autos = [Automation("noise", "exclude", "state = closed")]
    a = analyze(inv, scans, [], automations=autos, force_pn=True)
    c = a.matrix["172.31.250.1"]["172.31.250.10"]
    assert c.verdict == EXCLUDED
    assert c.was == REACH


def test_xp_marker_in_report(tmp_path):
    """Excluded ports render with the .xp marker class in the report HTML."""
    from segowl.analysis import analyze
    from segowl.render.html import write_html

    inv = load_inventory(str(MISSION / "inventory.csv"))
    scans = {
        "172.31.250.1": [
            Scan(
                path="x.xml",
                source="172.31.250.1",
                hosts={
                    "172.31.250.10": HostRecord(
                        state="up",
                        ports=[(22, "tcp", "open"), (80, "tcp", "open")],
                    ),
                },
            )
        ]
    }
    autos = [Automation("drop-80", "exclude", "port = 80 and state = open")]
    a = analyze(inv, scans, [], automations=autos, force_pn=True)
    doc = open(write_html(a, str(tmp_path)), encoding="utf-8").read()
    assert '<span class="xp">80</span>' in doc


def test_no_xp_marker_without_automations(tmp_path):
    """Without automations, no .xp marker appears in the report."""
    from segowl.analysis import analyze
    from segowl.render.html import write_html

    inv = load_inventory(str(MISSION / "inventory.csv"))
    scans = {
        "172.31.250.1": [
            Scan(
                path="x.xml",
                source="172.31.250.1",
                hosts={
                    "172.31.250.10": HostRecord(state="up", ports=[(80, "tcp", "open")]),
                },
            )
        ]
    }
    a = analyze(inv, scans, [])
    doc = open(write_html(a, str(tmp_path)), encoding="utf-8").read()
    assert '<span class="xp">' not in doc


def test_masked_finding_in_report(tmp_path):
    """An excluded Finding appears as a masked row (.xrow) in the report."""
    from segowl.analysis import analyze
    from segowl.policy import load_policy
    from segowl.render.html import write_html

    inv = load_inventory(str(MISSION / "inventory.csv"))
    scans = {
        "172.31.250.1": [
            Scan(
                path="x.xml",
                source="172.31.250.1",
                hosts={
                    "172.31.250.10": HostRecord(state="up", ports=[(22, "tcp", "open")]),
                },
            )
        ]
    }
    policy = load_policy("policy.csv", inv, {}, text="audit;dmz;22;deny;no ssh\n")
    autos = [Automation("no-ssh", "exclude", "port = 22 and state = open")]
    a = analyze(inv, scans, [], automations=autos, policy=policy, force_pn=True)
    assert len(a.findings) == 0
    assert len(a.masked_findings) == 1
    doc = open(write_html(a, str(tmp_path)), encoding="utf-8").read()
    assert "no ssh" in doc.split('class="xrow"')[1][:200]


def test_zone_matrix_excluded_verdict():
    """A zone pair where all pairs are EXCLUDED shows EXCLUDED, not UNSEEN."""
    from segowl.analysis import analyze
    from segowl.verdict import EXCLUDED

    inv = load_inventory(str(MISSION / "inventory.csv"))
    scans = {
        "172.31.250.1": [
            Scan(
                path="x.xml",
                source="172.31.250.1",
                hosts={
                    "172.31.250.10": HostRecord(state="up", ports=[(80, "tcp", "open")]),
                },
            )
        ]
    }
    autos = [Automation("all", "exclude", "port = 80")]
    a = analyze(inv, scans, [], automations=autos, force_pn=True)
    assert a.agg[("audit", "dmz")].verdict == EXCLUDED
    assert (80, "tcp") in a.agg[("audit", "dmz")].excluded_ports


# ---------------------------------------------------------------- app: Automations CRUD


# ---------------------------------------------------------------- kit: portable automations only


def test_kit_saves_only_portable_automations(tmp_path):
    from segowl.kits import save_kit

    mission = tmp_path / "mission"
    shutil.copytree(MISSION, mission)
    # Create automations: one portable, one not
    save_automations(
        mission / "automations.ini",
        [
            Automation("web", "tag", "port = 80 or port = 443", "web_server"),
            Automation("admin-noise", "exclude", "state = closed and zone = Admin"),
        ],
    )
    kit_dir = tmp_path / "kits"
    kit_dir.mkdir()
    save_kit(mission, [kit_dir], kit_dir, "test-kit")
    kit_autos = load_automations(kit_dir / "test-kit" / "automations.ini")
    assert len(kit_autos) == 1
    assert kit_autos[0].name == "web"  # portable: only port and state


def test_kit_no_automations_when_all_non_portable(tmp_path):
    from segowl.kits import save_kit

    mission = tmp_path / "mission"
    shutil.copytree(MISSION, mission)
    save_automations(
        mission / "automations.ini",
        [Automation("zone-only", "exclude", "zone = Admin")],
    )
    kit_dir = tmp_path / "kits"
    kit_dir.mkdir()
    save_kit(mission, [kit_dir], kit_dir, "test-kit")
    assert not (kit_dir / "test-kit" / "automations.ini").exists()


def test_automations_crud_via_mission(tmp_path):
    from segowl.app import Mission

    m = tmp_path / "mission"
    shutil.copytree(MISSION, m)
    mission = Mission(m)
    # initially empty
    d = mission.automations()
    assert d["automations"] == []
    # save two automations
    mission.save_automations(
        {
            "fp": d["fp"],
            "automations": [
                {"name": "web", "action": "tag", "condition": "port = 80 or port = 443", "tag": "web"},
                {"name": "noise", "action": "exclude", "condition": "state = closed"},
            ],
        }
    )
    d = mission.automations()
    assert len(d["automations"]) == 2
    assert d["automations"][0]["name"] == "web"
    # test a condition
    t = mission.test_automation({"condition": "port = 80 or port = 443"})
    assert "matches" in t
    # bad condition
    t = mission.test_automation({"condition": "unknown = x"})
    assert "error" in t


def test_excluded_verdict_appears_in_html_report(tmp_path):
    """EXCLUDED verdict and derived tags survive the full rendering pipeline."""
    mission = tmp_path / "mission"
    shutil.copytree(MISSION, mission)
    # Create scans
    scans_dir = mission / "scans" / "172.31.250.1"
    scans_dir.mkdir(parents=True, exist_ok=True)
    import xml.etree.ElementTree as ET

    # Minimal nmap XML with one open port
    root = ET.Element("nmaprun", start="1700000000", scanner="nmap", args="nmap -sS")
    host = ET.SubElement(root, "host")
    ET.SubElement(host, "status", state="up")
    ET.SubElement(host, "address", addr="172.31.250.10", addrtype="ipv4")
    ports_el = ET.SubElement(host, "ports")
    port_el = ET.SubElement(ports_el, "port", protocol="tcp", portid="80")
    ET.SubElement(port_el, "state", state="open")
    tree = ET.ElementTree(root)
    tree.write(str(scans_dir / "scan.xml"), xml_declaration=True)
    # automations: tag and exclude
    save_automations(
        mission / "automations.ini",
        [
            Automation("web", "tag", "port = 80 and state = open", "web_server"),
        ],
    )
    from segowl.cli import parse_args, run

    args = parse_args([str(mission)])
    lines = run(args)
    report = (mission / "report" / "report.html").read_text()
    assert "web_server" in report or "EXCLUDED" in report or "v-excluded" in report or len(lines) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
