"""Automations: condition → action engine for post-scan processing (GLOSSARY).

Stored in automations.ini (stdlib configparser), one section per Automation.
Two action types: tag (derive a Machine Tag) and exclude (remove observations).
"""

from __future__ import annotations

import configparser
import html
import os
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from segowl.inventory import Inventory
from segowl.nmap import HostRecord, Scan

if TYPE_CHECKING:
    from pathlib import Path

TAG_RE = re.compile(r"^[a-z0-9_-]{1,32}$")
FIELDS = {"port", "state", "protocol", "zone", "machine", "tag"}
STATES = {"open", "closed", "filtered", "unfiltered"}
PROTOCOLS = {"tcp", "udp"}
PORTABLE_FIELDS = {"port", "state", "protocol", "tag"}
MAX_LEN = 500
MAX_DEPTH = 4


# ---------------------------------------------------------------- condition parser

class ParseError(Exception):
    pass


def _tokenize(text: str) -> list[str]:
    """Split a condition into tokens: words, operators, parentheses, quoted strings."""
    tokens: list[str] = []
    i, n = 0, len(text)
    while i < n:
        if text[i].isspace():
            i += 1
        elif text[i] == '"':
            j = text.index('"', i + 1) if '"' in text[i + 1:] else n
            tokens.append(text[i + 1:j])
            i = j + 1
        elif text[i] in '()':
            tokens.append(text[i])
            i += 1
        elif text[i:i + 2] == '!=':
            tokens.append('!=')
            i += 2
        elif text[i] == '=':
            tokens.append('=')
            i += 1
        else:
            j = i
            while j < n and text[j] not in ' \t"()=' and text[j:j + 2] != '!=':
                j += 1
            tokens.append(text[i:j])
            i = j
    return tokens


@dataclass
class _Parser:
    tokens: list[str]
    pos: int = 0
    depth: int = 0
    fields_used: set[str] = field(default_factory=set)

    def peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def eat(self, expected: str | None = None) -> str:
        t = self.peek()
        if t is None:
            raise ParseError("unexpected end of condition")
        if expected is not None and t != expected:
            raise ParseError(f"expected {expected!r}, got {t!r}")
        self.pos += 1
        return t

    def parse_or(self):
        left = self.parse_and()
        while self.peek() == "or":
            self.eat("or")
            right = self.parse_and()
            a, b = left, right
            left = lambda obs, _a=a, _b=b: _a(obs) or _b(obs)
        return left

    def parse_and(self):
        left = self.parse_atom()
        while self.peek() == "and":
            self.eat("and")
            right = self.parse_atom()
            a, b = left, right
            left = lambda obs, _a=a, _b=b: _a(obs) and _b(obs)
        return left

    def parse_atom(self):
        t = self.peek()
        if t == "(":
            self.depth += 1
            if self.depth > MAX_DEPTH:
                raise ParseError(f"nesting depth > {MAX_DEPTH}")
            self.eat("(")
            node = self.parse_or()
            self.eat(")")
            self.depth -= 1
            return node
        f = self.eat()
        if f.lower() not in FIELDS:
            raise ParseError(f"unknown field {f!r}")
        f = f.lower()
        self.fields_used.add(f)
        op = self.eat()
        if op not in ("=", "!="):
            raise ParseError(f"unknown operator {op!r}")
        val = self.eat()
        return _comparison(f, op, val)


def _comparison(f: str, op: str, val: str):
    if f == "port":
        try:
            pval = int(val)
        except ValueError:
            raise ParseError(f"port must be an integer, got {val!r}") from None
        if not 1 <= pval <= 65535:
            raise ParseError(f"port must be 1–65535, got {pval}")
        if op == "=":
            return lambda obs, _v=pval: obs["port"] == _v
        return lambda obs, _v=pval: obs["port"] != _v
    if f == "state":
        v = val.lower()
        if v not in STATES:
            raise ParseError(f"state must be one of {STATES}, got {val!r}")
        if op == "=":
            return lambda obs, _v=v: obs["state"] == _v
        return lambda obs, _v=v: obs["state"] != _v
    if f == "protocol":
        v = val.lower()
        if v not in PROTOCOLS:
            raise ParseError(f"protocol must be tcp or udp, got {val!r}")
        if op == "=":
            return lambda obs, _v=v: obs["protocol"] == _v
        return lambda obs, _v=v: obs["protocol"] != _v
    # zone, machine, tag: string comparison
    if op == "=":
        return lambda obs, _f=f, _v=val: _v in obs[_f] if _f == "tag" else obs[_f] == _v
    return lambda obs, _f=f, _v=val: _v not in obs[_f] if _f == "tag" else obs[_f] != _v


def parse_condition(text: str) -> tuple[callable, set[str]]:
    """Parse a condition string into (predicate, fields_used).

    The predicate takes a dict with keys: port, state, protocol, zone, machine, tag (list[str]).
    """
    text = text.strip()
    if not text:
        raise ParseError("empty condition")
    if len(text) > MAX_LEN:
        raise ParseError(f"condition too long ({len(text)} > {MAX_LEN})")
    tokens = _tokenize(text)
    if not tokens:
        raise ParseError("empty condition")
    p = _Parser(tokens)
    pred = p.parse_or()
    if p.pos < len(p.tokens):
        raise ParseError(f"unexpected token {p.tokens[p.pos]!r}")
    return pred, p.fields_used


def is_portable(fields_used: set[str]) -> bool:
    return fields_used <= PORTABLE_FIELDS


# ---------------------------------------------------------------- Automation data

@dataclass
class Automation:
    name: str
    action: str  # "tag" or "exclude"
    condition: str
    tag: str = ""  # only for action=tag

    def safe_name(self) -> str:
        return html.escape(self.name)

    def safe_condition(self) -> str:
        return html.escape(self.condition)


def load_automations(path: str | Path) -> list[Automation]:
    """Read automations.ini; returns [] when the file does not exist."""
    path = str(path)
    if not os.path.isfile(path):
        return []
    cp = configparser.ConfigParser(interpolation=None)
    cp.read(path, encoding="utf-8")
    out: list[Automation] = []
    for name in cp.sections():
        s = cp[name]
        action = s.get("action", "").lower()
        if action not in ("tag", "exclude"):
            raise ValueError(f"[!] automations.ini [{name}]: action must be tag or exclude, not {action!r}")
        condition = s.get("condition", "").strip()
        if not condition:
            raise ValueError(f"[!] automations.ini [{name}]: missing condition")
        tag = s.get("tag", "").strip()
        if action == "tag":
            if not tag:
                raise ValueError(f"[!] automations.ini [{name}]: tag action requires a tag name")
            if not TAG_RE.match(tag):
                raise ValueError(f"[!] automations.ini [{name}]: invalid tag {tag!r}")
        try:
            parse_condition(condition)
        except ParseError as e:
            raise ValueError(f"[!] automations.ini [{name}]: {e}") from None
        out.append(Automation(name, action, condition, tag))
    return out


def save_automations(path: str | Path, automations: list[Automation]) -> None:
    """Write automations.ini from a list of Automations."""
    cp = configparser.ConfigParser(interpolation=None)
    for a in automations:
        cp.add_section(a.name)
        cp.set(a.name, "action", a.action)
        cp.set(a.name, "condition", a.condition)
        if a.action == "tag" and a.tag:
            cp.set(a.name, "tag", a.tag)
    tmp = str(path) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        cp.write(fh)
    os.replace(tmp, str(path))


# ---------------------------------------------------------------- observation extraction

def extract_observations(inv: Inventory, scans: dict) -> list[dict]:
    """Build the flat list of observations from parsed scans.

    Each observation: {source, target, port, protocol, state, zone, machine, tag}.
    tag is a list[str] of manual tags (from Host.extra["tags"]).
    """
    obs: list[dict] = []
    for src, scan_list in scans.items():
        if src not in inv:
            continue
        self_machine = inv[src].machine
        for sc in scan_list:
            for dip, rec in sc.hosts.items():
                if dip not in inv:
                    continue
                dst = inv[dip]
                if dst.machine == self_machine:
                    continue
                tags = [t.strip() for t in dst.extra.get("tags", "").split(",") if t.strip()]
                for port, proto, state in rec.ports:
                    obs.append({
                        "source": src,
                        "target": dip,
                        "port": port,
                        "protocol": proto,
                        "state": state,
                        "zone": dst.zone,
                        "machine": dst.machine,
                        "tag": tags,
                    })
                # grouped ports (rec.rest): a state like "closed" covering a range of ports
                for proto, ranges, state in rec.rest:
                    obs.append({
                        "source": src,
                        "target": dip,
                        "port": 0,  # sentinel: grouped ports have no single port number
                        "protocol": proto,
                        "state": state,
                        "zone": dst.zone,
                        "machine": dst.machine,
                        "tag": tags,
                        "_grouped": True,
                    })
    return obs


# ---------------------------------------------------------------- engine

@dataclass
class AutomationResult:
    derived_tags: dict[str, set[str]]  # machine -> derived tags
    excluded: set[tuple[str, str, int, str]]  # (source, target, port, protocol) to exclude
    excluded_grouped: set[tuple[str, str, str]]  # (source, target, protocol) grouped-ports exclusions
    warnings: list[str]


def run_automations(
    automations: list[Automation],
    inv: Inventory,
    scans: dict,
) -> AutomationResult:
    """Run all automations: tags first, then exclusions. Returns derived tags and exclusions."""
    observations = extract_observations(inv, scans)
    derived_tags: dict[str, set[str]] = {}
    excluded: set[tuple[str, str, int, str]] = set()
    excluded_grouped: set[tuple[str, str, str]] = set()
    warnings: list[str] = []

    # phase 1: tag automations on raw observations
    tag_autos = [a for a in automations if a.action == "tag"]
    for a in tag_autos:
        pred, _ = parse_condition(a.condition)
        matched_machines: set[str] = set()
        for obs in observations:
            if pred(obs):
                matched_machines.add(obs["machine"])
        for m in matched_machines:
            derived_tags.setdefault(m, set()).add(a.tag)

    # phase 2: exclusion automations (manual tags only, no chaining per spec rule 6)
    excl_autos = [a for a in automations if a.action == "exclude"]
    open_excluded = 0
    for a in excl_autos:
        pred, _ = parse_condition(a.condition)
        for obs in observations:
            if pred(obs):
                if obs.get("_grouped"):
                    excluded_grouped.add((obs["source"], obs["target"], obs["protocol"]))
                else:
                    excluded.add((obs["source"], obs["target"], obs["port"], obs["protocol"]))
                if obs["state"] == "open":
                    open_excluded += 1

    if open_excluded:
        warnings.append(
            f"Exclusion Automations mask {open_excluded} open-port observation(s): "
            f"this hides Findings and Pivot Machines."
        )

    return AutomationResult(derived_tags, excluded, excluded_grouped, warnings)


def filter_scans(
    scans: dict[str, list[Scan]],
    result: AutomationResult,
) -> dict[str, list[Scan]]:
    """Return a copy of scans with excluded observations removed from HostRecords.

    Grouped-port exclusions (rec.rest / rec.ignored) are removed when the whole protocol
    is excluded for that (source, target) pair.
    """
    if not result.excluded and not result.excluded_grouped:
        return scans
    out: dict[str, list[Scan]] = {}
    for src, scan_list in scans.items():
        new_list = []
        for sc in scan_list:
            new_hosts: dict[str, HostRecord] = {}
            for dip, rec in sc.hosts.items():
                ports = [
                    (p, proto, st)
                    for p, proto, st in rec.ports
                    if (src, dip, p, proto) not in result.excluded
                ]
                rest = [
                    (proto, ranges, st)
                    for proto, ranges, st in rec.rest
                    if (src, dip, proto) not in result.excluded_grouped
                ]
                ignored = rec.ignored if not any(
                    (src, dip, proto) in result.excluded_grouped
                    for proto, _, _ in rec.rest
                ) else []
                new_hosts[dip] = HostRecord(
                    state=rec.state,
                    name=rec.name,
                    ports=ports,
                    ignored=ignored,
                    rest=rest,
                )
            new_list.append(Scan(
                path=sc.path,
                source=sc.source,
                command=sc.command,
                started=sc.started,
                start_ts=sc.start_ts,
                pn=sc.pn,
                coverage=sc.coverage,
                hosts=new_hosts,
            ))
        out[src] = new_list
    return out


def had_observations(scans: dict[str, list[Scan]], inv: Inventory) -> set[tuple[str, str]]:
    """(source, target) pairs that had at least one port observation in the raw scans."""
    pairs: set[tuple[str, str]] = set()
    for src, scan_list in scans.items():
        if src not in inv:
            continue
        for sc in scan_list:
            for dip, rec in sc.hosts.items():
                if dip in inv and (rec.ports or rec.rest):
                    pairs.add((src, dip))
    return pairs
