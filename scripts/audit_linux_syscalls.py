#!/usr/bin/env python3
"""Audit the Linux x86-64 syscall decoder and production routing surface."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path


ENUM_RE = re.compile(r"pub enum LinuxSyscall\s*\{(?P<body>.*?)\n\}", re.DOTALL)
VARIANT_RE = re.compile(r"^\s*([A-Z][A-Za-z0-9_]*)\s*,\s*$", re.MULTILINE)
DECODE_RE = re.compile(r"(?m)^\s*(\d+)\s*=>\s*Some\(Self::([A-Za-z0-9_]+)\)")
ROUTE_RE = re.compile(r"LinuxSyscall::([A-Za-z0-9_]+)")
STUB_RE = re.compile(
    r"Some\(crate::process::abi::LinuxSyscall::([A-Za-z0-9_]+)\)\s*=>\s*linux_[a-z0-9_]*stub\(\)"
)
EXPECTED_STUBS = {"Fork", "Vfork", "InitModule", "FinitModule", "DeleteModule", "Syslog"}
SCHEDULED = {"Clone", "Execve", "Exit", "ExitGroup", "Futex", "RtSigreturn"}


class AuditError(ValueError):
    pass


@dataclass(frozen=True)
class Syscall:
    number: int
    name: str
    route: str


def parse_enum(source: str) -> set[str]:
    match = ENUM_RE.search(source)
    if match is None:
        raise AuditError("LinuxSyscall enum is missing")
    variants = set(VARIANT_RE.findall(match.group("body")))
    if not variants:
        raise AuditError("LinuxSyscall enum is empty")
    return variants


def parse_decoder(source: str) -> dict[str, int]:
    result: dict[str, int] = {}
    numbers: set[int] = set()
    for encoded, name in DECODE_RE.findall(source):
        number = int(encoded)
        if name in result:
            raise AuditError(f"duplicate decoder variant: {name}")
        if number in numbers:
            raise AuditError(f"duplicate syscall number: {number}")
        result[name] = number
        numbers.add(number)
    if not result:
        raise AuditError("Linux syscall decoder is empty")
    return result


def extract_function(source: str, signature: str) -> str:
    start = source.find(signature)
    if start < 0:
        raise AuditError(f"production syscall function is missing: {signature}")
    opening = source.find("{", start + len(signature))
    if opening < 0:
        raise AuditError(f"production syscall function has no body: {signature}")
    depth = 0
    for index in range(opening, len(source)):
        character = source[index]
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
    raise AuditError(f"production syscall function is unterminated: {signature}")


def audit(abi_source: str, syscall_source: str) -> list[Syscall]:
    variants = parse_enum(abi_source)
    decoder = parse_decoder(abi_source)
    decoded = set(decoder)
    if variants != decoded:
        missing = sorted(variants - decoded)
        extra = sorted(decoded - variants)
        raise AuditError(f"enum/decoder mismatch: missing={missing}, extra={extra}")

    direct_body = extract_function(syscall_source, "fn dispatch_linux_syscall(")
    scheduled_body = extract_function(syscall_source, 'extern "C" fn arach_syscall_dispatch(')
    direct_routes = set(ROUTE_RE.findall(direct_body))
    scheduled_routes = set(ROUTE_RE.findall(scheduled_body))
    expected_scheduled = SCHEDULED & decoded
    actual_scheduled = scheduled_routes & decoded
    if actual_scheduled != expected_scheduled:
        missing = sorted(expected_scheduled - actual_scheduled)
        extra = sorted(actual_scheduled - expected_scheduled)
        raise AuditError(f"scheduled route set changed: missing={missing}, extra={extra}")

    routed = direct_routes | scheduled_routes
    missing_routes = sorted(decoded - routed)
    if missing_routes:
        raise AuditError(f"decoded syscalls lack a production route: {missing_routes}")

    stubs = set(STUB_RE.findall(direct_body))
    expected_stubs = EXPECTED_STUBS & decoded
    if stubs != expected_stubs:
        raise AuditError(
            f"stub set changed: expected={sorted(expected_stubs)}, actual={sorted(stubs)}"
        )

    syscalls = []
    for name, number in decoder.items():
        if name in stubs:
            route = "stub"
        elif name in SCHEDULED:
            route = "scheduled"
        else:
            route = "direct"
        syscalls.append(Syscall(number=number, name=name, route=route))
    return sorted(syscalls, key=lambda item: item.number)


def write_report(path: Path, syscalls: list[Syscall]) -> None:
    if path.is_symlink():
        raise AuditError(f"report path cannot be a symlink: {path}")
    payload = {
        "format": 1,
        "architecture": "x86_64",
        "abi": "linux",
        "counts": {
            "decoded": len(syscalls),
            "direct": sum(item.route == "direct" for item in syscalls),
            "scheduled": sum(item.route == "scheduled" for item in syscalls),
            "stub": sum(item.route == "stub" for item in syscalls),
        },
        "syscalls": [
            {"number": item.number, "name": item.name, "route": item.route}
            for item in syscalls
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()
    root = arguments.root.resolve()

    try:
        abi_source = (root / "src/process/abi.rs").read_text(encoding="utf-8")
        syscall_source = (root / "src/syscalls.rs").read_text(encoding="utf-8")
        syscalls = audit(abi_source, syscall_source)
        if arguments.report is not None:
            write_report(arguments.report, syscalls)
    except (OSError, AuditError) as error:
        print(error, file=sys.stderr)
        return 1

    counts = {
        route: sum(item.route == route for item in syscalls)
        for route in ("direct", "scheduled", "stub")
    }
    print(
        f"validated {len(syscalls)} Linux x86-64 syscall routes: "
        f"{counts['direct']} direct, {counts['scheduled']} scheduled, {counts['stub']} stub"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
