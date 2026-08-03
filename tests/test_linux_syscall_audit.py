from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "audit_linux_syscalls.py"
SPEC = importlib.util.spec_from_file_location("audit_linux_syscalls", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def abi_source(entries: list[tuple[int, str]]) -> str:
    variants = "\n".join(f"    {name}," for _, name in entries)
    decoder = "\n".join(f"            {number} => Some(Self::{name})," for number, name in entries)
    return f"""
pub enum LinuxSyscall {{
{variants}
}}
impl LinuxSyscall {{
    pub const fn from_number(number: usize) -> Option<Self> {{
        match number {{
{decoder}
            _ => None,
        }}
    }}
}}
"""


def syscall_source(direct: str, scheduled: str = "", extra: str = "") -> str:
    return f"""
fn dispatch_linux_syscall(number: usize, arguments: [u64; 6]) -> isize {{
    match crate::process::abi::LinuxSyscall::from_number(number) {{
{direct}
        _ => -38,
    }}
}}

extern "C" fn arach_syscall_dispatch(frame: *mut SyscallFrame) {{
    match crate::process::abi::LinuxSyscall::from_number(0) {{
{scheduled}
        _ => (),
    }}
}}

{extra}
"""


class LinuxSyscallAuditTests(unittest.TestCase):
    def test_accepts_explicit_direct_scheduled_and_stub_routes(self) -> None:
        entries = [(0, "Read"), (56, "Clone"), (57, "Fork"), (58, "Vfork")]
        direct = """
        Some(crate::process::abi::LinuxSyscall::Read) => linux_read(arguments),
        Some(crate::process::abi::LinuxSyscall::Fork) => linux_fork_stub(),
        Some(crate::process::abi::LinuxSyscall::Vfork) => linux_fork_stub(),
"""
        scheduled = """
        Some(crate::process::abi::LinuxSyscall::Clone) => schedule_clone(),
"""
        result = MODULE.audit(abi_source(entries), syscall_source(direct, scheduled))
        self.assertEqual(
            [(item.name, item.route) for item in result],
            [("Read", "direct"), ("Clone", "scheduled"), ("Fork", "stub"), ("Vfork", "stub")],
        )

    def test_rejects_enum_decoder_drift(self) -> None:
        source = abi_source([(0, "Read")]).replace("    Read,\n", "    Read,\n    Write,\n")
        with self.assertRaisesRegex(MODULE.AuditError, "enum/decoder mismatch"):
            MODULE.audit(source, syscall_source(""))

    def test_rejects_duplicate_numbers(self) -> None:
        source = abi_source([(0, "Read"), (1, "Write")]).replace(
            "1 => Some(Self::Write)",
            "0 => Some(Self::Write)",
        )
        with self.assertRaisesRegex(MODULE.AuditError, "duplicate syscall number"):
            MODULE.audit(source, syscall_source(""))

    def test_rejects_missing_production_route(self) -> None:
        source = abi_source([(0, "Read"), (57, "Fork"), (58, "Vfork")])
        direct = """
        Some(crate::process::abi::LinuxSyscall::Fork) => linux_fork_stub(),
        Some(crate::process::abi::LinuxSyscall::Vfork) => linux_fork_stub(),
"""
        with self.assertRaisesRegex(MODULE.AuditError, "lack a production route"):
            MODULE.audit(source, syscall_source(direct))

    def test_test_only_mention_does_not_count_as_a_route(self) -> None:
        source = abi_source([(0, "Read"), (57, "Fork"), (58, "Vfork")])
        direct = """
        Some(crate::process::abi::LinuxSyscall::Fork) => linux_fork_stub(),
        Some(crate::process::abi::LinuxSyscall::Vfork) => linux_fork_stub(),
"""
        extra = """
#[test]
fn mentions_read() {
    let _ = crate::process::abi::LinuxSyscall::Read;
}
"""
        with self.assertRaisesRegex(MODULE.AuditError, "lack a production route"):
            MODULE.audit(source, syscall_source(direct, extra=extra))

    def test_rejects_missing_scheduled_route(self) -> None:
        source = abi_source([(56, "Clone"), (57, "Fork"), (58, "Vfork")])
        direct = """
        Some(crate::process::abi::LinuxSyscall::Fork) => linux_fork_stub(),
        Some(crate::process::abi::LinuxSyscall::Vfork) => linux_fork_stub(),
"""
        with self.assertRaisesRegex(MODULE.AuditError, "scheduled route set changed"):
            MODULE.audit(source, syscall_source(direct))

    def test_rejects_unreviewed_stub_change(self) -> None:
        source = abi_source([(0, "Read"), (57, "Fork"), (58, "Vfork")])
        direct = """
        Some(crate::process::abi::LinuxSyscall::Read) => linux_fork_stub(),
        Some(crate::process::abi::LinuxSyscall::Fork) => linux_fork_stub(),
        Some(crate::process::abi::LinuxSyscall::Vfork) => linux_fork_stub(),
"""
        with self.assertRaisesRegex(MODULE.AuditError, "stub set changed"):
            MODULE.audit(source, syscall_source(direct))


if __name__ == "__main__":
    unittest.main()
