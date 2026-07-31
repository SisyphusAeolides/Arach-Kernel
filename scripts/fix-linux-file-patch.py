#!/usr/bin/env python3
from pathlib import Path

path = Path("scripts/patch-linux-file-syscalls.py")
text = path.read_text(encoding="utf-8")
old = "'#[cfg(target_os = \"none\")]\\nfn linux_eventfd2(arguments: [u64; 6]) -> isize {'"
new = "'fn linux_eventfd2(arguments: [u64; 6]) -> isize {'"
if text.count(old) != 1:
    raise SystemExit("unexpected linux_eventfd2 patch boundary")
path.write_text(text.replace(old, new), encoding="utf-8")
