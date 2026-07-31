#!/usr/bin/env python3
from pathlib import Path

path = Path("scripts/patch-linux-file-syscalls.py")
text = path.read_text(encoding="utf-8")
old_boundary = "'#[cfg(target_os = \"none\")]\\nfn linux_eventfd2(arguments: [u64; 6]) -> isize {'"
new_boundary = "'fn linux_eventfd2(arguments: [u64; 6]) -> isize {'"
if text.count(old_boundary) == 1:
    text = text.replace(old_boundary, new_boundary)
elif text.count(new_boundary) != 1:
    raise SystemExit("unexpected linux_eventfd2 patch boundary")

old_logic = '''    second = text.find(end, first + len(start))
    if second < 0:
        raise SystemExit(f"{label}: end marker missing")
'''
new_logic = '''    second = text.find(end, first + len(start))
    if second < 0 and label == "Linux close and file operations":
        function = text.find("fn linux_eventfd2", first + len(start))
        if function >= 0:
            attribute = text.rfind(
                '#[cfg(target_os = "none")]', first + len(start), function
            )
            second = attribute if attribute >= 0 else function
    if second < 0:
        raise SystemExit(f"{label}: end marker missing")
'''
if text.count(old_logic) != 1:
    raise SystemExit("unexpected replace_region implementation")
path.write_text(text.replace(old_logic, new_logic), encoding="utf-8")
