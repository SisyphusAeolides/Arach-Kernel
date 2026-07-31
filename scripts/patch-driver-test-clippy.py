#!/usr/bin/env python3
from pathlib import Path

path = Path("libraries/driver-abi/src/prometheus.rs")
text = path.read_text(encoding="utf-8")
old = "1_usize as *const c_void"
new = "core::ptr::dangling::<c_void>()"
if text.count(old) != 1:
    raise SystemExit("unexpected driver ABI sentinel pointer")
path.write_text(text.replace(old, new), encoding="utf-8")
