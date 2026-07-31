#!/usr/bin/env python3
from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, found {count}")
    return text.replace(old, new, 1)


path = Path("libraries/driver-abi/src/prometheus.rs")
text = path.read_text(encoding="utf-8")
text = replace_once(
    text,
    '''    /// Generate a MS x64 → SysV AMD64 thunk for `arg_count` arguments.
    /// Returns pointer to thunk entry point (to be called with MS x64 convention).
    /// The thunk internally calls `target_sysv` using SysV ABI.
    ///
    /// Safety: caller must ensure pool memory is executable before calling thunk.
    pub unsafe fn gen_msx64_to_sysv(''',
    '''    /// Generate a MS x64 → SysV AMD64 thunk for `arg_count` arguments.
    /// Returns pointer to thunk entry point (to be called with MS x64 convention).
    /// The thunk internally calls `target_sysv` using SysV ABI.
    ///
    /// # Safety
    ///
    /// `target_sysv` must name a valid SysV AMD64 function accepting the declared
    /// argument count. The pool must not move while the returned pointer is in
    /// use, and the integrating kernel must publish the emitted bytes through a
    /// measured W^X transition before executing them.
    pub unsafe fn gen_msx64_to_sysv(''',
    "MS x64 thunk safety contract",
)
text = replace_once(
    text,
    '''    /// Generate a SysV passthrough (no-op thunk) — used for already-compatible drivers
    pub unsafe fn gen_passthrough(&mut self, target: *const c_void) -> Option<*const c_void> {''',
    '''    /// Generate a SysV passthrough jump for an already-compatible driver.
    ///
    /// # Safety
    ///
    /// `target` must name a valid SysV AMD64 function. The pool must not move
    /// while the returned pointer is in use, and the integrating kernel must
    /// publish the emitted bytes through a measured W^X transition before use.
    pub unsafe fn gen_passthrough(&mut self, target: *const c_void) -> Option<*const c_void> {''',
    "passthrough thunk safety contract",
)
text = replace_once(
    text,
    '''    }
}

// ─────────────────────────────────────────────
// ELF SYMBOL SCANNER''',
    '''    }
}

impl Default for ThunkPool {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────
// ELF SYMBOL SCANNER''',
    "thunk pool Default",
)
text = replace_once(
    text,
    "    if &blob[0..4] != ELF_MAGIC {",
    "    if blob[0..4] != ELF_MAGIC {",
    "ELF magic comparison",
)
text = replace_once(
    text,
    '''    /// Classifies one named entry in a bounded ELF64 image and emits a thunk.
    ///
    /// The symbol value must identify its function bytes within `blob`. The
    /// returned pointer names emitted storage, not an executable mapping.
    pub unsafe fn analyze_and_bridge(''',
    '''    /// Classifies one named entry in a bounded ELF64 image and emits a thunk.
    ///
    /// The symbol value must identify its function bytes within `blob`. The
    /// returned pointer names emitted storage, not an executable mapping.
    ///
    /// # Safety
    ///
    /// `kernel_entry_sysv` must name the authenticated SysV AMD64 driver entry
    /// selected for this image. The engine must not move while the returned
    /// thunk pointer is retained, and the integrating kernel must enforce a
    /// measured W^X transition before executing emitted bytes.
    pub unsafe fn analyze_and_bridge(''',
    "Prometheus bridge safety contract",
)
text = replace_once(
    text,
    '''        TranspileResult::Success {
            convention: conv,
            entry_offset: sym.offset,
            thunk_ptr,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]''',
    '''        TranspileResult::Success {
            convention: conv,
            entry_offset: sym.offset,
            thunk_ptr,
        }
    }
}

impl Default for PrometheusEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]''',
    "Prometheus engine Default",
)
path.write_text(text, encoding="utf-8")
