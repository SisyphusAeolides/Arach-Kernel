#!/usr/bin/env python3
from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, found {count}")
    return text.replace(old, new, 1)


root = Path(__file__).resolve().parents[1]

build_path = root / "build.rs"
build = build_path.read_text(encoding="utf-8")
old_call = '''        verify_formal_attestation(
            &workspace,
            driver_digest,
            package_digest,
            crucible_digest,
            aegis_digest,
            argus_markup_digest,
            granite_boot_digest,
            hermes_authority_digest,
            crest_shell_digest,
            privilege_digest,
            argus_layout_digest,
            granite_layout_digest,
            hermes_wire_digest,
            crest_overlay_digest,
            cosmic_compatibility_digest,
            cosmic_stack_digest,
            linux_contract_idris_digest,
            linux_contract_agda_digest,
        );'''
new_call = '''        verify_formal_attestation(
            &workspace,
            [
                driver_digest,
                package_digest,
                crucible_digest,
                aegis_digest,
                argus_markup_digest,
                granite_boot_digest,
                hermes_authority_digest,
                crest_shell_digest,
                privilege_digest,
                argus_layout_digest,
                granite_layout_digest,
                hermes_wire_digest,
                crest_overlay_digest,
                cosmic_compatibility_digest,
                cosmic_stack_digest,
                linux_contract_idris_digest,
                linux_contract_agda_digest,
            ],
        );'''
build = replace_once(build, old_call, new_call, "formal attestation call")

start = build.find("fn verify_formal_attestation(")
end = build.find("struct BootProcessPackage", start)
if start < 0 or end < 0:
    raise SystemExit("formal attestation function region is missing")
region = build[start:end]
closing = region.find(") {")
if closing < 0:
    raise SystemExit("formal attestation signature terminator is missing")
region = (
    "fn verify_formal_attestation(workspace: &Path, digests: [[u8; 32]; 17]) {"
    + region[closing + 3 :]
)
names = [
    "driver_digest",
    "package_digest",
    "crucible_digest",
    "aegis_digest",
    "argus_markup_digest",
    "granite_boot_digest",
    "hermes_authority_digest",
    "crest_shell_digest",
    "privilege_digest",
    "argus_layout_digest",
    "granite_layout_digest",
    "hermes_wire_digest",
    "crest_overlay_digest",
    "cosmic_compatibility_digest",
    "cosmic_stack_digest",
    "linux_contract_idris_digest",
    "linux_contract_agda_digest",
]
for index, name in enumerate(names):
    old = f"encode_sha256({name})"
    if region.count(old) != 1:
        raise SystemExit(f"formal digest {name} does not occur exactly once")
    region = region.replace(old, f"encode_sha256(digests[{index}])")
build = build[:start] + region + build[end:]
build_path.write_text(build, encoding="utf-8")

resonance_path = root / "core/aether/src/resonance_split.rs"
resonance = resonance_path.read_text(encoding="utf-8")
resonance = replace_once(
    resonance,
    '''    pub fn overwritten_frames(&self) -> u64 {
        self.core.overwritten_frames.load(Ordering::Acquire)
    }
}

#[repr(C, align(64))]
struct ObservationCore {''',
    '''    pub fn overwritten_frames(&self) -> u64 {
        self.core.overwritten_frames.load(Ordering::Acquire)
    }
}

impl Default for ResonanceIngressPage {
    fn default() -> Self {
        Self::new()
    }
}

#[repr(C, align(64))]
struct ObservationCore {''',
    "ingress page Default",
)
resonance = replace_once(
    resonance,
    '''    pub fn reply_publications(&self) -> u64 {
        self.core.reply_publications.load(Ordering::Acquire)
    }
}

fn encode_wire<T: Wire64>(value: &T) -> [u64; 8] {''',
    '''    pub fn reply_publications(&self) -> u64 {
        self.core.reply_publications.load(Ordering::Acquire)
    }
}

impl Default for ResonanceObservationPage {
    fn default() -> Self {
        Self::new()
    }
}

fn encode_wire<T: Wire64>(value: &T) -> [u64; 8] {''',
    "observation page Default",
)
resonance_path.write_text(resonance, encoding="utf-8")

memory_path = root / "libraries/slope/src/memory/mod.rs"
memory = memory_path.read_text(encoding="utf-8")
memory = replace_once(
    memory,
    '''        for i in 0..word_count.min(BITMASK_WORDS) {
            mask[i] = u64::MAX;
        }''',
    '''        for word in mask.iter_mut().take(word_count.min(BITMASK_WORDS)) {
            *word = u64::MAX;
        }''',
    "slab free-mask initialization",
)
memory = replace_once(
    memory,
    ".fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {",
    ".try_update(Ordering::AcqRel, Ordering::Acquire, |current| {",
    "atomic page cursor update",
)
memory = replace_once(
    memory,
    '''    pub fn stats(&self) -> HeapStats {
        // Try to observe — if busy, return zeros (non-blocking)
        // SAFETY: cell is process-local here; lock is a spinlock
        let pair = unsafe { crate::sync::entanglement::EntangledPair::from_mapping(&self.cell, 0) };
        pair.try_observe(|h| HeapStats {
            alloc_count: h.alloc_count,
            dealloc_count: h.dealloc_count,
            oom_count: h.oom_count,
        })
        .unwrap_or(HeapStats {
            alloc_count: 0,
            dealloc_count: 0,
            oom_count: 0,
        })
    }
}

#[derive(Clone, Copy, Debug)]''',
    '''    pub fn stats(&self) -> HeapStats {
        // Try to observe — if busy, return zeros (non-blocking)
        // SAFETY: cell is process-local here; lock is a spinlock
        let pair = unsafe { crate::sync::entanglement::EntangledPair::from_mapping(&self.cell, 0) };
        pair.try_observe(|h| HeapStats {
            alloc_count: h.alloc_count,
            dealloc_count: h.dealloc_count,
            oom_count: h.oom_count,
        })
        .unwrap_or(HeapStats {
            alloc_count: 0,
            dealloc_count: 0,
            oom_count: 0,
        })
    }
}

impl Default for GlobalSlabHeap {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug)]''',
    "global slab heap Default",
)
memory_path.write_text(memory, encoding="utf-8")

executor_path = root / "libraries/slope/src/executor.rs"
executor = executor_path.read_text(encoding="utf-8")
executor = replace_once(
    executor,
    '''    pub const fn task_count(&self) -> usize {
        self.count
    }
}

// ─── CEREBRAL SPAWNER ABI''',
    '''    pub const fn task_count(&self) -> usize {
        self.count
    }
}

impl Default for OuroborosExecutor {
    fn default() -> Self {
        Self::new()
    }
}

// ─── CEREBRAL SPAWNER ABI''',
    "Ouroboros executor Default",
)
executor_path.write_text(executor, encoding="utf-8")

fabric_path = root / "libraries/slope/src/fabric.rs"
fabric = fabric_path.read_text(encoding="utf-8")
fabric = replace_once(
    fabric,
    '''/// Called by the kernel on the new thread. Extracts args, runs F, exits.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _fabric_trampoline(args_ptr: *mut u8) -> ! {''',
    '''/// Called by the kernel on the new thread. Extracts args, runs F, exits.
///
/// # Safety
///
/// `args_ptr` must be non-null, properly aligned, and point to an initialized
/// `FiberArgs` whose closure and outcome storage remain valid for the lifetime
/// of this thread. The pointed-to closure must match its erased entry function.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _fabric_trampoline(args_ptr: *mut u8) -> ! {''',
    "fabric trampoline safety contract",
)
fabric = replace_once(
    fabric,
    '''    pub const fn live_count(&self) -> usize {
        self.count
    }
}

#[cfg(test)]''',
    '''    pub const fn live_count(&self) -> usize {
        self.count
    }
}

impl Default for FabricWeave {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]''',
    "fabric weave Default",
)
fabric_path.write_text(fabric, encoding="utf-8")

hypermedia_path = root / "libraries/slope/src/hypermedia.rs"
hypermedia = hypermedia_path.read_text(encoding="utf-8")
hypermedia = replace_once(
    hypermedia,
    '''    /// Imports a trust decision made by the authenticated Boulder/Hermes
    /// broker. A zero fingerprint or generation is never a valid authority.
    pub unsafe fn from_broker(''',
    '''    /// Imports a trust decision made by the authenticated Boulder/Hermes
    /// broker. A zero fingerprint or generation is never a valid authority.
    ///
    /// # Safety
    ///
    /// The caller must have received all three values from the authenticated
    /// broker after certificate-chain, hostname, and origin validation. Values
    /// assembled from untrusted application input must never enter this API.
    pub unsafe fn from_broker(''',
    "broker trust-anchor safety contract",
)
hypermedia_path.write_text(hypermedia, encoding="utf-8")

signal_path = root / "libraries/slope/src/signal.rs"
signal = signal_path.read_text(encoding="utf-8")
signal = replace_once(
    signal,
    '''    pub fn install(&self, trampoline: usize) -> Result<(), SyscallError> {
        let args = [trampoline, self as *const Self as usize, 0, 0, 0, 0];
        unsafe { syscall(SYS_SIGNAL_DELIVER, args) }.map(|_| ())
    }
}

/// The kernel calls this. It dispatches into the matrix.
/// # Safety: called from kernel context — no Rust stack unwinding.
#[unsafe(no_mangle)]''',
    '''    pub fn install(&self, trampoline: usize) -> Result<(), SyscallError> {
        let args = [trampoline, self as *const Self as usize, 0, 0, 0, 0];
        unsafe { syscall(SYS_SIGNAL_DELIVER, args) }.map(|_| ())
    }
}

impl Default for CoronalMatrix {
    fn default() -> Self {
        Self::new()
    }
}

/// The kernel calls this. It dispatches into the matrix.
///
/// # Safety
///
/// Both pointers must be non-null, properly aligned, and point to initialized
/// values that remain valid for the duration of the call. The trampoline runs
/// in kernel delivery context and must not unwind across the ABI boundary.
#[unsafe(no_mangle)]''',
    "coronal matrix Default and trampoline safety contract",
)
signal_path.write_text(signal, encoding="utf-8")

slope_lib_path = root / "libraries/slope/src/lib.rs"
slope_lib = slope_lib_path.read_text(encoding="utf-8")
slope_lib = replace_once(
    slope_lib,
    '''/// Executes Sisyphus's six-register syscall ABI only in a native Sisyphus
/// image. Host builds must never accidentally interpret these numbers as the
/// host kernel's unrelated syscall table.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]''',
    '''/// Executes Sisyphus's six-register syscall ABI only in a native Sisyphus
/// image. Host builds must never accidentally interpret these numbers as the
/// host kernel's unrelated syscall table.
///
/// # Safety
///
/// The caller must satisfy the selected syscall's pointer, length, ownership,
/// and lifetime contract. Invalid user pointers or mismatched argument layouts
/// can violate memory safety before the kernel can reject the request.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]''',
    "native syscall safety contract",
)
slope_lib = replace_once(
    slope_lib,
    '''#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub unsafe fn syscall''',
    '''/// Fail-closed host implementation of the native syscall ABI.
///
/// # Safety
///
/// The same call-site contract as the native implementation applies even
/// though this host stub never dereferences arguments and always returns
/// `ENOSYS`.
#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub unsafe fn syscall''',
    "host syscall safety contract",
)
slope_lib_path.write_text(slope_lib, encoding="utf-8")
