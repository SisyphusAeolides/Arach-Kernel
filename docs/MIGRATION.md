# Sisyphus-OS migration plan

Sisyphus-OS is the source repository for Arach and its future component
repositories. It remains read-only migration input until the retirement gate at
the end of this document passes.

## Inventory

| Sisyphus-OS path | Destination | Current state |
|---|---|---|
| `kernel/boulder/` | `Arach-Kernel` | Source imported and renamed; host requalification in progress |
| `core/*` | Separate core repositories, temporarily integrated in Arach | Imported snapshot |
| `libraries/driver-abi/` | Driver ABI repository | Imported snapshot |
| `libraries/slope/` | Retired legacy ABI | Removed from the Arach Kernel workspace |
| `boot/granite/` | Retired legacy firmware loader | Removed from the ArachOS boot path |
| `userland/push/` | Retired legacy PID 1 | Replaced by RustD |
| `userland/corinth/` | `Corinth` | Standalone repository established and pinned by ArachOS |
| `userland/crest/` | Explicit discard from the production desktop | Retained only as migration input; not on the COSMIC critical path |
| `userland/cerebral/` | Cerebral repository | Not migrated |
| `userland/crest-wayland/` | Crest Wayland experiment repository | Not migrated |
| `tools/reality-gate/` | Qualification tooling repository | Not migrated |
| `scripts/`, `docs/`, `assets/`, target JSON | Appropriate component repositories | Partially migrated |

Repository names are provisional until the split is approved. Use history
filtering (`git filter-repo` or subtree split) so authorship and commit identity
are retained; do not create repositories by copying only the latest files.

## Dependency direction

```text
Limine ──measured Multiboot2 modules────► Arach Kernel
                                │
Driver ABI ◄────────────────────┤
                                ├──► RustD PID 1
                                │         │
                                │         └──► ArachOS services
                                └────────────► Linux ABI/device compatibility

Idris/Agda specifications ──verified manifests──► all release gates
Fortran numerical kernels ──freestanding C ABI──► Arach safe wrappers
```

Component repositories must pin released dependencies by immutable tag and
digest. Local path dependencies are allowed only in an explicit integration
workspace.

Existing external projects—libinput-rs, elan-guardian, tuned-rs and ccze-rs—
remain separate and are integrated through the contracts in
[`SYSTEM_COMPONENTS.md`](SYSTEM_COMPONENTS.md). They are not copied into the
kernel repository.

## Retirement gate

Sisyphus-OS may be archived only after all of these are mechanically checked:

1. every tracked source, document, script, asset, issue, release, and tag has a
   recorded destination or an explicit discard decision;
2. every destination contains preserved history, license information, and a
   successful standalone CI run;
3. a clean integration checkout can build without reading Sisyphus-OS;
4. Arach boots through Limine and launches the measured RustD artifact;
5. the migration manifest maps retained commit IDs to destination commit IDs;
6. the old repository README points to every new home or records the explicit
   retirement decision.

Archive the old repository before considering deletion. Archival preserves
links and provenance while preventing accidental new development.
