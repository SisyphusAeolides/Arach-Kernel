# C0 measured boot qualification

C0 is not a boolean in a manifest. It requires one exact Arach revision to
produce four measured artifacts and then execute them under UEFI/QEMU:

1. Granite UEFI loader;
2. Arach kernel;
3. Push PID 1;
4. the bounded ring-3 syscall probe in `probes/c0`.

`scripts/build-c0-bundle.sh` builds those artifacts from separate immutable
component checkouts. `ARACH_PUSH_IMAGE` and `ARACH_BOOTSTRAP_IMAGE` remove the
legacy assumption that user images exist under Arach's own target directory.
The bootstrap variable currently feeds a legacy internal slot named `crest`;
the supplied artifact is the C0 probe, not the discarded Crest desktop.

The script accepts `ARACH_PUSH_FEATURES`. Its default `os-bin` builds the
minimal probe supervisor. A desktop bundle build must set
`ARACH_PUSH_FEATURES=os-bin,cosmic-boot` only after measured COSMIC service
artifacts have been assembled; the feature selects the complete ordered
session chain and is not a substitute for those artifact measurements.

The build gate records SHA-256 for every artifact. Qualification additionally
requires a deterministic FAT/UEFI image, a bounded QEMU run, and a serial log
containing all of the following evidence from the same bundle:

- Granite admitted the measured bundle;
- Arach initialized interrupts, scheduling, ring 3, and syscall entry;
- Push reached PID 1;
- `ARACH_C0_RING3_SYSCALL_PASS` was emitted by the measured probe;
- `ARACH_C1_THREAD_FUTEX_PASS` was emitted after shared descriptor access and
  cross-thread clear-child-tid futex wake completed;
- `ARACH_C1_ROBUST_FUTEX_PASS` was emitted after exact robust-list registration,
  private-futex block, atomic `OWNER_DIED` publication, and exit-driven wake;
- `ARACH_C1_LINUX_SYSCALL_PASS` was emitted after the Linux personality
  exercised identity, anonymous memory, `brk`, shared-address-space clone,
  shared descriptor access, independent private robust-futex and
  clear-child-tid block/wake paths, kernel owner-death publication, and clean
  thread/process exit.

The execution gate is implemented in the Arach validation workflow: CI installs
QEMU/OVMF, runs this helper against the freshly assembled image, and uploads
the serial transcript. Revision `b396d3a7fc6538eacc60058d7067bebe9de43537`
is the last qualified release before the Linux-personality probe was added.
The next release must pass the complete workflow, including every measured
marker. Future releases must keep this workflow green for their exact revision;
a host build or a missing local QEMU installation never counts as qualification.

The image and execution helpers are now available:

```sh
scripts/build-c0-fat-image.sh \
  target/c0/granite/x86_64-unknown-uefi/release/granite.efi \
  target/c0/kernel/x86_64-arach/release/arach \
  target/c0/push/x86_64-arach/release/push \
  target/c0/probe/x86_64-arach/release/arach-c0-probe \
  "$PWD/target/c0/arach-c0.img"

scripts/run-c0-qemu.sh "$PWD/target/c0/arach-c0.img"
```

The runner fails with status 69 when QEMU or OVMF is unavailable and never
turns a missing execution environment into a green qualification result.
