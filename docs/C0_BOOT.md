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
- `ARACH_C0_RING3_SYSCALL_PASS` was emitted by the measured probe.

Until that execution gate is implemented and green, C0 remains incomplete.
