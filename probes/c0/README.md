# Arach C0 ring-3 probe

This bounded `no_std` ELF is qualification input, not a desktop or production
service. It proves that a measured ring-3 image can enter Arach, issue a write
syscall, and request a clean exit. The serial evidence gate must observe
`ARACH_C0_RING3_SYSCALL_PASS` from the exact measured bundle.

The kernel currently carries a legacy internal `crest` name for its second
boot-process slot. `ARACH_BOOTSTRAP_IMAGE` deliberately replaces that artifact
with this probe during C0 qualification; it does not promote Crest into the
COSMIC architecture.
