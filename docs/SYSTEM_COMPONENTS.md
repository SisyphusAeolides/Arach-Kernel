# System component integration

Arach consumes these projects as independently released components. Their
repositories remain authoritative until the final integration monorepo is
created.

| Component | Initial pin | Arach/COSMIC role |
|---|---:|---|
| [libinput-rs](https://github.com/SisyphusAeolides/libinput-rs) | `v0.3.1` | COSMIC-compatible `libinput.so.10`, input tools and behavioral parity suite |
| [elan-guardian](https://github.com/SisyphusAeolides/elan-guardian) | `v0.2.2` | ELAN transport and consumer-stall evidence, recovery policy and diagnostics |
| [tuned-rs](https://github.com/SisyphusAeolides/tuned-rs) | release required after `v0.2.5` | system performance, thermal, storage, network, GPU and battery policy |
| [ccze-rs](https://github.com/SisyphusAeolides/ccze-rs) | release required after `v0.4.0` | bounded log rendering and operator diagnostics |

Pins advance only through integration CI. Branch heads are not release inputs.

## libinput-rs

Arach must provide the Linux interfaces libinput-rs and COSMIC observe:

- evdev event streams and complete ioctl semantics;
- udev-style properties, device groups, seats and hotplug;
- `poll`/`epoll`, monotonic clocks and timer readiness;
- permissions, restricted-open behavior and stable object lifetime;
- touchpad, mouse, TrackPoint, keyboard, switch, tablet and tablet-pad devices.

The current kernel bring-up provides the first bounded Linux wake object:
process-owned `eventfd2` descriptors support counter and semaphore reads,
eight-byte writes, close, ownership validation, and non-sleeping `EAGAIN` on
an empty read. `poll`/`epoll`, timerfd, and ordinary device descriptors remain
separate qualification work; they must not be treated as implemented merely
because their syscall numbers decode.

The gate runs upstream libinput behavioral tests plus COSMIC compositor tests.
No companion process may grab a physical device in the parity path.

## elan-guardian

On Linux, elan-guardian may monitor the kernel watchdog, sysfs, procfs and the
registered libinput consumer descriptors. Arach integration has two layers:

1. port the transport watchdog and hard-reset/re-enumeration hook to Arach's
   native ELAN I2C driver;
2. keep the userspace recorder, status command and evidence format compatible
   through Arach's Linux `/proc`, `/sys`, pidfd and device interfaces.

Recovery tests must inject bus silence, IRQ silence, dead event nodes and a
consumer that stops draining. Recovery must preserve seat identity, release
held keys/buttons, reannounce devices once, and avoid reset loops.

## tuned-rs

tuned-rs remains a userspace policy service. Its Arach backend must map each
plugin onto explicit kernel facilities such as CPU frequency policy, scheduler
classes, power caps, hwmon/thermal zones, block queues, network queues, GPU
policy and battery thresholds. Unsupported writes return an error rather than
success.

COSMIC power settings and tuned-rs need one authority owner and a documented
D-Bus contract so competing daemons cannot oscillate a profile.

## ccze-rs

ccze-rs remains an unprivileged userspace tool. It qualifies standard streams,
PTY behavior, Unicode terminals, journal/follow mode, backpressure and bounded
memory. It is part of recovery and CI diagnostics, not a kernel dependency.

## Integration manifest

The future system integration repository will carry an immutable manifest with
repository URL, signed tag, commit, source digest, ABI version and required
test suite for every component. Arach itself stores only the interface contract
and minimum compatible versions.
