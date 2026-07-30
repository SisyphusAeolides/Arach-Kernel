//! Capability-bound host tuning observations.
//!
//! A TuneD-compatible service may apply host policy, but Crest must only see
//! an authenticated observation of that transaction. This wire record is
//! deliberately small and fixed-size so a future Hermes endpoint can validate
//! it without allocating or trusting strings from a privileged service.

pub const TUNING_WIRE_VERSION: u16 = 1;
pub const MIN_THERMAL_LIMIT_MC: u32 = 20_000;
pub const MAX_THERMAL_LIMIT_MC: u32 = 200_000;

pub mod state {
    pub const UNKNOWN: u8 = 0;
    pub const APPLIED: u8 = 1;
    pub const ROLLED_BACK: u8 = 2;
    pub const REJECTED: u8 = 3;
}

pub mod gpu_policy {
    pub const OBSERVE: u8 = 0;
    pub const BALANCED: u8 = 1;
    pub const PERFORMANCE: u8 = 2;
    pub const POWER_SAVE: u8 = 3;
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TuningProfileLease {
    pub version: u16,
    pub state: u8,
    pub reserved: u8,
    pub generation: u64,
    pub capability: u64,
    /// SHA-256 of the profile and platform-census inputs used to apply it.
    pub profile_hash: [u8; 32],
    pub cpu_governor: u8,
    pub gpu_policy: u8,
    pub network_policy: u8,
    pub flags: u8,
    pub thermal_limit_mc: u32,
}

impl TuningProfileLease {
    pub const fn valid(self) -> bool {
        self.version == TUNING_WIRE_VERSION
            && matches!(
                self.state,
                state::APPLIED | state::ROLLED_BACK | state::REJECTED
            )
            && self.reserved == 0
            && self.generation != 0
            && self.capability != 0
            && !is_zero_hash(self.profile_hash)
            && self.cpu_governor <= 3
            && self.gpu_policy <= gpu_policy::POWER_SAVE
            && self.network_policy <= 3
            && self.thermal_limit_mc >= MIN_THERMAL_LIMIT_MC
            && self.thermal_limit_mc <= MAX_THERMAL_LIMIT_MC
    }

    pub const fn is_usable(self) -> bool {
        self.valid() && self.state == state::APPLIED
    }

    /// Validates a lease against the generation that Hermes/Aegis currently
    /// admits.  A well-formed record from an older transaction is still stale
    /// and must not reach Crest's settings surface.
    pub const fn valid_for_generation(self, expected_generation: u64) -> bool {
        expected_generation != 0 && self.valid() && self.generation == expected_generation
    }

    pub const fn is_usable_for_generation(self, expected_generation: u64) -> bool {
        self.valid_for_generation(expected_generation) && self.state == state::APPLIED
    }
}

const fn is_zero_hash(hash: [u8; 32]) -> bool {
    let mut index = 0;
    while index < hash.len() {
        if hash[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}

const _: () = assert!(core::mem::size_of::<TuningProfileLease>() == 64);

#[cfg(test)]
mod tests {
    use super::*;

    fn applied() -> TuningProfileLease {
        TuningProfileLease {
            version: TUNING_WIRE_VERSION,
            state: state::APPLIED,
            reserved: 0,
            generation: 9,
            capability: 17,
            profile_hash: [0xA5; 32],
            cpu_governor: 1,
            gpu_policy: gpu_policy::BALANCED,
            network_policy: 1,
            flags: 0,
            thermal_limit_mc: 85_000,
        }
    }

    #[test]
    fn authenticated_applied_profile_is_usable() {
        let profile = applied();
        assert!(profile.valid());
        assert!(profile.is_usable());
    }

    #[test]
    fn invalid_or_rolled_back_profile_fails_closed() {
        let profile = applied();
        assert!(
            !TuningProfileLease {
                profile_hash: [0; 32],
                ..profile
            }
            .valid()
        );
        assert!(
            !TuningProfileLease {
                state: state::ROLLED_BACK,
                ..profile
            }
            .is_usable()
        );
        assert!(
            !TuningProfileLease {
                thermal_limit_mc: MAX_THERMAL_LIMIT_MC + 1,
                ..profile
            }
            .valid()
        );
        assert!(
            !TuningProfileLease {
                reserved: 1,
                ..profile
            }
            .valid()
        );
    }

    #[test]
    fn stale_generation_cannot_be_used_as_a_current_observation() {
        let profile = applied();
        assert!(profile.valid_for_generation(9));
        assert!(profile.is_usable_for_generation(9));
        assert!(!profile.valid_for_generation(8));
        assert!(!profile.valid_for_generation(0));
        assert!(
            !TuningProfileLease {
                state: state::ROLLED_BACK,
                ..profile
            }
            .is_usable_for_generation(9)
        );
    }
}
