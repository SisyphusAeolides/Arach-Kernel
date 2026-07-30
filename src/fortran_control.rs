//! Safe boundary for allocation-free numerical routines implemented in
//! freestanding Fortran.

use core::ffi::{c_int, c_longlong};

pub const MAXIMUM_SCORE_FEATURES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScoreError {
    LengthMismatch,
    TooManyFeatures,
    InputOutOfRange,
    ForeignFailure(i32),
}

unsafe extern "C" {
    fn arach_fortran_dot_q16(
        features: *const i32,
        weights: *const i32,
        length: c_int,
        score: *mut c_longlong,
    ) -> c_int;
}

/// Computes a fixed-point dot product without allocation or floating-point
/// state. Inputs are bounded before entering Fortran, and the Fortran routine
/// independently enforces the same contract.
pub fn dot_q16(features: &[i32], weights: &[i32]) -> Result<i64, ScoreError> {
    if features.len() != weights.len() {
        return Err(ScoreError::LengthMismatch);
    }
    if features.len() > MAXIMUM_SCORE_FEATURES {
        return Err(ScoreError::TooManyFeatures);
    }
    const LIMIT: i32 = 1 << 20;
    if features
        .iter()
        .chain(weights)
        .any(|value| !(-LIMIT..=LIMIT).contains(value))
    {
        return Err(ScoreError::InputOutOfRange);
    }

    let mut score: c_longlong = 0;
    // SAFETY: Both slices have the same validated length, remain alive for
    // the call, and the output points to initialized writable storage. The
    // foreign routine is built from the checked source in `fortran/`.
    let status = unsafe {
        arach_fortran_dot_q16(
            features.as_ptr(),
            weights.as_ptr(),
            features.len() as c_int,
            &mut score,
        )
    };
    match status {
        0 => Ok(score),
        -2 => Err(ScoreError::InputOutOfRange),
        other => Err(ScoreError::ForeignFailure(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_point_score_crosses_the_fortran_boundary() {
        assert_eq!(dot_q16(&[1 << 16, 2 << 16], &[2, -1]), Ok(0));
        assert_eq!(dot_q16(&[3, -4, 5], &[7, 2, -1]), Ok(8));
    }

    #[test]
    fn wrapper_rejects_invalid_shapes_and_ranges() {
        assert_eq!(dot_q16(&[1], &[]), Err(ScoreError::LengthMismatch));
        assert_eq!(
            dot_q16(
                &[0; MAXIMUM_SCORE_FEATURES + 1],
                &[0; MAXIMUM_SCORE_FEATURES + 1]
            ),
            Err(ScoreError::TooManyFeatures)
        );
        assert_eq!(
            dot_q16(&[(1 << 20) + 1], &[1]),
            Err(ScoreError::InputOutOfRange)
        );
    }
}
