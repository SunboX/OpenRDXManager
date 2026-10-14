// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Opaque SDK token/logon/modification identifiers; only known/equal boolean comparisons escape.

/// No Debug, numeric output or ownership claim: TokenId is instance identity, other identifiers are observations.
#[derive(Clone, Copy)]
pub(super) struct Identity([[u32; 2]; 3]);
impl Identity {
    /// Receives copied fixed SDK fields after exact output-size/alignment validation.
    pub(super) fn copied(ids: [[u32; 2]; 3]) -> Self {
        Self(ids)
    }
    /// Compares token/logon/modification identifiers without exposing private LUIDs.
    pub(super) fn equal(self, other: Self) -> [bool; 3] {
        [
            self.0[0] == other.0[0],
            self.0[1] == other.0[1],
            self.0[2] == other.0[2],
        ]
    }
}
/// The actual SDK size/alignment are supplied by the compiled observer, not a guessed structure layout.
pub(super) fn layout(length: usize, address: usize, size: usize, alignment: usize) -> bool {
    size > 0 && alignment.is_power_of_two() && length == size && address % alignment == 0
}
/// Unavailability is represented by known=false, never inferred inequality.
pub(super) fn comparison(left: Option<Identity>, right: Option<Identity>) -> [bool; 4] {
    match (left, right) {
        (Some(a), Some(b)) => {
            let equal = a.equal(b);
            [true, equal[0], equal[1], equal[2]]
        }
        _ => [false; 4],
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    /// Same instance versus shared logon/different modification are independent comparisons.
    #[test]
    fn identity_and_logon_are_distinct() {
        let first = Identity::copied([[1, 2], [3, 4], [5, 6]]);
        let other = Identity::copied([[9, 2], [3, 4], [7, 6]]);
        assert!(comparison(Some(first), Some(other)) == [true, false, true, false]);
        assert!(comparison(Some(first), Some(first)) == [true, true, true, true]);
    }
    /// Missing metadata cannot be converted to a proved-different instance.
    #[test]
    fn unavailable_is_unknown() {
        let first = Identity::copied([[1, 2]; 3]);
        for (a, b) in [(None, None), (Some(first), None), (None, Some(first))] {
            assert!(comparison(a, b) == [false; 4]);
        }
    }
    /// Only exact pointer-free SDK extent and adequate aligned storage permit copying.
    #[test]
    fn sdk_layout_is_exact() {
        assert!(layout(56, 8, 56, 8));
        for (length, address, size, alignment) in [
            (55, 8, 56, 8),
            (57, 8, 56, 8),
            (56, 7, 56, 8),
            (0, 0, 0, 8),
            (56, 0, 56, 0),
            (56, 0, 56, 3),
        ] {
            assert!(!layout(length, address, size, alignment));
        }
    }
}
