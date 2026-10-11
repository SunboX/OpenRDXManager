// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared renderer-safe operation progress scalar contracts.

use serde::{Deserialize, Deserializer, Serialize, de};

/// One-based bounded whole-file firmware transfer attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct OperationAttempt(u8);

impl OperationAttempt {
    /// Creates one of the two supported whole-file transfer attempts.
    ///
    /// # Errors
    ///
    /// Returns an error unless `value` is one or two.
    pub const fn new(value: u8) -> Result<Self, &'static str> {
        if value == 1 || value == 2 {
            Ok(Self(value))
        } else {
            Err("firmware attempt must be one or two")
        }
    }

    /// Returns the validated one-based attempt number.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

impl<'de> Deserialize<'de> for OperationAttempt {
    /// Deserializes only one of the two supported transfer attempts.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(u8::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

/// Exact cancellation availability carried by every progress event.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CancellationState {
    /// The current stage still accepts an exact-owner cancellation request.
    Cancellable,
    /// The exact owner requested cancellation and mandatory recovery is running.
    Requested,
    /// The operation crossed its last safe cancellation boundary.
    Closed,
}
