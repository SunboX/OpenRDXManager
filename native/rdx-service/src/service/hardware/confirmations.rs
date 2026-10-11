// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! One-shot destructive confirmation ownership.

use super::*;

/// Private confirmation record bound to one service session and medium proof.
pub(super) struct ConfirmationRecord {
    pub(super) request: ConfirmationRequest,
    pub(super) binding_proof: ConfirmationToken,
    pub(super) expires_at: Instant,
    pub(super) service_session: [u8; 16],
}

impl<B: PlatformBackend> HardwareWorker<B> {
    /// Issues a cryptographically random token bound to fresh retained medium evidence.
    pub(super) fn issue_bound_confirmation(
        &mut self,
        request: ConfirmationRequest,
    ) -> Result<ConfirmationToken, ServiceRejection> {
        self.expire_confirmations(Instant::now());
        if self.confirmations.len() >= MAX_PENDING_CONFIRMATIONS {
            return Err(service_rejection("confirmation-capacity-exhausted"));
        }
        let (device_id, revision) = request.target();
        let resolved = self
            .registry
            .resolve(&mut self.platform, device_id, revision)
            .map_err(platform_rejection)?;
        let binding_proof = resolved
            .issue_host_mutation_confirmation()
            .map_err(platform_rejection)?;
        let token = random_confirmation_token()?;
        let expires_at = Instant::now()
            .checked_add(CONFIRMATION_LIFETIME)
            .ok_or_else(|| service_rejection("confirmation-unavailable"))?;
        self.confirmations.insert(
            token.clone(),
            ConfirmationRecord {
                request,
                binding_proof,
                expires_at,
                service_session: self.service_session,
            },
        );
        Ok(token)
    }

    /// Removes expired pending tokens without extending their one-shot lifetime.
    fn expire_confirmations(&mut self, now: Instant) {
        self.confirmations
            .retain(|_, confirmation| now < confirmation.expires_at);
    }
}

/// Atomically removes and validates one exact token before native dispatch.
pub(super) fn consume_confirmation(
    confirmations: &mut BTreeMap<ConfirmationToken, ConfirmationRecord>,
    service_session: [u8; 16],
    request: &OperationRequest,
    token: &ConfirmationToken,
    binding_proof: &ConfirmationToken,
) -> Result<(), ServiceRejection> {
    let Some(record) = confirmations.remove(token) else {
        return Err(service_rejection("confirmation-required"));
    };
    if Instant::now() >= record.expires_at {
        return Err(service_rejection("confirmation-expired"));
    }
    if record.service_session != service_session
        || !record.request.matches_operation(request)
        || record.binding_proof != *binding_proof
    {
        return Err(service_rejection("confirmation-mismatch"));
    }
    Ok(())
}

/// Creates one bounded random opaque confirmation token.
pub(super) fn random_confirmation_token() -> Result<ConfirmationToken, ServiceRejection> {
    let mut nonce = [0_u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let mut encoded = String::from("confirm:");
    for byte in nonce {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}")
            .map_err(|_| service_rejection("confirmation-unavailable"))?;
    }
    ConfirmationToken::new(encoded).map_err(|_| service_rejection("confirmation-unavailable"))
}
