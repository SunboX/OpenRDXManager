// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use zeroize::Zeroizing;

use rdx_service::operations::{
    SecurityEvidenceRegistry, SecurityMutator, SecurityOperationError, execute_security_mutator,
};
use rdx_service::protocol::{AuthenticationKdfParameters, derive_authentication_material};

const GENERATED_EVIDENCE_JSON: &str =
    include_str!("../../../test/fixtures/security-selector-fixtures.json");

/// Decodes one lowercase hexadecimal fixture without using production helpers.
fn decode_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}

/// Every documented mutator must fail before transport while its mapping is incomplete.
#[test]
fn every_security_mutator_fails_closed_without_exact_evidence() {
    let mutators = [
        SecurityMutator::EnableAccess,
        SecurityMutator::DisableAccess,
        SecurityMutator::CreateCredential,
        SecurityMutator::ChangeCredential,
        SecurityMutator::DeleteCredential,
        SecurityMutator::ResetProtection,
        SecurityMutator::ConfigureBasic,
        SecurityMutator::ConfigureAes,
        SecurityMutator::RemoveBasic,
        SecurityMutator::RemoveAes,
        SecurityMutator::AddAutomaticAssociation,
        SecurityMutator::DeleteAutomaticAssociation,
        SecurityMutator::DeleteDriveAutomaticCredential,
    ];

    for mutator in mutators {
        let error = execute_security_mutator(&SecurityEvidenceRegistry::bundled(), mutator, None)
            .unwrap_err();

        assert!(matches!(
            error,
            SecurityOperationError::EvidenceIncomplete {
                operation,
                reason: _
            } if operation == mutator
        ));
    }
}

/// Password-bearing blocked operations still erase caller-owned transient bytes.
#[test]
fn terminal_evidence_rejection_zeroizes_supplied_credential() {
    let mut secret = Zeroizing::new(b"OPENRDX-FIXTURE-CREDENTIAL".to_vec());

    let error = execute_security_mutator(
        &SecurityEvidenceRegistry::bundled(),
        SecurityMutator::EnableAccess,
        Some(&mut secret),
    )
    .unwrap_err();

    assert!(matches!(
        error,
        SecurityOperationError::EvidenceIncomplete {
            operation: SecurityMutator::EnableAccess,
            reason: _
        }
    ));
    assert!(secret.iter().all(|byte| *byte == 0));
}

/// The synthetic evidence fixture proves both 64-byte PBKDF2 stages exactly.
#[test]
fn reference_two_stage_kdf_matches_golden_fixture() {
    let credential = Zeroizing::new(decode_hex(
        "4f50454e5244582d464958545552452d43524544454e5449414c",
    ));
    let slot_salt: [u8; 32] =
        decode_hex("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f")
            .try_into()
            .unwrap();
    let global_salt: [u8; 32] =
        decode_hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
            .try_into()
            .unwrap();
    let parameters = AuthenticationKdfParameters::new(slot_salt, 1500, global_salt, 8192)
        .expect("bounded fixture parameters");

    let material = derive_authentication_material(credential, &parameters).expect("two-stage KDF");

    assert_eq!(
        material.as_bytes(),
        decode_hex(
            "68612e1d8dd371b03ca9e03bd44b40c614a8fab9ef5c4381885f8a6aa694a9287729a15600e3d4c7ac65be1637754d3f57e8b96d785faa208abbe4b62b5cf6ee"
        )
    );
    assert_eq!(
        format!("{material:?}"),
        "AuthenticationMaterial(<redacted:64 bytes>)"
    );
}

/// Zero iteration counts are rejected before any expensive derivation.
#[test]
fn kdf_rejects_zero_iteration_parameters() {
    assert!(AuthenticationKdfParameters::new([0; 32], 0, [0; 32], 1).is_err());
    assert!(AuthenticationKdfParameters::new([0; 32], 1, [0; 32], 0).is_err());
}

/// The compiled native registry must exactly match all generated JSON mutators.
#[test]
fn compiled_security_registry_matches_generated_evidence() {
    let document: serde_json::Value =
        serde_json::from_str(GENERATED_EVIDENCE_JSON).expect("generated evidence JSON");
    let mutators = document["mutators"]
        .as_object()
        .expect("generated mutator object");
    let entries = SecurityEvidenceRegistry::bundled().entries();

    assert_eq!(entries.len(), 13);
    assert_eq!(mutators.len(), entries.len());
    for (operation, reason) in entries {
        let decision = &mutators[operation.as_str()];
        assert_eq!(decision["state"], "evidence-incomplete");
        assert_eq!(decision["reason"], *reason);
    }
}
