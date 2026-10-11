// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use rdx_service::model::{ConfirmationToken, DriveLetter, Filesystem};
use rdx_service::operations::{
    FileSystem, force_eject, partition_and_format, reset_drive_letter, run_write_read_test,
    safe_eject, set_drive_letter,
};
use rdx_service::platform::fixtures::{FixtureHost, FixtureTopology};

fn confirmation(host: &FixtureHost) -> ConfirmationToken {
    host.issue_confirmation_token()
}

#[test]
fn format_never_starts_layout_change_when_unmount_fails() {
    let mut host = FixtureHost::ready().with_unmount_rejection();
    let token = confirmation(&host);
    let result = partition_and_format(&mut host, FileSystem::ExFat, &token);

    assert_eq!(result.unwrap_err().stage(), "unmount");
    assert_eq!(host.layout_change_count(), 0);
    assert_eq!(host.format_count(), 0);
}

#[test]
fn format_checks_dependency_and_topology_before_unmount() {
    let mut missing = FixtureHost::ready().with_missing_dependency(FileSystem::Ntfs);
    let token = confirmation(&missing);
    let error = partition_and_format(&mut missing, FileSystem::Ntfs, &token).unwrap_err();
    assert_eq!(error.code(), "host-dependency-missing");
    assert_eq!(missing.unmount_count(), 0);

    for topology in [
        FixtureTopology::BootOrSystem,
        FixtureTopology::Layered,
        FixtureTopology::Shared,
        FixtureTopology::Spanned,
        FixtureTopology::Ambiguous,
    ] {
        let mut unsafe_host = FixtureHost::ready().with_topology(topology);
        let token = confirmation(&unsafe_host);
        let error = partition_and_format(&mut unsafe_host, FileSystem::ExFat, &token).unwrap_err();
        assert_eq!(error.code(), "unsafe-volume-topology");
        assert_eq!(unsafe_host.unmount_count(), 0);
    }
}

#[test]
fn format_requires_exact_confirmation_and_invalidates_after_layout_attempt() {
    let mut host = FixtureHost::ready();
    let wrong = ConfirmationToken::new("confirm:other-device").unwrap();
    let error = partition_and_format(&mut host, FileSystem::ExFat, &wrong).unwrap_err();
    assert_eq!(error.code(), "confirmation-required");
    assert_eq!(host.unmount_count(), 0);

    let mut attempted = FixtureHost::ready().with_layout_completion_unknown();
    let token = confirmation(&attempted);
    let error = partition_and_format(&mut attempted, FileSystem::ExFat, &token).unwrap_err();
    assert_eq!(error.certainty().as_str(), "completion-unknown");
    assert!(attempted.session_invalidated());
    assert_eq!(attempted.format_count(), 0);
}

#[test]
fn successful_format_uses_nonzero_mbr_signature_and_requires_rediscovery() {
    let mut host = FixtureHost::ready();
    let token = confirmation(&host);
    let result = partition_and_format(&mut host, FileSystem::ExFat, &token).unwrap();

    assert!(result.rediscovery_required());
    assert_ne!(host.last_mbr_signature(), Some(0));
    assert_eq!(host.unmount_count(), 1);
    assert_eq!(host.layout_change_count(), 1);
    assert_eq!(host.format_count(), 1);
    assert!(host.session_invalidated());
}

#[test]
fn safe_eject_never_falls_back_to_force() {
    let mut host = FixtureHost::ready().with_unmount_rejection();
    let error = safe_eject(&mut host).unwrap_err();

    assert_eq!(error.code(), "volume-busy");
    assert_eq!(host.safe_eject_count(), 0);
    assert_eq!(host.force_eject_count(), 0);
}

#[test]
fn force_eject_is_distinct_and_confirmation_gated() {
    let mut host = FixtureHost::ready();
    let wrong = ConfirmationToken::new("confirm:other-device").unwrap();
    assert_eq!(
        force_eject(&mut host, &wrong).unwrap_err().code(),
        "confirmation-required"
    );
    assert_eq!(host.force_eject_count(), 0);

    let token = confirmation(&host);
    force_eject(&mut host, &token).unwrap();
    assert_eq!(host.unmount_count(), 0);
    assert_eq!(host.safe_eject_count(), 0);
    assert_eq!(host.force_eject_count(), 1);
}

#[test]
fn write_read_uses_bounded_random_app_file_and_reports_cleanup_uncertainty() {
    let mut first = FixtureHost::ready();
    let first_result = run_write_read_test(&mut first).unwrap();
    let first_name = first.last_test_filename().unwrap().to_owned();
    assert!(first_name.starts_with(".openrdx-write-read-"));
    assert!(first_name.ends_with(".tmp"));
    assert!(first_result.bytes_tested() > 0);
    assert!(first_result.bytes_tested() <= 4 * 1024 * 1024);
    assert_eq!(first.created_with_exclusive_no_follow(), Some(true));
    assert_eq!(first.flush_count(), 1);
    assert_eq!(first.reopen_count(), 1);
    assert_eq!(first.delete_count(), 1);

    let mut second = FixtureHost::ready();
    run_write_read_test(&mut second).unwrap();
    assert_ne!(first_name, second.last_test_filename().unwrap());

    let mut cleanup = FixtureHost::ready().with_cleanup_completion_unknown();
    let error = run_write_read_test(&mut cleanup).unwrap_err();
    assert_eq!(error.stage(), "cleanup");
    assert_eq!(error.cleanup().as_str(), "completion-unknown");
}

#[test]
fn write_read_detects_exact_compare_failure_and_still_cleans_up() {
    let mut host = FixtureHost::ready().with_readback_corruption();
    let error = run_write_read_test(&mut host).unwrap_err();

    assert_eq!(error.code(), "data-mismatch");
    assert_eq!(host.delete_count(), 1);
}

#[test]
fn drive_letter_is_windows_only_collision_safe_and_mapping_owned() {
    let mut host = FixtureHost::ready().without_media();
    let letter = DriveLetter::new('R').unwrap();
    set_drive_letter(&mut host, letter).unwrap();
    assert_eq!(host.current_drive_letter(), Some('R'));
    assert!(host.mapping_is_app_owned());

    let mut collision = FixtureHost::ready()
        .without_media()
        .with_letter_collision('R');
    assert_eq!(
        set_drive_letter(&mut collision, letter).unwrap_err().code(),
        "drive-letter-in-use"
    );
    assert_eq!(collision.set_drive_letter_count(), 0);

    let mut foreign = FixtureHost::ready()
        .without_media()
        .with_foreign_mapping('R');
    assert_eq!(
        reset_drive_letter(&mut foreign).unwrap_err().code(),
        "mapping-not-owned"
    );
    assert_eq!(foreign.reset_drive_letter_count(), 0);

    reset_drive_letter(&mut host).unwrap();
    assert_eq!(host.current_drive_letter(), None);
}

#[test]
fn drive_letter_configuration_rejects_freshly_inserted_media_before_mutation() {
    let letter = DriveLetter::new('R').unwrap();
    let mut set_host = FixtureHost::ready();
    let set_error = set_drive_letter(&mut set_host, letter).unwrap_err();
    assert_eq!(set_error.code(), "media-must-be-ejected");
    assert_eq!(set_host.set_drive_letter_count(), 0);

    let mut reset_host = FixtureHost::ready().with_foreign_mapping('R');
    let reset_error = reset_drive_letter(&mut reset_host).unwrap_err();
    assert_eq!(reset_error.code(), "media-must-be-ejected");
    assert_eq!(reset_host.reset_drive_letter_count(), 0);
}

#[test]
fn model_filesystem_maps_only_documented_choices() {
    assert_eq!(
        FileSystem::try_from(Filesystem::Ntfs).unwrap(),
        FileSystem::Ntfs
    );
    assert_eq!(
        FileSystem::try_from(Filesystem::Exfat).unwrap(),
        FileSystem::ExFat
    );
}

#[test]
fn production_confirmation_token_is_bound_bounded_and_uses_the_real_matcher() {
    let mut host = FixtureHost::ready();
    let token = host.issue_confirmation_token();

    assert!(token.as_str().starts_with("confirm:"));
    assert!(token.as_str().len() <= 64);
    assert_ne!(token.as_str(), "confirm:exact-device-medium-revision");
    assert!(partition_and_format(&mut host, FileSystem::ExFat, &token).is_ok());
}

#[test]
fn media_swap_at_every_mutation_boundary_invalidates_exact_authority() {
    for boundary in 1..=5 {
        let mut host = FixtureHost::ready().with_media_swap_at_revalidation(boundary);
        let token = confirmation(&host);
        let result = partition_and_format(&mut host, FileSystem::ExFat, &token);

        assert!(
            result.is_err(),
            "media swap at boundary {boundary} must fail"
        );
        assert_eq!(result.unwrap_err().code(), "stale-device-revision");
        if host.layout_change_count() > 0 {
            assert!(host.session_invalidated());
        }
    }
}

#[test]
fn post_layout_rejections_are_never_reported_not_attempted() {
    let mut host = FixtureHost::ready().with_format_not_attempted_after_layout();
    let token = confirmation(&host);
    let error = partition_and_format(&mut host, FileSystem::ExFat, &token).unwrap_err();

    assert_eq!(host.layout_change_count(), 1);
    assert_eq!(error.stage(), "format");
    assert_eq!(error.certainty().as_str(), "completion-unknown");
    assert!(host.session_invalidated());
}

#[test]
fn eject_and_format_require_authoritative_postconditions() {
    let mut eject = FixtureHost::ready().with_eject_departure_unconfirmed();
    let error = safe_eject(&mut eject).unwrap_err();
    assert_eq!(error.stage(), "eject-readback");
    assert_eq!(error.certainty().as_str(), "completion-unknown");

    let mut format = FixtureHost::ready().with_format_postcondition_unconfirmed();
    let token = confirmation(&format);
    let error = partition_and_format(&mut format, FileSystem::ExFat, &token).unwrap_err();
    assert_eq!(error.stage(), "rediscovery");
    assert_eq!(error.certainty().as_str(), "completion-unknown");
    assert!(format.session_invalidated());
}
