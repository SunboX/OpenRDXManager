// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::super::*;

impl FixtureBackend {
    /// Configures the renderer-safe Windows available-letter source result.
    fn with_available_drive_letters(mut self, letters: &[char]) -> Self {
        self.available_drive_letters = Ok(letters
            .iter()
            .map(|letter| DriveLetter::new(*letter).expect("uppercase fixture letter"))
            .collect());
        self
    }
}

/// An eligible Windows USB3 dock publishes only the native bounded free list.
#[test]
fn eligible_windows_usb3_no_media_snapshot_publishes_available_drive_letters() {
    let mut backend = complete_backend(&[("available-letters", "/dev/sg2", "7820999743")])
        .with_available_drive_letters(&['D', 'R', 'Z']);
    let mut registry = DeviceRegistry::new();

    let snapshot = discover_validated_devices(&mut backend, &mut registry)
        .expect("eligible no-media dock remains discoverable")
        .into_iter()
        .next()
        .expect("eligible device snapshot");

    assert_eq!(
        snapshot
            .drive
            .available_drive_letters
            .as_ref()
            .map(|letters| letters
                .iter()
                .map(|letter| letter.get())
                .collect::<Vec<_>>()),
        Some(vec!['D', 'R', 'Z'])
    );
}

/// Invalid evidence and media-present state never publish an assignable list.
#[test]
fn unavailable_or_invalid_letter_evidence_stays_absent_from_snapshot() {
    let mut unavailable = complete_backend(&[("letters-unavailable", "/dev/sg2", "7820999743")]);
    let mut registry = DeviceRegistry::new();
    let snapshot = discover_validated_devices(&mut unavailable, &mut registry)
        .expect("host letter failure does not reject validated device identity")
        .into_iter()
        .next()
        .expect("device remains visible");
    assert_eq!(snapshot.drive.available_drive_letters, None);

    for letters in [&['C', 'R'][..], &['R', 'D'][..], &['R', 'R'][..]] {
        let mut backend = complete_backend(&[("invalid-letters", "/dev/sg2", "7820999743")])
            .with_available_drive_letters(letters);
        let mut registry = DeviceRegistry::new();
        let snapshot = discover_validated_devices(&mut backend, &mut registry)
            .expect("invalid host letter evidence does not reject identity")
            .into_iter()
            .next()
            .expect("device remains visible");

        assert_eq!(snapshot.drive.available_drive_letters, None);
    }

    let mut with_media = complete_backend(&[("media-present", "/dev/sg2", "7820999743")])
        .with_available_drive_letters(&['R'])
        .with_media([0xA5; 32], 1_000_000_000);
    let mut registry = DeviceRegistry::new();
    let snapshot = discover_validated_devices(&mut with_media, &mut registry)
        .expect("media-present dock remains discoverable")
        .into_iter()
        .next()
        .expect("device remains visible");
    assert_eq!(snapshot.drive.available_drive_letters, None);
}
