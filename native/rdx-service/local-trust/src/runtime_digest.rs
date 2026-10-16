// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Streaming SHA-256 for complete runtime verification, with no content cache.

use crate::TrustError;
#[cfg(windows)]
use crate::deny;
#[cfg(not(windows))]
use sha2::{Digest, Sha256};
#[cfg(windows)]
use windows::Win32::Security::Cryptography::{
    BCRYPT_HASH_HANDLE, BCRYPT_SHA256_ALG_HANDLE, BCryptCreateHash, BCryptDestroyHash,
    BCryptFinishHash, BCryptHashData,
};

/// Owns one fresh SHA-256 state for one completely reread runtime file.
pub(super) struct RuntimeDigest {
    #[cfg(windows)]
    handle: BCRYPT_HASH_HANDLE,
    #[cfg(not(windows))]
    state: Sha256,
}

impl RuntimeDigest {
    /// Creates the fixed unkeyed SHA-256 algorithm; native failure denies verification.
    pub(super) fn new() -> Result<Self, TrustError> {
        #[cfg(windows)]
        {
            let mut handle = BCRYPT_HASH_HANDLE::default();
            // SAFETY: the Windows 10+ fixed SHA-256 pseudo-provider is not closed.
            // NULL object storage lets CNG own storage until BCryptDestroyHash.
            unsafe { BCryptCreateHash(BCRYPT_SHA256_ALG_HANDLE, &mut handle, None, None, 0) }
                .ok()
                .map_err(|_| deny("Windows SHA-256 initialization failed"))?;
            if handle.0.is_null() {
                return Err(deny("Windows SHA-256 state is unavailable"));
            }
            Ok(Self { handle })
        }
        #[cfg(not(windows))]
        {
            Ok(Self {
                state: Sha256::new(),
            })
        }
    }

    /// Hashes the next exact file chunk without retaining or omitting content.
    pub(super) fn update(&mut self, bytes: &[u8]) -> Result<(), TrustError> {
        #[cfg(windows)]
        {
            if bytes.len() > u32::MAX as usize {
                return Err(deny("Windows SHA-256 input exceeds bound"));
            }
            // SAFETY: this live owned hash retains its native allocation; the
            // input slice is retained throughout the synchronous bounded call.
            unsafe { BCryptHashData(self.handle, bytes, 0) }
                .ok()
                .map_err(|_| deny("Windows SHA-256 update failed"))
        }
        #[cfg(not(windows))]
        {
            self.state.update(bytes);
            Ok(())
        }
    }

    /// Finishes exactly 256 digest bits and keeps the existing lowercase hex format.
    pub(super) fn finish(self) -> Result<String, TrustError> {
        #[cfg(windows)]
        let bytes = {
            let mut output = [0_u8; 32];
            // SAFETY: this owned, unfinalized SHA-256 state has exactly 32 output
            // bytes, which remain writable throughout the synchronous call.
            unsafe { BCryptFinishHash(self.handle, &mut output, 0) }
                .ok()
                .map_err(|_| deny("Windows SHA-256 finalization failed"))?;
            output
        };
        #[cfg(not(windows))]
        let bytes: [u8; 32] = self.state.finalize().into();
        Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
    }
}

#[cfg(windows)]
impl Drop for RuntimeDigest {
    /// Destroys only this hash object and its CNG allocation on every exit path.
    fn drop(&mut self) {
        // SAFETY: construction owns this valid hash exactly once; the provider
        // pseudo-handle is never passed to a close or destroy API.
        let _ = unsafe { BCryptDestroyHash(self.handle) };
    }
}

#[cfg(test)]
mod tests {
    use super::RuntimeDigest;

    /// Empty, short and multi-block NIST vectors must retain the inventory format.
    #[test]
    fn known_sha256_vectors_match_exactly() {
        for (input, expected) in [
            (
                "",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                "abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
        ] {
            let mut digest = RuntimeDigest::new().unwrap();
            digest.update(input.as_bytes()).unwrap();
            assert_eq!(digest.finish().unwrap(), expected);
        }
    }

    /// Native state must hash all partial chunks, including empty and block boundaries.
    #[test]
    fn fragmented_updates_match_the_independent_portable_digest() {
        use sha2::{Digest, Sha256};
        let bytes: Vec<u8> = (0..131_073).map(|i| (i % 251) as u8).collect();
        let expected = format!("{:x}", Sha256::digest(&bytes));
        for width in [1, 63, 64, 65, 65_536, 131_073] {
            let mut digest = RuntimeDigest::new().unwrap();
            for chunk in bytes.chunks(width) {
                digest.update(&[]).unwrap();
                digest.update(chunk).unwrap();
            }
            assert_eq!(digest.finish().unwrap(), expected);
        }
    }

    /// Independent file digests must not reuse a previous object's finished state.
    #[test]
    fn successive_instances_do_not_share_hash_state() {
        let mut first = RuntimeDigest::new().unwrap();
        first.update(b"abc").unwrap();
        first.finish().unwrap();
        assert_eq!(
            RuntimeDigest::new().unwrap().finish().unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
