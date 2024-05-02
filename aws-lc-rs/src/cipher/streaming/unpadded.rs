// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::cipher::streaming::{
    DecryptingKey, EncryptingKey, SealedDecryptingKey, SealedEncryptingKey, StreamingDecryptingKey,
    StreamingEncryptingKey,
};
use crate::cipher::{DecryptionContext, EncryptionContext, OperatingMode, UnboundCipherKey};
use crate::error::Unspecified;
use crate::sealed::Sealed;

//
pub struct StreamingUnpaddedEncryptingKey(EncryptingKey);

impl SealedEncryptingKey for StreamingUnpaddedEncryptingKey {
    fn wrap(ek: EncryptingKey) -> Self {
        Self(ek)
    }

    fn unwrap(&self) -> &EncryptingKey {
        &self.0
    }

    fn consume(self) -> EncryptingKey {
        self.0
    }
}

impl Sealed for StreamingUnpaddedEncryptingKey {}
impl StreamingEncryptingKey for StreamingUnpaddedEncryptingKey {}

impl StreamingUnpaddedEncryptingKey {
    pub fn ctr(key: UnboundCipherKey) -> Result<Self, Unspecified> {
        let context = key.algorithm().new_encryption_context(OperatingMode::CTR)?;
        Self::less_safe_ctr(key, context)
    }

    pub fn less_safe_ctr(
        key: UnboundCipherKey,
        context: EncryptionContext,
    ) -> Result<Self, Unspecified> {
        Self::new(key, OperatingMode::CTR, context)
    }
}

pub struct StreamingUnpaddedDecryptingKey(DecryptingKey);

impl SealedDecryptingKey for StreamingUnpaddedDecryptingKey {
    fn wrap(dk: DecryptingKey) -> Self {
        Self(dk)
    }

    fn unwrap(&self) -> &DecryptingKey {
        &self.0
    }
}

impl Sealed for StreamingUnpaddedDecryptingKey {}
impl StreamingDecryptingKey for StreamingUnpaddedDecryptingKey {}

impl StreamingUnpaddedDecryptingKey {
    pub fn ctr(key: UnboundCipherKey, context: DecryptionContext) -> Result<Self, Unspecified> {
        Self::new(key, OperatingMode::CTR, context)
    }
}

#[cfg(test)]
mod tests {
    use crate::cipher::streaming::tests::helper_stream_step_encrypt_step_decrypt_test;
    use crate::cipher::{
        StreamingUnpaddedDecryptingKey, StreamingUnpaddedEncryptingKey, AES_256, AES_256_KEY_LEN,
    };

    helper_stream_step_encrypt_step_decrypt_test!(
        StreamingUnpaddedEncryptingKey,
        StreamingUnpaddedDecryptingKey,
        ctr
    );

    #[test]
    fn test_step_ctr() {
        let random = SystemRandom::new();
        let mut key = [0u8; AES_256_KEY_LEN];
        random.fill(&mut key).unwrap();
        for i in 13..=21 {
            for j in 124..=131 {
                let _ = helper_ctr_stream_step_encrypt_step_descrypt(&key, &AES_256, j, i);
            }
            for j in 124..=131 {
                let _ = helper_ctr_stream_step_encrypt_step_descrypt(&key, &AES_256, j, j - i);
            }
        }
        for j in 124..=131 {
            let _ = helper_ctr_stream_step_encrypt_step_descrypt(&key, &AES_256, j, j);
            let _ = helper_ctr_stream_step_encrypt_step_descrypt(&key, &AES_256, j, 256);
            let _ = helper_ctr_stream_step_encrypt_step_descrypt(&key, &AES_256, j, 1);
        }
    }
}
