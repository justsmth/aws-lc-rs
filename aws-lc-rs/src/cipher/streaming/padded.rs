// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::cipher::streaming::{
    DecryptingKey, EncryptingKey, SealedDecryptingKey, SealedEncryptingKey, StreamingDecryptingKey,
    StreamingEncryptingKey,
};
use crate::cipher::{DecryptionContext, EncryptionContext, OperatingMode, UnboundCipherKey};
use crate::error::Unspecified;
use crate::sealed::Sealed;

pub struct StreamingPaddedBlockEncryptingKey(EncryptingKey);

impl Sealed for StreamingPaddedBlockEncryptingKey {}
impl SealedEncryptingKey for StreamingPaddedBlockEncryptingKey {
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

impl StreamingEncryptingKey for StreamingPaddedBlockEncryptingKey {}

impl StreamingPaddedBlockEncryptingKey {
    pub fn cbc_pkcs7(key: UnboundCipherKey) -> Result<Self, Unspecified> {
        let context = key.algorithm().new_encryption_context(OperatingMode::CBC)?;
        Self::less_safe_cbc_pkcs7(key, context)
    }

    pub fn less_safe_cbc_pkcs7(
        key: UnboundCipherKey,
        context: EncryptionContext,
    ) -> Result<Self, Unspecified> {
        Self::new(key, OperatingMode::CBC, context)
    }
}

pub struct StreamingPaddedBlockDecryptingKey(DecryptingKey);

impl Sealed for StreamingPaddedBlockDecryptingKey {}
impl SealedDecryptingKey for StreamingPaddedBlockDecryptingKey {
    fn wrap(dk: DecryptingKey) -> Self {
        Self(dk)
    }

    fn unwrap(&self) -> &DecryptingKey {
        &self.0
    }
}

impl StreamingDecryptingKey for StreamingPaddedBlockDecryptingKey {}

impl StreamingPaddedBlockDecryptingKey {
    pub fn cbc_pkcs7(
        key: UnboundCipherKey,
        context: DecryptionContext,
    ) -> Result<Self, Unspecified> {
        Self::new(key, OperatingMode::CBC, context)
    }
}

#[cfg(test)]
mod tests {
    use crate::cipher::streaming::tests::helper_stream_step_encrypt_step_decrypt_test;
    use crate::cipher::{
        StreamingPaddedBlockDecryptingKey, StreamingPaddedBlockEncryptingKey, AES_256,
        AES_256_KEY_LEN,
    };

    helper_stream_step_encrypt_step_decrypt_test!(
        StreamingPaddedBlockEncryptingKey,
        StreamingPaddedBlockDecryptingKey,
        cbc_pkcs7
    );

    #[test]
    fn test_step_cbc() {
        let random = SystemRandom::new();
        let mut key = [0u8; AES_256_KEY_LEN];
        random.fill(&mut key).unwrap();

        for i in 13..=21 {
            for j in 124..=131 {
                let _ = helper_cbc_pkcs7_stream_step_encrypt_step_descrypt(&key, &AES_256, j, i);
            }
            for j in 124..=131 {
                let _ =
                    helper_cbc_pkcs7_stream_step_encrypt_step_descrypt(&key, &AES_256, j, j - i);
            }
        }
        for j in 124..=131 {
            let _ = helper_cbc_pkcs7_stream_step_encrypt_step_descrypt(&key, &AES_256, j, j);
            let _ = helper_cbc_pkcs7_stream_step_encrypt_step_descrypt(&key, &AES_256, j, 256);
            let _ = helper_cbc_pkcs7_stream_step_encrypt_step_descrypt(&key, &AES_256, j, 1);
        }
    }
}
