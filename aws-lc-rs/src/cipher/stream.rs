use crate::cipher::{
    Algorithm, DecryptionContext, EncryptionContext, OperatingMode, UnboundCipherKey,
};
use crate::error::Unspecified;
use crate::ptr::{LcPtr, Pointer};
use aws_lc::{
    EVP_CIPHER_CTX_new, EVP_CIPHER_iv_length, EVP_CIPHER_key_length, EVP_DecryptFinal_ex,
    EVP_DecryptInit_ex, EVP_DecryptUpdate, EVP_EncryptFinal_ex, EVP_EncryptInit_ex,
    EVP_EncryptUpdate, EVP_CIPHER_CTX,
};
use std::ptr::null_mut;

struct EncryptingKey {
    algorithm: &'static Algorithm,
    mode: OperatingMode,
    cipher_ctx: LcPtr<EVP_CIPHER_CTX>,
    context: EncryptionContext,
}

trait EncryptingKeyWrapper: Sized {
    fn wrap(ek: EncryptingKey) -> Self;
    fn unwrap(&self) -> &EncryptingKey;

    fn consume(self) -> EncryptingKey;

    fn new(
        key: UnboundCipherKey,
        mode: OperatingMode,
        context: EncryptionContext,
    ) -> Result<Self, Unspecified> {
        let algorithm = key.algorithm();
        let cipher_ctx = LcPtr::new(unsafe { EVP_CIPHER_CTX_new() })?;
        let cipher = mode.evp_cipher(key.algorithm);
        let key_bytes = key.key_bytes.as_ref();
        debug_assert_eq!(
            key_bytes.len(),
            <usize>::try_from(unsafe { EVP_CIPHER_key_length(*cipher) }).unwrap()
        );
        let iv = <&[u8]>::try_from(&context)?;
        debug_assert_eq!(
            iv.len(),
            <usize>::try_from(unsafe { EVP_CIPHER_iv_length(*cipher) }).unwrap()
        );

        if 1 != unsafe {
            EVP_EncryptInit_ex(
                cipher_ctx.as_mut_ptr(),
                *cipher,
                null_mut(),
                key_bytes.as_ptr(),
                iv.as_ptr(),
            )
        } {
            return Err(Unspecified);
        }

        Ok(Self::wrap(EncryptingKey {
            algorithm,
            mode,
            cipher_ctx,
            context,
        }))
    }
}

pub trait StreamingEncryptingKey: EncryptingKeyWrapper {
    /// Returns the cipher operating mode.
    #[must_use]
    fn mode(&self) -> OperatingMode {
        self.unwrap().mode
    }

    #[must_use]
    fn algorithm(&self) -> &'static Algorithm {
        self.unwrap().algorithm
    }

    fn update<'a>(&self, input: &[u8], output: &'a mut [u8]) -> Result<&'a [u8], Unspecified> {
        if output.len() < (input.len() + self.unwrap().algorithm.block_len) {
            return Err(Unspecified);
        }

        let mut outlen: i32 = output.len().try_into()?;
        let inlen: i32 = input.len().try_into()?;
        if 1 != unsafe {
            EVP_EncryptUpdate(
                *self.unwrap().cipher_ctx,
                output.as_mut_ptr(),
                &mut outlen,
                input.as_ptr(),
                inlen,
            )
        } {
            return Err(Unspecified);
        }
        let outlen: usize = outlen.try_into()?;
        Ok(&output[0..outlen])
    }

    fn finish(self, output: &mut [u8]) -> Result<(DecryptionContext, &[u8]), Unspecified> {
        if output.len() < self.unwrap().algorithm.block_len {
            return Err(Unspecified);
        }
        let mut outlen: i32 = output.len().try_into()?;
        if 1 != unsafe {
            EVP_EncryptFinal_ex(*self.unwrap().cipher_ctx, output.as_mut_ptr(), &mut outlen)
        } {
            return Err(Unspecified);
        }
        let outlen: usize = outlen.try_into()?;
        let context = self.consume().context;
        Ok((context.into(), &output[0..outlen]))
    }
}

struct DecryptingKey {
    algorithm: &'static Algorithm,
    mode: OperatingMode,
    cipher_ctx: LcPtr<EVP_CIPHER_CTX>,
}
trait DecryptingKeyWrapper: Sized {
    fn wrap(dk: DecryptingKey) -> Self;
    fn unwrap(&self) -> &DecryptingKey;

    fn new(
        key: UnboundCipherKey,
        mode: OperatingMode,
        context: DecryptionContext,
    ) -> Result<Self, Unspecified> {
        let cipher_ctx = LcPtr::new(unsafe { EVP_CIPHER_CTX_new() })?;
        let algorithm = key.algorithm();
        let cipher = mode.evp_cipher(key.algorithm);
        let key_bytes = key.key_bytes.as_ref();
        debug_assert_eq!(
            key_bytes.len(),
            <usize>::try_from(unsafe { EVP_CIPHER_key_length(*cipher) }).unwrap()
        );
        let iv = <&[u8]>::try_from(&context)?;
        debug_assert_eq!(
            iv.len(),
            <usize>::try_from(unsafe { EVP_CIPHER_iv_length(*cipher) }).unwrap()
        );

        if 1 != unsafe {
            EVP_DecryptInit_ex(
                cipher_ctx.as_mut_ptr(),
                *cipher,
                null_mut(),
                key_bytes.as_ptr(),
                iv.as_ptr(),
            )
        } {
            return Err(Unspecified);
        }

        Ok(Self::wrap(DecryptingKey {
            algorithm,
            mode,
            cipher_ctx,
        }))
    }
}

pub trait StreamingDecryptingKey: DecryptingKeyWrapper {
    fn update<'a>(&self, input: &[u8], output: &'a mut [u8]) -> Result<&'a [u8], Unspecified> {
        if output.len() < (input.len() + self.unwrap().algorithm.block_len) {
            return Err(Unspecified);
        }

        let mut outlen: i32 = output.len().try_into()?;
        let inlen: i32 = input.len().try_into()?;
        if 1 != unsafe {
            EVP_DecryptUpdate(
                *self.unwrap().cipher_ctx,
                output.as_mut_ptr(),
                &mut outlen,
                input.as_ptr(),
                inlen,
            )
        } {
            return Err(Unspecified);
        }
        let outlen: usize = outlen.try_into()?;
        Ok(&output[0..outlen])
    }

    fn finish(self, output: &mut [u8]) -> Result<&[u8], Unspecified> {
        let mut outlen: i32 = output.len().try_into()?;
        if 1 != unsafe {
            EVP_DecryptFinal_ex(*self.unwrap().cipher_ctx, output.as_mut_ptr(), &mut outlen)
        } {
            return Err(Unspecified);
        }
        let outlen: usize = outlen.try_into()?;
        Ok(&output[0..outlen])
    }

    fn algorithm(&self) -> &'static Algorithm {
        self.unwrap().algorithm
    }

    fn mode(&self) -> OperatingMode {
        self.unwrap().mode
    }
}

pub struct StreamingPaddedBlockEncryptingKey(EncryptingKey);
impl EncryptingKeyWrapper for StreamingPaddedBlockEncryptingKey {
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
    fn cbc_pkcs7(key: UnboundCipherKey) -> Result<Self, Unspecified> {
        let context = key.algorithm().new_encryption_context(OperatingMode::CBC)?;
        Self::less_safe_cbc_pkcs7(key, context)
    }

    fn less_safe_cbc_pkcs7(
        key: UnboundCipherKey,
        context: EncryptionContext,
    ) -> Result<Self, Unspecified> {
        Self::new(key, OperatingMode::CBC, context)
    }
}

//
pub struct StreamingUnpaddedEncryptingKey(EncryptingKey);
impl EncryptingKeyWrapper for StreamingUnpaddedEncryptingKey {
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

impl StreamingUnpaddedEncryptingKey {
    fn ctr(key: UnboundCipherKey) -> Result<Self, Unspecified> {
        let context = key.algorithm().new_encryption_context(OperatingMode::CTR)?;
        Self::less_safe_ctr(key, context)
    }

    fn less_safe_ctr(
        key: UnboundCipherKey,
        context: EncryptionContext,
    ) -> Result<Self, Unspecified> {
        Self::new(key, OperatingMode::CTR, context)
    }
}

pub struct StreamingPaddedBlockDecryptingKey(DecryptingKey);
impl DecryptingKeyWrapper for StreamingPaddedBlockDecryptingKey {
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

pub struct StreamingUnpaddedDecryptingKey(DecryptingKey);
impl DecryptingKeyWrapper for StreamingUnpaddedDecryptingKey {
    fn wrap(dk: DecryptingKey) -> Self {
        Self(dk)
    }

    fn unwrap(&self) -> &DecryptingKey {
        &self.0
    }
}
impl StreamingDecryptingKey for StreamingUnpaddedDecryptingKey {}
impl StreamingUnpaddedDecryptingKey {
    pub fn ctr(key: UnboundCipherKey, context: DecryptionContext) -> Result<Self, Unspecified> {
        Self::new(key, OperatingMode::CTR, context)
    }
}

#[cfg(test)]
mod tests {
    use crate::cipher::stream::{
        StreamingDecryptingKey, StreamingEncryptingKey, StreamingPaddedBlockDecryptingKey,
        StreamingPaddedBlockEncryptingKey, StreamingUnpaddedDecryptingKey,
        StreamingUnpaddedEncryptingKey,
    };
    use crate::cipher::{
        Algorithm, DecryptionContext, OperatingMode, UnboundCipherKey, AES_256, AES_256_KEY_LEN,
    };
    use crate::rand::{SecureRandom, SystemRandom};
    use paste::*;

    fn step_encrypt<E: StreamingEncryptingKey>(
        encrypting_key: E,
        plaintext: &[u8],
        step: usize,
    ) -> (Box<[u8]>, DecryptionContext) {
        let alg = encrypting_key.algorithm();
        let mode = encrypting_key.mode();
        let n = plaintext.len();
        let mut ciphertext = vec![0u8; n + alg.block_len()];

        let mut in_idx: usize = 0;
        let mut out_idx: usize = 0;
        loop {
            let mut in_end = in_idx + step;
            if in_end > n {
                in_end = n;
            }
            let out_end = out_idx + (in_end - in_idx) + alg.block_len();
            let output = encrypting_key
                .update(
                    &plaintext[in_idx..in_end],
                    &mut ciphertext[out_idx..out_end],
                )
                .unwrap();
            in_idx += step;
            out_idx += output.len();
            if in_idx >= n {
                break;
            }
        }
        let out_end = out_idx + alg.block_len();
        let (decrypt_iv, output) = encrypting_key
            .finish(&mut ciphertext[out_idx..out_end])
            .unwrap();
        let outlen = output.len();
        ciphertext.truncate(out_idx + outlen);
        match mode {
            OperatingMode::CBC => {
                assert!(ciphertext.len() > plaintext.len());
                assert!(ciphertext.len() <= plaintext.len() + alg.block_len());
            }
            OperatingMode::CTR => {
                assert_eq!(ciphertext.len(), plaintext.len());
            }
        }

        (ciphertext.into_boxed_slice(), decrypt_iv)
    }

    fn step_decrypt<D: StreamingDecryptingKey>(
        decrypting_key: D,
        ciphertext: &[u8],
        step: usize,
    ) -> Box<[u8]> {
        let alg = decrypting_key.algorithm();
        let mode = decrypting_key.mode();
        let n = ciphertext.len();
        let mut plaintext = vec![0u8; n + alg.block_len()];

        let mut in_idx: usize = 0;
        let mut out_idx: usize = 0;
        loop {
            let mut in_end = in_idx + step;
            if in_end > n {
                in_end = n;
            }
            let out_end = out_idx + (in_end - in_idx) + alg.block_len();
            let output = decrypting_key
                .update(
                    &ciphertext[in_idx..in_end],
                    &mut plaintext[out_idx..out_end],
                )
                .unwrap();
            in_idx += step;
            out_idx += output.len();
            if in_idx >= n {
                break;
            }
        }
        let out_end = out_idx + alg.block_len();
        let output = decrypting_key
            .finish(&mut plaintext[out_idx..out_end])
            .unwrap();
        let outlen = output.len();
        plaintext.truncate(out_idx + outlen);
        match mode {
            OperatingMode::CBC => {
                assert!(ciphertext.len() > plaintext.len());
                assert!(ciphertext.len() <= plaintext.len() + alg.block_len());
            }
            OperatingMode::CTR => {
                assert_eq!(ciphertext.len(), plaintext.len());
            }
        }
        plaintext.into_boxed_slice()
    }

    macro_rules! helper_stream_step_encrypt_test {
        ($encstr:ident, $decstr:ident, $mode:ident) => {
            paste! {
                fn [<helper_test_ $mode _stream_encrypt_step_n_bytes>](
                    key: &[u8],
                    alg: &'static Algorithm,
                    n: usize,
                    step: usize,
                ) {
                    let mut input = vec![0u8; n];
                    let random = SystemRandom::new();
                    random.fill(&mut input).unwrap();

                    let cipher_key = UnboundCipherKey::new(alg, key).unwrap();
                    let encrypting_key = $encstr::$mode(cipher_key).unwrap();

                    let (ciphertext, decrypt_iv) = step_encrypt(encrypting_key, &input, step);

                    let cipher_key2 = UnboundCipherKey::new(alg, key).unwrap();
                    let decrypting_key = $decstr::$mode(cipher_key2, decrypt_iv).unwrap();

                    let plaintext = step_decrypt(decrypting_key, &ciphertext, step);

                    assert_eq!(input.as_slice(), &*plaintext);
                }
            }
        };
    }

    helper_stream_step_encrypt_test!(
        StreamingPaddedBlockEncryptingKey,
        StreamingPaddedBlockDecryptingKey,
        cbc_pkcs7
    );
    helper_stream_step_encrypt_test!(
        StreamingUnpaddedEncryptingKey,
        StreamingUnpaddedDecryptingKey,
        ctr
    );

    #[test]
    fn test_step_cbc() {
        let random = SystemRandom::new();
        let mut key = [0u8; AES_256_KEY_LEN];
        random.fill(&mut key).unwrap();

        for i in 13..=21 {
            for j in 124..=131 {
                let _ = helper_test_cbc_pkcs7_stream_encrypt_step_n_bytes(&key, &AES_256, j, i);
            }
            for j in 124..=131 {
                let _ = helper_test_cbc_pkcs7_stream_encrypt_step_n_bytes(&key, &AES_256, j, j - i);
            }
        }
        for j in 124..=131 {
            let _ = helper_test_cbc_pkcs7_stream_encrypt_step_n_bytes(&key, &AES_256, j, j);
            let _ = helper_test_cbc_pkcs7_stream_encrypt_step_n_bytes(&key, &AES_256, j, 256);
            let _ = helper_test_cbc_pkcs7_stream_encrypt_step_n_bytes(&key, &AES_256, j, 1);
        }
    }

    #[test]
    fn test_step_ctr() {
        let random = SystemRandom::new();
        let mut key = [0u8; AES_256_KEY_LEN];
        random.fill(&mut key).unwrap();
        for i in 13..=21 {
            for j in 124..=131 {
                let _ = helper_test_ctr_stream_encrypt_step_n_bytes(&key, &AES_256, j, i);
            }
            for j in 124..=131 {
                let _ = helper_test_ctr_stream_encrypt_step_n_bytes(&key, &AES_256, j, j - i);
            }
        }
        for j in 124..=131 {
            let _ = helper_test_ctr_stream_encrypt_step_n_bytes(&key, &AES_256, j, j);
            let _ = helper_test_ctr_stream_encrypt_step_n_bytes(&key, &AES_256, j, 256);
            let _ = helper_test_ctr_stream_encrypt_step_n_bytes(&key, &AES_256, j, 1);
        }
    }
}
