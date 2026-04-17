// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::aws_lc::{
    DES_cblock, DES_ecb3_encrypt, DES_ede3_cbc_encrypt, DES_key_schedule, DES_DECRYPT, DES_ENCRYPT,
};
use crate::error::Unspecified;
use zeroize::Zeroize;

use super::{DecryptionContext, EncryptionContext, SymmetricCipherKey};

/// Length of a 2TDEA (DES-EDE) key in bytes.
pub const DES_EDE_KEY_LEN: usize = 16;

/// Length of a 3TDEA (DES-EDE3) key in bytes.
pub const DES_EDE3_KEY_LEN: usize = 24;

/// The number of bytes for an DES CBC initialization vector (IV)
pub const DES_CBC_IV_LEN: usize = 8;

pub const DES_BLOCK_LEN: usize = 8;

pub(crate) struct DesKey(pub(super) [DES_key_schedule; 3]);

pub(super) fn encrypt_cbc_mode(
    key: &SymmetricCipherKey,
    context: EncryptionContext,
    in_out: &mut [u8],
) -> Result<DecryptionContext, Unspecified> {
    let (SymmetricCipherKey::DesEde { key } | SymmetricCipherKey::DesEde3 { key }) = key else {
        unreachable!()
    };

    let iv_bytes: &[u8] = (&context).try_into()?;
    let mut iv = [0u8; DES_CBC_IV_LEN];
    iv.copy_from_slice(iv_bytes);

    des_ede_cbc_encrypt(
        &key.0[0],
        &key.0[1],
        &key.0[2],
        &mut iv,
        in_out,
        DES_ENCRYPT,
    );

    iv.zeroize();
    Ok(context.into())
}

pub(super) fn decrypt_cbc_mode<'in_out>(
    key: &SymmetricCipherKey,
    context: DecryptionContext,
    in_out: &'in_out mut [u8],
) -> Result<&'in_out mut [u8], Unspecified> {
    let (SymmetricCipherKey::DesEde { key } | SymmetricCipherKey::DesEde3 { key }) = key else {
        unreachable!()
    };

    let iv_bytes: &[u8] = (&context).try_into()?;
    let mut iv = [0u8; DES_CBC_IV_LEN];
    iv.copy_from_slice(iv_bytes);

    des_ede_cbc_encrypt(
        &key.0[0],
        &key.0[1],
        &key.0[2],
        &mut iv,
        in_out,
        DES_DECRYPT,
    );

    iv.zeroize();
    Ok(in_out)
}

pub(super) fn encrypt_ecb_mode(
    key: &SymmetricCipherKey,
    context: EncryptionContext,
    in_out: &mut [u8],
) -> Result<DecryptionContext, Unspecified> {
    if !matches!(context, EncryptionContext::None) {
        return Err(Unspecified);
    }

    let (SymmetricCipherKey::DesEde { key } | SymmetricCipherKey::DesEde3 { key }) = key else {
        unreachable!()
    };

    for block in in_out.chunks_exact_mut(DES_BLOCK_LEN) {
        des_ecb3_encrypt(&key.0[0], &key.0[1], &key.0[2], block, DES_ENCRYPT);
    }

    Ok(context.into())
}

pub(super) fn decrypt_ecb_mode<'in_out>(
    key: &SymmetricCipherKey,
    context: DecryptionContext,
    in_out: &'in_out mut [u8],
) -> Result<&'in_out mut [u8], Unspecified> {
    if !matches!(context, DecryptionContext::None) {
        return Err(Unspecified);
    }

    let (SymmetricCipherKey::DesEde { key } | SymmetricCipherKey::DesEde3 { key }) = key else {
        unreachable!()
    };

    for block in in_out.chunks_exact_mut(DES_BLOCK_LEN) {
        des_ecb3_encrypt(&key.0[0], &key.0[1], &key.0[2], block, DES_DECRYPT);
    }

    Ok(in_out)
}

fn des_ede_cbc_encrypt(
    ks1: &DES_key_schedule,
    ks2: &DES_key_schedule,
    ks3: &DES_key_schedule,
    iv: &mut [u8; DES_CBC_IV_LEN],
    in_out: &mut [u8],
    enc: i32,
) {
    unsafe {
        DES_ede3_cbc_encrypt(
            in_out.as_ptr(),
            in_out.as_mut_ptr(),
            in_out.len(),
            ks1,
            ks2,
            ks3,
            iv.as_mut_ptr() as *mut DES_cblock,
            enc,
        );
    }
}

fn des_ecb3_encrypt(
    ks1: &DES_key_schedule,
    ks2: &DES_key_schedule,
    ks3: &DES_key_schedule,
    block: &mut [u8],
    enc: i32,
) {
    let input_block = block.as_ptr() as *const DES_cblock;
    let output_block = block.as_mut_ptr() as *mut DES_cblock;
    unsafe {
        DES_ecb3_encrypt(input_block, output_block, ks1, ks2, ks3, enc);
    }
}
