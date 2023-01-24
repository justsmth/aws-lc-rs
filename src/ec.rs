// Copyright 2015-2016 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::error::{KeyRejected, Unspecified};
use core::fmt;

use crate::ptr::{ConstPointer, DetachableLcPtr, LcPtr};

use crate::signature::{Signature, VerificationAlgorithm};
use crate::{digest, sealed, test};
#[cfg(feature = "fips")]
use aws_lc::EC_KEY_check_fips;
#[cfg(not(feature = "fips"))]
use aws_lc::EC_KEY_check_key;
use aws_lc::{
    point_conversion_form_t, ECDSA_SIG_from_bytes, ECDSA_SIG_get0_r, ECDSA_SIG_get0_s,
    ECDSA_SIG_new, ECDSA_SIG_set0, ECDSA_SIG_to_bytes, ECDSA_do_verify, EC_GROUP_new_by_curve_name,
    EC_GROUP_order_bits, EC_KEY_get0_group, EC_KEY_get0_public_key, EC_KEY_new, EC_KEY_set_group,
    EC_KEY_set_private_key, EC_KEY_set_public_key, EC_POINT_mul, EC_POINT_new, EC_POINT_oct2point,
    EC_POINT_point2oct, NID_X9_62_prime256v1, NID_secp384r1, BIGNUM, ECDSA_SIG, EC_GROUP, EC_KEY,
    EC_POINT,
};

use std::fmt::{Debug, Formatter};
use std::mem::MaybeUninit;
use std::ops::Deref;
use std::os::raw::c_uint;
use std::ptr::{null, null_mut};
use std::slice;
use untrusted::Input;

pub(crate) mod key_pair;

const ELEM_MAX_BITS: usize = 384;
pub const ELEM_MAX_BYTES: usize = (ELEM_MAX_BITS + 7) / 8;

pub const SCALAR_MAX_BYTES: usize = ELEM_MAX_BYTES;

/// The maximum length, in bytes, of an encoded public key.
pub(crate) const PUBLIC_KEY_MAX_LEN: usize = 1 + (2 * ELEM_MAX_BYTES);

/// The maximum length of a PKCS#8 documents generated by *ring* for ECC keys.
///
/// This is NOT the maximum length of a PKCS#8 document that can be consumed by
/// `pkcs8::unwrap_key()`.
///
/// `40` is the length of the P-384 template. It is actually one byte shorter
/// than the P-256 template, but the private key and the public key are much
/// longer.
pub const PKCS8_DOCUMENT_MAX_LEN: usize = 40 + SCALAR_MAX_BYTES + PUBLIC_KEY_MAX_LEN;

/// An ECDSA verification algorithm.
#[derive(Debug, Eq, PartialEq)]
pub struct EcdsaVerificationAlgorithm {
    pub(super) id: &'static AlgorithmID,
    pub(super) digest: &'static digest::Algorithm,
    pub(super) bits: c_uint,
    pub(super) sig_format: EcdsaSignatureFormat,
}

/// An ECDSA signing algorithm.
#[derive(Debug, Eq, PartialEq)]
pub struct EcdsaSigningAlgorithm(pub(crate) &'static EcdsaVerificationAlgorithm);

impl Deref for EcdsaSigningAlgorithm {
    type Target = EcdsaVerificationAlgorithm;
    #[inline]
    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl sealed::Sealed for EcdsaVerificationAlgorithm {}
impl sealed::Sealed for EcdsaSigningAlgorithm {}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum EcdsaSignatureFormat {
    ASN1,
    Fixed,
}

#[derive(Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
pub(crate) enum AlgorithmID {
    ECDSA_P256,
    ECDSA_P384,
}

impl AlgorithmID {
    #[inline]
    pub(crate) fn nid(&'static self) -> i32 {
        match self {
            AlgorithmID::ECDSA_P256 => NID_X9_62_prime256v1,
            AlgorithmID::ECDSA_P384 => NID_secp384r1,
        }
    }
}

#[derive(Clone)]
pub struct PublicKey(Box<[u8]>);

impl Debug for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(&format!("PublicKey(\"{}\")", test::to_hex(self.0.as_ref())))
    }
}

impl PublicKey {
    fn new(pubkey_box: Box<[u8]>) -> Self {
        PublicKey(pubkey_box)
    }
}

impl AsRef<[u8]> for PublicKey {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

unsafe impl Send for PublicKey {}
unsafe impl Sync for PublicKey {}

impl VerificationAlgorithm for EcdsaVerificationAlgorithm {
    #[inline]
    fn verify(
        &self,
        public_key: Input<'_>,
        msg: Input<'_>,
        signature: Input<'_>,
    ) -> Result<(), Unspecified> {
        unsafe {
            let ec_group = ec_group_from_nid(self.id.nid())?;
            let ec_point = ec_point_from_bytes(&ec_group, public_key.as_slice_less_safe())?;
            let ec_key = ec_key_from_public_point(&ec_group, &ec_point)?;

            let ecdsa_sig = match self.sig_format {
                EcdsaSignatureFormat::ASN1 => ecdsa_sig_from_asn1(signature.as_slice_less_safe()),
                EcdsaSignatureFormat::Fixed => {
                    ecdsa_sig_from_fixed(self.id, signature.as_slice_less_safe())
                }
            }?;
            let msg_digest = digest::digest(self.digest, msg.as_slice_less_safe());
            let msg_digest = msg_digest.as_ref();

            if 1 != ECDSA_do_verify(msg_digest.as_ptr(), msg_digest.len(), *ecdsa_sig, *ec_key) {
                return Err(Unspecified);
            }

            Ok(())
        }
    }
}

#[inline]
unsafe fn validate_ec_key(
    ec_key: &ConstPointer<EC_KEY>,
    expected_bits: c_uint,
) -> Result<(), KeyRejected> {
    let ec_group = ConstPointer::new(EC_KEY_get0_group(**ec_key))?;
    let bits = c_uint::try_from(EC_GROUP_order_bits(*ec_group))?;

    if bits < expected_bits {
        return Err(KeyRejected::too_small());
    }

    if bits > expected_bits {
        return Err(KeyRejected::too_large());
    }

    #[cfg(not(feature = "fips"))]
    if 1 != EC_KEY_check_key(**ec_key) {
        return Err(KeyRejected::inconsistent_components());
    }

    #[cfg(feature = "fips")]
    if 1 != EC_KEY_check_fips(**ec_key) {
        return Err(KeyRejected::inconsistent_components());
    }

    Ok(())
}

pub(crate) unsafe fn marshal_public_key_to_buffer(
    buffer: &mut [u8; PUBLIC_KEY_MAX_LEN],
    ec_key: &ConstPointer<EC_KEY>,
) -> Result<usize, Unspecified> {
    let ec_group = ConstPointer::new(EC_KEY_get0_group(**ec_key))?;

    let ec_point = ConstPointer::new(EC_KEY_get0_public_key(**ec_key))?;

    let out_len = ec_point_to_bytes(&ec_group, &ec_point, buffer)?;
    Ok(out_len)
}

pub(crate) fn marshal_public_key(ec_key: &ConstPointer<EC_KEY>) -> Result<PublicKey, Unspecified> {
    unsafe {
        let mut pub_key_bytes = [0u8; PUBLIC_KEY_MAX_LEN];
        let key_len = marshal_public_key_to_buffer(&mut pub_key_bytes, ec_key)?;
        let pub_key = Vec::from(&pub_key_bytes[0..key_len]);
        Ok(PublicKey::new(pub_key.into_boxed_slice()))
    }
}

#[inline]
pub(crate) unsafe fn ec_key_from_public_point(
    ec_group: &LcPtr<*mut EC_GROUP>,
    public_ec_point: &LcPtr<*mut EC_POINT>,
) -> Result<DetachableLcPtr<*mut EC_KEY>, Unspecified> {
    let ec_key = DetachableLcPtr::new(EC_KEY_new())?;
    if 1 != EC_KEY_set_group(*ec_key, **ec_group) {
        return Err(Unspecified);
    }
    if 1 != EC_KEY_set_public_key(*ec_key, **public_ec_point) {
        return Err(Unspecified);
    }
    Ok(ec_key)
}

#[inline]
pub(crate) unsafe fn ec_key_from_private(
    ec_group: &ConstPointer<EC_GROUP>,
    private_big_num: &ConstPointer<BIGNUM>,
) -> Result<DetachableLcPtr<*mut EC_KEY>, Unspecified> {
    let ec_key = DetachableLcPtr::new(EC_KEY_new())?;
    if 1 != EC_KEY_set_group(*ec_key, **ec_group) {
        return Err(Unspecified);
    }
    if 1 != EC_KEY_set_private_key(*ec_key, **private_big_num) {
        return Err(Unspecified);
    }
    let pub_key = LcPtr::new(EC_POINT_new(**ec_group))?;
    if 1 != EC_POINT_mul(
        **ec_group,
        *pub_key,
        **private_big_num,
        null(),
        null(),
        null_mut(),
    ) {
        return Err(Unspecified);
    }
    if 1 != EC_KEY_set_public_key(*ec_key, *pub_key) {
        return Err(Unspecified);
    }

    Ok(ec_key)
}

#[inline]
unsafe fn ec_key_from_public_private(
    ec_group: &LcPtr<*mut EC_GROUP>,
    public_ec_point: &LcPtr<*mut EC_POINT>,
    private_bignum: &DetachableLcPtr<*mut BIGNUM>,
) -> Result<LcPtr<*mut EC_KEY>, ()> {
    let ec_key = LcPtr::new(EC_KEY_new())?;
    if 1 != EC_KEY_set_group(*ec_key, **ec_group) {
        return Err(());
    }
    if 1 != EC_KEY_set_public_key(*ec_key, **public_ec_point) {
        return Err(());
    }
    if 1 != EC_KEY_set_private_key(*ec_key, **private_bignum) {
        return Err(());
    }
    Ok(ec_key)
}

#[inline]
pub(crate) unsafe fn ec_group_from_nid(nid: i32) -> Result<LcPtr<*mut EC_GROUP>, ()> {
    LcPtr::new(EC_GROUP_new_by_curve_name(nid))
}

#[inline]
pub(crate) unsafe fn ec_point_from_bytes(
    ec_group: &LcPtr<*mut EC_GROUP>,
    bytes: &[u8],
) -> Result<LcPtr<*mut EC_POINT>, Unspecified> {
    let ec_point = LcPtr::new(EC_POINT_new(**ec_group))?;

    if 1 != EC_POINT_oct2point(
        **ec_group,
        *ec_point,
        bytes.as_ptr(),
        bytes.len(),
        null_mut(),
    ) {
        return Err(Unspecified);
    }

    Ok(ec_point)
}

#[inline]
unsafe fn ec_point_to_bytes(
    ec_group: &ConstPointer<EC_GROUP>,
    ec_point: &ConstPointer<EC_POINT>,
    buf: &mut [u8; PUBLIC_KEY_MAX_LEN],
) -> Result<usize, Unspecified> {
    let pt_conv_form = point_conversion_form_t::POINT_CONVERSION_UNCOMPRESSED;

    let out_len = EC_POINT_point2oct(
        **ec_group,
        **ec_point,
        pt_conv_form,
        buf.as_mut_ptr().cast(),
        PUBLIC_KEY_MAX_LEN,
        null_mut(),
    );
    if out_len == 0 {
        return Err(Unspecified);
    }

    Ok(out_len)
}

#[inline]
unsafe fn ecdsa_sig_to_asn1(ecdsa_sig: &LcPtr<*mut ECDSA_SIG>) -> Result<Signature, Unspecified> {
    let mut out_bytes = MaybeUninit::<*mut u8>::uninit();
    let mut out_len = MaybeUninit::<usize>::uninit();

    if 1 != ECDSA_SIG_to_bytes(out_bytes.as_mut_ptr(), out_len.as_mut_ptr(), **ecdsa_sig) {
        return Err(Unspecified);
    }
    let out_bytes = LcPtr::new(out_bytes.assume_init())?;
    let out_len = out_len.assume_init();

    Ok(Signature::new(|slice| {
        let out_bytes = slice::from_raw_parts(*out_bytes, out_len);
        slice[0..out_len].copy_from_slice(out_bytes);
        out_len
    }))
}

#[inline]
unsafe fn ecdsa_sig_to_fixed(
    alg_id: &'static AlgorithmID,
    sig: &LcPtr<*mut ECDSA_SIG>,
) -> Result<Signature, Unspecified> {
    let expected_number_size = ecdsa_fixed_number_byte_size(alg_id);

    let r_bn = ConstPointer::new(ECDSA_SIG_get0_r(**sig))?;
    let r_buffer = r_bn.to_be_bytes();

    let s_bn = ConstPointer::new(ECDSA_SIG_get0_s(**sig))?;
    let s_buffer = s_bn.to_be_bytes();

    Ok(Signature::new(|slice| {
        let (r_start, r_end) = (
            (expected_number_size - r_buffer.len()),
            expected_number_size,
        );
        let (s_start, s_end) = (
            (2 * expected_number_size - s_buffer.len()),
            2 * expected_number_size,
        );

        slice[r_start..r_end].copy_from_slice(r_buffer.as_slice());
        slice[s_start..s_end].copy_from_slice(s_buffer.as_slice());
        2 * expected_number_size
    }))
}

#[inline]
unsafe fn ecdsa_sig_from_asn1(signature: &[u8]) -> Result<LcPtr<*mut ECDSA_SIG>, ()> {
    LcPtr::new(ECDSA_SIG_from_bytes(signature.as_ptr(), signature.len()))
}

#[inline]
const fn ecdsa_fixed_number_byte_size(alg_id: &'static AlgorithmID) -> usize {
    match alg_id {
        AlgorithmID::ECDSA_P256 => 32,
        AlgorithmID::ECDSA_P384 => 48,
    }
}

#[inline]
unsafe fn ecdsa_sig_from_fixed(
    alg_id: &'static AlgorithmID,
    signature: &[u8],
) -> Result<LcPtr<*mut ECDSA_SIG>, ()> {
    let num_size_bytes = ecdsa_fixed_number_byte_size(alg_id);
    if signature.len() != 2 * num_size_bytes {
        return Err(());
    }
    let r_bn = DetachableLcPtr::try_from(&signature[..num_size_bytes])?;
    let s_bn = DetachableLcPtr::try_from(&signature[num_size_bytes..])?;

    let ecdsa_sig = LcPtr::new(ECDSA_SIG_new())?;

    if 1 != ECDSA_SIG_set0(*ecdsa_sig, *r_bn, *s_bn) {
        return Err(());
    }
    r_bn.detach();
    s_bn.detach();

    Ok(ecdsa_sig)
}

#[cfg(test)]
mod tests {
    use crate::ec::key_pair::EcdsaKeyPair;
    use crate::signature::ECDSA_P256_SHA256_FIXED_SIGNING;
    use crate::test::from_dirty_hex;
    use crate::{signature, test};

    #[test]
    fn test_from_pkcs8() {
        let input = from_dirty_hex(
            r#"308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420090460075f15d
            2a256248000fb02d83ad77593dde4ae59fc5e96142dffb2bd07a14403420004cf0d13a3a7577231ea1b66cf4
            021cd54f21f4ac4f5f2fdd28e05bc7d2bd099d1374cd08d2ef654d6f04498db462f73e0282058dd661a4c9b0
            437af3f7af6e724"#,
        );

        let result = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &input);
        result.unwrap();
    }

    #[test]
    fn test_ecdsa_asn1_verify() {
        /*
                Curve = P-256
        Digest = SHA256
        Msg = ""
        Q = 0430345fd47ea21a11129be651b0884bfac698377611acc9f689458e13b9ed7d4b9d7599a68dcf125e7f31055ccb374cd04f6d6fd2b217438a63f6f667d50ef2f0
        Sig = 30440220341f6779b75e98bb42e01095dd48356cbf9002dc704ac8bd2a8240b88d3796c60220555843b1b4e264fe6ffe6e2b705a376c05c09404303ffe5d2711f3e3b3a010a1
        Result = P (0 )
                 */

        let alg = &signature::ECDSA_P256_SHA256_ASN1;
        let msg = "";
        let public_key = from_dirty_hex(
            r#"0430345fd47ea21a11129be651b0884bfac698377611acc9f689458e1
        3b9ed7d4b9d7599a68dcf125e7f31055ccb374cd04f6d6fd2b217438a63f6f667d50ef2f0"#,
        );
        let sig = from_dirty_hex(
            r#"30440220341f6779b75e98bb42e01095dd48356cbf9002dc704ac8bd2a8240b8
        8d3796c60220555843b1b4e264fe6ffe6e2b705a376c05c09404303ffe5d2711f3e3b3a010a1"#,
        );
        let actual_result =
            signature::UnparsedPublicKey::new(alg, &public_key).verify(msg.as_bytes(), &sig);
        assert!(actual_result.is_ok(), "Key: {}", test::to_hex(public_key));
    }
}
