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

// *R* and *r* in Montgomery math refer to different things, so we always use
// `R` to refer to *R* to avoid confusion, even when that's against the normal
// naming conventions. Also the standard camelCase names are used for `KeyPair`
// components.

use crate::digest::match_digest_type;
use crate::error::{KeyRejected, Unspecified};
use crate::ptr::{DetachableLcPtr, LcPtr, NonNullPtr};
use crate::sealed::Sealed;
use crate::signature::{KeyPair, VerificationAlgorithm};
use crate::{cbs, digest, rand, test};
use aws_lc_sys::{BN_cmp, BN_new, BN_set_u64, EVP_parse_private_key, RSA_new, BIGNUM, RSA};
use std::cmp::Ordering;
use std::fmt::{Debug, Formatter};
use std::mem::MaybeUninit;
use std::ops::RangeInclusive;
use std::os::raw::c_uint;
use std::ptr::{null, null_mut};
use std::slice;
use untrusted::Input;
use zeroize::Zeroize;

pub mod evp_pkey;

pub struct RsaKeyPair {
    // https://github.com/awslabs/aws-lc/blob/main/include/openssl/rsa.h#L286
    // An |RSA| object represents a public or private RSA key. A given object may be
    // used concurrently on multiple threads by non-mutating functions, provided no
    // other thread is concurrently calling a mutating function. Unless otherwise
    // documented, functions which take a |const| pointer are non-mutating and
    // functions which take a non-|const| pointer are mutating.
    rsa_key: LcPtr<*mut RSA>,
    serialized_public_key: RsaSubjectPublicKey,
}

impl Sealed for RsaKeyPair {}
unsafe impl Send for RsaKeyPair {}
unsafe impl Sync for RsaKeyPair {}

impl Drop for RsaKeyPair {
    fn drop(&mut self) {
        self.serialized_public_key.0.zeroize();
    }
}

impl RsaKeyPair {
    fn new(rsa_key: LcPtr<*mut RSA>) -> Result<Self, Unspecified> {
        unsafe {
            let pubkey_bytes = serialize_RSA_pubkey(rsa_key.as_non_null())?;
            let serialized_public_key = RsaSubjectPublicKey::new(pubkey_bytes);
            Ok(RsaKeyPair {
                rsa_key,
                serialized_public_key,
            })
        }
    }

    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, KeyRejected> {
        unsafe {
            let mut cbs = cbs::build_CBS(pkcs8);
            let evp_pkey = LcPtr::new(EVP_parse_private_key(&mut cbs))
                .map_err(|_| KeyRejected::invalid_encoding())?;
            let rsa = LcPtr::new(aws_lc_sys::EVP_PKEY_get1_RSA(*evp_pkey))
                .map_err(|_| KeyRejected::wrong_algorithm())?;
            Self::validate_rsa(rsa.as_non_null())?;

            Self::new(rsa).map_err(|_| KeyRejected::unexpected_error())
        }
    }

    pub fn from_der(der: &[u8]) -> Result<Self, KeyRejected> {
        unsafe {
            let rsa = build_private_RSA(der)?;
            Self::validate_rsa(rsa.as_non_null())?;
            Self::new(rsa).map_err(|_| KeyRejected::unexpected_error())
        }
    }
    const MIN_RSA_BITS: c_uint = 1024;
    const MAX_RSA_BITS: c_uint = 2048;

    unsafe fn validate_rsa(rsa: NonNullPtr<*mut RSA>) -> Result<(), KeyRejected> {
        let p = aws_lc_sys::RSA_get0_p(*rsa);
        let q = aws_lc_sys::RSA_get0_q(*rsa);
        let p_bits = aws_lc_sys::BN_num_bits(p);
        let q_bits = aws_lc_sys::BN_num_bits(q);
        if p_bits != q_bits {
            return Err(KeyRejected::inconsistent_components());
        }
        if p_bits % 512 != 0 {
            return Err(KeyRejected::private_modulus_len_not_multiple_of_512_bits());
        }
        if p_bits < Self::MIN_RSA_BITS {
            return Err(KeyRejected::too_small());
        }
        if p_bits > Self::MAX_RSA_BITS {
            return Err(KeyRejected::too_large());
        }
        let exponent = aws_lc_sys::RSA_get0_e(*rsa);
        if Self::compare(exponent, 65537)? == Ordering::Less {
            return Err(KeyRejected::too_small());
        }
        Ok(())
    }

    unsafe fn compare(a: *const BIGNUM, b: u64) -> Result<Ordering, KeyRejected> {
        let b_val = LcPtr::new(BN_new()).map_err(|_| KeyRejected::unexpected_error())?;
        if 1 != BN_set_u64(*b_val, b) {
            return Err(KeyRejected::unexpected_error());
        }
        let result = BN_cmp(a, *b_val) as i32;

        Ok(result.cmp(&0))
    }
}

impl VerificationAlgorithm for RsaParameters {
    fn verify(
        &self,
        public_key: Input<'_>,
        msg: Input<'_>,
        signature: Input<'_>,
    ) -> Result<(), Unspecified> {
        unsafe {
            let rsa = build_public_RSA(public_key.as_slice_less_safe())?;
            RSA_verify(
                self.0,
                self.1,
                rsa,
                msg.as_slice_less_safe(),
                signature.as_slice_less_safe(),
                &self.2,
            )
        }
    }
}

impl RsaKeyPair {
    /// Sign `msg`. `msg` is digested using the digest algorithm from
    /// `padding_alg` and the digest is then padded using the padding algorithm
    /// from `padding_alg`. The signature it written into `signature`;
    /// `signature`'s length must be exactly the length returned by
    /// `public_modulus_len()`. `rng` may be used to randomize the padding
    /// (e.g. for PSS).
    ///
    /// Many other crypto libraries have signing functions that takes a
    /// precomputed digest as input, instead of the message to digest. This
    /// function does *not* take a precomputed digest; instead, `sign`
    /// calculates the digest itself.
    ///
    /// Lots of effort has been made to make the signing operations close to
    /// constant time to protect the private key from side channel attacks. On
    /// x86-64, this is done pretty well, but not perfectly. On other
    /// platforms, it is done less perfectly.
    pub fn sign(
        &self,
        padding_alg: &'static dyn RsaEncoding,
        _rng: &dyn rand::SecureRandom,
        msg: &[u8],
        signature: &mut [u8],
    ) -> Result<(), Unspecified> {
        let encoding = padding_alg.encoding();
        let mut output_len = self.public_modulus_len();
        if signature.len() != output_len {
            return Err(Unspecified);
        }
        unsafe {
            let digest_alg = encoding.0;
            let digest = digest::digest(digest_alg, msg);
            let digest = digest.as_ref();

            let padding = encoding.1;
            // These functions are non-mutating of RSA:
            // https://github.com/awslabs/aws-lc/blob/main/include/openssl/rsa.h#L286
            let result = match padding {
                RsaPadding::RSA_PKCS1_PADDING => aws_lc_sys::RSA_sign(
                    digest_alg.hash_nid,
                    digest.as_ptr(),
                    digest.len() as c_uint,
                    signature.as_mut_ptr(),
                    &mut (output_len as c_uint),
                    *self.rsa_key,
                ),
                RsaPadding::RSA_PKCS1_PSS_PADDING => aws_lc_sys::RSA_sign_pss_mgf1(
                    *self.rsa_key,
                    &mut output_len,
                    signature.as_mut_ptr(),
                    output_len,
                    digest.as_ptr(),
                    digest.len(),
                    digest::match_digest_type(&digest_alg.id),
                    null(),
                    -1,
                ),
            };

            debug_assert_eq!(output_len as usize, signature.len());

            if result != 1 {
                return Err(Unspecified);
            }
        }
        Ok(())
    }

    pub fn public_modulus_len(&self) -> usize {
        // https://github.com/awslabs/aws-lc/blob/main/include/openssl/rsa.h#L99
        unsafe { (aws_lc_sys::RSA_bits(*self.rsa_key) / 8) as usize }
    }
}

impl Debug for RsaKeyPair {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!(
            "RsaKeyPair {{ public_key: {:?} }}",
            self.serialized_public_key
        ))
    }
}

#[derive(Clone)]
pub struct RsaSubjectPublicKey(Box<[u8]>);

impl RsaSubjectPublicKey {
    fn new(pubkey_box: Box<[u8]>) -> Self {
        RsaSubjectPublicKey(pubkey_box)
    }
}

#[allow(non_snake_case)]
unsafe fn serialize_RSA_pubkey(pubkey: NonNullPtr<*mut RSA>) -> Result<Box<[u8]>, Unspecified> {
    let mut pubkey_bytes = MaybeUninit::<*mut u8>::uninit();
    let mut outlen = MaybeUninit::<usize>::uninit();
    if 1 != aws_lc_sys::RSA_public_key_to_bytes(
        pubkey_bytes.as_mut_ptr(),
        outlen.as_mut_ptr(),
        *pubkey,
    ) {
        return Err(Unspecified);
    }
    let pubkey_bytes = LcPtr::new(pubkey_bytes.assume_init()).map_err(|_| Unspecified)?;
    let outlen = outlen.assume_init();
    let pubkey_slice = slice::from_raw_parts(*pubkey_bytes, outlen);
    let mut pubkey_vec = Vec::<u8>::new();
    pubkey_vec.extend_from_slice(pubkey_slice);

    Ok(pubkey_vec.into_boxed_slice())
}

impl KeyPair for RsaKeyPair {
    type PublicKey = RsaSubjectPublicKey;

    fn public_key(&self) -> &Self::PublicKey {
        &self.serialized_public_key
    }
}

impl Debug for RsaSubjectPublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!(
            "RsaSubjectPublicKey(\"{}\")",
            test::to_hex(self.0.as_ref())
        ))
    }
}

impl AsRef<[u8]> for RsaSubjectPublicKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum RSASigningAlgorithmId {
    RSA_PSS_SHA256,
    RSA_PSS_SHA384,
    RSA_PSS_SHA512,
    RSA_PKCS1_SHA256,
    RSA_PKCS1_SHA384,
    RSA_PKCS1_SHA512,
}

#[cfg(feature = "alloc")]
pub struct RsaSignatureEncoding(
    pub(super) &'static digest::Algorithm,
    pub(super) &'static RsaPadding,
    pub(super) &'static RSASigningAlgorithmId,
);

#[allow(non_camel_case_types)]
pub enum RsaPadding {
    RSA_PKCS1_PADDING,
    RSA_PKCS1_PSS_PADDING,
}

pub trait RsaEncoding {
    fn encoding(&'static self) -> &'static RsaSignatureEncoding;
}

impl RsaEncoding for RsaSignatureEncoding {
    fn encoding(&'static self) -> &'static RsaSignatureEncoding {
        self
    }
}

impl Debug for RsaSignatureEncoding {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("{{ {:?} }}", self.2))
    }
}

#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum RSAVerificationAlgorithmId {
    RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
    RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
    RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY,
    RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
    RSA_PKCS1_2048_8192_SHA256,
    RSA_PKCS1_2048_8192_SHA384,
    RSA_PKCS1_2048_8192_SHA512,
    RSA_PKCS1_3072_8192_SHA384,
    RSA_PSS_2048_8192_SHA256,
    RSA_PSS_2048_8192_SHA384,
    RSA_PSS_2048_8192_SHA512,
}

#[cfg(feature = "alloc")]
pub struct RsaParameters(
    pub(super) &'static digest::Algorithm,
    pub(super) &'static RsaPadding,
    pub(super) RangeInclusive<u32>,
    pub(super) &'static RSAVerificationAlgorithmId,
);
impl Sealed for RsaParameters {}

impl Debug for RsaParameters {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("{{ {:?} }}", self.3))
    }
}

impl RsaParameters {
    pub fn public_modulus_len(public_key: &[u8]) -> Result<u32, Unspecified> {
        unsafe {
            let mut cbs = cbs::build_CBS(public_key);
            let rsa =
                LcPtr::new(aws_lc_sys::RSA_parse_public_key(&mut cbs)).map_err(|_| Unspecified)?;
            let mod_len = aws_lc_sys::RSA_bits(*rsa);

            Ok(mod_len)
        }
    }

    pub fn min_modulus_len(&self) -> u32 {
        *self.2.start()
    }

    pub fn max_modulus_len(&self) -> u32 {
        *self.2.end()
    }
}

#[inline]
#[allow(non_snake_case)]
unsafe fn build_public_RSA(public_key: &[u8]) -> Result<LcPtr<*mut RSA>, Unspecified> {
    let mut cbs = cbs::build_CBS(public_key);

    let rsa = LcPtr::new(aws_lc_sys::RSA_parse_public_key(&mut cbs)).map_err(|_| Unspecified)?;
    Ok(rsa)
}

#[inline]
#[allow(non_snake_case)]
unsafe fn build_private_RSA(public_key: &[u8]) -> Result<LcPtr<*mut RSA>, KeyRejected> {
    let mut cbs = cbs::build_CBS(public_key);

    let rsa = LcPtr::new(aws_lc_sys::RSA_parse_private_key(&mut cbs))
        .map_err(|_| KeyRejected::invalid_encoding())?;
    Ok(rsa)
}

#[inline]
#[allow(non_snake_case)]
fn RSA_verify(
    algorithm: &'static digest::Algorithm,
    padding: &'static RsaPadding,
    public_key: LcPtr<*mut RSA>,
    msg: &[u8],
    signature: &[u8],
    allowed_bit_size: &RangeInclusive<u32>,
) -> Result<(), Unspecified> {
    unsafe {
        let n = NonNullPtr::new(aws_lc_sys::RSA_get0_n(*public_key))?;
        let n_bits = aws_lc_sys::BN_num_bits(*n);
        let n_bits = n_bits as c_uint;
        if !allowed_bit_size.contains(&n_bits) {
            return Err(Unspecified);
        }

        let digest = digest::digest(algorithm, msg);
        let digest = digest.as_ref();

        let result = match padding {
            RsaPadding::RSA_PKCS1_PADDING => aws_lc_sys::RSA_verify(
                algorithm.hash_nid,
                digest.as_ptr(),
                digest.len(),
                signature.as_ptr(),
                signature.len(),
                *public_key,
            ),
            RsaPadding::RSA_PKCS1_PSS_PADDING => aws_lc_sys::RSA_verify_pss_mgf1(
                *public_key,
                digest.as_ptr(),
                digest.len(),
                match_digest_type(&algorithm.id),
                null(),
                -1,
                signature.as_ptr(),
                signature.len(),
            ),
        };

        if result != 1 {
            return Err(Unspecified);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct RsaPublicKeyComponents<B>
where
    B: AsRef<[u8]> + Debug,
{
    pub n: B,
    pub e: B,
}

impl<B> RsaPublicKeyComponents<B>
where
    B: AsRef<[u8]> + Debug,
{
    #[allow(non_snake_case)]
    #[inline]
    unsafe fn build_RSA(&self) -> Result<LcPtr<*mut RSA>, Unspecified> {
        let n_bytes = self.n.as_ref();
        if n_bytes.is_empty() || n_bytes[0] == 0u8 {
            return Err(Unspecified);
        }
        let n_bn = DetachableLcPtr::new(aws_lc_sys::BN_bin2bn(
            n_bytes.as_ptr(),
            n_bytes.len(),
            null_mut(),
        ))
        .map_err(|_| Unspecified)?;

        let e_bytes = self.e.as_ref();
        if e_bytes.is_empty() || e_bytes[0] == 0u8 {
            return Err(Unspecified);
        }
        let e_bn = DetachableLcPtr::new(aws_lc_sys::BN_bin2bn(
            e_bytes.as_ptr(),
            e_bytes.len(),
            null_mut(),
        ))
        .map_err(|_| Unspecified)?;

        let rsa = LcPtr::new(RSA_new()).map_err(|_| Unspecified)?;
        if 1 != aws_lc_sys::RSA_set0_key(*rsa, *n_bn, *e_bn, null_mut()) {
            return Err(Unspecified);
        }
        n_bn.detach();
        e_bn.detach();
        Ok(rsa)
    }

    #[allow(unused_variables, dead_code)]
    pub fn verify(
        &self,
        params: &RsaParameters,
        msg: &[u8],
        signature: &[u8],
    ) -> Result<(), Unspecified> {
        unsafe {
            let rsa = self.build_RSA()?;
            RSA_verify(params.0, params.1, rsa, msg, signature, &params.2)
        }
    }
}
