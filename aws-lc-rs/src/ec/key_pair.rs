// Copyright 2015-2016 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use aws_lc::{
    ECDSA_SIG_get0_r, ECDSA_SIG_get0_s, ECDSA_SIG_to_bytes, ECDSA_do_sign, EVP_DigestSign,
    EVP_DigestSignInit, EVP_PKEY_get0_EC_KEY, ECDSA_SIG, EVP_PKEY,
};
use core::fmt;
use core::fmt::{Debug, Formatter};
use core::mem::MaybeUninit;
use core::ptr::{null, null_mut};
use std::slice;

use crate::digest::digest_ctx::DigestContext;
#[cfg(feature = "fips")]
use crate::ec::validate_evp_key;
#[cfg(not(feature = "fips"))]
use crate::ec::verify_evp_key_nid;
use crate::ec::{
    evp_key_generate, AlgorithmID, EcdsaSignatureFormat, EcdsaSigningAlgorithm, PublicKey,
};

use crate::digest::Digest;
use crate::encoding::{AsBigEndian, AsDer, EcPrivateKeyBin, EcPrivateKeyRfc5915Der};
use crate::error::{KeyRejected, Unspecified};
use crate::fips::indicator_check;
use crate::pkcs8::{Document, Version};
use crate::ptr::{ConstPointer, DetachableLcPtr, LcPtr};
use crate::rand::SecureRandom;
use crate::signature::{KeyPair, Signature};
use crate::{digest, ec};

/// An ECDSA key pair, used for signing.
#[allow(clippy::module_name_repetitions)]
pub struct EcdsaKeyPair {
    algorithm: &'static EcdsaSigningAlgorithm,
    evp_pkey: LcPtr<EVP_PKEY>,
    pubkey: PublicKey,
}

impl Debug for EcdsaKeyPair {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(&format!("EcdsaKeyPair {{ public_key: {:?} }}", self.pubkey))
    }
}

unsafe impl Send for EcdsaKeyPair {}

unsafe impl Sync for EcdsaKeyPair {}

impl KeyPair for EcdsaKeyPair {
    type PublicKey = PublicKey;

    #[inline]
    /// Provides the public key.
    fn public_key(&self) -> &Self::PublicKey {
        &self.pubkey
    }
}

impl EcdsaKeyPair {
    #[allow(clippy::needless_pass_by_value)]
    fn new(
        algorithm: &'static EcdsaSigningAlgorithm,
        evp_pkey: LcPtr<EVP_PKEY>,
    ) -> Result<Self, ()> {
        let pubkey = ec::marshal_public_key(&evp_pkey.as_const(), algorithm)?;

        Ok(Self {
            algorithm,
            evp_pkey,
            pubkey,
        })
    }

    /// Generates a new key pair.
    ///
    /// # Errors
    /// `error::Unspecified` on internal error.
    ///
    pub fn generate(alg: &'static EcdsaSigningAlgorithm) -> Result<Self, Unspecified> {
        let evp_pkey = evp_key_generate(alg.0.id.nid())?;

        Ok(Self::new(alg, evp_pkey)?)
    }

    /// Constructs an ECDSA key pair by parsing an unencrypted PKCS#8 v1
    /// id-ecPublicKey `ECPrivateKey` key.
    ///
    /// # Errors
    /// `error::KeyRejected` if bytes do not encode an ECDSA key pair or if the key is otherwise not
    /// acceptable.
    pub fn from_pkcs8(
        alg: &'static EcdsaSigningAlgorithm,
        pkcs8: &[u8],
    ) -> Result<Self, KeyRejected> {
        // Includes a call to `EC_KEY_check_key`
        let evp_pkey = LcPtr::<EVP_PKEY>::try_from(pkcs8)?;

        #[cfg(not(feature = "fips"))]
        verify_evp_key_nid(&evp_pkey.as_const(), alg.id.nid())?;
        #[cfg(feature = "fips")]
        validate_evp_key(&evp_pkey.as_const(), alg.id.nid())?;

        let key_pair = Self::new(alg, evp_pkey)?;

        Ok(key_pair)
    }

    /// Generates a new key pair and returns the key pair serialized as a
    /// PKCS#8 v1 document.
    ///
    /// # *ring* Compatibility
    /// Our implementation ignores the `SecureRandom` parameter.
    ///
    /// # Errors
    /// `error::Unspecified` on internal error.
    pub fn generate_pkcs8(
        alg: &'static EcdsaSigningAlgorithm,
        _rng: &dyn SecureRandom,
    ) -> Result<Document, Unspecified> {
        let key_pair = Self::generate(alg)?;

        key_pair.to_pkcs8v1()
    }

    /// Serializes this `EcdsaKeyPair` into a PKCS#8 v1 document.
    ///
    /// # Errors
    /// `error::Unspecified` on internal error.
    ///
    pub fn to_pkcs8v1(&self) -> Result<Document, Unspecified> {
        self.evp_pkey.marshall_private_key(Version::V1)
    }

    /// Constructs an ECDSA key pair from the private key and public key bytes
    ///
    /// The private key must encoded as a big-endian fixed-length integer. For
    /// example, a P-256 private key must be 32 bytes prefixed with leading
    /// zeros as needed.
    ///
    /// The public key is encoding in uncompressed form using the
    /// Octet-String-to-Elliptic-Curve-Point algorithm in
    /// [SEC 1: Elliptic Curve Cryptography, Version 2.0].
    ///
    /// This is intended for use by code that deserializes key pairs. It is
    /// recommended to use `EcdsaKeyPair::from_pkcs8()` (with a PKCS#8-encoded
    /// key) instead.
    ///
    /// [SEC 1: Elliptic Curve Cryptography, Version 2.0]:
    ///     http://www.secg.org/sec1-v2.pdf
    ///
    /// # Errors
    /// `error::KeyRejected` if parsing failed or key otherwise unacceptable.
    pub fn from_private_key_and_public_key(
        alg: &'static EcdsaSigningAlgorithm,
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<Self, KeyRejected> {
        let ec_group = ec::ec_group_from_nid(alg.0.id.nid())?;
        let public_ec_point = ec::ec_point_from_bytes(&ec_group, public_key)
            .map_err(|_| KeyRejected::invalid_encoding())?;
        let private_bn = DetachableLcPtr::try_from(private_key)?;
        let evp_pkey =
            ec::evp_key_from_public_private(&ec_group, Some(&public_ec_point), &private_bn)?;

        let key_pair = Self::new(alg, evp_pkey)?;
        Ok(key_pair)
    }

    /// Deserializes a DER-encoded private key structure to produce a `EcdsaKeyPair`.
    ///
    /// This function is typically used to deserialize RFC 5915 encoded private keys, but it will
    /// attempt to automatically detect other key formats. This function supports unencrypted
    /// PKCS#8 `PrivateKeyInfo` structures as well as key type specific formats.
    ///
    /// See `EcdsaPrivateKey::as_der`.
    ///
    /// # Errors
    /// `error::KeyRejected` if parsing failed or key otherwise unacceptable.
    ///
    /// # Panics
    pub fn from_private_key_der(
        alg: &'static EcdsaSigningAlgorithm,
        private_key: &[u8],
    ) -> Result<Self, KeyRejected> {
        let evp_pkey = ec::unmarshal_der_to_private_key(private_key, alg.id.nid())?;

        Ok(Self::new(alg, evp_pkey)?)
    }

    /// Access functions related to the private key.
    #[must_use]
    pub fn private_key(&self) -> PrivateKey<'_> {
        PrivateKey(self)
    }

    /// Returns the signature of the message using a random nonce.
    ///
    /// # *ring* Compatibility
    /// Our implementation ignores the `SecureRandom` parameter.
    ///
    /// # Errors
    /// `error::Unspecified` on internal error.
    //
    // # FIPS
    // The following conditions must be met:
    // * NIST Elliptic Curves: P256, P384, P521
    // * Digest Algorithms: SHA256, SHA384, SHA512
    #[inline]
    pub fn sign(&self, _rng: &dyn SecureRandom, message: &[u8]) -> Result<Signature, Unspecified> {
        let mut md_ctx = DigestContext::new_uninit();

        let digest = digest::match_digest_type(&self.algorithm.digest.id);

        if 1 != unsafe {
            EVP_DigestSignInit(
                md_ctx.as_mut_ptr(),
                null_mut(),
                *digest,
                null_mut(),
                *self.evp_pkey,
            )
        } {
            return Err(Unspecified);
        }

        let mut out_sig = vec![0u8; get_signature_length(&mut md_ctx)?];

        let out_sig = compute_ecdsa_signature(&mut md_ctx, message, out_sig.as_mut_slice())?;

        Ok(match self.algorithm.sig_format {
            EcdsaSignatureFormat::ASN1 => Signature::new(|slice| {
                slice[..out_sig.len()].copy_from_slice(out_sig);
                out_sig.len()
            }),
            EcdsaSignatureFormat::Fixed => ec::ecdsa_asn1_to_fixed(self.algorithm.id, out_sig)?,
        })
    }

    /// Returns the signature of the digest using a random nonce.
    ///
    /// # Errors
    /// `error::Unspecified` on internal error.
    ///
    #[inline]
    pub fn sign_digest(&self, digest: &Digest) -> Result<Signature, Unspecified> {
        if self.algorithm.digest != digest.algorithm() {
            return Err(Unspecified);
        }
        let ec_key = ConstPointer::new(unsafe { EVP_PKEY_get0_EC_KEY(*self.evp_pkey) })?;
        let digest_bytes = digest.as_ref();
        let ecdsa_sig = LcPtr::new(unsafe {
            ECDSA_do_sign(digest_bytes.as_ptr(), digest_bytes.len(), *ec_key)
        })?;
        match self.algorithm.sig_format {
            EcdsaSignatureFormat::ASN1 => ecdsa_sig_to_asn1(&ecdsa_sig),
            EcdsaSignatureFormat::Fixed => ecdsa_sig_to_fixed(self.algorithm.id, &ecdsa_sig),
        }
    }
}

#[inline]
fn ecdsa_sig_to_asn1(ecdsa_sig: &LcPtr<ECDSA_SIG>) -> Result<Signature, Unspecified> {
    let mut out_bytes: *mut u8 = null_mut();
    let mut out_len: usize = 0;

    if 1 != unsafe { ECDSA_SIG_to_bytes(&mut out_bytes, &mut out_len, **ecdsa_sig) } {
        return Err(Unspecified);
    }
    let out_bytes = LcPtr::new(out_bytes)?;

    Ok(Signature::new(|slice| {
        let out_bytes = unsafe { slice::from_raw_parts(*out_bytes, out_len) };
        slice[0..out_len].copy_from_slice(out_bytes);
        out_len
    }))
}

#[inline]
const fn ecdsa_fixed_number_byte_size(alg_id: &'static AlgorithmID) -> usize {
    match alg_id {
        AlgorithmID::ECDSA_P256 | AlgorithmID::ECDSA_P256K1 => 32,
        AlgorithmID::ECDSA_P384 => 48,
        AlgorithmID::ECDSA_P521 => 66,
    }
}

#[inline]
fn ecdsa_sig_to_fixed(
    alg_id: &'static AlgorithmID,
    sig: &LcPtr<ECDSA_SIG>,
) -> Result<Signature, Unspecified> {
    let expected_number_size = ecdsa_fixed_number_byte_size(alg_id);

    let r_bn = ConstPointer::new(unsafe { ECDSA_SIG_get0_r(**sig) })?;
    let r_buffer = r_bn.to_be_bytes();

    let s_bn = ConstPointer::new(unsafe { ECDSA_SIG_get0_s(**sig) })?;
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
fn get_signature_length(ctx: &mut DigestContext) -> Result<usize, Unspecified> {
    let mut out_sig_len = MaybeUninit::<usize>::uninit();

    // determine signature size
    if 1 != unsafe {
        EVP_DigestSign(
            ctx.as_mut_ptr(),
            null_mut(),
            out_sig_len.as_mut_ptr(),
            null(),
            0,
        )
    } {
        return Err(Unspecified);
    }

    Ok(unsafe { out_sig_len.assume_init() })
}

#[inline]
fn compute_ecdsa_signature<'a>(
    ctx: &mut DigestContext,
    message: &[u8],
    signature: &'a mut [u8],
) -> Result<&'a mut [u8], Unspecified> {
    let mut out_sig_len = signature.len();

    if 1 != indicator_check!(unsafe {
        EVP_DigestSign(
            ctx.as_mut_ptr(),
            signature.as_mut_ptr(),
            &mut out_sig_len,
            message.as_ptr(),
            message.len(),
        )
    }) {
        return Err(Unspecified);
    }

    Ok(&mut signature[0..out_sig_len])
}

/// Elliptic curve private key.
pub struct PrivateKey<'a>(&'a EcdsaKeyPair);

impl Debug for PrivateKey<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&format!("EcdsaPrivateKey({:?})", self.0.algorithm.id))
    }
}

impl AsBigEndian<EcPrivateKeyBin<'static>> for PrivateKey<'_> {
    /// Exposes the private key encoded as a big-endian fixed-length integer.
    ///
    /// For most use-cases, `EcdsaKeyPair::to_pkcs8()` should be preferred.
    ///
    /// # Errors
    /// `error::Unspecified` if serialization failed.
    fn as_be_bytes(&self) -> Result<EcPrivateKeyBin<'static>, Unspecified> {
        unsafe {
            let buffer = ec::marshal_private_key_to_buffer(
                self.0.algorithm.id.private_key_size(),
                &self.0.evp_pkey.as_const(),
            )?;
            Ok(EcPrivateKeyBin::new(buffer))
        }
    }
}

impl AsDer<EcPrivateKeyRfc5915Der<'static>> for PrivateKey<'_> {
    /// Serializes the key as a DER-encoded `ECPrivateKey` (RFC 5915) structure.
    ///
    /// # Errors
    /// `error::Unspecified`  if serialization failed.
    fn as_der(&self) -> Result<EcPrivateKeyRfc5915Der<'static>, Unspecified> {
        unsafe {
            let mut outp = null_mut::<u8>();
            let ec_key = ConstPointer::new(EVP_PKEY_get0_EC_KEY(*self.0.evp_pkey))?;
            let length = usize::try_from(aws_lc::i2d_ECPrivateKey(*ec_key, &mut outp))
                .map_err(|_| Unspecified)?;
            let outp = LcPtr::new(outp)?;
            Ok(EcPrivateKeyRfc5915Der::take_from_slice(
                core::slice::from_raw_parts_mut(*outp, length),
            ))
        }
    }
}
