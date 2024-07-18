// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

//! Serialization formats

#![allow(clippy::module_name_repetitions)]

use crate::buffer::Buffer;
use paste::paste;

macro_rules! generated_encodings {
    ($($name:ident),*) => { paste! {
        use core::fmt::{Debug, Error, Formatter};
        use core::ops::Deref;
        mod buffer_type {
            $(
                pub struct [<$name Type>] {
                    _priv: (),
                }
            )*
        }
        $(
            /// Serialized bytes
            pub struct $name<'a>(Buffer<'a, buffer_type::[<$name Type>]>);

            impl<'a> Deref for $name<'a> {
                type Target = Buffer<'a, buffer_type::[<$name Type>]>;

                fn deref(&self) -> &Self::Target {
                    &self.0
                }
            }

            impl $name<'static> {
                #[allow(dead_code)]
                pub(crate) fn new(owned: Vec<u8>) -> Self {
                    Self(Buffer::new(owned))
                }
                #[allow(dead_code)]
                pub(crate) fn take_from_slice(owned: &mut [u8]) -> Self {
                    Self(Buffer::take_from_slice(owned))
                }
            }

            impl Debug for $name<'_> {
                fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
                    f.debug_struct(stringify!($name)).finish()
                }
            }

            impl<'a> From<Buffer<'a, buffer_type::[<$name Type>]>> for $name<'a> {
                fn from(value: Buffer<'a, buffer_type::[<$name Type>]>) -> Self {
                    Self(value)
                }
            }
        )*
    }}
}
pub(crate) use generated_encodings;
generated_encodings!(
    EcPrivateKeyBin,
    EcPrivateKeyRfc5915Der,
    PublicKeyX509Der,
    Curve25519SeedBin,
    Pkcs8V1Der
);

/// Trait for types that can be serialized into a DER format.
pub trait AsDer<T> {
    /// Serializes into a DER format.
    ///
    /// # Errors
    /// Returns Unspecified if serialization fails.
    fn as_der(&self) -> Result<T, crate::error::Unspecified>;
}

/// Trait for values that can be serialized into a big-endian format
pub trait AsBigEndian<T> {
    /// Serializes into a big-endian format.
    ///
    /// # Errors
    /// Returns Unspecified if serialization fails.
    fn as_be_bytes(&self) -> Result<T, crate::error::Unspecified>;
}

// TODO: convert logic below into macro
mod pem_type {

    /// Marker types for PEM encoding
    pub struct X509Asn1PemType {
        _priv: (),
    }

    pub struct Pkcs8PemType {
        _priv: (),
    }
}

#[allow(dead_code, missing_docs)]
pub struct X509Asn1Pem<'a>(Buffer<'a, pem_type::X509Asn1PemType>);

#[allow(dead_code)]
impl X509Asn1Pem<'static> {
    pub(crate) fn new(owned: Vec<u8>) -> Self {
        Self(Buffer::new(owned))
    }
    pub(crate) fn take_from_slice(slice: &mut [u8]) -> Self {
        Self(Buffer::take_from_slice(slice))
    }
}

impl<'a> Deref for X509Asn1Pem<'a> {
    type Target = Buffer<'a, pem_type::X509Asn1PemType>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[allow(dead_code, missing_docs)]
pub struct Pkcs8Pem<'a>(Buffer<'a, pem_type::Pkcs8PemType>);

#[allow(dead_code)]
impl Pkcs8Pem<'static> {
    pub(crate) fn new(owned: Vec<u8>) -> Self {
        Self(Buffer::new(owned))
    }
    pub(crate) fn take_from_slice(slice: &mut [u8]) -> Self {
        Self(Buffer::take_from_slice(slice))
    }
}

impl<'a> Deref for Pkcs8Pem<'a> {
    type Target = Buffer<'a, pem_type::Pkcs8PemType>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Trait for types that can be serialized into a DER format.
pub trait AsPem<T> {
    /// Serializes into a PEM format.
    ///
    /// # Errors
    /// Returns Unspecified if serialization fails.
    fn as_pem(&self) -> Result<T, crate::error::Unspecified>;
}

pub(crate) mod pem {
    use crate::error::{KeyRejected, Unspecified};
    use crate::ptr::{LcPtr, Pointer};
    use aws_lc::{
        ossl_ssize_t, BIO_get_mem_data, BIO_new, BIO_new_mem_buf, BIO_s_mem, PEM_read_bio_PUBKEY,
        PEM_read_bio_PrivateKey, PEM_write_bio_PKCS8PrivateKey, PEM_write_bio_PUBKEY, EVP_PKEY,
    };
    use std::ffi::c_char;
    use std::ptr::{null, null_mut};

    pub(crate) fn encode_pubkey_pem(key: &mut LcPtr<EVP_PKEY>) -> Result<Vec<u8>, Unspecified> {
        let mut bio_pem = LcPtr::new(unsafe { BIO_new(BIO_s_mem()) })?;
        if 1 != unsafe { PEM_write_bio_PUBKEY(bio_pem.as_mut_ptr(), **key) } {
            return Err(Unspecified);
        }
        let mut buff_ptr: *mut c_char = null_mut();
        let size = BIO_get_mem_data(bio_pem.as_mut_ptr(), &mut buff_ptr);
        let buff_ptr: *const u8 = buff_ptr.cast();
        let mut my_buffer = vec![0u8; size.try_into()?];
        let other_buffer = unsafe { std::slice::from_raw_parts(buff_ptr, size.try_into()?) };
        my_buffer.copy_from_slice(other_buffer);

        Ok(my_buffer)
    }

    pub(crate) fn encode_pkcs8_pem(key: &LcPtr<EVP_PKEY>) -> Result<Vec<u8>, Unspecified> {
        let mut bio_pem = LcPtr::new(unsafe { BIO_new(BIO_s_mem()) })?;
        if 1 != unsafe {
            PEM_write_bio_PKCS8PrivateKey(
                bio_pem.as_mut_ptr(),
                #[cfg(feature = "fips")]
                **key,
                #[cfg(not(feature = "fips"))]
                key.as_const_ptr(),
                null(),
                null_mut(),
                0,
                None,
                null_mut(),
            )
        } {
            return Err(Unspecified);
        }
        let mut buff_ptr: *mut c_char = null_mut();
        let size = BIO_get_mem_data(bio_pem.as_mut_ptr(), &mut buff_ptr);
        let buff_ptr: *const u8 = buff_ptr.cast();
        let mut my_buffer = vec![0u8; size.try_into()?];
        let other_buffer = unsafe { std::slice::from_raw_parts(buff_ptr, size.try_into()?) };
        my_buffer.copy_from_slice(other_buffer);

        Ok(my_buffer)
    }

    pub(crate) fn decode_private_key_pem(pem_data: &str) -> Result<LcPtr<EVP_PKEY>, KeyRejected> {
        let pem_size: ossl_ssize_t = pem_data.len().try_into()?;
        let mut bio_pem =
            LcPtr::new(unsafe { BIO_new_mem_buf(pem_data.as_ptr().cast(), pem_size) })?;
        Ok(LcPtr::new(unsafe {
            PEM_read_bio_PrivateKey(bio_pem.as_mut_ptr(), null_mut(), None, null_mut())
        })?)
    }

    pub(crate) fn decode_public_key_pem(pem_data: &str) -> Result<LcPtr<EVP_PKEY>, KeyRejected> {
        let pem_size: ossl_ssize_t = pem_data.len().try_into()?;
        let mut bio_pem =
            LcPtr::new(unsafe { BIO_new_mem_buf(pem_data.as_ptr().cast(), pem_size) })?;
        Ok(LcPtr::new(unsafe {
            PEM_read_bio_PUBKEY(bio_pem.as_mut_ptr(), null_mut(), None, null_mut())
        })?)
    }
}
