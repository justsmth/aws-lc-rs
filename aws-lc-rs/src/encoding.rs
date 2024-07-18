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
pub trait AsPEM<T> {
    /// Serializes into a PEM format.
    ///
    /// # Errors
    /// Returns Unspecified if serialization fails.
    fn as_pem(&self) -> Result<T, crate::error::Unspecified>;
}
