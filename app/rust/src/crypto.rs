/*******************************************************************************
*   (c) 2018-2024 Zondax AG
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/
use core::{mem::MaybeUninit, ptr::addr_of_mut};
use std::convert::{TryFrom, TryInto};

use crate::{constants::SECP256_SIGN_BUFFER_MIN_LENGTH, sys, utils::ApduPanic};
use sys::{
    crypto::{bip32::BIP32Path, CHAIN_CODE_LEN},
    errors::Error,
    hash::Sha256,
};

pub use sys::crypto::ecfp256::{BitFlags, ECCInfo};
pub type ECCInfoFlags = BitFlags<ECCInfo>;

#[derive(Clone, Copy)]
pub struct PublicKey(pub(crate) sys::crypto::ecfp256::PublicKey);

impl PublicKey {
    pub fn compress(&mut self) -> Result<(), Error> {
        match self.curve() {
            Curve::Secp256K1 => self.0.compress(),
            Curve::Ed25519 => Ok(()),
        }
    }

    pub fn curve(&self) -> Curve {
        //this unwrap is ok because the curve
        // can only be initialized by the library and not the user

        self.0.curve().try_into().apdu_unwrap()
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub enum Curve {
    Secp256K1,
    Ed25519,
}

impl From<Curve> for sys::crypto::Curve {
    fn from(from: Curve) -> Self {
        match from {
            Curve::Secp256K1 => Self::Secp256K1,
            Curve::Ed25519 => Self::Ed25519,
        }
    }
}

impl TryFrom<sys::crypto::Curve> for Curve {
    type Error = ();

    fn try_from(ccrv: sys::crypto::Curve) -> Result<Self, Self::Error> {
        use sys::crypto::Curve as CCurve;

        match ccrv {
            CCurve::Secp256K1 => Ok(Self::Secp256K1),
            CCurve::Ed25519 => Ok(Self::Ed25519),
            #[allow(unreachable_patterns)]
            //this isn't actually unreachable because CCurve mock is just incomplete
            _ => Err(()),
        }
    }
}

pub struct SecretKey<const B: usize>(sys::crypto::ecfp256::SecretKey<B>);

pub enum SignError {
    BufferTooSmall,
    Sys(Error),
}

impl<const B: usize> SecretKey<B> {
    pub fn new(curve: Curve, path: BIP32Path<B>) -> Self {
        use sys::crypto::Mode;

        Self(sys::crypto::ecfp256::SecretKey::new(
            Mode::BIP32,
            curve.into(),
            path,
        ))
    }

    pub fn public(&self) -> Result<PublicKey, Error> {
        self.0.public().map(PublicKey)
    }

    pub fn into_public(self) -> Result<PublicKey, Error> {
        self.0.public().map(PublicKey)
    }

    #[inline(never)]
    pub fn into_public_into(
        self,
        chaincode: Option<&mut [u8; CHAIN_CODE_LEN]>,
        out: &mut MaybeUninit<PublicKey>,
    ) -> Result<(), Error> {
        let inner_pk: &mut MaybeUninit<_> =
            //this is safe because the pointer is valid
            unsafe { &mut *addr_of_mut!((*out.as_mut_ptr()).0).cast() };

        self.0.public_into(chaincode, inner_pk)
    }

    pub fn curve(&self) -> Curve {
        //this unwrap is ok because the curve
        // can only be initialized by the library and not the user

        self.0.curve().try_into().apdu_unwrap()
    }

    pub fn sign(&self, data: &[u8], out: &mut [u8]) -> Result<(ECCInfoFlags, usize), SignError> {
        if out.len() < SECP256_SIGN_BUFFER_MIN_LENGTH {
            Err(SignError::BufferTooSmall)
        } else {
            self.0
                .sign::<Sha256>(data, out) //pass Sha256 for the signature nonce hasher
                .map_err(SignError::Sys)
        }
    }
}

impl Curve {
    pub fn to_secret<const B: usize>(self, path: &BIP32Path<B>) -> SecretKey<B> {
        SecretKey::new(self, *path)
    }
}
