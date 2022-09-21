/*******************************************************************************
*   (c) 2022 Zondax AG
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
//! This file was originally generated via `uint::construct_uint!`
//! and afterwards has been refactored to remove unwanted functionality
//! and provide alternative implementations for some items

#![allow(non_camel_case_types, non_upper_case_globals, unused_comparisons)]

use core::cmp::{Ord, Ordering};
use core::iter::{Product, Sum};
use core::ops::{
    Add, AddAssign, BitAnd, BitOr, BitXor, Div, DivAssign, Mul, MulAssign, Not, Rem, RemAssign,
    Shl, ShlAssign, Shr, ShrAssign, Sub, SubAssign,
};

use bolos::PIC;

/// Little-endian large integer type
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct u256(pub [u64; 4]);

/// Get a reference to the underlying little-endian words.
impl AsRef<[u64]> for u256 {
    #[inline]
    fn as_ref(&self) -> &[u64] {
        &self.0
    }
}

impl Default for u256 {
    fn default() -> Self {
        *Self::min()
    }
}

impl u256 {
    const WORD_BITS: usize = 64;
    /// Maximum value.
    const MAX: &'static u256 = &Self([u64::MAX; 4]);

    #[inline]
    pub fn max() -> &'static Self {
        PIC::new(Self::MAX).into_inner()
    }

    /// Minimum value
    const MIN: &'static u256 = &Self([0; 4]);

    #[inline]
    pub fn min() -> &'static Self {
        PIC::new(Self::MIN).into_inner()
    }

    /// Number of bits of the integer
    pub const BITS: u32 = 256;

    /// Conversion to u32
    #[inline]
    pub const fn low_u32(&self) -> u32 {
        let &u256(ref arr) = self;
        arr[0] as u32
    }

    /// Low word (u64)
    #[inline]
    pub const fn low_u64(&self) -> u64 {
        let &u256(ref arr) = self;
        arr[0]
    }

    /// Conversion to u32 with overflow checking
    ///
    /// # Panics
    ///
    /// Panics if the number is larger than 2^32.
    #[inline]
    pub fn as_u32(&self) -> u32 {
        let &u256(ref arr) = self;
        if !self.fits_word() || arr[0] > u32::max_value() as u64 {
            panic!("Integer overflow when casting to u32");
        }
        self.as_u64() as u32
    }

    /// Conversion to u64 with overflow checking
    ///
    /// # Panics
    ///
    /// Panics if the number is larger than u64::max_value().
    #[inline]
    pub fn as_u64(&self) -> u64 {
        let &u256(ref arr) = self;
        if !self.fits_word() {
            panic!("Integer overflow when casting to u64");
        }
        arr[0]
    }

    /// Conversion to usize with overflow checking
    ///
    /// # Panics
    ///
    /// Panics if the number is larger than usize::max_value().
    #[inline]
    pub fn as_usize(&self) -> usize {
        let &u256(ref arr) = self;
        if !self.fits_word() || arr[0] > usize::max_value() as u64 {
            panic!("Integer overflow when casting to usize");
        }
        arr[0] as usize
    }

    /// Whether this is zero.
    #[inline]
    pub fn is_zero(&self) -> bool {
        self == Self::min()
    }

    #[inline]
    fn fits_word(&self) -> bool {
        let &u256(ref arr) = self;
        for i in 1..4 {
            if arr[i] != 0 {
                return false;
            }
        }
        true
    }

    /// Return the least number of bits needed to represent the number
    #[inline]
    pub fn bits(&self) -> usize {
        let &u256(ref arr) = self;
        for i in 1..4 {
            if arr[4 - i] > 0 {
                return (0x40 * (4 - i + 1)) - arr[4 - i].leading_zeros() as usize;
            }
        }
        0x40 - arr[0].leading_zeros() as usize
    }

    /// Return if specific bit is set.
    ///
    /// # Panics
    ///
    /// Panics if `index` exceeds the bit width of the number.
    #[inline]
    pub const fn bit(&self, index: usize) -> bool {
        let &u256(ref arr) = self;
        arr[index / 64] & (1 << (index % 64)) != 0
    }

    /// Returns the number of leading zeros in the binary representation of self.
    pub fn leading_zeros(&self) -> u32 {
        let mut r = 0;
        for i in 0..4 {
            let w = self.0[4 - i - 1];
            if w == 0 {
                r += 64;
            } else {
                r += w.leading_zeros();
                break;
            }
        }
        r
    }

    /// Returns the number of trailing zeros in the binary representation of self.
    pub fn trailing_zeros(&self) -> u32 {
        let mut r = 0;
        for i in 0..4 {
            let w = self.0[i];
            if w == 0 {
                r += 64;
            } else {
                r += w.trailing_zeros();
                break;
            }
        }
        r
    }

    /// Return specific byte.
    ///
    /// # Panics
    ///
    /// Panics if `index` exceeds the byte width of the number.
    #[inline]
    pub const fn byte(&self, index: usize) -> u8 {
        let &u256(ref arr) = self;
        (arr[index / 8] >> ((index % 8) * 8)) as u8
    }

    /// Write to the slice in big-endian format.
    #[inline]
    pub fn to_big_endian(&self, bytes: &mut [u8]) {
        use byteorder::{BigEndian, ByteOrder};
        if 4 * 8 != bytes.len() {
            panic!("assertion failed: 4 * 8 == bytes.len()")
        }

        for i in 0..4 {
            BigEndian::write_u64(&mut bytes[8 * i..], self.0[4 - i - 1]);
        }
    }

    /// Write to the slice in little-endian format.
    #[inline]
    pub fn to_little_endian(&self, bytes: &mut [u8]) {
        use byteorder::{ByteOrder, LittleEndian};
        if 4 * 8 != bytes.len() {
            panic!("assertion failed: 4 * 8 == bytes.len()")
        }
        for i in 0..4 {
            LittleEndian::write_u64(&mut bytes[8 * i..], self.0[i]);
        }
    }

    /// Create `10**n` as this type.
    ///
    /// # Panics
    ///
    /// Panics if the result overflows the type.
    #[inline]
    pub fn exp10(n: usize) -> Self {
        match n {
            0 => Self::from(1u64),
            _ => Self::exp10(n - 1) * 10u32,
        }
    }

    /// Zero (additive identity) of this type.
    #[inline]
    pub const fn zero() -> Self {
        Self([0; 4])
    }

    /// One (multiplicative identity) of this type.
    #[inline]
    pub fn one() -> Self {
        From::from(1u64)
    }

    /// The maximum value which can be inhabited by this type.
    #[inline]
    pub fn max_value() -> Self {
        *Self::max()
    }

    fn full_shl(self, shift: u32) -> [u64; 4 + 1] {
        if shift >= Self::WORD_BITS as u32 {
            panic!("assertion failed: shift < Self::WORD_BITS as u32")
        }
        let mut u = [0u64; 4 + 1];
        let u_lo = self.0[0] << shift;
        let u_hi = self >> (Self::WORD_BITS as u32 - shift);
        u[0] = u_lo;
        u[1..].copy_from_slice(&u_hi.0[..]);
        u
    }

    fn full_shr(u: [u64; 4 + 1], shift: u32) -> Self {
        if shift >= Self::WORD_BITS as u32 {
            panic!("assertion failed: shift < Self::WORD_BITS as u32")
        };
        let mut res = Self::zero();
        for i in 0..4 {
            res.0[i] = u[i] >> shift;
        }
        if shift > 0 {
            for i in 1..=4 {
                res.0[i - 1] |= u[i] << (Self::WORD_BITS as u32 - shift);
            }
        }
        res
    }

    fn full_mul_u64(self, by: u64) -> [u64; 4 + 1] {
        let (prod, carry) = self.overflowing_mul_u64(by);
        let mut res = [0u64; 4 + 1];
        res[..4].copy_from_slice(&prod.0[..]);
        res[4] = carry;
        res
    }

    fn div_mod_small(mut self, other: u64) -> (Self, Self) {
        let mut rem = 0u64;
        self.0.iter_mut().rev().for_each(|d| {
            let (q, r) = Self::div_mod_word(rem, *d, other);
            *d = q;
            rem = r;
        });
        (self, rem.into())
    }

    fn div_mod_knuth(self, mut v: Self, n: usize, m: usize) -> (Self, Self) {
        if !(self.bits() >= v.bits() && !v.fits_word()) {
            panic!("assertion failed: self.bits() >= v.bits() && !v.fits_word()",)
        }
        if n + m > 4 {
            panic!("assertion failed: n + m <= 4")
        };
        let shift = v.0[n - 1].leading_zeros();
        v <<= shift;
        let mut u = self.full_shl(shift);
        let mut q = Self::zero();
        let v_n_1 = v.0[n - 1];
        let v_n_2 = v.0[n - 2];
        for j in (0..=m).rev() {
            let u_jn = u[j + n];
            let mut q_hat = if u_jn < v_n_1 {
                let (mut q_hat, mut r_hat) = Self::div_mod_word(u_jn, u[j + n - 1], v_n_1);
                loop {
                    let (hi, lo) = Self::split_u128(u128::from(q_hat) * u128::from(v_n_2));
                    if (hi, lo) <= (r_hat, u[j + n - 2]) {
                        break;
                    }
                    q_hat -= 1;
                    let (new_r_hat, overflow) = r_hat.overflowing_add(v_n_1);
                    r_hat = new_r_hat;
                    if overflow {
                        break;
                    }
                }
                q_hat
            } else {
                u64::max_value()
            };
            let q_hat_v = v.full_mul_u64(q_hat);
            let c = Self::sub_slice(&mut u[j..], &q_hat_v[..n + 1]);
            if c {
                q_hat -= 1;
                let c = Self::add_slice(&mut u[j..], &v.0[..n]);
                u[j + n] = u[j + n].wrapping_add(u64::from(c));
            }
            q.0[j] = q_hat;
        }
        let remainder = Self::full_shr(u, shift);
        (q, remainder)
    }

    fn words(bits: usize) -> usize {
        1 + (bits - 1) / Self::WORD_BITS
    }

    /// Returns a pair `(self / other, self % other)`.
    ///
    /// # Panics
    ///
    /// Panics if `other` is zero.
    pub fn div_mod(self, other: Self) -> (Self, Self) {
        let my_bits = self.bits();
        let your_bits = other.bits();
        if your_bits == 0 {
            panic!("division by zero")
        };
        if my_bits < your_bits {
            return (Self::zero(), self);
        }
        if your_bits <= Self::WORD_BITS {
            return self.div_mod_small(other.low_u64());
        }
        let (n, m) = {
            let my_words = Self::words(my_bits);
            let your_words = Self::words(your_bits);
            (your_words, my_words - your_words)
        };
        self.div_mod_knuth(other, n, m)
    }

    /// Compute the highest `n` such that `n * n <= self`.
    pub fn integer_sqrt(&self) -> Self {
        let this = *self;

        let one = Self::one();
        if this <= one {
            return this;
        }

        let shift: u32 = (this.bits() as u32 + 1) / 2;
        let mut x_prev = one << shift;
        loop {
            let x = (x_prev + this / x_prev) >> 1usize;
            if x >= x_prev {
                return x_prev;
            }
            x_prev = x;
        }
    }

    /// Fast exponentiation by squaring
    /// https://en.wikipedia.org/wiki/Exponentiation_by_squaring
    ///
    /// # Panics
    ///
    /// Panics if the result overflows the type.
    pub fn pow(self, expon: Self) -> Self {
        if expon.is_zero() {
            return Self::one();
        }
        let is_even = |x: &Self| x.low_u64() & 1 == 0;
        let u_one = Self::one();
        let mut y = u_one;
        let mut n = expon;
        let mut x = self;
        while n > u_one {
            if is_even(&n) {
                x = x * x;
                n >>= 1usize;
            } else {
                y = x * y;
                x = x * x;
                n.0[4 - 1] &= (!0u64) >> 1;
                n >>= 1usize;
            }
        }
        x * y
    }

    /// Fast exponentiation by squaring. Returns result and overflow flag.
    pub fn overflowing_pow(self, expon: Self) -> (Self, bool) {
        if expon.is_zero() {
            return (Self::one(), false);
        }
        let is_even = |x: &Self| x.low_u64() & 1 == 0;
        let u_one = Self::one();
        let mut y = u_one;
        let mut n = expon;
        let mut x = self;
        let mut overflow = false;
        while n > u_one {
            if is_even(&n) {
                x = {
                    let (overflow_x, overflow_overflow) = x.overflowing_mul(x);
                    overflow |= overflow_overflow;
                    overflow_x
                };
                n >>= 1usize;
            } else {
                y = {
                    let (overflow_x, overflow_overflow) = x.overflowing_mul(y);
                    overflow |= overflow_overflow;
                    overflow_x
                };
                x = {
                    let (overflow_x, overflow_overflow) = x.overflowing_mul(x);
                    overflow |= overflow_overflow;
                    overflow_x
                };
                n = (n - u_one) >> 1usize;
            }
        }
        let res = {
            let (overflow_x, overflow_overflow) = x.overflowing_mul(y);
            overflow |= overflow_overflow;
            overflow_x
        };
        (res, overflow)
    }

    /// Checked exponentiation. Returns `None` if overflow occurred.
    pub fn checked_pow(self, expon: u256) -> Option<u256> {
        match self.overflowing_pow(expon) {
            (_, true) => None,
            (val, _) => Some(val),
        }
    }

    /// Add with overflow.
    #[inline(always)]
    pub fn overflowing_add(self, other: u256) -> (u256, bool) {
        {
            let u256(ref me) = self;
            let u256(ref you) = other;
            let mut ret = [0u64; 4];
            let ret_ptr = &mut ret as *mut [u64; 4] as *mut u64;
            let mut carry = 0u64;
            #[allow(unknown_lints, clippy::eq_op)]
            const _: [(); 0 - !{
                const ASSERT: bool = core::isize::MAX as usize / core::mem::size_of::<u64>() > 4;
                ASSERT
            } as usize] = [];

            {
                const i: usize = 0;
                {
                    if carry != 0 {
                        let (res1, overflow1) = (u64::overflowing_add)(me[i], you[i]);
                        let (res2, overflow2) = (u64::overflowing_add)(res1, carry);
                        unsafe { *ret_ptr.add(i) = res2 }
                        carry = (overflow1 as u8 + overflow2 as u8) as u64;
                    } else {
                        let (res, overflow) = (u64::overflowing_add)(me[i], you[i]);
                        unsafe { *ret_ptr.add(i) = res }
                        carry = overflow as u64;
                    }
                }
            }
            {
                const i: usize = 1;
                if carry != 0 {
                    let (res1, overflow1) = (u64::overflowing_add)(me[i], you[i]);
                    let (res2, overflow2) = (u64::overflowing_add)(res1, carry);
                    unsafe { *ret_ptr.add(i) = res2 }
                    carry = (overflow1 as u8 + overflow2 as u8) as u64;
                } else {
                    let (res, overflow) = (u64::overflowing_add)(me[i], you[i]);
                    unsafe { *ret_ptr.add(i) = res }
                    carry = overflow as u64;
                }
            }
            {
                const i: usize = 2;
                if carry != 0 {
                    let (res1, overflow1) = (u64::overflowing_add)(me[i], you[i]);
                    let (res2, overflow2) = (u64::overflowing_add)(res1, carry);
                    unsafe { *ret_ptr.add(i) = res2 }
                    carry = (overflow1 as u8 + overflow2 as u8) as u64;
                } else {
                    let (res, overflow) = (u64::overflowing_add)(me[i], you[i]);
                    unsafe { *ret_ptr.add(i) = res }
                    carry = overflow as u64;
                }
            }
            {
                const i: usize = 3;
                if carry != 0 {
                    let (res1, overflow1) = (u64::overflowing_add)(me[i], you[i]);
                    let (res2, overflow2) = (u64::overflowing_add)(res1, carry);
                    unsafe { *ret_ptr.add(i) = res2 }
                    carry = (overflow1 as u8 + overflow2 as u8) as u64;
                } else {
                    let (res, overflow) = (u64::overflowing_add)(me[i], you[i]);
                    unsafe { *ret_ptr.add(i) = res }
                    carry = overflow as u64;
                }
            }

            (u256(ret), carry > 0)
        }
    }

    /// Addition which saturates at the maximum value (Self::max_value()).
    pub fn saturating_add(self, other: u256) -> u256 {
        match self.overflowing_add(other) {
            (_, true) => u256::max_value(),
            (val, false) => val,
        }
    }

    /// Checked addition. Returns `None` if overflow occurred.
    pub fn checked_add(self, other: u256) -> Option<u256> {
        match self.overflowing_add(other) {
            (_, true) => None,
            (val, _) => Some(val),
        }
    }

    /// Subtraction which underflows and returns a flag if it does.
    #[inline(always)]
    pub fn overflowing_sub(self, other: u256) -> (u256, bool) {
        {
            let u256(ref me) = self;
            let u256(ref you) = other;
            let mut ret = [0u64; 4];
            let ret_ptr = &mut ret as *mut [u64; 4] as *mut u64;
            let mut carry = 0u64;
            #[allow(unknown_lints, clippy::eq_op)]
            const _: [(); 0 - !{
                const ASSERT: bool = core::isize::MAX as usize / core::mem::size_of::<u64>() > 4;
                ASSERT
            } as usize] = [];

            {
                const i: usize = 0;
                if carry != 0 {
                    let (res1, overflow1) = (u64::overflowing_sub)(me[i], you[i]);
                    let (res2, overflow2) = (u64::overflowing_sub)(res1, carry);
                    unsafe { *ret_ptr.add(i) = res2 }
                    carry = (overflow1 as u8 + overflow2 as u8) as u64;
                } else {
                    let (res, overflow) = (u64::overflowing_sub)(me[i], you[i]);
                    unsafe { *ret_ptr.add(i) = res }
                    carry = overflow as u64;
                }
            }
            {
                const i: usize = 1;
                if carry != 0 {
                    let (res1, overflow1) = (u64::overflowing_sub)(me[i], you[i]);
                    let (res2, overflow2) = (u64::overflowing_sub)(res1, carry);
                    unsafe { *ret_ptr.add(i) = res2 }
                    carry = (overflow1 as u8 + overflow2 as u8) as u64;
                } else {
                    let (res, overflow) = (u64::overflowing_sub)(me[i], you[i]);
                    unsafe { *ret_ptr.add(i) = res }
                    carry = overflow as u64;
                }
            }
            {
                const i: usize = 2;
                if carry != 0 {
                    let (res1, overflow1) = (u64::overflowing_sub)(me[i], you[i]);
                    let (res2, overflow2) = (u64::overflowing_sub)(res1, carry);
                    unsafe { *ret_ptr.add(i) = res2 }
                    carry = (overflow1 as u8 + overflow2 as u8) as u64;
                } else {
                    let (res, overflow) = (u64::overflowing_sub)(me[i], you[i]);
                    unsafe { *ret_ptr.add(i) = res }
                    carry = overflow as u64;
                }
            }
            {
                const i: usize = 3;
                if carry != 0 {
                    let (res1, overflow1) = (u64::overflowing_sub)(me[i], you[i]);
                    let (res2, overflow2) = (u64::overflowing_sub)(res1, carry);
                    unsafe { *ret_ptr.add(i) = res2 }
                    carry = (overflow1 as u8 + overflow2 as u8) as u64;
                } else {
                    let (res, overflow) = (u64::overflowing_sub)(me[i], you[i]);
                    unsafe { *ret_ptr.add(i) = res }
                    carry = overflow as u64;
                }
            }

            (u256(ret), carry > 0)
        }
    }

    /// Subtraction which saturates at zero.
    pub fn saturating_sub(self, other: u256) -> u256 {
        match self.overflowing_sub(other) {
            (_, true) => u256::zero(),
            (val, false) => val,
        }
    }

    /// Checked subtraction. Returns `None` if overflow occurred.
    pub fn checked_sub(self, other: u256) -> Option<u256> {
        match self.overflowing_sub(other) {
            (_, true) => None,
            (val, _) => Some(val),
        }
    }

    /// Multiply with overflow, returning a flag if it does.
    #[inline(always)]
    pub fn overflowing_mul(self, other: u256) -> (u256, bool) {
        {
            let ret: [u64; 4 * 2] = {
                let u256(ref me) = self;
                let u256(ref you) = other;
                let mut ret = [0u64; 4 * 2];

                {
                    const i: usize = 0;

                    let mut carry = 0u64;
                    let b = you[i];

                    {
                        const j: usize = 0;

                        let a = me[j];
                        let (hi, low) = Self::split_u128(a as u128 * b as u128);
                        let overflow = {
                            let existing_low = &mut ret[i + j];
                            let (low, o) = low.overflowing_add(*existing_low);
                            *existing_low = low;
                            o
                        };
                        carry = {
                            let existing_hi = &mut ret[i + j + 1];
                            let hi = hi + overflow as u64;
                            let (hi, o0) = hi.overflowing_add(carry);
                            let (hi, o1) = hi.overflowing_add(*existing_hi);
                            *existing_hi = hi;
                            (o0 | o1) as u64
                        }
                    }
                    {
                        const j: usize = 1;

                        let a = me[j];
                        let (hi, low) = Self::split_u128(a as u128 * b as u128);
                        let overflow = {
                            let existing_low = &mut ret[i + j];
                            let (low, o) = low.overflowing_add(*existing_low);
                            *existing_low = low;
                            o
                        };
                        carry = {
                            let existing_hi = &mut ret[i + j + 1];
                            let hi = hi + overflow as u64;
                            let (hi, o0) = hi.overflowing_add(carry);
                            let (hi, o1) = hi.overflowing_add(*existing_hi);
                            *existing_hi = hi;
                            (o0 | o1) as u64
                        }
                    }
                    {
                        const j: usize = 2;

                        let a = me[j];
                        let (hi, low) = Self::split_u128(a as u128 * b as u128);
                        let overflow = {
                            let existing_low = &mut ret[i + j];
                            let (low, o) = low.overflowing_add(*existing_low);
                            *existing_low = low;
                            o
                        };
                        carry = {
                            let existing_hi = &mut ret[i + j + 1];
                            let hi = hi + overflow as u64;
                            let (hi, o0) = hi.overflowing_add(carry);
                            let (hi, o1) = hi.overflowing_add(*existing_hi);
                            *existing_hi = hi;
                            (o0 | o1) as u64
                        }
                    }
                    {
                        const j: usize = 3;

                        let a = me[j];
                        let (hi, low) = Self::split_u128(a as u128 * b as u128);
                        let overflow = {
                            let existing_low = &mut ret[i + j];
                            let (low, o) = low.overflowing_add(*existing_low);
                            *existing_low = low;
                            o
                        };
                        carry = {
                            let existing_hi = &mut ret[i + j + 1];
                            let hi = hi + overflow as u64;
                            let (hi, o0) = hi.overflowing_add(carry);
                            let (hi, o1) = hi.overflowing_add(*existing_hi);
                            *existing_hi = hi;
                            (o0 | o1) as u64
                        }
                    }
                }
                {
                    const i: usize = 1;

                    let mut carry = 0u64;
                    let b = you[i];

                    {
                        {
                            const j: usize = 0;

                            let a = me[j];
                            let (hi, low) = Self::split_u128(a as u128 * b as u128);
                            let overflow = {
                                let existing_low = &mut ret[i + j];
                                let (low, o) = low.overflowing_add(*existing_low);
                                *existing_low = low;
                                o
                            };
                            carry = {
                                let existing_hi = &mut ret[i + j + 1];
                                let hi = hi + overflow as u64;
                                let (hi, o0) = hi.overflowing_add(carry);
                                let (hi, o1) = hi.overflowing_add(*existing_hi);
                                *existing_hi = hi;
                                (o0 | o1) as u64
                            }
                        }
                        {
                            const j: usize = 1;

                            let a = me[j];
                            let (hi, low) = Self::split_u128(a as u128 * b as u128);
                            let overflow = {
                                let existing_low = &mut ret[i + j];
                                let (low, o) = low.overflowing_add(*existing_low);
                                *existing_low = low;
                                o
                            };
                            carry = {
                                let existing_hi = &mut ret[i + j + 1];
                                let hi = hi + overflow as u64;
                                let (hi, o0) = hi.overflowing_add(carry);
                                let (hi, o1) = hi.overflowing_add(*existing_hi);
                                *existing_hi = hi;
                                (o0 | o1) as u64
                            }
                        }
                        {
                            const j: usize = 2;

                            let a = me[j];
                            let (hi, low) = Self::split_u128(a as u128 * b as u128);
                            let overflow = {
                                let existing_low = &mut ret[i + j];
                                let (low, o) = low.overflowing_add(*existing_low);
                                *existing_low = low;
                                o
                            };
                            carry = {
                                let existing_hi = &mut ret[i + j + 1];
                                let hi = hi + overflow as u64;
                                let (hi, o0) = hi.overflowing_add(carry);
                                let (hi, o1) = hi.overflowing_add(*existing_hi);
                                *existing_hi = hi;
                                (o0 | o1) as u64
                            }
                        }
                        {
                            const j: usize = 3;

                            let a = me[j];
                            let (hi, low) = Self::split_u128(a as u128 * b as u128);
                            let overflow = {
                                let existing_low = &mut ret[i + j];
                                let (low, o) = low.overflowing_add(*existing_low);
                                *existing_low = low;
                                o
                            };
                            carry = {
                                let existing_hi = &mut ret[i + j + 1];
                                let hi = hi + overflow as u64;
                                let (hi, o0) = hi.overflowing_add(carry);
                                let (hi, o1) = hi.overflowing_add(*existing_hi);
                                *existing_hi = hi;
                                (o0 | o1) as u64
                            }
                        }
                    }
                }
                {
                    const i: usize = 2;

                    let mut carry = 0u64;
                    let b = you[i];

                    {
                        {
                            const j: usize = 0;

                            let a = me[j];
                            let (hi, low) = Self::split_u128(a as u128 * b as u128);
                            let overflow = {
                                let existing_low = &mut ret[i + j];
                                let (low, o) = low.overflowing_add(*existing_low);
                                *existing_low = low;
                                o
                            };
                            carry = {
                                let existing_hi = &mut ret[i + j + 1];
                                let hi = hi + overflow as u64;
                                let (hi, o0) = hi.overflowing_add(carry);
                                let (hi, o1) = hi.overflowing_add(*existing_hi);
                                *existing_hi = hi;
                                (o0 | o1) as u64
                            }
                        }
                        {
                            const j: usize = 1;

                            let a = me[j];
                            let (hi, low) = Self::split_u128(a as u128 * b as u128);
                            let overflow = {
                                let existing_low = &mut ret[i + j];
                                let (low, o) = low.overflowing_add(*existing_low);
                                *existing_low = low;
                                o
                            };
                            carry = {
                                let existing_hi = &mut ret[i + j + 1];
                                let hi = hi + overflow as u64;
                                let (hi, o0) = hi.overflowing_add(carry);
                                let (hi, o1) = hi.overflowing_add(*existing_hi);
                                *existing_hi = hi;
                                (o0 | o1) as u64
                            }
                        }
                        {
                            const j: usize = 2;

                            let a = me[j];
                            let (hi, low) = Self::split_u128(a as u128 * b as u128);
                            let overflow = {
                                let existing_low = &mut ret[i + j];
                                let (low, o) = low.overflowing_add(*existing_low);
                                *existing_low = low;
                                o
                            };
                            carry = {
                                let existing_hi = &mut ret[i + j + 1];
                                let hi = hi + overflow as u64;
                                let (hi, o0) = hi.overflowing_add(carry);
                                let (hi, o1) = hi.overflowing_add(*existing_hi);
                                *existing_hi = hi;
                                (o0 | o1) as u64
                            }
                        }
                        {
                            const j: usize = 3;

                            let a = me[j];
                            let (hi, low) = Self::split_u128(a as u128 * b as u128);
                            let overflow = {
                                let existing_low = &mut ret[i + j];
                                let (low, o) = low.overflowing_add(*existing_low);
                                *existing_low = low;
                                o
                            };
                            carry = {
                                let existing_hi = &mut ret[i + j + 1];
                                let hi = hi + overflow as u64;
                                let (hi, o0) = hi.overflowing_add(carry);
                                let (hi, o1) = hi.overflowing_add(*existing_hi);
                                *existing_hi = hi;
                                (o0 | o1) as u64
                            }
                        }
                    }
                }
                {
                    const i: usize = 3;

                    let mut carry = 0u64;
                    let b = you[i];

                    {
                        {
                            const j: usize = 0;

                            let a = me[j];
                            let (hi, low) = Self::split_u128(a as u128 * b as u128);
                            let overflow = {
                                let existing_low = &mut ret[i + j];
                                let (low, o) = low.overflowing_add(*existing_low);
                                *existing_low = low;
                                o
                            };
                            carry = {
                                let existing_hi = &mut ret[i + j + 1];
                                let hi = hi + overflow as u64;
                                let (hi, o0) = hi.overflowing_add(carry);
                                let (hi, o1) = hi.overflowing_add(*existing_hi);
                                *existing_hi = hi;
                                (o0 | o1) as u64
                            }
                        }
                        {
                            const j: usize = 1;

                            let a = me[j];
                            let (hi, low) = Self::split_u128(a as u128 * b as u128);
                            let overflow = {
                                let existing_low = &mut ret[i + j];
                                let (low, o) = low.overflowing_add(*existing_low);
                                *existing_low = low;
                                o
                            };
                            carry = {
                                let existing_hi = &mut ret[i + j + 1];
                                let hi = hi + overflow as u64;
                                let (hi, o0) = hi.overflowing_add(carry);
                                let (hi, o1) = hi.overflowing_add(*existing_hi);
                                *existing_hi = hi;
                                (o0 | o1) as u64
                            }
                        }
                        {
                            const j: usize = 2;

                            let a = me[j];
                            let (hi, low) = Self::split_u128(a as u128 * b as u128);
                            let overflow = {
                                let existing_low = &mut ret[i + j];
                                let (low, o) = low.overflowing_add(*existing_low);
                                *existing_low = low;
                                o
                            };
                            carry = {
                                let existing_hi = &mut ret[i + j + 1];
                                let hi = hi + overflow as u64;
                                let (hi, o0) = hi.overflowing_add(carry);
                                let (hi, o1) = hi.overflowing_add(*existing_hi);
                                *existing_hi = hi;
                                (o0 | o1) as u64
                            }
                        }
                        {
                            const j: usize = 3;

                            let a = me[j];
                            let (hi, low) = Self::split_u128(a as u128 * b as u128);
                            let overflow = {
                                let existing_low = &mut ret[i + j];
                                let (low, o) = low.overflowing_add(*existing_low);
                                *existing_low = low;
                                o
                            };
                            carry = {
                                let existing_hi = &mut ret[i + j + 1];
                                let hi = hi + overflow as u64;
                                let (hi, o0) = hi.overflowing_add(carry);
                                let (hi, o1) = hi.overflowing_add(*existing_hi);
                                *existing_hi = hi;
                                (o0 | o1) as u64
                            }
                        }
                    }
                }

                ret
            };

            let ret: [[u64; 4]; 2] = bytemuck::cast(ret);

            #[inline(always)]
            fn any_nonzero(arr: &[u64; 4]) -> bool {
                arr.iter().any(|n| n != &0)
            }

            (u256(ret[0]), any_nonzero(&ret[1]))
        }
    }

    /// Multiplication which saturates at the maximum value.
    pub fn saturating_mul(self, other: u256) -> u256 {
        match self.overflowing_mul(other) {
            (_, true) => u256::max_value(),
            (val, false) => val,
        }
    }

    /// Checked multiplication. Returns `None` if overflow occurred.
    pub fn checked_mul(self, other: u256) -> Option<u256> {
        match self.overflowing_mul(other) {
            (_, true) => None,
            (val, _) => Some(val),
        }
    }

    /// Checked division. Returns `None` if `other == 0`.
    pub fn checked_div(self, other: u256) -> Option<u256> {
        if other.is_zero() {
            None
        } else {
            Some(self / other)
        }
    }

    /// Checked modulus. Returns `None` if `other == 0`.
    pub fn checked_rem(self, other: u256) -> Option<u256> {
        if other.is_zero() {
            None
        } else {
            Some(self % other)
        }
    }

    /// Negation with overflow.
    pub fn overflowing_neg(self) -> (u256, bool) {
        if self.is_zero() {
            (self, false)
        } else {
            (!self + 1usize, true)
        }
    }

    /// Checked negation. Returns `None` unless `self == 0`.
    pub fn checked_neg(self) -> Option<u256> {
        match self.overflowing_neg() {
            (_, true) => None,
            (zero, false) => Some(zero),
        }
    }

    #[inline(always)]
    fn div_mod_word(hi: u64, lo: u64, y: u64) -> (u64, u64) {
        if hi >= y {
            panic!("assertion failed: hi < y")
        }
        let x = (u128::from(hi) << 64) + u128::from(lo);
        let y = u128::from(y);
        ((x / y) as u64, (x % y) as u64)
    }

    #[inline(always)]
    fn add_slice(a: &mut [u64], b: &[u64]) -> bool {
        Self::binop_slice(a, b, u64::overflowing_add)
    }

    #[inline(always)]
    fn sub_slice(a: &mut [u64], b: &[u64]) -> bool {
        Self::binop_slice(a, b, u64::overflowing_sub)
    }

    #[inline(always)]
    fn binop_slice(
        a: &mut [u64],
        b: &[u64],
        binop: impl Fn(u64, u64) -> (u64, bool) + Copy,
    ) -> bool {
        let mut c = false;
        a.iter_mut().zip(b.iter()).for_each(|(x, y)| {
            let (res, carry) = Self::binop_carry(*x, *y, c, binop);
            *x = res;
            c = carry;
        });
        c
    }

    #[inline(always)]
    fn binop_carry(
        a: u64,
        b: u64,
        c: bool,
        binop: impl Fn(u64, u64) -> (u64, bool),
    ) -> (u64, bool) {
        let (res1, overflow1) = b.overflowing_add(u64::from(c));
        let (res2, overflow2) = binop(a, res1);
        (res2, overflow1 || overflow2)
    }

    #[inline(always)]
    const fn mul_u64(a: u64, b: u64, carry: u64) -> (u64, u64) {
        let (hi, lo) = Self::split_u128(a as u128 * b as u128 + carry as u128);
        (lo, hi)
    }

    #[inline(always)]
    const fn split_u128(a: u128) -> (u64, u64) {
        ((a >> 64) as _, (a & 0xFFFFFFFFFFFFFFFF) as _)
    }

    /// Overflowing multiplication by u64.
    /// Returns the result and carry.
    fn overflowing_mul_u64(mut self, other: u64) -> (Self, u64) {
        let mut carry = 0u64;
        for d in self.0.iter_mut() {
            let (res, c) = Self::mul_u64(*d, other, carry);
            *d = res;
            carry = c;
        }
        (self, carry)
    }

    /// Converts from big endian representation bytes in memory.
    #[inline(never)]
    fn from_big_endian(slice: &[u8]) -> Self {
        use byteorder::{BigEndian, ByteOrder};
        if 4 * 8 < slice.len() {
            panic!("assertion failed: 4 * 8 >= slice.len()")
        };
        let mut padded = [0u8; 4 * 8];
        padded[4 * 8 - slice.len()..4 * 8].copy_from_slice(slice);
        let mut ret = [0; 4];
        for i in 0..4 {
            ret[4 - i - 1] = BigEndian::read_u64(&padded[8 * i..]);
        }
        u256(ret)
    }

    /// Retrieve the function used to convert a slice of BE bytes into u256
    pub fn pic_from_big_endian() -> fn(&[u8]) -> Self {
        let to_pic = Self::from_big_endian as usize;

        //we go thru "data" pointer here to force provenance
        let picced = unsafe { PIC::manual(to_pic) } as *const ();

        unsafe { core::mem::transmute(picced) }
    }

    /// Converts from little endian representation bytes in memory.
    pub fn from_little_endian(slice: &[u8]) -> Self {
        use byteorder::{ByteOrder, LittleEndian};
        if 4 * 8 < slice.len() {
            panic!("assertion failed: 4 * 8 >= slice.len()")
        };
        let mut padded = [0u8; 4 * 8];
        padded[0..slice.len()].copy_from_slice(slice);
        let mut ret = [0; 4];
        for i in 0..4 {
            ret[i] = LittleEndian::read_u64(&padded[8 * i..]);
        }
        u256(ret)
    }
}

impl From<u256> for [u8; 4 * 8] {
    fn from(number: u256) -> Self {
        let mut arr = [0u8; 4 * 8];
        number.to_big_endian(&mut arr);
        arr
    }
}

impl From<u64> for u256 {
    fn from(value: u64) -> u256 {
        let mut ret = [0; 4];
        ret[0] = value;
        u256(ret)
    }
}

impl From<u8> for u256 {
    fn from(value: u8) -> u256 {
        From::from(value as u64)
    }
}

impl From<u16> for u256 {
    fn from(value: u16) -> u256 {
        From::from(value as u64)
    }
}

impl From<u32> for u256 {
    fn from(value: u32) -> u256 {
        From::from(value as u64)
    }
}

impl From<usize> for u256 {
    fn from(value: usize) -> u256 {
        From::from(value as u64)
    }
}

impl<T> Add<T> for u256
where
    T: Into<u256>,
{
    type Output = u256;
    fn add(self, other: T) -> u256 {
        let (result, overflow) = self.overflowing_add(other.into());
        if overflow {
            panic!("arithmetic operation overflow")
        };
        result
    }
}

impl Sum for u256 {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), |acc, x| acc + x)
    }
}

impl<T> AddAssign<T> for u256
where
    T: Into<u256>,
{
    fn add_assign(&mut self, rhs: T) {
        let other: Self = rhs.into();
        *self = *self + other;
    }
}

impl<T> Sub<T> for u256
where
    T: Into<u256>,
{
    type Output = u256;
    #[inline]
    fn sub(self, other: T) -> u256 {
        let (result, overflow) = self.overflowing_sub(other.into());
        if overflow {
            panic!("arithmetic operation overflow")
        };
        result
    }
}

impl<T> SubAssign<T> for u256
where
    T: Into<u256>,
{
    fn sub_assign(&mut self, rhs: T) {
        let other: Self = rhs.into();
        *self = *self - other;
    }
}

impl<T> Mul<T> for u256
where
    T: Into<u256>,
{
    type Output = u256;
    fn mul(self, other: T) -> u256 {
        let other: Self = other.into();
        let (result, overflow) = self.overflowing_mul(other);
        if overflow {
            panic!("arithmetic operation overflow")
        };
        result
    }
}

impl Product for u256 {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), |acc, x| acc * x)
    }
}

impl<T> MulAssign<T> for u256
where
    T: Into<u256>,
{
    fn mul_assign(&mut self, rhs: T) {
        let other: Self = rhs.into();
        *self = *self * other
    }
}

impl<T> Div<T> for u256
where
    T: Into<u256>,
{
    type Output = u256;
    fn div(self, other: T) -> u256 {
        let other: Self = other.into();
        self.div_mod(other).0
    }
}

impl<T> DivAssign<T> for u256
where
    T: Into<u256>,
{
    fn div_assign(&mut self, rhs: T) {
        let other: Self = rhs.into();
        *self = *self / other
    }
}

impl<T> Rem<T> for u256
where
    T: Into<u256> + Copy,
{
    type Output = u256;
    fn rem(self, other: T) -> u256 {
        let mut sub_copy = self;
        sub_copy %= other;
        sub_copy
    }
}

impl<T> RemAssign<T> for u256
where
    T: Into<u256> + Copy,
{
    fn rem_assign(&mut self, other: T) {
        let other: Self = other.into();
        let rem = self.div_mod(other).1;
        *self = rem;
    }
}

impl BitAnd<u256> for u256 {
    type Output = u256;
    #[inline]
    fn bitand(self, other: u256) -> u256 {
        let u256(ref arr1) = self;
        let u256(ref arr2) = other;
        let mut ret = [0u64; 4];
        for i in 0..4 {
            ret[i] = arr1[i] & arr2[i];
        }
        u256(ret)
    }
}

impl BitXor<u256> for u256 {
    type Output = u256;
    #[inline]
    fn bitxor(self, other: u256) -> u256 {
        let u256(ref arr1) = self;
        let u256(ref arr2) = other;
        let mut ret = [0u64; 4];
        for i in 0..4 {
            ret[i] = arr1[i] ^ arr2[i];
        }
        u256(ret)
    }
}

impl BitOr<u256> for u256 {
    type Output = u256;
    #[inline]
    fn bitor(self, other: u256) -> u256 {
        let u256(ref arr1) = self;
        let u256(ref arr2) = other;
        let mut ret = [0u64; 4];
        for i in 0..4 {
            ret[i] = arr1[i] | arr2[i];
        }
        u256(ret)
    }
}

impl Not for u256 {
    type Output = u256;
    #[inline]
    fn not(self) -> u256 {
        let u256(ref arr) = self;
        let mut ret = [0u64; 4];
        for i in 0..4 {
            ret[i] = !arr[i];
        }
        u256(ret)
    }
}

impl<T> Shl<T> for u256
where
    T: Into<u256>,
{
    type Output = u256;
    fn shl(self, shift: T) -> u256 {
        let shift = shift.into().as_usize();
        let u256(ref original) = self;
        let mut ret = [0u64; 4];
        let word_shift = shift / 64;
        let bit_shift = shift % 64;
        for i in word_shift..4 {
            ret[i] = original[i - word_shift] << bit_shift;
        }
        if bit_shift > 0 {
            for i in word_shift + 1..4 {
                ret[i] += original[i - 1 - word_shift] >> (64 - bit_shift);
            }
        }
        u256(ret)
    }
}

impl<T> ShlAssign<T> for u256
where
    T: Into<u256>,
{
    fn shl_assign(&mut self, shift: T) {
        *self = *self << shift;
    }
}

impl<T> Shr<T> for u256
where
    T: Into<u256>,
{
    type Output = u256;
    fn shr(self, shift: T) -> u256 {
        let shift = shift.into().as_usize();
        let u256(ref original) = self;
        let mut ret = [0u64; 4];
        let word_shift = shift / 64;
        let bit_shift = shift % 64;
        for i in word_shift..4 {
            ret[i - word_shift] = original[i] >> bit_shift;
        }
        if bit_shift > 0 {
            for i in word_shift + 1..4 {
                ret[i - word_shift - 1] += original[i] << (64 - bit_shift);
            }
        }
        u256(ret)
    }
}

impl<T> ShrAssign<T> for u256
where
    T: Into<u256>,
{
    fn shr_assign(&mut self, shift: T) {
        *self = *self >> shift;
    }
}

impl Ord for u256 {
    fn cmp(&self, other: &u256) -> Ordering {
        self.as_ref().iter().rev().cmp(other.as_ref().iter().rev())
    }
}

impl PartialOrd for u256 {
    fn partial_cmp(&self, other: &u256) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl From<u128> for u256 {
    fn from(value: u128) -> u256 {
        let mut ret = [0; 4];
        ret[0] = value as u64;
        ret[1] = (value >> 64) as u64;
        u256(ret)
    }
}

impl u256 {
    /// Low 2 words (u128)
    #[inline]
    pub const fn low_u128(&self) -> u128 {
        let &u256(ref arr) = self;
        ((arr[1] as u128) << 64) + arr[0] as u128
    }

    /// Conversion to u128 with overflow checking
    ///
    /// # Panics
    ///
    /// Panics if the number is larger than 2^128.
    #[inline]
    pub fn as_u128(&self) -> u128 {
        let &u256(ref arr) = self;
        for i in 2..4 {
            if arr[i] != 0 {
                panic!("Integer overflow when casting to u128");
            }
        }
        self.low_u128()
    }
}

#[cfg(any(test, feature = "derive-debug"))]
impl core::fmt::Debug for u256 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        self.fmt_dec(f)
    }
}

#[cfg(any(test, feature = "derive-debug"))]
impl core::fmt::Display for u256 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        core::fmt::Debug::fmt(self, f)
    }
}

#[cfg(any(test, feature = "derive-debug"))]
impl core::fmt::UpperHex for u256 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        self.fmt_hex(f, false)
    }
}

#[cfg(any(test, feature = "derive-debug"))]
impl core::fmt::LowerHex for u256 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        self.fmt_hex(f, true)
    }
}

#[cfg(any(test, feature = "derive-debug"))]
impl u256 {
    fn fmt_dec(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        if self.is_zero() {
            return f.write_str("0");
        }
        let mut buf = [0_u8; 4 * 20];
        let mut i = buf.len() - 1;
        let mut current = *self;
        let ten = u256::from(10u32);
        loop {
            let digit = (current % ten).low_u64() as u8;
            buf[i] = digit + b'0';
            current /= ten;
            if current.is_zero() {
                break;
            }
            i -= 1;
        }
        let s = unsafe { core::str::from_utf8_unchecked(&buf[i..]) };
        f.pad_integral(true, "", s)
    }

    fn fmt_hex(&self, f: &mut core::fmt::Formatter, is_lower: bool) -> core::fmt::Result {
        let &u256(ref data) = self;
        if self.is_zero() {
            return f.pad_integral(true, "0x", "0");
        }
        let mut latch = false;
        let mut buf = [0_u8; 4 * 16];
        let mut i = 0;
        for ch in data.iter().rev() {
            for x in 0..16 {
                let nibble = (ch & (15u64 << ((15 - x) * 4) as u64)) >> (((15 - x) * 4) as u64);
                if !latch {
                    latch = nibble != 0;
                }
                if latch {
                    let nibble = match nibble {
                        0..=9 => nibble as u8 + b'0',
                        _ if is_lower => nibble as u8 - 10 + b'a',
                        _ => nibble as u8 - 10 + b'A',
                    };
                    buf[i] = nibble;
                    i += 1;
                }
            }
        }
        let s = unsafe { core::str::from_utf8_unchecked(&buf[0..i]) };
        f.pad_integral(true, "0x", s)
    }
}

impl u256 {
    pub const FORMATTED_SIZE: usize = (Self::BITS / 4) as usize;

    ///u258::MAX is
    /// 115792089237316195423570985008687907853269984665640564039457584007913129639935
    /// which is 78 characters long
    pub const FORMATTED_SIZE_DECIMAL: usize = 78;

    /// Equivalent of [`lexical_core::ToLexical`]
    ///
    /// Will format the number in the provided buffer and return the slice
    /// of the given buffer that was actually written
    ///
    /// # Panic
    /// Will panic if there's not enough space in the input slice
    ///
    /// To make sure there are enough bytes, use a buffer of size [`Self::FORMATTED_SIZE_DECIMAL`]
    pub fn to_lexical(mut self, bytes: &mut [u8]) -> &mut [u8] {
        //this is equivalent to Self::from(10)
        const TEN: &u256 = &Self([10, 0, 0, 0]);

        let ten = *PIC::new(TEN).into_inner();

        //write it from the front
        // this is counter intuitive since we start
        // with the digit with the smallest position
        // but later we'll .reverse() the slice
        // so it's ordered properly
        //
        // We do that so we write from the start of the buffer, not the end
        let mut i = 0;
        loop {
            let (this, digit) = self.div_mod(ten);
            let digit = digit.low_u64() as u8;

            //use the ascii property that we can
            // start from the character code for `0`
            // and increment from there
            bytes[i] = b'0' + digit;
            i += 1;

            //we are done
            if this.is_zero() {
                //retrieve the slice that we have written so far
                let bytes = &mut bytes[..i];
                //then reverse so we have the digits written in the right order
                bytes.reverse();

                break bytes;
            }

            //set for new iteration
            // and move to the next byte in the buffer
            self = this;
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use std::string::ToString;

    use super::*;

    fn formatting_impl(value: u256) {
        let mut buffer = [0; u256::FORMATTED_SIZE_DECIMAL];

        let expected = value.to_string();

        assert_eq!(expected.as_bytes(), &*value.to_lexical(&mut buffer))
    }

    #[test]
    fn formatting_max() {
        formatting_impl(*u256::max());
    }

    #[cfg(not(miri))]
    proptest! {
        #[test]
        fn formatting(a: u64, b: u64, c: u64, d: u64) {
            formatting_impl(u256([a, b, c, d]))
        }
    }
}
