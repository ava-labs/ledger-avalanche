/// Code Taken from the tiny-keccak crate

const RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

const RC: [u64; ROUNDS] = [
    1u64,
    0x8082u64,
    0x800000000000808au64,
    0x8000000080008000u64,
    0x808bu64,
    0x80000001u64,
    0x8000000080008081u64,
    0x8000000000008009u64,
    0x8au64,
    0x88u64,
    0x80008009u64,
    0x8000000au64,
    0x8000808bu64,
    0x800000000000008bu64,
    0x8000000000008089u64,
    0x8000000000008003u64,
    0x8000000000008002u64,
    0x8000000000000080u64,
    0x800au64,
    0x800000008000000au64,
    0x8000000080008081u64,
    0x8000000000008080u64,
    0x80000001u64,
    0x8000000080008008u64,
];

const WORDS: usize = 25;
const ROUNDS: usize = 24;

macro_rules! keccak_function {
    ($doc: expr, $name: ident, $rounds: expr, $rc: expr) => {
        #[doc = $doc]
        #[allow(unused_assignments)]
        #[allow(non_upper_case_globals)]
        pub fn $name(a: &mut [u64; WORDS]) {
            use bolos::{PIC};
            use crunchy::unroll;

            let rho = unsafe {
               let ptr = PIC::manual(RHO.as_ptr() as usize);
                core::slice::from_raw_parts(ptr as *const u32, RHO.len())
            };
            let pi = unsafe {
                let ptr = PIC::manual(PI.as_ptr() as usize);
                core::slice::from_raw_parts(ptr as *const usize, PI.len())
            };


            for i in 0..$rounds {
                let mut array: [u64; 5] = [0; 5];

                // Theta
                unroll! {
                    for x in 0..5 {
                        unroll! {
                            for y_count in 0..5 {
                                let y = y_count * 5;
                                array[x] ^= a[x + y];
                            }
                        }
                    }
                }

                unroll! {
                    for x in 0..5 {
                        unroll! {
                            for y_count in 0..5 {
                                let y = y_count * 5;
                                a[y + x] ^= array[(x + 4) % 5] ^ array[(x + 1) % 5].rotate_left(1);
                            }
                        }
                    }
                }

                // Rho and pi
                let mut last = a[1];
                unroll! {
                    for x in 0..24 {
                        array[0] = a[pi[x]];
                        a[pi[x]] = last.rotate_left(rho[x]);
                        last = array[0];
                    }
                }


                // Chi
                unroll! {
                    for y_step in 0..5 {
                        let y = y_step * 5;

                        unroll! {
                            for x in 0..5 {
                                array[x] = a[y + x];
                            }
                        }

                        unroll! {
                            for x in 0..5 {
                                a[y + x] = array[x] ^ ((!array[(x + 1) % 5]) & (array[(x + 2) % 5]));
                            }
                        }
                    }
                };

                // Iota
            let rc = unsafe {
                let ptr = PIC::manual($rc.as_ptr() as usize);
                core::slice::from_raw_parts(ptr as *const u64, $rc.len())
            };
                a[0] ^= rc[i];
            }
        }
    }
}

/// A trait for hashing an arbitrary stream of bytes.
///
/// # Example
///
/// ```
/// # use tiny_keccak::Hasher;
/// #
/// # fn foo<H: Hasher>(mut hasher: H) {
/// let input_a = b"hello world";
/// let input_b = b"!";
/// let mut output = [0u8; 32];
/// hasher.update(input_a);
/// hasher.update(input_b);
/// hasher.finalize(&mut output);
/// # }
/// ```
pub(crate) trait Hasher {
    /// Absorb additional input. Can be called multiple times.
    fn update(&mut self, input: &[u8]);

    /// Pad and squeeze the state to the output.
    fn finalize(self, output: &mut [u8]);
}

/// A trait used to convert [`Hasher`] into it's [`Xof`] counterpart.
///
/// # Example
///
/// ```
/// # use tiny_keccak::IntoXof;
/// #
/// # fn foo<H: IntoXof>(hasher: H) {
/// let xof = hasher.into_xof();
/// # }
/// ```
///
/// [`Hasher`]: trait.Hasher.html
/// [`Xof`]: trait.Xof.html
pub trait IntoXof {
    /// A type implementing [`Xof`], eXtendable-output function interface.
    ///
    /// [`Xof`]: trait.Xof.html
    type Xof: Xof;

    /// A method used to convert type into [`Xof`].
    ///
    /// [`Xof`]: trait.Xof.html
    fn into_xof(self) -> Self::Xof;
}

/// Extendable-output function (`XOF`) is a function on bit strings in which the output can be
/// extended to any desired length.
///
/// # Example
///
/// ```
/// # use tiny_keccak::Xof;
/// #
/// # fn foo<X: Xof>(mut xof: X) {
/// let mut output = [0u8; 64];
/// xof.squeeze(&mut output[0..32]);
/// xof.squeeze(&mut output[32..]);
/// # }
/// ```
pub trait Xof {
    /// A method used to retrieve another part of hash function output.
    fn squeeze(&mut self, output: &mut [u8]);
}

struct EncodedLen {
    offset: usize,
    buffer: [u8; 9],
}

impl EncodedLen {
    fn value(&self) -> &[u8] {
        &self.buffer[self.offset..]
    }
}

fn left_encode(len: usize) -> EncodedLen {
    let mut buffer = [0u8; 9];
    buffer[1..].copy_from_slice(&(len as u64).to_be_bytes());
    let offset = buffer.iter().position(|i| *i != 0).unwrap_or(8);
    buffer[offset - 1] = 9 - offset as u8;

    EncodedLen {
        offset: offset - 1,
        buffer,
    }
}

fn right_encode(len: usize) -> EncodedLen {
    let mut buffer = [0u8; 9];
    buffer[..8].copy_from_slice(&(len as u64).to_be_bytes());
    let offset = buffer.iter().position(|i| *i != 0).unwrap_or(7);
    buffer[8] = 8 - offset as u8;
    EncodedLen { offset, buffer }
}

#[derive(Default, Clone)]
pub(crate) struct Buffer([u64; WORDS]);

impl Buffer {
    pub fn words(&mut self) -> &mut [u64; 25] {
        &mut self.0
    }

    #[cfg(target_endian = "little")]
    #[inline]
    pub fn execute<F: FnOnce(&mut [u8])>(&mut self, offset: usize, len: usize, f: F) {
        let buffer: &mut [u8; 25 * 8] = unsafe { core::mem::transmute(&mut self.0) };
        f(&mut buffer[offset..][..len]);
    }

    #[cfg(target_endian = "big")]
    #[inline]
    pub fn execute<F: FnOnce(&mut [u8])>(&mut self, offset: usize, len: usize, f: F) {
        fn swap_endianess(buffer: &mut [u64]) {
            for item in buffer {
                *item = item.swap_bytes();
            }
        }

        let start = offset / 8;
        let end = (offset + len + 7) / 8;
        swap_endianess(&mut self.0[start..end]);
        let buffer: &mut [u8; 25 * 8] = unsafe { core::mem::transmute(&mut self.0) };
        f(&mut buffer[offset..][..len]);
        swap_endianess(&mut self.0[start..end]);
    }

    fn setout(&mut self, dst: &mut [u8], offset: usize, len: usize) {
        self.execute(offset, len, |buffer| dst[..len].copy_from_slice(buffer));
    }

    fn xorin(&mut self, src: &[u8], offset: usize, len: usize) {
        self.execute(offset, len, |dst| {
            assert!(dst.len() <= src.len());
            let len = dst.len();
            let mut dst_ptr = dst.as_mut_ptr();
            let mut src_ptr = src.as_ptr();
            for _ in 0..len {
                unsafe {
                    *dst_ptr ^= *src_ptr;
                    src_ptr = src_ptr.offset(1);
                    dst_ptr = dst_ptr.offset(1);
                }
            }
        });
    }

    fn pad(&mut self, offset: usize, delim: u8, rate: usize) {
        self.execute(offset, 1, |buff| buff[0] ^= delim);
        self.execute(rate - 1, 1, |buff| buff[0] ^= 0x80);
    }
}

pub(crate) trait Permutation {
    fn execute(a: &mut Buffer);
}

#[derive(Clone, Copy)]
enum Mode {
    Absorbing,
    Squeezing,
}

pub(crate) struct KeccakState<P> {
    buffer: Buffer,
    offset: usize,
    rate: usize,
    delim: u8,
    mode: Mode,
    permutation: core::marker::PhantomData<P>,
}

impl<P> Clone for KeccakState<P> {
    fn clone(&self) -> Self {
        KeccakState {
            buffer: self.buffer.clone(),
            offset: self.offset,
            rate: self.rate,
            delim: self.delim,
            mode: self.mode,
            permutation: core::marker::PhantomData,
        }
    }
}

impl<P: Permutation> KeccakState<P> {
    pub fn new(rate: usize, delim: u8) -> Self {
        assert!(rate != 0, "rate cannot be equal 0");
        KeccakState {
            buffer: Buffer::default(),
            offset: 0,
            rate,
            delim,
            mode: Mode::Absorbing,
            permutation: core::marker::PhantomData,
        }
    }

    fn keccak(&mut self) {
        P::execute(&mut self.buffer);
    }

    pub fn update(&mut self, input: &[u8]) {
        if let Mode::Squeezing = self.mode {
            self.mode = Mode::Absorbing;
            self.fill_block();
        }

        //first foldp
        let mut ip = 0;
        let mut l = input.len();
        let mut rate = self.rate - self.offset;
        let mut offset = self.offset;
        while l >= rate {
            self.buffer.xorin(&input[ip..], offset, rate);
            self.keccak();
            ip += rate;
            l -= rate;
            rate = self.rate;
            offset = 0;
        }

        self.buffer.xorin(&input[ip..], offset, l);
        self.offset = offset + l;
    }

    fn pad(&mut self) {
        self.buffer.pad(self.offset, self.delim, self.rate);
    }

    fn squeeze(&mut self, output: &mut [u8]) {
        if let Mode::Absorbing = self.mode {
            self.mode = Mode::Squeezing;
            self.pad();
            self.fill_block();
        }

        // second foldp
        let mut op = 0;
        let mut l = output.len();
        let mut rate = self.rate - self.offset;
        let mut offset = self.offset;
        while l >= rate {
            self.buffer.setout(&mut output[op..], offset, rate);
            self.keccak();
            op += rate;
            l -= rate;
            rate = self.rate;
            offset = 0;
        }

        self.buffer.setout(&mut output[op..], offset, l);
        self.offset = offset + l;
    }

    pub fn finalize(mut self, output: &mut [u8]) {
        self.squeeze(output);
    }

    fn fill_block(&mut self) {
        self.keccak();
        self.offset = 0;
    }

    fn reset(&mut self) {
        self.buffer = Buffer::default();
        self.offset = 0;
        self.mode = Mode::Absorbing;
    }
}

pub(crate) fn bits_to_rate(bits: usize) -> usize {
    200 - bits / 4
}

keccak_function!("`keccak-f[1600, 24]`", keccakf, ROUNDS, RC);

pub struct KeccakF;

impl Permutation for KeccakF {
    fn execute(buffer: &mut Buffer) {
        keccakf(buffer.words());
    }
}
