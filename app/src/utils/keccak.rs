//! The `Keccak` hash functions.

mod keccak_impl;
pub(crate) use keccak_impl::Hasher;
use keccak_impl::{bits_to_rate, KeccakF, KeccakState};

/// The `Keccak` hash functions defined in [`Keccak SHA3 submission`].
/// [`Keccak SHA3 submission`]: https://keccak.team/files/Keccak-submission-3.pdf
#[derive(Clone)]
pub struct Keccak<const N: usize> {
    state: KeccakState<KeccakF>,
}

impl<const N: usize> Keccak<N> {
    pub const DIGEST_LEN: usize = N;

    const DELIM: u8 = 0x01;

    pub fn new() -> Keccak<N> {
        Keccak {
            state: KeccakState::new(bits_to_rate(N * 8), Self::DELIM),
        }
    }
}

impl<const N: usize> Hasher for Keccak<N> {
    /// Absorb additional input. Can be called multiple times.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use tiny_keccak::{Hasher, Keccak};
    /// #
    /// # fn main() {
    /// # let mut keccak = Keccak::v256();
    /// keccak.update(b"hello");
    /// keccak.update(b" world");
    /// # }
    /// ```
    fn update(&mut self, input: &[u8]) {
        self.state.update(input);
    }

    /// Pad and squeeze the state to the output.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use tiny_keccak::{Hasher, Keccak};
    /// #
    /// # fn main() {
    /// # let keccak = Keccak::v256();
    /// # let mut output = [0u8; 32];
    /// keccak.finalize(&mut output);
    /// # }
    /// #
    /// ```
    fn finalize(self, output: &mut [u8]) {
        self.state.finalize(output);
    }
}
