use std::error::Error;

/// A source for random bytes used in cryptographic algorithms.
///
/// NOTE: This trait is `unsafe` because it assumes the source is cryptographically secure.
pub unsafe trait EntropySource {
    type EntropySourceError: Error;

    fn read_bytes(&self, buffer: &mut [u8]) -> Result<(), Self::EntropySourceError>;
}

/// A simple wrapper over a generic byte array sourced from an `EntropySource`.
pub struct Entropy<const LENGTH: usize> {
    pub bytes: [u8; LENGTH],
}

impl<const LENGTH: usize> Entropy<LENGTH> {
    /// Attempt to generate entropy from the provided `EntropySource`.
    pub fn try_generate<S: EntropySource>(source: &S) -> Result<Self, S::EntropySourceError> {
        let mut bytes = [0u8; LENGTH];

        match source.read_bytes(&mut bytes) {
            Ok(_) => Ok(Self { bytes }),
            Err(e) => Err(e),
        }
    }

    /// Generate entropy from the provided 'EntropySource'.
    ///
    /// NOTE: This function will panic if the generation fails. See `try_generate` for a version with error handling.
    pub fn generate(source: &impl EntropySource) -> Self {
        Self::try_generate(source).unwrap()
    }
}

#[cfg(feature = "os")]
pub mod os {
    pub enum OsEntropySourceError {}

    /// Entropy from the underlying Operating System.
    ///
    /// NOTE: Implemented using the cross-platform `getrandom` crate.
    pub struct OsEntropy;

    unsafe impl EntropySource for OsEntropy {
        type EntropySourceError = OsEntropySourceError;

        fn read_bytes(&self, bytes: &mut [u8]) -> Result<(), Self::EntropySourceError> {
            match getrandom::getrandom(bytes) {
                Ok(_) => Ok(()),
                Err(_) => Err(Self::EntropySourceError),
            }
        }
    }
}
