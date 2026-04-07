use super::BackendId;
use crate::error::{PreError, PreResult};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A PRE public key (backend-agnostic wrapper)
#[derive(Clone, Debug)]
pub struct PublicKey {
    pub(crate) backend: BackendId,
    pub(crate) bytes: Vec<u8>,
}

impl PublicKey {
    pub fn new(backend: BackendId, bytes: Vec<u8>) -> Self {
        Self { backend, bytes }
    }

    pub fn backend(&self) -> BackendId {
        self.backend
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Serialize with backend tag
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![self.backend as u8];
        out.extend(&self.bytes);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> PreResult<Self> {
        if bytes.is_empty() {
            return Err(PreError::InvalidKey("Empty public key".into()));
        }
        let backend = BackendId::try_from(bytes[0])?;
        Ok(Self {
            backend,
            bytes: bytes[1..].to_vec(),
        })
    }
}

/// A PRE secret key (zeroized on drop)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    #[zeroize(skip)]
    pub(crate) backend: BackendId,
    #[zeroize(skip)]
    _backend_skip: (), // Backend ID doesn't need zeroizing
    pub(crate) bytes: Vec<u8>,
}

impl SecretKey {
    pub fn new(backend: BackendId, bytes: Vec<u8>) -> Self {
        Self {
            backend,
            _backend_skip: (),
            bytes,
        }
    }

    pub fn backend(&self) -> BackendId {
        self.backend
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// A keypair (public + secret)
pub struct KeyPair {
    pub public: PublicKey,
    pub secret: SecretKey,
}

/// A recryption key (transforms ciphertexts from one recipient to another)
#[derive(Clone)]
pub struct RecryptKey {
    pub(crate) backend: BackendId,
    pub(crate) from_public: PublicKey,
    pub(crate) to_public: PublicKey,
    pub(crate) bytes: Vec<u8>,
}

impl RecryptKey {
    pub fn new(
        backend: BackendId,
        from_public: PublicKey,
        to_public: PublicKey,
        bytes: Vec<u8>,
    ) -> Self {
        Self {
            backend,
            from_public,
            to_public,
            bytes,
        }
    }

    pub fn backend(&self) -> BackendId {
        self.backend
    }

    pub fn from_public(&self) -> &PublicKey {
        &self.from_public
    }

    pub fn to_public(&self) -> &PublicKey {
        &self.to_public
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Serialize with backend tag and public keys
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![self.backend as u8];
        // Length-prefixed from_public
        let from_bytes = self.from_public.to_bytes();
        out.extend((from_bytes.len() as u32).to_le_bytes());
        out.extend(from_bytes);
        // Length-prefixed to_public
        let to_bytes = self.to_public.to_bytes();
        out.extend((to_bytes.len() as u32).to_le_bytes());
        out.extend(to_bytes);
        // Remainder is recrypt key bytes
        out.extend(&self.bytes);
        out
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> PreResult<Self> {
        if bytes.len() < 9 {
            return Err(PreError::Deserialization("RecryptKey too short".into()));
        }

        let backend = BackendId::try_from(bytes[0])?;
        let mut pos = 1;

        // Read from_public
        let from_len = u32::from_le_bytes(
            bytes[pos..pos + 4]
                .try_into()
                .map_err(|_| PreError::Deserialization("Invalid from_public length".into()))?,
        ) as usize;
        pos += 4;
        if pos + from_len > bytes.len() {
            return Err(PreError::Deserialization("from_public truncated".into()));
        }
        let from_public = PublicKey::from_bytes(&bytes[pos..pos + from_len])?;
        pos += from_len;

        // Read to_public
        if pos + 4 > bytes.len() {
            return Err(PreError::Deserialization("to_public length missing".into()));
        }
        let to_len = u32::from_le_bytes(
            bytes[pos..pos + 4]
                .try_into()
                .map_err(|_| PreError::Deserialization("Invalid to_public length".into()))?,
        ) as usize;
        pos += 4;
        if pos + to_len > bytes.len() {
            return Err(PreError::Deserialization("to_public truncated".into()));
        }
        let to_public = PublicKey::from_bytes(&bytes[pos..pos + to_len])?;
        pos += to_len;

        // Remainder is key bytes
        let key_bytes = bytes[pos..].to_vec();

        Ok(Self {
            backend,
            from_public,
            to_public,
            bytes: key_bytes,
        })
    }
}

/// A PRE ciphertext
#[derive(Clone, Debug)]
pub struct Ciphertext {
    pub(crate) backend: BackendId,
    pub(crate) level: u8, // 0 = original, 1+ = recrypted
    pub(crate) bytes: Vec<u8>,
}

impl Ciphertext {
    pub fn new(backend: BackendId, level: u8, bytes: Vec<u8>) -> Self {
        Self {
            backend,
            level,
            bytes,
        }
    }

    pub fn backend(&self) -> BackendId {
        self.backend
    }

    pub fn level(&self) -> u8 {
        self.level
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![self.backend as u8, self.level];
        out.extend(&self.bytes);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> PreResult<Self> {
        if bytes.len() < 2 {
            return Err(PreError::Deserialization("Ciphertext too short".into()));
        }
        let backend = BackendId::try_from(bytes[0])?;
        Ok(Self {
            backend,
            level: bytes[1],
            bytes: bytes[2..].to_vec(),
        })
    }
}
