use std::fmt::{Display, Formatter};

use base64::Engine;
use proxy_wasm::types::Bytes;
use serde::{Deserialize, Serialize};

pub trait Hasher {
    fn hash(&self, input: Bytes) -> Bytes;
    fn hash_base64(&self, input: Bytes) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.hash(input))
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum HashAlg {
    SHA256,
    SHA512,
    Unknown(String),
}

impl Default for HashAlg {
    fn default() -> Self {
        Self::SHA256
    }
}

impl Display for HashAlg {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            HashAlg::Unknown(alg) => f.write_str(format!("Unknown ({alg})").as_str()),
            HashAlg::SHA256 => f.write_str("SHA-256"),
            HashAlg::SHA512 => f.write_str("SHA-512"),
        }
    }
}

impl From<&str> for HashAlg {
    fn from(alg: &str) -> Self {
        match alg {
            "sha256" | "sha-256" | "SHA256" | "SHA-256" => Self::SHA256,
            "sha512" | "sha-512" | "SHA512" | "SHA-512" => Self::SHA512,
            _ => Self::Unknown(alg.to_string()),
        }
    }
}
impl HashAlg {
    pub fn new(&self) -> Box<dyn Hasher> {
        match self {
            Self::SHA256 => Box::new(sha::Sha256Hasher {}),
            Self::SHA512 => Box::new(sha::Sha512Hasher {}),
            _ => Box::new(sha::PanicHasher {}),
        }
    }
}

mod sha {
    use proxy_wasm::types::Bytes;
    use sha2::{Digest, Sha256, Sha512};

    use super::Hasher;

    pub struct Sha256Hasher {}

    impl Hasher for Sha256Hasher {
        fn hash(&self, input: Bytes) -> Bytes {
            Sha256::digest(&input).to_vec()
        }
    }

    pub struct Sha512Hasher {}

    impl Hasher for Sha512Hasher {
        fn hash(&self, input: Bytes) -> Bytes {
            Sha512::digest(&input).to_vec()
        }
    }

    pub struct PanicHasher {}

    impl Hasher for PanicHasher {
        fn hash(&self, _input: Bytes) -> Bytes {
            panic!("Unknown hash algorithm used!")
        }
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use proxy_wasm::types::Bytes;

    use super::HashAlg;

    #[test]
    fn in_registry() {
        for alg in [
            "sha256", "sha-256", "SHA256", "SHA-256", "sha512", "sha-512", "SHA512", "SHA-512",
        ] {
            // load or panic
            let _ = HashAlg::from(alg);
        }
    }

    #[test]
    #[should_panic]
    fn not_in_registry() {
        let alg = HashAlg::from("foo").new();
        alg.hash("".as_bytes().to_vec());
    }

    #[test]
    fn sha256() {
        let bytes = Vec::from("hello world") as Bytes;
        let result = HashAlg::SHA256.new().hash(bytes);
        assert_eq!(
            result[..],
            hex!("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")[..]
        );
    }

    #[test]
    fn sha256_from() {
        let bytes = Vec::from("hello world") as Bytes;
        let result = HashAlg::from("SHA256").new().hash(bytes);
        assert_eq!(
            result[..],
            hex!("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")[..]
        );
    }

    #[test]
    fn sha512() {
        let bytes = Vec::from("hello world") as Bytes;
        let result = HashAlg::SHA512.new().hash(bytes);
        assert_eq!(
            result[..],
            hex!(
                "
    309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f
    989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f
"
            )[..]
        );
    }
}
