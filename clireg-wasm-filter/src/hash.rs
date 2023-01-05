use proxy_wasm::types::Bytes;

pub trait Hasher {
    fn hash(&self, input: Bytes) -> Bytes;
    fn hash_base64(&self, input: Bytes) -> String {
        base64::encode(self.hash(input))
    }
}

pub enum HashAlg {
    SHA256,
    SHA512,
}


impl HashAlg {
    fn from(alg: &str) -> HashAlg {
        match alg {
            "sha256" | "sha-256" | "SHA256" | "SHA-256" => {
                HashAlg::SHA256
            }
            "sha512" | "sha-512" | "SHA512" | "SHA-512" => {
                HashAlg::SHA512
            }
            _ => {
                panic!("hash alg '{}' is unknown, only sha256 and sha512 are supported", alg)
            }
        }
    }

    pub fn new(self) -> Box<dyn Hasher> {
        match self {
            HashAlg::SHA256 => {
                Box::new(sha::Sha256Hasher {})
            }
            HashAlg::SHA512 => {
                Box::new(sha::Sha512Hasher {})
            }
        }
    }
}


mod sha {
    use proxy_wasm::types::Bytes;
    use super::Hasher;

    use sha2::{Digest, Sha256, Sha512};

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
}

#[cfg(test)]
mod tests {
    use proxy_wasm::types::Bytes;
    use super::HashAlg;
    use hex_literal::hex;
    use crate::hash;

    #[test]
    fn in_registry() {
        for alg in [
            "sha256",
            "sha-256",
            "SHA256",
            "SHA-256",
            "sha512",
            "sha-512",
            "SHA512",
            "SHA-512",
        ] {
            // load or panic
            HashAlg::from(alg);
        }
    }

    #[test]
    #[should_panic]
    fn not_in_registry() {
        HashAlg::from("foo");
    }

    #[test]
    fn sha256() {
        let bytes = Vec::from("hello world") as Bytes;
        let result = HashAlg::SHA256.new().hash(bytes);
        assert_eq!(result[..], hex!("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")[..]);
    }

    #[test]
    fn sha256_from() {
        let bytes = Vec::from("hello world") as Bytes;
        let result = HashAlg::from("SHA256").new().hash(bytes);
        assert_eq!(result[..], hex!("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")[..]);
    }

    #[test]
    fn sha512() {
        let bytes = Vec::from("hello world") as Bytes;
        let result = HashAlg::SHA512.new().hash(bytes);
        assert_eq!(result[..], hex!("
    309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f
    989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f
")[..]);
    }
}