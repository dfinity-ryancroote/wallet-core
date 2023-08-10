use candid::Principal;
use k256::SecretKey;
use pkcs8::EncodePublicKey;

pub struct Signature {
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
}

pub struct Identity {
    secret_key: SecretKey,
    der_encoded_public_key: Vec<u8>,
}

impl Identity {
    pub fn new(secret_key: SecretKey) -> Result<Self, String> {
        let public_key = secret_key.public_key();
        let der_encoded_public_key = public_key
            .to_public_key_der()
            .map_err(|e| format!("Failed to encode public key: {}", e))?
            .as_bytes()
            .to_vec();

        let identity = Self {
            secret_key,
            der_encoded_public_key,
        };

        Ok(identity)
    }

    pub fn sender(&self) -> Principal {
        Principal::self_authenticating(&self.der_encoded_public_key)
    }

    pub fn sign(&self) -> Signature {
        todo!()
    }
}
