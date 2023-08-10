use candid::Principal;
use k256::{
    ecdsa::{signature::Signer, SigningKey},
    SecretKey,
};
use pkcs8::EncodePublicKey;

pub struct Signature {
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
}

pub struct Identity {
    private_key: SigningKey,
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
            private_key: secret_key.into(),
            der_encoded_public_key,
        };

        Ok(identity)
    }

    pub fn sender(&self) -> Principal {
        Principal::self_authenticating(&self.der_encoded_public_key)
    }

    pub fn sign(&self, content: Vec<u8>) -> Result<Signature, String> {
        let (ecdsa_sig, _recovery_id) = self
            .private_key
            .try_sign(&content)
            .map_err(|e| format!("Failed to sign: {}", e))?;
        let r = ecdsa_sig.r().as_ref().to_bytes();
        let s = ecdsa_sig.s().as_ref().to_bytes();
        let mut bytes = [0u8; 64];
        if r.len() > 32 || s.len() > 32 {
            return Err("Cannot create secp256k1 signature: malformed signature.".to_string());
        }
        bytes[(32 - r.len())..32].clone_from_slice(&r);
        bytes[32 + (32 - s.len())..].clone_from_slice(&s);

        let signature = Signature {
            public_key: self.der_encoded_public_key.clone(),
            signature: bytes.to_vec(), //Signature bytes
        };

        Ok(signature)
    }
}
