pub use ed25519_dalek::{Keypair, PublicKey, Signature, SignatureError, Signer};
use sdk_types::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Authorization {
    public_key: PublicKey,
    signature: Signature,
}

impl GetAddress for Authorization {
    fn get_address(&self) -> Address {
        Address::from(hash(&self.public_key.to_bytes()))
    }
}

pub fn verify_authorizations<C: Clone + Serialize>(
    transactions: &[Transaction<Authorization, C>],
) -> Result<(), SignatureError> {
    let capacity: usize = transactions
        .iter()
        .map(|transaction| transaction.authorizations.len())
        .sum();

    let mut messages = Vec::with_capacity(capacity);
    let mut signatures = Vec::with_capacity(capacity);
    let mut public_keys = Vec::with_capacity(capacity);

    for transaction in transactions {
        let transaction_without_authorizations = Transaction {
            authorizations: vec![],
            ..transaction.clone()
        };
        let message = hash(&transaction_without_authorizations);
        for authorization in &transaction.authorizations {
            messages.push(message);
            signatures.push(authorization.signature);
            public_keys.push(authorization.public_key);
        }
    }
    let messages: Vec<&[u8]> = messages.iter().map(|message| message.as_slice()).collect();

    ed25519_dalek::verify_batch(
        messages.as_slice(),
        signatures.as_slice(),
        public_keys.as_slice(),
    )?;
    Ok(())
}

pub fn authorize<C: Clone + Serialize>(
    addresses_keypairs: &[(Address, &Keypair)],
    transaction: Transaction<Authorization, C>,
) -> Result<Transaction<Authorization, C>, AuthorizationError> {
    let mut authorizations: Vec<Authorization> = Vec::with_capacity(addresses_keypairs.len());
    let transaction_hash_without_authorizations = hash(&transaction);
    for (address, keypair) in addresses_keypairs {
        let hash_public_key = Address::from(hash(&keypair.public.to_bytes()));
        if *address != hash_public_key {
            return Err(AuthorizationError::WrongKeypairForAddress {
                address: *address,
                hash_public_key,
            });
        }
        let authorization = Authorization {
            public_key: keypair.public,
            signature: keypair.sign(&transaction_hash_without_authorizations),
        };
        authorizations.push(authorization);
    }
    Ok(Transaction {
        authorizations,
        ..transaction
    })
}

#[derive(Debug, thiserror::Error)]
pub enum AuthorizationError {
    #[error(
        "wrong keypair for address: address = {address},  hash(public_key) = {hash_public_key}"
    )]
    WrongKeypairForAddress {
        address: Address,
        hash_public_key: Address,
    },
}
