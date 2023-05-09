pub use ed25519_dalek::{Keypair, PublicKey, Signature, SignatureError, Signer, Verifier};
use rayon::prelude::*;
use sdk_types::{hash, Address, AuthorizedTransaction, Body, GetAddress, Transaction};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Authorization {
    pub public_key: PublicKey,
    pub signature: Signature,
}

impl GetAddress for Authorization {
    fn get_address(&self) -> Address {
        get_address(&self.public_key)
    }
}

pub fn get_address(public_key: &PublicKey) -> Address {
    Address::from(hash(&public_key.to_bytes()))
}

pub fn verify_authorizations<C: Clone + Serialize + Sync>(
    body: &Body<Authorization, C>,
) -> Result<bool, Error> {
    let input_numbers = body
        .transactions
        .iter()
        .map(|transaction| transaction.inputs.len());
    let serialized_transactions: Vec<Vec<u8>> = body
        .transactions
        .par_iter()
        .map(bincode::serialize)
        .collect::<Result<_, _>>()?;
    let serialized_transactions = serialized_transactions.iter().map(Vec::as_slice);
    let messages = input_numbers
        .zip(serialized_transactions)
        .flat_map(|(input_number, serialized_transaction)| {
            std::iter::repeat(serialized_transaction).take(input_number)
        })
        .zip(body.authorizations.iter())
        .collect::<Vec<_>>();
    Ok(messages.par_iter().all(|(message, authorization)| {
        authorization
            .public_key
            .verify(message, &authorization.signature)
            .is_ok()
    }))
}

pub fn authorize<C: Clone + Serialize>(
    addresses_keypairs: &[(Address, &Keypair)],
    transaction: Transaction<C>,
) -> Result<AuthorizedTransaction<Authorization, C>, Error> {
    let mut authorizations: Vec<Authorization> = Vec::with_capacity(addresses_keypairs.len());
    let message = bincode::serialize(&transaction)?;
    for (address, keypair) in addresses_keypairs {
        let hash_public_key = Address::from(hash(&keypair.public.to_bytes()));
        if *address != hash_public_key {
            return Err(Error::WrongKeypairForAddress {
                address: *address,
                hash_public_key,
            });
        }
        let authorization = Authorization {
            public_key: keypair.public,
            signature: keypair.sign(&message),
        };
        authorizations.push(authorization);
    }
    Ok(AuthorizedTransaction {
        authorizations,
        transaction,
    })
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(
        "wrong keypair for address: address = {address},  hash(public_key) = {hash_public_key}"
    )]
    WrongKeypairForAddress {
        address: Address,
        hash_public_key: Address,
    },
    #[error("ed25519_dalek error")]
    DalekError(#[from] SignatureError),
    #[error("bincode error")]
    BincodeError(#[from] bincode::Error),
}
