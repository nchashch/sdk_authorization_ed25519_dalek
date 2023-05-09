use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ed25519_dalek::Signer;
use fake::{Fake};
use sdk_authorization_ed25519_dalek::{verify_authorizations, Authorization};

type Output = sdk_types::Output<()>;
type Transaction = sdk_types::Transaction<()>;
type AuthorizedTransaction = sdk_types::AuthorizedTransaction<Authorization, ()>;
type Body = sdk_types::Body<Authorization, ()>;

pub fn random_output() -> Output {
    use rand::Rng;
    Output {
        address: sdk_types::Address::from(rand::thread_rng().gen::<[u8; 32]>()),
        content: sdk_types::Content::Value(0),
    }
}

pub fn random_transaction(num_inputs: usize, num_outputs: usize) -> AuthorizedTransaction {
    use ed25519_dalek::Keypair;
    use rand::rngs::OsRng;
    use rand::Rng;
    let inputs = (0..num_inputs)
        .map(|_| sdk_types::OutPoint::Regular {
            txid: sdk_types::Txid::from(rand::thread_rng().gen::<[u8; 32]>()),
            vout: (0..256).fake(),
        })
        .collect::<Vec<_>>();
    let outputs = (0..num_outputs)
        .map(|_| random_output())
        .collect::<Vec<_>>();
    let transaction = Transaction { inputs, outputs };
    let mut csprng = OsRng {};
    let authorizations = (0..num_inputs)
        .map(|_| {
            let keypair = Keypair::generate(&mut csprng);
            let serialized_transaction = bincode::serialize(&transaction).unwrap();
            let signature = keypair.sign(&serialized_transaction);
            Authorization {
                public_key: keypair.public,
                signature,
            }
        })
        .collect::<Vec<_>>();
    AuthorizedTransaction {
        authorizations,
        transaction,
    }
}

pub fn random_body(num_transactions: usize, num_coinbase_outputs: usize) -> Body {
    const NUM_INPUTS: usize = 10;
    const NUM_OUTPUTS: usize = 10;
    let transactions = (0..num_transactions)
        .map(|_| random_transaction(NUM_INPUTS, NUM_OUTPUTS))
        .collect::<Vec<_>>();
    let coinbase = (0..num_coinbase_outputs)
        .map(|_| random_output())
        .collect::<Vec<_>>();
    Body::new(transactions, coinbase)
}

pub fn criterion_benchmark(c: &mut Criterion) {
    // const NUM_TRANSACTIONS: usize = 1_200_000;
    const NUM_TRANSACTIONS: usize = 100;
    const NUM_COINBASE_OUTPUTS: usize = 0;
    let body = random_body(NUM_TRANSACTIONS, NUM_COINBASE_OUTPUTS);
    c.bench_function("verify_authorizations", |b| b.iter(|| verify_authorizations(black_box(&body))));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
