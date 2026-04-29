#[macro_use]
extern crate criterion;

use bellman::groth16::*;
use bls12_381::Bls12;
use criterion::Criterion;
use group::{Group, ff::Field};
use masp_primitives::{
    asset_type::AssetType,
    sapling::{Diversifier, ProofGenerationKey},
};
use masp_proofs::circuit::sapling::Output;
use rand_core::{RngCore, SeedableRng};
use rand_xorshift::XorShiftRng;

fn criterion_benchmark(c: &mut Criterion) {
    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x3d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let groth_params = generate_random_parameters::<Bls12, _, _>(
        Output {
            value_commitment: None,
            asset_id: None,
            payment_address: None,
            commitment_randomness: None,
            esk: None,
        },
        &mut rng,
    )
    .unwrap();

    c.bench_function("output", |b| {
        let asset_type = AssetType::new(b"benchmark").unwrap();
        let value_commitment = asset_type.value_commitment(1, jubjub::Fr::random(&mut rng));

        let proof_generation_key = ProofGenerationKey {
            ak: jubjub::SubgroupPoint::random(&mut rng),
            nsk: jubjub::Fr::random(&mut rng),
        };

        let viewing_key = proof_generation_key.to_viewing_key();

        let payment_address;
        loop {
            let diversifier = {
                let mut d = [0; 11];
                rng.fill_bytes(&mut d);
                Diversifier(d)
            };

            if let Some(p) = viewing_key.to_payment_address(diversifier) {
                payment_address = p;
                break;
            }
        }

        let commitment_randomness = jubjub::Fr::random(&mut rng);
        let esk = jubjub::Fr::random(&mut rng);

        b.iter(|| {
            create_random_proof(
                Output {
                    value_commitment: Some(value_commitment.clone()),
                    asset_id: Some(asset_type.asset_id()),
                    payment_address: Some(payment_address),
                    commitment_randomness: Some(commitment_randomness),
                    esk: Some(esk),
                },
                &groth_params,
                &mut rng,
            )
        });
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = criterion_benchmark
);
criterion_main!(benches);
