#[macro_use]
extern crate criterion;

use bellman::groth16::*;
use bls12_381::Bls12;
use criterion::Criterion;
use ff::Field;
use masp_primitives::{asset_type::AssetType, convert::AllowedConversion};
use masp_proofs::circuit::convert::{Convert, TREE_DEPTH};
use rand_core::{RngCore, SeedableRng};
use rand_xorshift::XorShiftRng;

fn criterion_benchmark(c: &mut Criterion) {
    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x3d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let groth_params = generate_random_parameters::<Bls12, _, _>(
        Convert {
            value_commitment: None,
            auth_path: vec![None; TREE_DEPTH],
            anchor: None,
        },
        &mut rng,
    )
    .unwrap();

    c.bench_function("convert", |b| {
        let i = rng.next_u32();
        let spend_asset = AssetType::new(format!("asset {}", i).as_bytes()).unwrap();
        let output_asset = AssetType::new(format!("asset {}", i + 1).as_bytes()).unwrap();
        let mint_asset = AssetType::new(b"reward").unwrap();

        let spend_value = -(i as i64 + 1);
        let output_value = i as i64 + 1;
        let mint_value = i as i64 + 1;

        let allowed_conversion = AllowedConversion::new(
            vec![
                (spend_asset, spend_value),
                (output_asset, output_value),
                (mint_asset, mint_value),
            ]
        );

        let value = rng.next_u64();

        let value_commitment =
            allowed_conversion.value_commitment(value, jubjub::Fr::random(&mut rng));

        let auth_path =
            vec![Some((bls12_381::Scalar::random(&mut rng), rng.next_u32() % 2 != 0)); TREE_DEPTH];
        let anchor = bls12_381::Scalar::random(&mut rng);

        b.iter(|| {
            create_random_proof(
                Convert {
                    value_commitment: Some(value_commitment.clone()),
                    auth_path: auth_path.clone(),
                    anchor: Some(anchor),
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
    targets = criterion_benchmark);
criterion_main!(benches);
