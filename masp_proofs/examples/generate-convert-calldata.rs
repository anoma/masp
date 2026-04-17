use bellman::groth16::Parameters;
use bellman::groth16::create_random_proof;
use bls12_381::Bls12;
use bls12_381::Fp;
use bls12_381::Scalar;
use group::Curve;
use group::{ff::Field, ff::PrimeField, ff::PrimeFieldBits};
use masp_primitives::convert::AllowedConversion;
use masp_primitives::transaction::components::ValueSum;
use masp_primitives::{asset_type::AssetType, sapling::pedersen_hash};
use masp_proofs::circuit::convert::Convert;
use rand_core::{RngCore, SeedableRng};
use rand_xorshift::XorShiftRng;

// Extract the lowest 32 bytes of the base field element
fn lo_string(fp: Fp) -> String {
    let lo = &fp.to_bytes_be()[16..48];
    format!("0x{}", const_hex::encode(lo))
}

// Extract the highest 16 bytes of the base field element
fn hi_string(fp: Fp) -> String {
    let hi = &fp.to_bytes_be()[0..16];
    format!("0x{}", const_hex::encode(hi))
}

// Extract the bytes of the scalar field element
fn to_string(fp: Scalar) -> String {
    let b = &fp.to_bytes_be()[0..32];
    format!("0x{}", const_hex::encode(b))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut params_file =
        std::fs::File::open(&args[1]).expect("unable to open verifier parameters");
    let proving_key =
        Parameters::<Bls12>::read(&mut params_file, false).expect("unable to open parameters");

    let mut rng = XorShiftRng::from_seed([
        0x58, 0x62, 0xbe, 0x3d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let tree_depth = 32;

    let i = rng.next_u32();
    let spend_asset = AssetType::new(format!("asset {}", i).as_bytes()).unwrap();
    let output_asset = AssetType::new(format!("asset {}", i + 1).as_bytes()).unwrap();
    let mint_asset = AssetType::new(b"reward").unwrap();

    let spend_value = -(i as i128 + 1);
    let output_value = i as i128 + 1;
    let mint_value = i as i128 + 1;

    let allowed_conversion: AllowedConversion = (ValueSum::from_pair(spend_asset, spend_value)
        + ValueSum::from_pair(output_asset, output_value)
        + ValueSum::from_pair(mint_asset, mint_value))
    .into();

    let value = rng.next_u64();

    let value_commitment = allowed_conversion.value_commitment(value, jubjub::Fr::random(&mut rng));

    let auth_path =
        vec![Some((bls12_381::Scalar::random(&mut rng), rng.next_u32() % 2 != 0)); tree_depth];

    let expected_value_commitment =
        jubjub::ExtendedPoint::from(value_commitment.commitment()).to_affine();

    let cmu = allowed_conversion.cmu();
    let mut cur = cmu;

    for (i, val) in auth_path.clone().into_iter().enumerate() {
        let (uncle, b) = val.unwrap();

        let mut lhs = cur;
        let mut rhs = uncle;

        if b {
            ::std::mem::swap(&mut lhs, &mut rhs);
        }

        let lhs = lhs.to_le_bits();
        let rhs = rhs.to_le_bits();

        cur = jubjub::ExtendedPoint::from(pedersen_hash::pedersen_hash(
            pedersen_hash::Personalization::MerkleTree(i),
            lhs.iter()
                .by_vals()
                .take(bls12_381::Scalar::NUM_BITS as usize)
                .chain(
                    rhs.iter()
                        .by_vals()
                        .take(bls12_381::Scalar::NUM_BITS as usize),
                ),
        ))
        .to_affine()
        .get_u();
    }

    let instance = Convert {
        value_commitment: Some(value_commitment.clone()),
        auth_path: auth_path.clone(),
        anchor: Some(cur),
    };

    let proof = create_random_proof(instance, &proving_key, &mut rng)
        .expect("failed to generate spend proof");

    let pi_a_g1_x = proof.a.x();
    let pi_a_g1_y = proof.a.y();
    let pi_b_g2_x_c0 = proof.b.x().c0();
    let pi_b_g2_x_c1 = proof.b.x().c1();
    let pi_b_g2_y_c0 = proof.b.y().c0();
    let pi_b_g2_y_c1 = proof.b.y().c1();
    let pi_c_g1_x = proof.c.x();
    let pi_c_g1_y = proof.c.y();
    println!(
        "[{}, {}, {}, {}], [[{}, {}, {}, {}],[{}, {}, {}, {}]], [{}, {}, {}, {}], [{}, {}, {}]",
        hi_string(pi_a_g1_x),
        lo_string(pi_a_g1_x),
        hi_string(pi_a_g1_y),
        lo_string(pi_a_g1_y),
        hi_string(pi_b_g2_x_c1),
        lo_string(pi_b_g2_x_c1),
        hi_string(pi_b_g2_x_c0),
        lo_string(pi_b_g2_x_c0),
        hi_string(pi_b_g2_y_c1),
        lo_string(pi_b_g2_y_c1),
        hi_string(pi_b_g2_y_c0),
        lo_string(pi_b_g2_y_c0),
        hi_string(pi_c_g1_x),
        lo_string(pi_c_g1_x),
        hi_string(pi_c_g1_y),
        lo_string(pi_c_g1_y),
        to_string(expected_value_commitment.get_u()),
        to_string(expected_value_commitment.get_v()),
        to_string(cur),
    );
}
