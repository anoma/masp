use bellman::groth16::Parameters;
use bellman::groth16::create_random_proof;
use bls12_381::Bls12;
use bls12_381::Fp;
use bls12_381::Scalar;
use group::Curve;
use group::{Group, ff::Field};
use masp_primitives::{
    asset_type::AssetType,
    sapling::{Diversifier, ProofGenerationKey, Rseed},
};
use masp_proofs::circuit::sapling::Output;
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

    let i = 23;
    let asset_type = if i < 10 {
        AssetType::new(b"default")
    } else {
        AssetType::new(i.to_string().as_bytes())
    }
    .unwrap();
    let value_commitment =
        asset_type.value_commitment(rng.next_u64(), jubjub::Fr::random(&mut rng));

    let nsk = jubjub::Fr::random(&mut rng);
    let ak = jubjub::SubgroupPoint::random(&mut rng);

    let proof_generation_key = ProofGenerationKey { ak, nsk };

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

    let instance = Output {
        value_commitment: Some(value_commitment.clone()),
        payment_address: Some(payment_address),
        commitment_randomness: Some(commitment_randomness),
        esk: Some(esk),
        asset_identifier: asset_type.identifier_bits(),
    };

    let expected_cmu = payment_address
        .create_note(
            asset_type,
            value_commitment.value,
            Rseed::BeforeZip212(commitment_randomness),
        )
        .expect("should be valid")
        .cmu();

    let expected_value_commitment =
        jubjub::ExtendedPoint::from(value_commitment.commitment()).to_affine();

    let expected_epk =
        jubjub::ExtendedPoint::from(payment_address.g_d().expect("should be valid") * esk)
            .to_affine();

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
        "[{}, {}, {}, {}], [[{}, {}, {}, {}],[{}, {}, {}, {}]], [{}, {}, {}, {}], [{}, {}, {}, {}, {}]",
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
        to_string(expected_epk.get_u()),
        to_string(expected_epk.get_v()),
        to_string(expected_cmu),
    );
}
