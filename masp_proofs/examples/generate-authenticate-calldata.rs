use bellman::groth16::Parameters;
use bls12_381::Bls12;
use bls12_381::Fp;
use bls12_381::Scalar;
use group::ff::Field;
use masp_proofs::circuit::authenticate::MAX_ASSETS;

use rand_core::SeedableRng;
use rand_xorshift::XorShiftRng;

use rand_core::RngCore;
use masp_primitives::sapling::redjubjub::PrivateKey;
use masp_primitives::constants::{value_commitment_randomness_generator, spending_key_generator};
use masp_primitives::asset_type::AssetType;
use masp_primitives::transaction::components::I128Sum;
use masp_primitives::sapling::redjubjub::PublicKey;
use masp_proofs::sapling::authenticate_proof;
use bellman::groth16::prepare_verifying_key;

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

    let r_sapling = value_commitment_randomness_generator();
    // Generate random key
    let bsk = PrivateKey(jubjub::Fr::random(&mut rng));
    let bvk = PublicKey::from_private(&bsk, r_sapling);
    // Generate random message
    let mut data_to_be_signed0 = [0u8; 64];
    rng.fill_bytes(&mut data_to_be_signed0);
    // Sign random message
    let (binding_c, binding_sig) = bsk.sign(&data_to_be_signed0, &mut rng, r_sapling);
    
    let g_sapling = spending_key_generator();
    // Generate random key
    let rsks = PrivateKey(jubjub::Fr::random(&mut rng));
    let rks = PublicKey::from_private(&rsks, g_sapling);
    // Generate random message
    let mut data_to_be_signed1 = [0u8; 64];
    rng.fill_bytes(&mut data_to_be_signed1);
    // Sign random message
    let (spend_auths_c, spend_auths_sig) = rsks.sign(&data_to_be_signed1, &mut rng, g_sapling);

    // Generate a value balance
    let mut value_sum = I128Sum::zero();
    
    for _j in 0..MAX_ASSETS {
        let mut asset_type = [0u8; 64];
        rng.fill_bytes(&mut asset_type);
        let asset_type = AssetType::new(&asset_type).unwrap();
        let value: i64 = rng.next_u64() as i64;
        value_sum += I128Sum::from_pair(asset_type, i128::from(value));
    }

    // Generate an authenticate proof
    let (proof, x_challenge, x_response, y_challenge, y_response) = authenticate_proof(
        bvk,
        binding_c,
        binding_sig,
        rks,
        spend_auths_c,
        spend_auths_sig,
        value_sum,
        MAX_ASSETS,
        &proving_key,
        &prepare_verifying_key(&proving_key.vk),
    ).expect("failed to generate authenticate proof");

    // Output the calldata
    let pi_a_g1_x = proof.a.x();
    let pi_a_g1_y = proof.a.y();
    let pi_b_g2_x_c0 = proof.b.x().c0();
    let pi_b_g2_x_c1 = proof.b.x().c1();
    let pi_b_g2_y_c0 = proof.b.y().c0();
    let pi_b_g2_y_c1 = proof.b.y().c1();
    let pi_c_g1_x = proof.c.x();
    let pi_c_g1_y = proof.c.y();
    println!(
        "[{}, {}, {}, {}], [[{}, {}, {}, {}],[{}, {}, {}, {}]], [{}, {}, {}, {}], [{}, {}, {}, {}]",
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
        to_string(x_challenge),
        to_string(x_response),
        to_string(y_challenge),
        to_string(y_response),
    );
}
