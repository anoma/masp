use bellman::gadgets::multipack;
use masp_proofs::circuit::sapling::Output;
use group::Curve;
use bellman::ConstraintSystem;
use bellman::Circuit;
use bellman::groth16::create_random_proof;
use bls12_381::Bls12;
use bellman::groth16::Parameters;
use bls12_381::Fp;
use bls12_381::Scalar;
use masp_primitives::transaction::components::ValueSum;
use masp_proofs::circuit::convert::Convert;
use masp_primitives::convert::AllowedConversion;
use masp_proofs::circuit::append::BATCH_SIZE;
use masp_proofs::circuit::append::Append;
use masp_primitives::merkle_tree::FrozenCommitmentTree;
use masp_primitives::sapling::Node;

// Extract the lowest 32 bytes of the base field element
fn lo_string(fp: Fp) -> String {
    let lo = &fp.to_bytes_le()[0..32];
    format!("0x{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}", lo[31], lo[30], lo[29], lo[28], lo[27], lo[26], lo[25], lo[24], lo[23], lo[22], lo[21], lo[20], lo[19], lo[18], lo[17], lo[16], lo[15], lo[14], lo[13], lo[12], lo[11], lo[10], lo[9], lo[8], lo[7], lo[6], lo[5], lo[4], lo[3], lo[2], lo[1], lo[0])
}

// Extract the highest 16 bytes of the base field element
fn hi_string(fp: Fp) -> String {
    let hi = &fp.to_bytes_le()[32..48];
    format!("0x{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}", hi[15], hi[14], hi[13], hi[12], hi[11], hi[10], hi[9], hi[8], hi[7], hi[6], hi[5], hi[4], hi[3], hi[2], hi[1], hi[0])
}

// Extract the bytes of the scalar field element
fn to_string(fp: Scalar) -> String {
    let b = &fp.to_bytes_le()[0..32];
    format!("0x{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}", b[31], b[30], b[29], b[28], b[27], b[26], b[25], b[24], b[23], b[22], b[21], b[20], b[19], b[18], b[17], b[16], b[15], b[14], b[13], b[12], b[11], b[10], b[9], b[8], b[7], b[6], b[5], b[4], b[3], b[2], b[1], b[0])
}

fn main() {
    use bellman::gadgets::test::*;
    use group::{Group, ff::Field, ff::PrimeField, ff::PrimeFieldBits};
    use masp_primitives::{
        asset_type::AssetType,
        sapling::pedersen_hash,
        sapling::{Diversifier, Note, ProofGenerationKey, Rseed},
    };
    use rand_core::{RngCore, SeedableRng};
    use rand_xorshift::XorShiftRng;

    let args: Vec<String> = std::env::args().collect();
    let mut params_file = std::fs::File::open(&args[1])
        .expect("unable to open verifier parameters");
    let proving_key = Parameters::<Bls12>::read(&mut params_file, false)
        .expect("unable to open parameters");

    let mut rng = XorShiftRng::from_seed([
        0x58, 0x62, 0xbe, 0x3d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let i = 53;
    let commitment_randomness = jubjub::Fr::random(&mut rng);
    let mut leaves = vec![];

    for j in 0..i {
        leaves.push(Node::from_scalar(bls12_381::Scalar::random(&mut rng)));
    }
    let old_tree = FrozenCommitmentTree::new(&leaves);
    let old_root = old_tree.root();
    let old_size = leaves.len();
    let old_size_scalar = bls12_381::Scalar::from(old_size as u64);
    let auth_path = old_tree.path(leaves.len());
    for j in 0..BATCH_SIZE {
        leaves.push(Node::from_scalar(bls12_381::Scalar::random(&mut rng)));
    }
    let new_tree = FrozenCommitmentTree::new(&leaves);
    let new_root = new_tree.root();

    let auth_path: Vec<_> = auth_path.auth_path.iter().map(|x| Some(bls12_381::Scalar::from(x.0))).collect();
    let k = i as usize;

    let instance = Append {
        old_size: Some(old_size_scalar),
        auth_path: auth_path.clone(),
        new_cmus: leaves[k..(k+BATCH_SIZE)].iter().map(|x| Some(bls12_381::Scalar::from(*x))).collect(),
    };

    let proof = create_random_proof(instance, &proving_key, &mut rng)
        .expect("failed to generate spend proof");

    let mut response = bls12_381::Scalar::ZERO;
    for m in (0..BATCH_SIZE).rev() {
        response *= bls12_381::Scalar::from(new_root);
        response += bls12_381::Scalar::from(leaves[old_size+m]);
    }

    let pi_a_g1_x = proof.a.x();
    let pi_a_g1_y = proof.a.y();
    let pi_b_g2_x_c0 = proof.b.x().c0();
    let pi_b_g2_x_c1 = proof.b.x().c1();
    let pi_b_g2_y_c0 = proof.b.y().c0();
    let pi_b_g2_y_c1 = proof.b.y().c1();
    let pi_c_g1_x = proof.c.x();
    let pi_c_g1_y = proof.c.y();
    println!("[{}, {}, {}, {}], [[{}, {}, {}, {}],[{}, {}, {}, {}]], [{}, {}, {}, {}], [{}, {}, {}, {}]",
             hi_string(pi_a_g1_x), lo_string(pi_a_g1_x), hi_string(pi_a_g1_y), lo_string(pi_a_g1_y),
             hi_string(pi_b_g2_x_c1), lo_string(pi_b_g2_x_c1), hi_string(pi_b_g2_x_c0), lo_string(pi_b_g2_x_c0),
             hi_string(pi_b_g2_y_c1), lo_string(pi_b_g2_y_c1), hi_string(pi_b_g2_y_c0), lo_string(pi_b_g2_y_c0),
             hi_string(pi_c_g1_x), lo_string(pi_c_g1_x), hi_string(pi_c_g1_y), lo_string(pi_c_g1_y),
             to_string(old_size_scalar), to_string(bls12_381::Scalar::from(old_root)), to_string(bls12_381::Scalar::from(new_root)),
             to_string(response),
    );
}
