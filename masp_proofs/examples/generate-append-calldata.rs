use bellman::groth16::Parameters;
use bellman::groth16::create_random_proof;
use bls12_381::Bls12;
use bls12_381::Fp;
use bls12_381::Scalar;
use group::ff::Field;
use masp_primitives::merkle_tree::FrozenCommitmentTree;
use masp_primitives::sapling::Node;
use masp_proofs::circuit::append::Append;
use masp_proofs::circuit::append::BATCH_SIZE;

use rand_core::SeedableRng;
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

    let i = 53;
    let mut leaves = vec![];

    for _j in 0..i {
        leaves.push(Node::from_scalar(bls12_381::Scalar::random(&mut rng)));
    }
    let old_tree = FrozenCommitmentTree::new(&leaves);
    let old_root = old_tree.root();
    let old_size = leaves.len();
    let old_size_scalar = bls12_381::Scalar::from(old_size as u64);
    let auth_path = old_tree.path(leaves.len());
    for _j in 0..BATCH_SIZE {
        leaves.push(Node::from_scalar(bls12_381::Scalar::random(&mut rng)));
    }
    let new_tree = FrozenCommitmentTree::new(&leaves);
    let new_root = new_tree.root();

    let auth_path: Vec<_> = auth_path
        .auth_path
        .iter()
        .map(|x| Some(bls12_381::Scalar::from(x.0)))
        .collect();
    let k = i as usize;

    let instance = Append {
        old_size: Some(old_size_scalar),
        auth_path: auth_path.clone(),
        new_cmus: leaves[k..(k + BATCH_SIZE)]
            .iter()
            .map(|x| Some(bls12_381::Scalar::from(*x)))
            .collect(),
    };

    let proof = create_random_proof(instance, &proving_key, &mut rng)
        .expect("failed to generate spend proof");

    let mut response = bls12_381::Scalar::ZERO;
    for m in (0..BATCH_SIZE).rev() {
        response *= bls12_381::Scalar::from(new_root);
        response += bls12_381::Scalar::from(leaves[old_size + m]);
    }

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
        to_string(old_size_scalar),
        to_string(bls12_381::Scalar::from(old_root)),
        to_string(bls12_381::Scalar::from(new_root)),
        to_string(response),
    );
}
