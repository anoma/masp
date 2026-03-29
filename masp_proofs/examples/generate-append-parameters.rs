use masp_proofs::circuit::append::{BATCH_SIZE, Append};
use masp_primitives::sapling::SAPLING_COMMITMENT_TREE_DEPTH;
use bellman::groth16;
use bls12_381::Bls12;
use rand_core::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let params_file = std::fs::File::create(&args[1])
        .expect("unable to open verifier parameters");
    let c = Append {
        auth_path: vec![None; SAPLING_COMMITMENT_TREE_DEPTH],
        new_cmus: vec![None; BATCH_SIZE],
        old_size: None,
    };
    let params = groth16::generate_random_parameters::<Bls12, _, _>(c, &mut OsRng)
        .expect("unable to generate random parameters for append circuit");
    params.write(params_file)?;
    Ok(())
}
