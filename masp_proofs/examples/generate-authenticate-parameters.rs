use bellman::groth16;
use bls12_381::Bls12;
use masp_proofs::circuit::authenticate::{Authenticate, MAX_ASSETS};
use rand_core::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let params_file = std::fs::File::create(&args[1]).expect("unable to open verifier parameters");
    let c = Authenticate {
        bvk: None,
        rks: None,
        binding_c: None,
        spend_auths_c: None,
        binding_sig: None,
        spend_auths_sig: None,
        value_balance: vec![(None, None); MAX_ASSETS],
    };
    let params = groth16::generate_random_parameters::<Bls12, _, _>(c, &mut OsRng)
        .expect("unable to generate random parameters for authenticate circuit");
    params.write(params_file)?;
    Ok(())
}
