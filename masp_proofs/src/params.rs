use bellman::groth16::VerifyingKey;
use bls12_381::Bls12;
use lazy_static::lazy_static;

lazy_static! {
    pub static ref spend_vk: VerifyingKey::<Bls12> =
        VerifyingKey::<Bls12>::read(&include_bytes!("params/spend_TESTING_vk.params")[..]).unwrap();
    pub static ref output_vk: VerifyingKey::<Bls12> =
        VerifyingKey::<Bls12>::read(&include_bytes!("params/output_TESTING_vk.params")[..])
            .unwrap();
}
