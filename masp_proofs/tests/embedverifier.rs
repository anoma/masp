use bellman::groth16::prepare_verifying_key;
use bellman::groth16::VerifyingKey;
use bls12_381::Bls12;
use wasm_bindgen_test::*;
use web_sys::console;

wasm_bindgen_test_configure!(run_in_browser);

/*
How to run the bench:

```
cd masp_proof
wasm-pack test --headless --chrome --features="serialize-params embed-verifying-key" --release
```

*/

#[wasm_bindgen_test]
fn bench_embedverifier_full() {
    // Set bench time to 20s
    let run_time = 20.0;

    let spend_vk_bytes = include_bytes!("../src/params/spend_TESTING_vk.params");
    let output_vk_bytes = include_bytes!("../src/params/output_TESTING_vk.params");

    let bench_result = easybench_wasm::bench_limit(run_time, || {
        // Load spend_vk from binary
        let spend_vk: VerifyingKey<Bls12> =
            VerifyingKey::<Bls12>::read(&spend_vk_bytes[..]).unwrap();

        // Prepare spend_vk
        let _prepared_spend_vk = prepare_verifying_key(&spend_vk);

        // Load output_vk from binary
        let output_vk: VerifyingKey<Bls12> =
            VerifyingKey::<Bls12>::read(&output_vk_bytes[..]).unwrap();

        // Prepare output_vk
        let _prepared_output_vk = prepare_verifying_key(&output_vk);
    });
    console::log_1(&format!("bench_embedverifier full:        {}", bench_result).into());
}

#[wasm_bindgen_test]
fn bench_embedverifier_load() {
    // Set bench time to 20s
    let run_time = 20.0;

    let spend_vk_bytes = include_bytes!("../src/params/spend_TESTING_vk.params");
    let output_vk_bytes = include_bytes!("../src/params/output_TESTING_vk.params");

    let bench_result = easybench_wasm::bench_limit(run_time, || {
        // Load spend_vk from binary
        let _spend_vk: VerifyingKey<Bls12> =
            VerifyingKey::<Bls12>::read(&spend_vk_bytes[..]).unwrap();

        // Load output_vk from binary
        let _output_vk: VerifyingKey<Bls12> =
            VerifyingKey::<Bls12>::read(&output_vk_bytes[..]).unwrap();
    });
    console::log_1(&format!("bench_embedverifier load:        {}", bench_result).into());
}

#[wasm_bindgen_test]
fn bench_embedverifier_prepare() {
    // Set bench time to 20s
    let run_time = 20.0;

    // Load spend_vk
    let spend_vk: VerifyingKey<Bls12> =
        VerifyingKey::<Bls12>::read(&include_bytes!("../src/params/spend_TESTING_vk.params")[..])
            .unwrap();

    // Load output_vk
    let output_vk: VerifyingKey<Bls12> =
        VerifyingKey::<Bls12>::read(&include_bytes!("../src/params/output_TESTING_vk.params")[..])
            .unwrap();

    let bench_result = easybench_wasm::bench_limit(run_time, || {
        // Prepare spend_vk
        let _prepared_spend_vk = prepare_verifying_key(&spend_vk);

        // Prepare output_vk
        let _prepared_output_vk = prepare_verifying_key(&output_vk);
    });
    console::log_1(&format!("bench_embedverifier prepare:        {}", bench_result).into());
}
