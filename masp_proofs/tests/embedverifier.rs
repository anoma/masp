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
fn bench_embedverifier() {
    // Set bench time to 100s
    let run_time = 100.0;

    let bench_result = easybench_wasm::bench_limit(run_time, || {
        // Load spend_vk
        let spend_vk: VerifyingKey<Bls12> = VerifyingKey::<Bls12>::read(
            &include_bytes!("../src/params/spend_TESTING_vk.params")[..],
        )
        .unwrap();

        // Prepare spend_vk
        let _prepared_spend_vk = prepare_verifying_key(&spend_vk);

        // Load output_vk
        let output_vk: VerifyingKey<Bls12> = VerifyingKey::<Bls12>::read(
            &include_bytes!("../src/params/output_TESTING_vk.params")[..],
        )
        .unwrap();

        // Prepare output_vk
        let _prepared_output_vk = prepare_verifying_key(&output_vk);
    });
    console::log_1(&format!("bench_embedverifier:        {}", bench_result).into());
}
