use std::io::Write;

fn main() {
    // Download params first
    masp_proofs::download_parameters().unwrap();

    if let Some(path) = masp_proofs::default_params_folder() {
        let params = masp_proofs::load_parameters(
            &path.join("masp-spend.params"),
            &path.join("masp-output.params"),
        );

        for (filename, vk) in [
            ("spend_TESTING_vk.params", params.spend_params.vk),
            ("output_TESTING_vk.params", params.output_params.vk),
        ]
        .iter()
        {
            let mut bytes = vec![];
            vk.write(&mut bytes).unwrap();
            let mut file = std::fs::File::create(filename)
                .unwrap_or_else(|err| panic!("cannot create {} with {}", filename, err));
            file.write_all(&bytes).unwrap();
        }
    }
}
