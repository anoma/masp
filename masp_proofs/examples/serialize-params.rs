use std::io::Write;

fn main() {
    // Download params first
    #[cfg(feature = "download-params")]
    masp_proofs::download_masp_parameters(None).unwrap();

    if let Some(path) = masp_proofs::default_params_folder() {
        let params = masp_proofs::load_parameters(
            &path.join("masp-spend.params"),
            &path.join("masp-output.params"),
            &path.join("masp-convert.params"),
        );

        for (filename, vk) in [
            ("masp-spend.vk", params.spend_params.vk),
            ("masp-output.vk", params.output_params.vk),
            ("masp-convert.vk", params.convert_params.vk),
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
