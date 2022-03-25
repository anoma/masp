use std::io::Write;

fn main() {
    if false {
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
    #[cfg(feature = "embed-verifying-key")]
    {
        test_serialization();
        println!("Embedded verifying key passed test");
    }
}

// TODO: waiting to fix other tests
//#[cfg(feature = "embed-verifying-key")]
//#[test]
fn test_serialization() {
    if let Some(path) = masp_proofs::default_params_folder() {
        let params = masp_proofs::load_parameters(
            &path.join("masp-spend.params"),
            &path.join("masp-output.params"),
        );
        assert_eq!(
            masp_proofs::params::spend_vk.alpha_g1,
            params.spend_params.vk.alpha_g1
        );
        assert_eq!(
            masp_proofs::params::output_vk.alpha_g1,
            params.output_params.vk.alpha_g1
        );

        assert_eq!(
            masp_proofs::params::spend_vk.beta_g1,
            params.spend_params.vk.beta_g1
        );
        assert_eq!(
            masp_proofs::params::output_vk.beta_g1,
            params.output_params.vk.beta_g1
        );

        assert_eq!(
            masp_proofs::params::spend_vk.beta_g2,
            params.spend_params.vk.beta_g2
        );
        assert_eq!(
            masp_proofs::params::output_vk.beta_g2,
            params.output_params.vk.beta_g2
        );

        assert_eq!(
            masp_proofs::params::spend_vk.gamma_g2,
            params.spend_params.vk.gamma_g2
        );
        assert_eq!(
            masp_proofs::params::output_vk.gamma_g2,
            params.output_params.vk.gamma_g2
        );

        assert_eq!(
            masp_proofs::params::spend_vk.delta_g1,
            params.spend_params.vk.delta_g1
        );
        assert_eq!(
            masp_proofs::params::output_vk.delta_g1,
            params.output_params.vk.delta_g1
        );

        assert_eq!(
            masp_proofs::params::spend_vk.delta_g2,
            params.spend_params.vk.delta_g2
        );
        assert_eq!(
            masp_proofs::params::output_vk.delta_g2,
            params.output_params.vk.delta_g2
        );

        assert_eq!(masp_proofs::params::spend_vk.ic, params.spend_params.vk.ic);
        assert_eq!(
            masp_proofs::params::output_vk.ic,
            params.output_params.vk.ic
        );
    }
}
