use bellman::groth16::VerifyingKey;
use bls12_381::Bls12;
use lazy_static::lazy_static;

lazy_static! {
    pub static ref SPEND_VK: VerifyingKey::<Bls12> =
        VerifyingKey::<Bls12>::read(&include_bytes!("../params/masp-spend.vk")[..]).unwrap();
    pub static ref OUTPUT_VK: VerifyingKey::<Bls12> =
        VerifyingKey::<Bls12>::read(&include_bytes!("../params/masp-output.vk")[..])
            .unwrap();
    pub static ref CONVERT_VK: VerifyingKey::<Bls12> =
        VerifyingKey::<Bls12>::read(&include_bytes!("../params/masp-convert.vk")[..])
            .unwrap();
}

#[cfg(feature = "download-params")]
#[test]
fn test_serialization() {
    // Download params first
    #[cfg(feature = "download-params")]
    crate::download_masp_parameters(None).unwrap();

    if let Some(path) = crate::default_params_folder() {
        let params = crate::load_parameters(
            &path.join("masp-spend.params"),
            &path.join("masp-output.params"),
            &path.join("masp-convert.params"),
        );
        assert_eq!(SPEND_VK.alpha_g1, params.spend_params.vk.alpha_g1);
        assert_eq!(OUTPUT_VK.alpha_g1, params.output_params.vk.alpha_g1);
        assert_eq!(CONVERT_VK.alpha_g1, params.convert_params.vk.alpha_g1);

        assert_eq!(SPEND_VK.beta_g1, params.spend_params.vk.beta_g1);
        assert_eq!(OUTPUT_VK.beta_g1, params.output_params.vk.beta_g1);
        assert_eq!(CONVERT_VK.beta_g1, params.convert_params.vk.beta_g1);

        assert_eq!(SPEND_VK.beta_g2, params.spend_params.vk.beta_g2);
        assert_eq!(OUTPUT_VK.beta_g2, params.output_params.vk.beta_g2);
        assert_eq!(CONVERT_VK.beta_g2, params.convert_params.vk.beta_g2);

        assert_eq!(SPEND_VK.gamma_g2, params.spend_params.vk.gamma_g2);
        assert_eq!(OUTPUT_VK.gamma_g2, params.output_params.vk.gamma_g2);
        assert_eq!(CONVERT_VK.gamma_g2, params.convert_params.vk.gamma_g2);

        assert_eq!(SPEND_VK.delta_g1, params.spend_params.vk.delta_g1);
        assert_eq!(OUTPUT_VK.delta_g1, params.output_params.vk.delta_g1);
        assert_eq!(CONVERT_VK.delta_g1, params.convert_params.vk.delta_g1);

        assert_eq!(SPEND_VK.delta_g2, params.spend_params.vk.delta_g2);
        assert_eq!(OUTPUT_VK.delta_g2, params.output_params.vk.delta_g2);
        assert_eq!(CONVERT_VK.delta_g2, params.convert_params.vk.delta_g2);

        assert_eq!(SPEND_VK.ic, params.spend_params.vk.ic);
        assert_eq!(OUTPUT_VK.ic, params.output_params.vk.ic);
        assert_eq!(CONVERT_VK.ic, params.convert_params.vk.ic);
    }
}
