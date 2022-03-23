fn main() {
    if let Some(path) = masp_proofs::default_params_folder() {
        let params = masp_proofs::load_parameters(
            &path.join("masp-spend.params"),
            &path.join("masp-output.params"),
        );

        for vk in [params.spend_params, params.output_params].iter() {
            dbg!(vk.alpha_g1_beta_g2);
            dbg!(vk.neg_gamma_g2.coeffs);
            dbg!(vk.neg_delta_g2.coeffs);
            dbg!(vk.ic);
        }
    }
}
