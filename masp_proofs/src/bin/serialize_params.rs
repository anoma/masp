use bls12_381::{Fp12, Fp2, Fp6, G2Prepared};

pub fn print_prepared(p: &G2Prepared) {
    assert_eq!(p.infinity.unwrap_u8(), 0u8);
    print!("G2Prepared{{ infinity: Choice::from(0u8), coeffs: vec![");

    for coeff in p.coeffs.iter() {
        print!("(");
        print_fp2(&coeff.0);
        print_fp2(&coeff.1);
        print_fp2(&coeff.2);
        print!("),");
    }
    println!("]}}")
}

pub fn print_fp12(fp12: &Fp12) {
    print!("Fp12 {{");
    for (c, fp6) in [("c0", fp12.c0), ("c1", fp12.c1)] {
        print!("{} :", c);
        print_fp6(&fp6);
    }
    print!("}},");
}

pub fn print_fp6(fp6: &Fp6) {
    print!("Fp6 {{");
    for (c, fp2) in [("c0", fp6.c0), ("c1", fp6.c1), ("c2", fp6.c2)] {
        print!("{} :", c);
        print_fp2(&fp2);
    }
    print!("}},");
}

pub fn print_fp2(fp2: &Fp2) {
    print!("Fp2 {{");
    for (c, fp) in [
        ("c0: Fp::from_raw_unchecked(", fp2.c0),
        ("c1: Fp::from_raw_unchecked(", fp2.c1),
    ] {
        print!("{}", c);
        print!("{:#04x?}", &fp.0);
        print!("),");
    }
    print!("}},");
}

fn main() {
    if let Some(path) = masp_proofs::default_params_folder() {
        if true {
            let params = masp_proofs::load_parameters(
                &path.join("masp-spend.params"),
                &path.join("masp-output.params"),
            );

            // alpha_g1_beta_g2 : Gt 48*12 bytes

            for (_, vk) in [
                ("spend_vk", params.spend_vk),
                ("output_vk", params.output_vk),
            ]
            .iter()
            {
                dbg!(vk.neg_gamma_g2.coeffs.len()); // 68 * (3 * 2 * 48 bytes) (Fp2, Fp2, Fp2)
                dbg!(vk.neg_delta_g2.coeffs.len()); // 68 * (3 * 2 * 48 bytes) (Fp2, Fp2, Fp2)
                dbg!(vk.ic.len()); // 8 * ( 96 bytes G1Affine uncompressed) for spend, 6*96 bytes for output
            }
        }
        if false {
            let params = masp_proofs::load_parameters(
                &path.join("masp-spend.params"),
                &path.join("masp-output.params"),
            );

            print!("use bellman::groth16::PreparedVerifyingKey;use bls12_381::{{Bls12,Fp, Fp12, Fp2, Fp6, G1Affine, G2Prepared, Gt}};");
            print!("use lazy_static::lazy_static;use subtle::Choice; lazy_static!{{ ");
            for (name, vk) in [
                ("spend_vk", params.spend_vk),
                ("output_vk", params.output_vk),
            ]
            .iter()
            {
                print!(
                    "pub static ref {} : PreparedVerifyingKey<Bls12> = PreparedVerifyingKey::<Bls12> {{",
                    name
                );

                print!("alpha_g1_beta_g2 : Gt(");
                print_fp12(&vk.alpha_g1_beta_g2.0);
                println!("),");

                print!("neg_gamma_g2 : ");
                print_prepared(&vk.neg_gamma_g2);
                print!(",");

                print!("neg_delta_g2 : ");
                print_prepared(&vk.neg_delta_g2);
                print!(",");

                print!("ic : vec![");

                for g in vk.ic.iter() {
                    print!("G1Affine::from_uncompressed_unchecked(&");
                    print!("{:#04x?}", g.to_uncompressed());
                    print!(").unwrap(),");
                }
                print!("],}};")
            }
            println!("}}");
        }
        /*
        if true {
            let params = masp_proofs::load_parameters(
                &path.join("masp-spend.params"),
                &path.join("masp-output.params"),
            );
            assert_eq!(
                masp_proofs::sapling::params::spend_vk.alpha_g1_beta_g2,
                params.spend_vk.alpha_g1_beta_g2
            );
            assert_eq!(
                masp_proofs::sapling::params::output_vk.alpha_g1_beta_g2,
                params.output_vk.alpha_g1_beta_g2
            );

            assert_eq!(
                masp_proofs::sapling::params::spend_vk.neg_gamma_g2.coeffs,
                params.spend_vk.neg_gamma_g2.coeffs
            );
            assert_eq!(
                masp_proofs::sapling::params::output_vk.neg_gamma_g2.coeffs,
                params.output_vk.neg_gamma_g2.coeffs
            );

            assert_eq!(
                masp_proofs::sapling::params::spend_vk.neg_delta_g2.coeffs,
                params.spend_vk.neg_delta_g2.coeffs
            );
            assert_eq!(
                masp_proofs::sapling::params::output_vk.neg_delta_g2.coeffs,
                params.output_vk.neg_delta_g2.coeffs
            );

            assert_eq!(
                masp_proofs::sapling::params::spend_vk.ic,
                params.spend_vk.ic
            );
            assert_eq!(
                masp_proofs::sapling::params::output_vk.ic,
                params.output_vk.ic
            );
        }*/
    }
}
