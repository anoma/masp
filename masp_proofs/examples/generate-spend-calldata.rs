use bellman::gadgets::multipack;
use bellman::groth16::Parameters;
use bellman::groth16::create_random_proof;
use bls12_381::Bls12;
use bls12_381::Fp;
use bls12_381::Scalar;
use group::Curve;
use group::{Group, ff::Field, ff::PrimeField, ff::PrimeFieldBits};
use masp_primitives::{
    asset_type::AssetType,
    sapling::pedersen_hash,
    sapling::{Diversifier, Note, ProofGenerationKey, Rseed},
};
use masp_proofs::circuit::sapling::Spend;
use rand_core::{RngCore, SeedableRng};
use rand_xorshift::XorShiftRng;

// Extract the lowest 32 bytes of the base field element
fn lo_string(fp: Fp) -> String {
    let lo = &fp.to_bytes_le()[0..32];
    format!(
        "0x{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        lo[31],
        lo[30],
        lo[29],
        lo[28],
        lo[27],
        lo[26],
        lo[25],
        lo[24],
        lo[23],
        lo[22],
        lo[21],
        lo[20],
        lo[19],
        lo[18],
        lo[17],
        lo[16],
        lo[15],
        lo[14],
        lo[13],
        lo[12],
        lo[11],
        lo[10],
        lo[9],
        lo[8],
        lo[7],
        lo[6],
        lo[5],
        lo[4],
        lo[3],
        lo[2],
        lo[1],
        lo[0]
    )
}

// Extract the highest 16 bytes of the base field element
fn hi_string(fp: Fp) -> String {
    let hi = &fp.to_bytes_le()[32..48];
    format!(
        "0x{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        hi[15],
        hi[14],
        hi[13],
        hi[12],
        hi[11],
        hi[10],
        hi[9],
        hi[8],
        hi[7],
        hi[6],
        hi[5],
        hi[4],
        hi[3],
        hi[2],
        hi[1],
        hi[0]
    )
}

// Extract the bytes of the scalar field element
fn to_string(fp: Scalar) -> String {
    let b = &fp.to_bytes_le()[0..32];
    format!(
        "0x{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[31],
        b[30],
        b[29],
        b[28],
        b[27],
        b[26],
        b[25],
        b[24],
        b[23],
        b[22],
        b[21],
        b[20],
        b[19],
        b[18],
        b[17],
        b[16],
        b[15],
        b[14],
        b[13],
        b[12],
        b[11],
        b[10],
        b[9],
        b[8],
        b[7],
        b[6],
        b[5],
        b[4],
        b[3],
        b[2],
        b[1],
        b[0]
    )
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut params_file =
        std::fs::File::open(&args[1]).expect("unable to open verifier parameters");
    let proving_key =
        Parameters::<Bls12>::read(&mut params_file, false).expect("unable to open parameters");

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x3d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let tree_depth = 32;

    let expected_commitment_us = [
        "15274760159508878651789682992925045402656388195689586056903525226511870631006",
        "17926082480702379779301751040578316677060182517930108360303758506447415843229",
        "47560733217722603616763811825500591868568811326811130069535870262273364981945",
        "3800891689291852208719409763066191375952446148569504124915840587177301316887",
        "42605451358726896269346670960800907068736580931770467343442333651979812783507",
        "2186124196248736405363923904916329765421958395459957351012037099196644523519",
        "1141914194379178008776608799121446552214386159445356778422457950073807217391",
        "4723282540978794624483635488138659467675602905263923545920612233258386488162",
        "9817985978230076566482131380463677459892992710371329861360645363311468893053",
        "27618789340710350120647137095252986938132361388195675764406370494688910938013",
    ];

    let expected_commitment_vs = [
        "34821791232396287888199995100305255761362584209078006239735148846881442279277",
        "25119990066174545608121950753413857831099772082356729649061420500567639159355",
        "37379068700729686079521798425830021519833420633231595656391703260880647751299",
        "41866535334944468208261223722134220321702695454463459117958311496151517396608",
        "22815243378235771837066051140494563507512924813701395974049305004556621752999",
        "32580943391199462206001867000285792160642911175912464838584939697793150575579",
        "19466322163466228937035549603042240330689838936758470332197790607062875140040",
        "37409705443279116387495124812424670311932220465698221026006921521796611194301",
        "4817145647901840172966045688653436033808505237142136464043537162611284452519",
        "33112537425917174283144333017659536059363113223507009786626165162100944911092",
    ];

    // b'default' under repeated hashing (different than AssetType::new)
    // hex '734f0ec56f731e02cc737e6b693db52b821f6f6e4cd7fe3c764353f263669fbe'
    let asset_type = AssetType::from_identifier(
        b"sO\x0e\xc5os\x1e\x02\xccs~ki=\xb5+\x82\x1fonL\xd7\xfe<vCS\xf2cf\x9f\xbe",
    )
    .unwrap();

    let i = 8; // i must be 0..10
    let value_commitment = asset_type.value_commitment(i, jubjub::Fr::from(1000 * (i + 1)));

    let proof_generation_key = ProofGenerationKey {
        ak: jubjub::SubgroupPoint::random(&mut rng),
        nsk: jubjub::Fr::random(&mut rng),
    };

    let viewing_key = proof_generation_key.to_viewing_key();

    let payment_address;

    loop {
        let diversifier = {
            let mut d = [0; 11];
            rng.fill_bytes(&mut d);
            Diversifier(d)
        };

        if let Some(p) = viewing_key.to_payment_address(diversifier) {
            payment_address = p;
            break;
        }
    }

    let g_d = payment_address.diversifier().g_d().unwrap();
    let commitment_randomness = jubjub::Fr::random(&mut rng);
    let auth_path =
        vec![Some((bls12_381::Scalar::random(&mut rng), rng.next_u32() % 2 != 0)); tree_depth];
    let ar = jubjub::Fr::random(&mut rng);

    {
        let rk = jubjub::ExtendedPoint::from(viewing_key.rk(ar)).to_affine();
        let expected_value_commitment =
            jubjub::ExtendedPoint::from(value_commitment.commitment()).to_affine();
        assert_eq!(
            expected_value_commitment.get_u(),
            bls12_381::Scalar::from_str_vartime(expected_commitment_us[i as usize]).unwrap()
        );
        assert_eq!(
            expected_value_commitment.get_v(),
            bls12_381::Scalar::from_str_vartime(expected_commitment_vs[i as usize]).unwrap()
        );
        let note = Note {
            asset_type,
            value: value_commitment.value,
            g_d,
            pk_d: *payment_address.pk_d(),
            rseed: Rseed::BeforeZip212(commitment_randomness),
        };

        let mut position = 0u64;
        let cmu = note.cmu();
        let mut cur = cmu;

        for (i, val) in auth_path.clone().into_iter().enumerate() {
            let (uncle, b) = val.unwrap();

            let mut lhs = cur;
            let mut rhs = uncle;

            if b {
                ::std::mem::swap(&mut lhs, &mut rhs);
            }

            let lhs = lhs.to_le_bits();
            let rhs = rhs.to_le_bits();

            cur = jubjub::ExtendedPoint::from(pedersen_hash::pedersen_hash(
                pedersen_hash::Personalization::MerkleTree(i),
                lhs.iter()
                    .by_vals()
                    .take(bls12_381::Scalar::NUM_BITS as usize)
                    .chain(
                        rhs.iter()
                            .by_vals()
                            .take(bls12_381::Scalar::NUM_BITS as usize),
                    ),
            ))
            .to_affine()
            .get_u();

            if b {
                position |= 1 << i;
            }
        }

        let expected_nf = note.nf(&viewing_key.nk, position);
        let expected_nf = multipack::bytes_to_bits_le(&expected_nf.0);
        let expected_nf: Vec<Scalar> = multipack::compute_multipacking(&expected_nf);
        assert_eq!(expected_nf.len(), 2);

        let instance = Spend {
            value_commitment: Some(value_commitment.clone()),
            proof_generation_key: Some(proof_generation_key.clone()),
            payment_address: Some(payment_address),
            commitment_randomness: Some(commitment_randomness),
            ar: Some(ar),
            auth_path: auth_path.clone(),
            anchor: Some(cur),
        };

        let proof = create_random_proof(instance, &proving_key, &mut rng)
            .expect("failed to generate spend proof");

        let pi_a_g1_x = proof.a.x();
        let pi_a_g1_y = proof.a.y();
        let pi_b_g2_x_c0 = proof.b.x().c0();
        let pi_b_g2_x_c1 = proof.b.x().c1();
        let pi_b_g2_y_c0 = proof.b.y().c0();
        let pi_b_g2_y_c1 = proof.b.y().c1();
        let pi_c_g1_x = proof.c.x();
        let pi_c_g1_y = proof.c.y();
        println!(
            "[{}, {}, {}, {}], [[{}, {}, {}, {}],[{}, {}, {}, {}]], [{}, {}, {}, {}], [{}, {}, {}, {}, {}, {}, {}]",
            hi_string(pi_a_g1_x),
            lo_string(pi_a_g1_x),
            hi_string(pi_a_g1_y),
            lo_string(pi_a_g1_y),
            hi_string(pi_b_g2_x_c1),
            lo_string(pi_b_g2_x_c1),
            hi_string(pi_b_g2_x_c0),
            lo_string(pi_b_g2_x_c0),
            hi_string(pi_b_g2_y_c1),
            lo_string(pi_b_g2_y_c1),
            hi_string(pi_b_g2_y_c0),
            lo_string(pi_b_g2_y_c0),
            hi_string(pi_c_g1_x),
            lo_string(pi_c_g1_x),
            hi_string(pi_c_g1_y),
            lo_string(pi_c_g1_y),
            to_string(rk.get_u()),
            to_string(rk.get_v()),
            to_string(
                jubjub::ExtendedPoint::from(value_commitment.commitment())
                    .to_affine()
                    .get_u()
            ),
            to_string(
                jubjub::ExtendedPoint::from(value_commitment.commitment())
                    .to_affine()
                    .get_v()
            ),
            to_string(cur),
            to_string(expected_nf[0]),
            to_string(expected_nf[1]),
        );
    }
}
