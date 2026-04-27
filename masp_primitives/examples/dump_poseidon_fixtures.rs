use ff::{Field, PrimeField};
use group::GroupEncoding;
use masp_primitives::{
    asset_type::AssetType,
    consensus::{NetworkUpgrade, Parameters, TEST_NETWORK, TestNetwork},
    memo::MemoBytes,
    sapling::{
        Diversifier, SaplingIvk,
        note_encryption::{
            PreparedIncomingViewingKey, sapling_note_encryption, try_sapling_note_decryption,
            try_sapling_output_recovery,
        },
        util::generate_random_rseed,
    },
    transaction::components::{GROTH_PROOF_SIZE, sapling::OutputDescription},
};
use rand::{SeedableRng, rngs::StdRng};
use rand_core::RngCore;

fn hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn main() {
    let mut roots = Vec::new();
    for i in 0..=32u8 {
        let root = <masp_primitives::sapling::Node as incrementalmerkletree::Hashable>::empty_root(
            i.into(),
        );
        roots.push(hex(root.as_ref()));
    }

    let mut parent_cases = Vec::new();
    for (depth, (left_idx, right_idx)) in [
        (0usize, (0usize, 0usize)),
        (1, (1, 1)),
        (5, (4, 5)),
        (12, (10, 11)),
        (31, (30, 31)),
    ] {
        let left_hex = roots[left_idx].clone();
        let right_hex = roots[right_idx].clone();
        let left =
            bls12_381::Scalar::from_repr(hex::decode(&left_hex).unwrap().try_into().unwrap())
                .unwrap();
        let right =
            bls12_381::Scalar::from_repr(hex::decode(&right_hex).unwrap().try_into().unwrap())
                .unwrap();
        let result = masp_primitives::sapling::poseidon_hash::merkle_hash(depth, left, right);
        parent_cases.push((depth, left_hex, right_hex, hex(&result.to_repr())));
    }

    let mut rng = StdRng::seed_from_u64(0x5862be3d763d318d);

    let mut vectors = Vec::new();
    for i in 0..3u64 {
        let ivk = SaplingIvk(jubjub::Fr::random(&mut rng));
        let ovk = masp_primitives::keys::OutgoingViewingKey({
            let mut v = [0u8; 32];
            rng.fill_bytes(&mut v);
            v
        });
        let diversifier = Diversifier([10u8; 11]);
        let pk_d = diversifier.g_d().unwrap() * ivk.0;
        let to = masp_primitives::sapling::PaymentAddress::from_parts(diversifier, pk_d).unwrap();

        let value = (i + 1) * 100;
        let height = TEST_NETWORK
            .activation_height(NetworkUpgrade::MASP)
            .unwrap();
        let rseed = generate_random_rseed(&TEST_NETWORK, height, &mut rng);
        let asset_type = AssetType::new(b"poseidon-fixture").unwrap();
        let note = to.create_note(asset_type, value, rseed).unwrap();
        let cmu = note.cmu();
        let cv = asset_type.value_commitment(value, jubjub::Fr::random(&mut rng));

        let enc = sapling_note_encryption::<TestNetwork>(Some(ovk), note, to, MemoBytes::empty());
        let enc_ciphertext = enc.encrypt_note_plaintext();
        let out_ciphertext =
            enc.encrypt_outgoing_plaintext(&cv.commitment().into(), &cmu, &mut rng);

        let output = OutputDescription {
            cv: cv.commitment().into(),
            cmu,
            ephemeral_key: enc.epk().to_bytes().into(),
            enc_ciphertext,
            out_ciphertext,
            zkproof: [0u8; GROTH_PROOF_SIZE],
        };

        let dec = try_sapling_note_decryption(
            &TEST_NETWORK,
            height,
            &PreparedIncomingViewingKey::new(&ivk),
            &output,
        )
        .unwrap();
        let rec = try_sapling_output_recovery(&TEST_NETWORK, height, &ovk, &output).unwrap();
        assert_eq!(dec.0.cmu(), note.cmu());
        assert_eq!(rec.0.cmu(), note.cmu());

        vectors.push((
            hex(&ovk.0),
            hex(&ivk.to_repr()),
            hex(&to.to_bytes()),
            value,
            hex(&note.rcm().to_bytes()),
            hex(&output.cv.to_bytes()),
            hex(&cmu.to_repr()),
            hex(output.ephemeral_key.as_ref()),
            hex(&output.enc_ciphertext),
            hex(&output.out_ciphertext),
        ));
    }

    println!("{{\n  \"empty_roots\": [");
    for (i, root) in roots.iter().enumerate() {
        let comma = if i + 1 == roots.len() { "" } else { "," };
        println!("    \"{}\"{}", root, comma);
    }
    println!("  ],");
    println!("  \"parent_cases\": [");
    for (i, (depth, left, right, result)) in parent_cases.iter().enumerate() {
        println!(
            "    {{\"depth\":{},\"left\":\"{}\",\"right\":\"{}\",\"result\":\"{}\"}}{}",
            depth,
            left,
            right,
            result,
            if i + 1 == parent_cases.len() { "" } else { "," },
        );
    }
    println!("  ],");
    println!("  \"note_vectors\": [");
    for (idx, v) in vectors.iter().enumerate() {
        println!(
            "    {{\"ovk\":\"{}\",\"ivk\":\"{}\",\"to\":\"{}\",\"value\":{},\"rcm\":\"{}\",\"cv\":\"{}\",\"cmu\":\"{}\",\"epk\":\"{}\",\"enc_ciphertext\":\"{}\",\"out_ciphertext\":\"{}\"}}{}",
            v.0,
            v.1,
            v.2,
            v.3,
            v.4,
            v.5,
            v.6,
            v.7,
            v.8,
            v.9,
            if idx + 1 == vectors.len() { "" } else { "," },
        );
    }
    println!("  ]\n}}");
}
