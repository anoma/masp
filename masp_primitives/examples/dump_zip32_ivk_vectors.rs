use masp_primitives::zip32::{ChildIndex, ExtendedFullViewingKey, ExtendedSpendingKey};

fn main() {
    let seed = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ];

    let i1 = ChildIndex::NonHardened(1);
    let i2h = ChildIndex::Hardened(2);
    let i3 = ChildIndex::NonHardened(3);

    let m = ExtendedSpendingKey::master(&seed);
    let m_1 = m.derive_child(i1);
    let m_1_2h = ExtendedSpendingKey::from_path(&m, &[i1, i2h]);
    let m_1_2hv = ExtendedFullViewingKey::from(&m_1_2h);
    let m_1_2hv_3 = m_1_2hv.derive_child(i3).unwrap();

    let xfvks = [
        ExtendedFullViewingKey::from(&m),
        ExtendedFullViewingKey::from(&m_1),
        ExtendedFullViewingKey::from(&m_1_2h),
        m_1_2hv,
        m_1_2hv_3,
    ];

    println!("[");
    for (i, xfvk) in xfvks.iter().enumerate() {
        let internal = xfvk.derive_internal();
        let comma = if i + 1 == xfvks.len() { "" } else { "," };
        println!(
            "  {{\"ivk\":\"{}\",\"internal_ivk\":\"{}\"}}{}",
            hex::encode(xfvk.fvk.vk.ivk().to_repr()),
            hex::encode(internal.fvk.vk.ivk().to_repr()),
            comma,
        );
    }
    println!("]");
}
