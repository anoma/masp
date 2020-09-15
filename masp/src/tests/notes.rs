use crate::libmasp_sapling_compute_cmu;
use crate::libmasp_sapling_compute_nf;

#[test]
fn notes() {
    #![allow(dead_code)]
    struct TestVector {
        sk: [u8; 32],
        ask: [u8; 32],
        nsk: [u8; 32],
        ovk: [u8; 32],
        ak: [u8; 32],
        nk: [u8; 32],
        ivk: [u8; 32],
        default_d: [u8; 11],
        default_pk_d: [u8; 32],
        note_v: u64,
        note_r: [u8; 32],
        note_cm: [u8; 32],
        note_pos: u64,
        note_nf: [u8; 32],
    };

    // From https://github.com/zcash-hackworks/zcash-test-vectors/blob/master/sapling_key_components.py
    let test_vectors = vec![
        TestVector {
            sk: [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ],
            ask: [
                0x3a, 0xc8, 0x4c, 0x16, 0x60, 0x46, 0x8d, 0x8c, 0x48, 0xae, 0xec, 0x37, 0x05, 0xc4,
                0x4a, 0x5c, 0xa5, 0x0d, 0xce, 0xe9, 0x2f, 0x87, 0xf2, 0x7a, 0x8f, 0x87, 0x2e, 0xfa,
                0x84, 0x05, 0x22, 0x03,
            ],
            nsk: [
                0xbf, 0x80, 0xaa, 0x5f, 0xb7, 0x70, 0x74, 0x02, 0xb0, 0x09, 0xd4, 0x31, 0xee, 0x10,
                0xc7, 0x7d, 0x80, 0xf6, 0xdb, 0x0a, 0x55, 0x2a, 0xda, 0x06, 0xa3, 0x84, 0x17, 0xed,
                0x8c, 0x40, 0x3b, 0x01,
            ],
            ovk: [
                0x52, 0xac, 0x15, 0x88, 0x17, 0x5f, 0x5a, 0x5e, 0x97, 0x94, 0xe6, 0xdd, 0xb8, 0x53,
                0x63, 0x61, 0x63, 0xc1, 0x3f, 0x91, 0x5d, 0x76, 0x08, 0x9d, 0x20, 0xde, 0x9f, 0x32,
                0x05, 0xf0, 0x18, 0x5c,
            ],
            ak: [
                0x9a, 0x3d, 0xe9, 0x6f, 0x83, 0x2c, 0xd0, 0xd9, 0x04, 0x59, 0x39, 0xbb, 0xb5, 0x54,
                0x89, 0xf2, 0xef, 0x44, 0xf0, 0x16, 0x3f, 0x04, 0xe0, 0x9c, 0x2b, 0x0a, 0x5a, 0x79,
                0xa2, 0x33, 0xe8, 0x0b,
            ],
            nk: [
                0xe0, 0x8a, 0x89, 0x6e, 0x27, 0xd9, 0xda, 0x48, 0x24, 0xc4, 0xbc, 0xa4, 0xe3, 0x68,
                0xa3, 0xaf, 0x10, 0x86, 0x8f, 0x7e, 0x26, 0x65, 0xe7, 0xba, 0x6a, 0xab, 0x77, 0x86,
                0xa7, 0x51, 0x35, 0xbe,
            ],
            ivk: [
                0xbc, 0xc2, 0x5a, 0x9b, 0xf1, 0x42, 0xff, 0x98, 0x79, 0x67, 0x96, 0xea, 0xa1, 0xbc,
                0xd5, 0xff, 0xb7, 0x28, 0xb3, 0x65, 0x0f, 0xf0, 0x49, 0x4a, 0x17, 0x02, 0x7d, 0xee,
                0x93, 0x06, 0x6f, 0x02,
            ],
            default_d: [
                0x84, 0x4f, 0x9a, 0x4b, 0x31, 0x8b, 0x71, 0x39, 0xab, 0x60, 0x56,
            ],
            default_pk_d: [
                0x47, 0xd2, 0x3d, 0x02, 0xa8, 0x0a, 0x28, 0xaf, 0xc0, 0xd2, 0xc5, 0xfc, 0x57, 0xbd,
                0x30, 0x1b, 0xb3, 0x99, 0xf8, 0x26, 0xb2, 0xca, 0xba, 0x6b, 0x62, 0x88, 0x36, 0x77,
                0x23, 0x29, 0x4a, 0x64,
            ],
            note_v: 0,
            note_r: [
                0x39, 0x17, 0x6d, 0xac, 0x39, 0xac, 0xe4, 0x98, 0x0e, 0xcc, 0x8d, 0x77, 0x8e, 0x89,
                0x86, 0x02, 0x55, 0xec, 0x36, 0x15, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ],
            note_cm: [
                0x13, 0x82, 0x30, 0x27, 0x1b, 0x0e, 0x24, 0x6f, 0x31, 0xec, 0x61, 0xa7, 0x6d, 0xbf,
                0xe1, 0xaa, 0x38, 0x69, 0x0b, 0x3a, 0xc2, 0x06, 0xab, 0xb3, 0x09, 0x1c, 0xa4, 0x40,
                0x80, 0x6e, 0xfa, 0x51,
            ],
            note_pos: 0,
            note_nf: [
                0x27, 0x13, 0xac, 0x19, 0xdb, 0x77, 0xf4, 0x55, 0x69, 0x99, 0x37, 0x7c, 0xfc, 0x16,
                0x7c, 0x6f, 0xbd, 0xd7, 0xd4, 0x6e, 0xa1, 0xa9, 0x20, 0xaa, 0x2f, 0x2e, 0xaf, 0x22,
                0xc9, 0x08, 0xbe, 0xac,
            ],
        },
        TestVector {
            sk: [
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01,
            ],
            ask: [
                0x7b, 0x3f, 0xea, 0x38, 0xed, 0x11, 0x83, 0x2c, 0x89, 0xfe, 0xb6, 0x71, 0xad, 0xa5,
                0x27, 0xac, 0x5d, 0xd3, 0xf6, 0x03, 0xf5, 0xaf, 0x0d, 0xbe, 0x9d, 0xac, 0x54, 0x34,
                0xc7, 0x4d, 0x46, 0x06,
            ],
            nsk: [
                0x01, 0x81, 0x64, 0xdb, 0x4a, 0xc8, 0x7d, 0xc9, 0x4e, 0xef, 0xea, 0x33, 0x28, 0xc9,
                0x2e, 0x71, 0x79, 0x27, 0xaa, 0x37, 0xc1, 0xa7, 0x59, 0xeb, 0xcb, 0xe0, 0x5b, 0x81,
                0xdc, 0x04, 0x7a, 0x05,
            ],
            ovk: [
                0x38, 0x2e, 0x85, 0xa6, 0x11, 0x09, 0xb0, 0x8a, 0x35, 0x88, 0xe0, 0x97, 0xa1, 0xe4,
                0x87, 0xbe, 0x9b, 0x49, 0xc1, 0x8c, 0x9d, 0x3b, 0x70, 0xb5, 0x57, 0xd3, 0x77, 0x8e,
                0xe3, 0xf1, 0x28, 0x44,
            ],
            ak: [
                0xd9, 0x39, 0x6b, 0x90, 0xa4, 0xb4, 0xd3, 0xa3, 0xd6, 0x71, 0xaf, 0x3c, 0xef, 0xe8,
                0x83, 0x10, 0xc0, 0xbf, 0x9d, 0x56, 0x3c, 0xe2, 0x11, 0xb1, 0x2d, 0x6b, 0xdc, 0xc3,
                0x6b, 0x25, 0x68, 0xda,
            ],
            nk: [
                0x34, 0x43, 0xac, 0x69, 0x6e, 0xb9, 0x95, 0x43, 0xa7, 0x9a, 0xb4, 0x45, 0xce, 0x3b,
                0x2e, 0x7a, 0x8f, 0xa2, 0xe2, 0x90, 0x1e, 0x78, 0x98, 0x27, 0xd6, 0xbb, 0x35, 0xb4,
                0x35, 0x0e, 0x62, 0x0e,
            ],
            ivk: [
                0xb4, 0xed, 0xfb, 0x7c, 0x92, 0xb5, 0xef, 0xd2, 0x88, 0x7c, 0xb7, 0xce, 0x32, 0x0d,
                0xde, 0xc2, 0x85, 0xf6, 0xfd, 0xfb, 0xa2, 0xa9, 0x81, 0x3c, 0x2f, 0x16, 0x68, 0x0c,
                0x4e, 0x6b, 0x78, 0x01,
            ],
            default_d: [
                0xe6, 0x77, 0xa4, 0xdd, 0x26, 0x76, 0xe0, 0x81, 0x88, 0xb9, 0x0f,
            ],
            default_pk_d: [
                0xdc, 0x53, 0x68, 0x2c, 0x0d, 0xd8, 0x90, 0x38, 0x2d, 0x89, 0x28, 0x30, 0xf6, 0xf3,
                0x7c, 0x80, 0x83, 0x87, 0x34, 0xa2, 0xaf, 0xaa, 0xc4, 0x0e, 0x8b, 0xee, 0xec, 0x09,
                0xa5, 0x7d, 0x24, 0xee,
            ],
            note_v: 12227227834928555328,
            note_r: [
                0x47, 0x8b, 0xa0, 0xee, 0x6e, 0x1a, 0x75, 0xb6, 0x00, 0x03, 0x6f, 0x26, 0xf1, 0x8b,
                0x70, 0x15, 0xab, 0x55, 0x6b, 0xed, 0xdf, 0x8b, 0x96, 0x02, 0x38, 0x86, 0x9f, 0x89,
                0xdd, 0x80, 0x4e, 0x06,
            ],
            note_cm: [
                0x4a, 0xeb, 0xaa, 0x45, 0x05, 0xb6, 0x56, 0x00, 0xb4, 0xd8, 0x23, 0x5d, 0x5a, 0xfb,
                0xcb, 0xf6, 0x07, 0x06, 0xb8, 0xa9, 0xbf, 0x53, 0x0a, 0x9f, 0x5f, 0x57, 0x63, 0xe2,
                0x35, 0xf6, 0xae, 0x16,
            ],
            note_pos: 763714296,
            note_nf: [
                0x0b, 0xf1, 0x99, 0x7a, 0x77, 0x7b, 0x9a, 0xb9, 0xf8, 0x96, 0x7d, 0x21, 0x59, 0x4a,
                0x8f, 0xb1, 0xa5, 0xfe, 0x6f, 0x26, 0x93, 0xb9, 0x4b, 0xc0, 0x8f, 0x1f, 0xbd, 0xbb,
                0x7a, 0x38, 0x21, 0xd9,
            ],
        },
        TestVector {
            sk: [
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x02, 0x02, 0x02, 0x02,
            ],
            ask: [
                0xfb, 0x9d, 0xfd, 0x9b, 0x6d, 0x16, 0xb9, 0xcd, 0x3d, 0xf2, 0x98, 0x75, 0xf6, 0x31,
                0xdf, 0x88, 0x8e, 0xb4, 0xc0, 0x8f, 0xe9, 0x65, 0x9e, 0xee, 0xa7, 0xa4, 0xc4, 0x1d,
                0xe6, 0x63, 0xb7, 0x08,
            ],
            nsk: [
                0xa7, 0x13, 0xb3, 0xaa, 0x70, 0x93, 0x45, 0xaa, 0x16, 0xca, 0xac, 0x1a, 0xd3, 0x90,
                0x2b, 0x37, 0x0c, 0xdb, 0x2e, 0xe8, 0x7b, 0x68, 0xea, 0x2f, 0x4f, 0x0d, 0x8c, 0xe5,
                0xa0, 0x63, 0x17, 0x0a,
            ],
            ovk: [
                0x8d, 0xc3, 0x73, 0xff, 0xec, 0xa3, 0xd8, 0x57, 0x8d, 0x51, 0x6f, 0x35, 0x4a, 0xa8,
                0xa9, 0x73, 0x6f, 0x27, 0x8b, 0xee, 0xf1, 0x7a, 0x54, 0x4b, 0x16, 0xb3, 0x47, 0x8d,
                0xc5, 0x95, 0x46, 0xbd,
            ],
            ak: [
                0xde, 0x3a, 0x74, 0xaf, 0xad, 0xf2, 0xf0, 0x7d, 0x87, 0xe7, 0x07, 0xa6, 0x85, 0x36,
                0x30, 0x71, 0x12, 0x2b, 0x67, 0xec, 0x62, 0x0c, 0x4a, 0xc4, 0x66, 0xbc, 0xfd, 0xeb,
                0x82, 0xfd, 0x1b, 0x3f,
            ],
            nk: [
                0x42, 0xc6, 0xc8, 0x2e, 0x90, 0x0a, 0x73, 0x05, 0x58, 0x9b, 0xaf, 0xcf, 0xb2, 0xa1,
                0x29, 0x2b, 0xf3, 0xe2, 0xef, 0x0b, 0x8e, 0x11, 0x3b, 0xf2, 0xb7, 0xd4, 0x21, 0xa1,
                0x3a, 0x9d, 0xfa, 0x30,
            ],
            ivk: [
                0xdf, 0x4a, 0xfb, 0x34, 0x37, 0x3a, 0x88, 0x4f, 0x8d, 0x86, 0x53, 0x5a, 0x2c, 0x45,
                0xd6, 0xd3, 0x21, 0x66, 0x9e, 0xbf, 0xb8, 0x59, 0x99, 0x03, 0xa6, 0x40, 0x7d, 0xd3,
                0x82, 0x09, 0x76, 0x01,
            ],
            default_d: [
                0xa1, 0xe0, 0xf5, 0x3c, 0x47, 0x3e, 0xd9, 0x8c, 0x17, 0xb6, 0xd0,
            ],
            default_pk_d: [
                0xb3, 0x23, 0xbb, 0x8b, 0x98, 0x03, 0x11, 0x44, 0x88, 0x26, 0x0f, 0x9f, 0x51, 0xe5,
                0x46, 0xc2, 0xb4, 0x5f, 0x3d, 0x03, 0x6d, 0x03, 0x9b, 0x0f, 0x0c, 0xb2, 0x86, 0x13,
                0x9d, 0x4c, 0x25, 0xb5,
            ],
            note_v: 6007711596147559040,
            note_r: [
                0x14, 0x7c, 0xf2, 0xb5, 0x1b, 0x4c, 0x7c, 0x63, 0xcb, 0x77, 0xb9, 0x9e, 0x8b, 0x78,
                0x3e, 0x5b, 0x51, 0x11, 0xdb, 0x0a, 0x7c, 0xa0, 0x4d, 0x6c, 0x01, 0x4a, 0x1d, 0x7d,
                0xa8, 0x3b, 0xae, 0x0a,
            ],
            note_cm: [
                0x7b, 0x65, 0xc4, 0xda, 0xe0, 0x3c, 0xcf, 0xeb, 0xaf, 0xbe, 0x78, 0x92, 0x1a, 0xfe,
                0x4a, 0x81, 0x5b, 0x81, 0xbb, 0x33, 0x5a, 0x9e, 0xa7, 0x8d, 0x42, 0x19, 0x8d, 0xe4,
                0xef, 0xc4, 0x3e, 0x08,
            ],
            note_pos: 1527428592,
            note_nf: [
                0x28, 0x83, 0xe2, 0x74, 0xf2, 0x71, 0xd6, 0xa5, 0x70, 0x21, 0xdf, 0x39, 0x22, 0x49,
                0x9f, 0x5b, 0xda, 0x7d, 0x47, 0x51, 0x27, 0xb0, 0x63, 0x05, 0xad, 0x4f, 0xe6, 0x45,
                0x10, 0x82, 0x3c, 0x70,
            ],
        },
        TestVector {
            sk: [
                0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
                0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
                0x03, 0x03, 0x03, 0x03,
            ],
            ask: [
                0x26, 0x59, 0xdd, 0xc5, 0x9b, 0x1c, 0x36, 0x0b, 0x71, 0x8e, 0x32, 0x6a, 0xd2, 0xa7,
                0xda, 0xb9, 0x9c, 0xe1, 0x14, 0xc3, 0xdb, 0xe4, 0xf2, 0x0a, 0xbd, 0xdc, 0xbe, 0xb2,
                0xaf, 0xb0, 0x97, 0x0a,
            ],
            nsk: [
                0x76, 0x62, 0x25, 0xc2, 0x39, 0x32, 0x13, 0x72, 0x6d, 0x02, 0x97, 0xbc, 0x3d, 0xf0,
                0x86, 0x4e, 0x03, 0x4d, 0x40, 0xbd, 0xdb, 0xef, 0x01, 0xaa, 0x4e, 0x7a, 0xf9, 0xb8,
                0xd9, 0x9d, 0xaf, 0x0c,
            ],
            ovk: [
                0x30, 0x2a, 0x78, 0xb5, 0xce, 0xe5, 0xd9, 0x84, 0x22, 0xf2, 0xdd, 0x13, 0xd8, 0xc4,
                0x6f, 0xe7, 0x27, 0x67, 0x25, 0x52, 0x23, 0x3c, 0xc8, 0x21, 0x7a, 0xe2, 0xf1, 0x44,
                0xb3, 0xd6, 0x0d, 0x04,
            ],
            ak: [
                0x5b, 0xba, 0x75, 0x8d, 0x10, 0xcd, 0xff, 0x02, 0xa5, 0x95, 0x97, 0xa4, 0x6e, 0x25,
                0x37, 0xd6, 0x94, 0xe9, 0xc0, 0x15, 0x12, 0x91, 0x56, 0x96, 0x6a, 0x5a, 0xd8, 0x91,
                0x2b, 0x08, 0x94, 0x1f,
            ],
            nk: [
                0x0d, 0x29, 0xcb, 0x40, 0x35, 0x35, 0xd1, 0xa4, 0x50, 0x0e, 0x17, 0x93, 0x68, 0xcd,
                0x47, 0xb2, 0x24, 0x7a, 0xb1, 0x92, 0xb8, 0x67, 0x6b, 0x71, 0x53, 0xf7, 0xf1, 0x2a,
                0x91, 0x8d, 0xf1, 0x0e,
            ],
            ivk: [
                0x2a, 0xa4, 0x0d, 0xd9, 0x3b, 0x51, 0xe7, 0xf6, 0x81, 0xb1, 0x1c, 0xdc, 0xde, 0x55,
                0xe3, 0x3a, 0xcb, 0x3c, 0x9d, 0xe6, 0x25, 0x9d, 0x78, 0xae, 0xa5, 0x39, 0xbf, 0x80,
                0xad, 0xfe, 0x67, 0x07,
            ],
            default_d: [
                0x14, 0xbf, 0xe9, 0x79, 0x77, 0x94, 0x6a, 0x54, 0x7d, 0x5f, 0x3f,
            ],
            default_pk_d: [
                0x65, 0xcd, 0x93, 0xd6, 0x16, 0xc2, 0x69, 0xae, 0x15, 0x7a, 0x0a, 0xaa, 0xbe, 0xfd,
                0xb6, 0xb3, 0x27, 0xbd, 0xb9, 0xaa, 0xba, 0xef, 0xa1, 0xb9, 0xc1, 0x70, 0x1b, 0x60,
                0x0e, 0x01, 0x08, 0xae,
            ],
            note_v: 18234939431076114368,
            note_r: [
                0x34, 0xa4, 0xb2, 0xa9, 0x14, 0x4f, 0xf5, 0xea, 0x54, 0xef, 0xee, 0x87, 0xcf, 0x90,
                0x1b, 0x5b, 0xed, 0x5e, 0x35, 0xd2, 0x1f, 0xbb, 0xd7, 0x88, 0xd5, 0xbd, 0x9d, 0x83,
                0x3e, 0x11, 0x28, 0x04,
            ],
            note_cm: [
                0xf8, 0x95, 0x85, 0xef, 0x60, 0x05, 0xaa, 0x31, 0x41, 0x00, 0xc6, 0x08, 0x04, 0x7b,
                0x28, 0xc1, 0x02, 0x11, 0xd9, 0xe1, 0xab, 0x7d, 0xa5, 0xbb, 0x17, 0xd3, 0x26, 0x42,
                0xd5, 0x06, 0xd4, 0x5c,
            ],
            note_pos: 2291142888,
            note_nf: [
                0xb3, 0x33, 0x82, 0x88, 0x39, 0x09, 0x22, 0x56, 0x4b, 0xe2, 0x4d, 0xc4, 0xa8, 0xb4,
                0x37, 0xa8, 0x9e, 0xd3, 0xe2, 0x4b, 0xf2, 0xc2, 0x2e, 0x1c, 0xac, 0x72, 0x90, 0xe7,
                0xa6, 0xe1, 0x9e, 0x2b,
            ],
        },
        TestVector {
            sk: [
                0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                0x04, 0x04, 0x04, 0x04,
            ],
            ask: [
                0x1b, 0xc6, 0x41, 0xa1, 0x38, 0x80, 0xda, 0x85, 0xf9, 0x8a, 0xcc, 0x43, 0xfb, 0xe0,
                0x4a, 0x76, 0x85, 0x4e, 0x87, 0x44, 0xb4, 0x20, 0x6b, 0x2e, 0xec, 0x26, 0xe0, 0xe2,
                0xe0, 0x88, 0xf0, 0x0b,
            ],
            nsk: [
                0x6a, 0x8b, 0x46, 0x89, 0x39, 0x45, 0x4f, 0x6a, 0xb0, 0x4d, 0x31, 0x71, 0xf9, 0x49,
                0x18, 0xb2, 0x4d, 0xe7, 0xb5, 0x53, 0x69, 0x28, 0xaf, 0x17, 0xe1, 0xd0, 0xc8, 0xa0,
                0x8d, 0xac, 0x24, 0x0d,
            ],
            ovk: [
                0x82, 0x42, 0xe0, 0x59, 0xba, 0x92, 0x8e, 0xc6, 0xbe, 0x85, 0x65, 0x4a, 0x3d, 0xeb,
                0xa1, 0xbe, 0xe2, 0x47, 0xf1, 0x61, 0x84, 0x08, 0x0d, 0x69, 0xcf, 0x76, 0xa9, 0xc6,
                0x5e, 0x10, 0xf2, 0xc5,
            ],
            ak: [
                0x74, 0xdf, 0x47, 0xb3, 0xde, 0x05, 0x0e, 0xae, 0xf0, 0xa7, 0x1b, 0x43, 0xbf, 0xcc,
                0x3f, 0x49, 0xeb, 0x23, 0xba, 0xae, 0x69, 0xdf, 0xb1, 0x45, 0x9c, 0x0f, 0x5e, 0x1c,
                0xb5, 0x61, 0xbd, 0x67,
            ],
            nk: [
                0x38, 0x15, 0x29, 0x06, 0x59, 0x6e, 0x58, 0x66, 0xfa, 0xf7, 0x81, 0x9b, 0x02, 0xc1,
                0xb7, 0x17, 0x36, 0xf5, 0x24, 0x3f, 0x09, 0xd9, 0x4c, 0x76, 0x61, 0x52, 0x5f, 0xed,
                0xa7, 0x76, 0x6b, 0xc0,
            ],
            ivk: [
                0x38, 0x19, 0xa7, 0xdb, 0x66, 0xb7, 0x20, 0x61, 0x09, 0xdf, 0xee, 0xab, 0xc8, 0xe9,
                0x4e, 0xcd, 0xc8, 0xd7, 0xfe, 0x98, 0x3e, 0x48, 0x86, 0xde, 0xa6, 0x6e, 0xdc, 0xcd,
                0xeb, 0xcf, 0xbc, 0x00,
            ],
            default_d: [
                0xb8, 0xfd, 0x08, 0x5d, 0xf4, 0x66, 0x75, 0x8b, 0x8d, 0xef, 0x70,
            ],
            default_pk_d: [
                0xdf, 0x7d, 0xc9, 0xf5, 0x82, 0x3c, 0x2f, 0x25, 0x12, 0x07, 0xc3, 0xd0, 0x75, 0x47,
                0x8c, 0x54, 0x59, 0x8f, 0x2b, 0x59, 0x3e, 0xa1, 0x09, 0x31, 0x2d, 0xbd, 0x6e, 0x83,
                0x8b, 0x90, 0x2f, 0x2d,
            ],
            note_v: 12015423192295118080,
            note_r: [
                0xe5, 0x57, 0x85, 0x13, 0x55, 0x74, 0x7c, 0x09, 0xac, 0x59, 0x01, 0x3c, 0xbd, 0xe8,
                0x59, 0x80, 0x96, 0x4e, 0xc1, 0x84, 0x4d, 0x9c, 0x69, 0x67, 0xca, 0x0c, 0x02, 0x9c,
                0x84, 0x57, 0xbb, 0x04,
            ],
            note_cm: [
                0xaf, 0x50, 0x88, 0x77, 0xe1, 0x65, 0xb4, 0x63, 0x97, 0xa5, 0xa5, 0x21, 0xa7, 0xa0,
                0xb6, 0xc9, 0x5c, 0x3f, 0x4b, 0x13, 0x12, 0x02, 0x62, 0x2f, 0xf2, 0x2f, 0x84, 0xaa,
                0xb0, 0x44, 0xbb, 0x6f,
            ],
            note_pos: 3054857184,
            note_nf: [
                0x63, 0xb1, 0x47, 0x4c, 0x75, 0xe4, 0x27, 0x08, 0x67, 0x03, 0x49, 0x31, 0x28, 0x5a,
                0x58, 0x8d, 0xee, 0x20, 0x5f, 0x73, 0x76, 0xc1, 0x1d, 0x3f, 0x54, 0x59, 0x95, 0x8e,
                0x99, 0xb1, 0x9e, 0x91,
            ],
        },
        TestVector {
            sk: [
                0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
                0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
                0x05, 0x05, 0x05, 0x05,
            ],
            ask: [
                0x85, 0xdb, 0xa7, 0x95, 0xd8, 0xf9, 0xc9, 0x64, 0xdd, 0x55, 0x11, 0x3f, 0x27, 0x9c,
                0x48, 0x00, 0x2b, 0x6c, 0x82, 0xae, 0x22, 0xf7, 0x3b, 0x4d, 0x49, 0x47, 0x7b, 0xc4,
                0x62, 0x15, 0x42, 0x08,
            ],
            nsk: [
                0xb8, 0xe7, 0x43, 0x1b, 0xb9, 0x04, 0xf2, 0x97, 0x16, 0x27, 0x13, 0x17, 0x88, 0x9a,
                0x41, 0xf0, 0x44, 0x89, 0xe3, 0x62, 0x21, 0xb0, 0x34, 0xe6, 0x6e, 0xf6, 0xc1, 0x2e,
                0x5e, 0xd4, 0x9b, 0x00,
            ],
            ovk: [
                0x61, 0x1f, 0x89, 0x77, 0x5b, 0x10, 0x86, 0xbc, 0x30, 0xc1, 0x97, 0xa4, 0x3b, 0xbb,
                0x3a, 0x55, 0xd3, 0xfd, 0x4a, 0xac, 0x41, 0x82, 0x68, 0xbd, 0x8e, 0x6c, 0x9d, 0xe8,
                0xe9, 0x32, 0xe2, 0x3c,
            ],
            ak: [
                0xed, 0x48, 0x0a, 0x8f, 0xab, 0x26, 0x0c, 0x72, 0x74, 0xdf, 0x75, 0x02, 0xf1, 0x60,
                0xbd, 0xd5, 0x45, 0xa7, 0xec, 0x43, 0x03, 0x5e, 0x7a, 0xff, 0x87, 0x50, 0x2a, 0xd1,
                0xa8, 0xeb, 0x39, 0xa6,
            ],
            nk: [
                0xd4, 0x1b, 0x64, 0xe2, 0xfe, 0x6c, 0x25, 0x20, 0x3b, 0x09, 0x3d, 0xdf, 0x04, 0x60,
                0x1b, 0x56, 0xcc, 0x8f, 0x07, 0xef, 0x9b, 0x3d, 0xf1, 0x2b, 0xb9, 0x60, 0x5e, 0x94,
                0x8b, 0xcf, 0x9f, 0xd1,
            ],
            ivk: [
                0xd0, 0xc2, 0xfb, 0xf8, 0x7a, 0x28, 0xcd, 0xce, 0x8e, 0x22, 0x98, 0x96, 0xa9, 0x44,
                0xd0, 0x74, 0x2f, 0xe1, 0x5c, 0x61, 0x88, 0x8f, 0x10, 0x39, 0x18, 0x9a, 0x8e, 0x80,
                0x5c, 0x6c, 0xdf, 0x06,
            ],
            default_d: [
                0x91, 0xd8, 0x0c, 0x32, 0x53, 0x00, 0xd9, 0x7e, 0x0c, 0x3b, 0x05,
            ],
            default_pk_d: [
                0xe7, 0x25, 0xc0, 0x2a, 0xc9, 0x18, 0x84, 0xe1, 0x45, 0x2e, 0x5b, 0xbe, 0x8d, 0xbf,
                0xb1, 0xe0, 0xcd, 0xee, 0x00, 0x56, 0xdc, 0x2f, 0x5f, 0xc1, 0x92, 0x39, 0xb2, 0x0b,
                0x7b, 0xe7, 0x62, 0xe0,
            ],
            note_v: 5795906953514121792,
            note_r: [
                0x68, 0xf0, 0x61, 0x04, 0x60, 0x6b, 0x0c, 0x54, 0x49, 0x84, 0x5f, 0xf4, 0xc6, 0x5f,
                0x73, 0xe9, 0x0f, 0x45, 0xef, 0x5a, 0x43, 0xc9, 0xd7, 0x4c, 0xb2, 0xc8, 0x5c, 0xf5,
                0x6c, 0x94, 0xc0, 0x02,
            ],
            note_cm: [
                0xf0, 0x47, 0x65, 0xf8, 0x03, 0x72, 0xa9, 0xe0, 0xc4, 0xfe, 0x77, 0x88, 0xcb, 0xa9,
                0x49, 0x29, 0xb0, 0xe0, 0xe5, 0x77, 0x05, 0xca, 0xe4, 0x79, 0xc4, 0xb1, 0x33, 0x26,
                0x86, 0x83, 0xf1, 0x34,
            ],
            note_pos: 3818571480,
            note_nf: [
                0x4c, 0xb5, 0xc6, 0xde, 0xd1, 0x26, 0x16, 0xdd, 0xc8, 0xb5, 0xd6, 0x73, 0x11, 0x15,
                0x93, 0xb4, 0xa5, 0x9f, 0x29, 0xc3, 0x5a, 0x50, 0xfb, 0x69, 0x7f, 0x1f, 0xc9, 0x58,
                0x27, 0x1d, 0x98, 0x7f,
            ],
        },
        TestVector {
            sk: [
                0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
                0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
                0x06, 0x06, 0x06, 0x06,
            ],
            ask: [
                0xee, 0xba, 0xb3, 0x9a, 0xe3, 0x7c, 0x3d, 0xe9, 0xad, 0xad, 0xc4, 0x01, 0x43, 0x14,
                0x68, 0x77, 0xe7, 0x36, 0x8e, 0xed, 0xe0, 0xe4, 0x1e, 0x3e, 0xf0, 0x95, 0x17, 0x2a,
                0x8f, 0x7f, 0x3a, 0x01,
            ],
            nsk: [
                0x23, 0x5d, 0xd8, 0x4a, 0x4e, 0x7f, 0xa4, 0x03, 0xb6, 0xc2, 0x3a, 0x25, 0x7c, 0xed,
                0x2c, 0xed, 0x49, 0x94, 0xca, 0xea, 0xf4, 0xde, 0xfd, 0xf8, 0x1e, 0x8d, 0xde, 0xa7,
                0x6a, 0x97, 0xae, 0x08,
            ],
            ovk: [
                0xda, 0x02, 0x6d, 0x6e, 0x32, 0xc4, 0xc9, 0xf4, 0x5a, 0x79, 0x3d, 0xb3, 0x23, 0xf8,
                0x2b, 0xe1, 0xec, 0xcd, 0x30, 0x49, 0x3d, 0xc0, 0x70, 0x89, 0x35, 0xe0, 0xb4, 0x2e,
                0x12, 0x5b, 0xfe, 0xd5,
            ],
            ak: [
                0x31, 0x3d, 0x19, 0xcb, 0x75, 0xaa, 0x8c, 0x71, 0x67, 0xe2, 0xd0, 0x57, 0xe8, 0x0b,
                0x3d, 0xa1, 0x2d, 0xe7, 0x82, 0xd1, 0x8d, 0x51, 0xa9, 0x6d, 0x8c, 0x92, 0x20, 0x17,
                0x7d, 0x3f, 0x06, 0x31,
            ],
            nk: [
                0x53, 0x6c, 0x4f, 0xba, 0x3b, 0xab, 0xec, 0xe7, 0xa1, 0x28, 0xc6, 0x51, 0xdd, 0x8d,
                0x27, 0x89, 0xa0, 0xfe, 0x8c, 0xc9, 0x5b, 0xf9, 0x10, 0x13, 0x0c, 0x8e, 0x6a, 0x33,
                0x2b, 0xb1, 0xc8, 0xc8,
            ],
            ivk: [
                0xff, 0x6a, 0xc3, 0x6c, 0x82, 0xc1, 0x94, 0x57, 0x1e, 0x3f, 0xba, 0x8b, 0xdb, 0x26,
                0x7a, 0xc9, 0x0e, 0xdb, 0x6c, 0xa7, 0xb4, 0x21, 0x60, 0x60, 0xe8, 0x26, 0xa4, 0x3a,
                0x93, 0xde, 0x3c, 0x07,
            ],
            default_d: [
                0xce, 0x57, 0xe4, 0x2f, 0x7d, 0x60, 0x05, 0xd0, 0xc3, 0x28, 0xb2,
            ],
            default_pk_d: [
                0x75, 0x8a, 0x9a, 0xd6, 0x6f, 0xe3, 0x1a, 0x08, 0x30, 0xcb, 0x5d, 0x39, 0x89, 0x4d,
                0x62, 0x23, 0xad, 0xaa, 0x11, 0x08, 0xc0, 0xae, 0xcd, 0x54, 0xcc, 0xd9, 0xfd, 0x1c,
                0x1e, 0xd5, 0xe7, 0x62,
            ],
            note_v: 18023134788442677120,
            note_r: [
                0x49, 0xf9, 0x0b, 0x47, 0xfd, 0x52, 0xfe, 0xe7, 0xc1, 0xc8, 0x1f, 0x0d, 0xcb, 0x5b,
                0x74, 0xc3, 0xfb, 0x9b, 0x3e, 0x03, 0x97, 0x6f, 0x8b, 0x75, 0x24, 0xea, 0xba, 0xd0,
                0x08, 0x89, 0x21, 0x07,
            ],
            note_cm: [
                0xe1, 0xdc, 0x76, 0x6f, 0x5e, 0x90, 0xa6, 0xf0, 0xcd, 0xd7, 0x66, 0x3e, 0x11, 0xe5,
                0xf3, 0xde, 0x7b, 0x28, 0x45, 0x5b, 0x76, 0xb7, 0x02, 0x16, 0xa5, 0x98, 0x11, 0xf0,
                0x72, 0x77, 0x0f, 0x48,
            ],
            note_pos: 287318480,
            note_nf: [
                0x63, 0xff, 0xe5, 0x76, 0xf1, 0x3e, 0x99, 0x18, 0xa3, 0x9c, 0xc7, 0xc5, 0x3c, 0x5b,
                0xd4, 0x34, 0x2b, 0x84, 0x01, 0xf6, 0x8a, 0x7c, 0xf8, 0xd4, 0x05, 0xf7, 0xf8, 0xd0,
                0xc4, 0x65, 0xfe, 0xdb,
            ],
        },
        TestVector {
            sk: [
                0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
                0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
                0x07, 0x07, 0x07, 0x07,
            ],
            ask: [
                0x5d, 0x95, 0x7d, 0x1e, 0x47, 0x44, 0xa1, 0x1f, 0x92, 0x6b, 0xdc, 0xaf, 0xb6, 0xa3,
                0xd5, 0x0c, 0x9f, 0x12, 0x6f, 0x82, 0x3b, 0x3a, 0xf9, 0xa7, 0xc1, 0x94, 0x19, 0x67,
                0xcc, 0x16, 0x52, 0x08,
            ],
            nsk: [
                0xa3, 0x97, 0x1b, 0x83, 0x4a, 0x9c, 0xef, 0x13, 0x2b, 0x80, 0x3d, 0xd1, 0x0f, 0x84,
                0x26, 0x63, 0x92, 0x49, 0xb7, 0xc1, 0x4a, 0x41, 0xf6, 0xd4, 0x0d, 0x11, 0x3b, 0xca,
                0x8a, 0x7d, 0xcd, 0x02,
            ],
            ovk: [
                0xbd, 0x39, 0x7c, 0x76, 0x26, 0xdf, 0x00, 0xc4, 0x06, 0x78, 0xa4, 0xca, 0x22, 0x64,
                0x6a, 0xd2, 0x13, 0x6b, 0xd4, 0xb0, 0xac, 0x55, 0x11, 0x53, 0x76, 0x03, 0x75, 0x75,
                0x24, 0xee, 0x11, 0x4e,
            ],
            ak: [
                0x27, 0x63, 0x8b, 0x9c, 0x64, 0x8f, 0x06, 0x81, 0x90, 0x10, 0x25, 0x14, 0xd5, 0xf8,
                0xb0, 0xa8, 0x5a, 0xbf, 0x48, 0xdb, 0x17, 0x7c, 0x42, 0xbf, 0x31, 0x13, 0xd7, 0x7c,
                0x63, 0x18, 0x9d, 0x0a,
            ],
            nk: [
                0x11, 0x10, 0x97, 0xf5, 0x43, 0x52, 0x31, 0x91, 0x88, 0xac, 0xa2, 0x53, 0xe9, 0x3a,
                0x4c, 0x89, 0x17, 0xec, 0xd4, 0xf9, 0x85, 0x3c, 0xc8, 0xa9, 0xff, 0x28, 0xa4, 0xfe,
                0xe2, 0x9f, 0x42, 0xa0,
            ],
            ivk: [
                0xd0, 0xb0, 0x3d, 0x9d, 0x8a, 0xd5, 0x3a, 0xe7, 0x70, 0xc0, 0xc8, 0x70, 0x8e, 0xc9,
                0x20, 0xff, 0xd6, 0x01, 0x6c, 0x89, 0x97, 0xeb, 0x3b, 0x24, 0x13, 0xad, 0x17, 0xb8,
                0xcd, 0xfd, 0xec, 0x05,
            ],
            default_d: [
                0xef, 0x83, 0x2c, 0xf6, 0x6f, 0x46, 0xd8, 0x3e, 0x97, 0xbd, 0x79,
            ],
            default_pk_d: [
                0x34, 0xfe, 0x17, 0xbd, 0x7f, 0xbd, 0x16, 0xa1, 0x69, 0x06, 0xd7, 0xfe, 0x2e, 0x62,
                0x60, 0xe8, 0xb7, 0x25, 0x9b, 0x7c, 0x6e, 0xa3, 0x45, 0x64, 0x6f, 0x7b, 0x28, 0xf0,
                0xb7, 0xe3, 0xc6, 0xce,
            ],
            note_v: 11803618549661680832,
            note_r: [
                0x51, 0x65, 0xaf, 0xf2, 0x2d, 0xd4, 0xed, 0x56, 0xb4, 0xd8, 0x1d, 0x1f, 0x17, 0x1c,
                0xc3, 0xd6, 0x43, 0x2f, 0xed, 0x1b, 0xeb, 0xf2, 0x0a, 0x7b, 0xea, 0xb1, 0x2d, 0xb1,
                0x42, 0xf9, 0x4a, 0x0c,
            ],
            note_cm: [
                0xbd, 0xba, 0x79, 0x56, 0x1f, 0xde, 0x6a, 0x21, 0xbc, 0xcb, 0x25, 0x4a, 0xe1, 0x07,
                0x7b, 0x4b, 0xdd, 0x43, 0xbd, 0xac, 0xc9, 0x0c, 0xd7, 0x17, 0x73, 0x17, 0x26, 0xa5,
                0x84, 0xc4, 0xbe, 0x3a,
            ],
            note_pos: 1051032776,
            note_nf: [
                0x77, 0xc8, 0xb4, 0x23, 0x37, 0xfd, 0x71, 0x45, 0x0e, 0x74, 0x37, 0x52, 0xaa, 0x6f,
                0xf9, 0x38, 0xa8, 0xb0, 0xe3, 0x56, 0x11, 0x4d, 0x74, 0x89, 0x52, 0x14, 0x87, 0xed,
                0x44, 0x83, 0xe6, 0x8d,
            ],
        },
        TestVector {
            sk: [
                0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
                0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
                0x08, 0x08, 0x08, 0x08,
            ],
            ask: [
                0x1b, 0x06, 0x37, 0x6e, 0xe3, 0xa3, 0x65, 0xe3, 0xb8, 0xd7, 0xc8, 0x99, 0x71, 0x6c,
                0x13, 0x67, 0xc4, 0x85, 0x9d, 0xbc, 0x1d, 0xab, 0x20, 0xef, 0x83, 0x11, 0x28, 0x28,
                0x86, 0xda, 0x83, 0x00,
            ],
            nsk: [
                0x23, 0x52, 0xc2, 0xdc, 0xf8, 0x28, 0x22, 0x1b, 0xbb, 0x80, 0xd0, 0xfc, 0x9a, 0x75,
                0x78, 0x05, 0x15, 0xb3, 0x58, 0x1a, 0x8e, 0xaa, 0x78, 0xe7, 0x51, 0x5e, 0x2f, 0x3f,
                0xb4, 0x51, 0xb4, 0x04,
            ],
            ovk: [
                0x21, 0x15, 0x33, 0xa6, 0x4b, 0xc1, 0x87, 0xb9, 0x93, 0x35, 0x99, 0xb4, 0x10, 0x12,
                0x37, 0xe5, 0x05, 0x8d, 0x67, 0x7e, 0xb0, 0xa8, 0xb8, 0xdb, 0x91, 0x88, 0x67, 0x55,
                0x71, 0x2f, 0xfb, 0x54,
            ],
            ak: [
                0xba, 0xd8, 0x04, 0x03, 0xa2, 0x9a, 0x1a, 0x1c, 0x97, 0x77, 0x77, 0xc4, 0xe2, 0xe3,
                0x63, 0x30, 0xca, 0xd0, 0x8e, 0x69, 0x2a, 0xe2, 0x97, 0x72, 0x40, 0x61, 0x70, 0x6d,
                0x68, 0x4f, 0x5b, 0x05,
            ],
            nk: [
                0x14, 0x10, 0x87, 0xe8, 0x65, 0x53, 0xb1, 0x85, 0xc5, 0xd1, 0x1f, 0xf0, 0xce, 0x00,
                0x03, 0xd8, 0xb8, 0xcb, 0x33, 0xe5, 0xe1, 0xaa, 0x14, 0x8c, 0xd7, 0x28, 0xce, 0x38,
                0xac, 0x60, 0xff, 0x19,
            ],
            ivk: [
                0xc4, 0x86, 0x04, 0x3b, 0x54, 0xf2, 0x1f, 0x93, 0xbf, 0x29, 0xe7, 0x0d, 0x38, 0xae,
                0x9a, 0x2d, 0xa7, 0xfc, 0x48, 0x23, 0x35, 0xc9, 0x39, 0xc3, 0xbd, 0x86, 0xdb, 0xe3,
                0xa6, 0x6e, 0x6e, 0x03,
            ],
            default_d: [
                0x55, 0x63, 0x11, 0xd5, 0x93, 0xaf, 0x50, 0xe3, 0x1c, 0x4d, 0x1e,
            ],
            default_pk_d: [
                0x44, 0x7e, 0xfa, 0x0f, 0x22, 0x05, 0x00, 0x44, 0x26, 0x3d, 0x7d, 0x98, 0xd4, 0x75,
                0xc2, 0x60, 0x14, 0x26, 0xf1, 0xae, 0xa1, 0x9e, 0xd5, 0xaf, 0xe3, 0xb5, 0xfc, 0x75,
                0xd0, 0x81, 0x24, 0xa4,
            ],
            note_v: 5584102310880684544,
            note_r: [
                0x8c, 0x3e, 0x56, 0x44, 0x9d, 0xc8, 0x63, 0x54, 0xd3, 0x3b, 0x02, 0x5e, 0xf2, 0x79,
                0x34, 0x60, 0xbc, 0xb1, 0x69, 0xf3, 0x32, 0x4e, 0x4a, 0x6b, 0x64, 0xba, 0xa6, 0x08,
                0x32, 0x31, 0x57, 0x04,
            ],
            note_cm: [
                0x7c, 0x35, 0xc8, 0xeb, 0xa3, 0xc2, 0xbb, 0x68, 0x37, 0xfa, 0x2b, 0x45, 0xc2, 0xfc,
                0x53, 0x9f, 0x02, 0x0a, 0x9e, 0xb9, 0x35, 0x95, 0xd0, 0xb9, 0xa0, 0xb5, 0xe4, 0x24,
                0x64, 0x27, 0xe9, 0x45,
            ],
            note_pos: 1814747072,
            note_nf: [
                0x44, 0x9f, 0x3b, 0xb8, 0x88, 0x5f, 0xa5, 0xd3, 0x80, 0x31, 0x20, 0x65, 0x09, 0x0e,
                0x1b, 0x29, 0x46, 0xa5, 0x37, 0x72, 0x5b, 0x79, 0xa2, 0x2a, 0xe5, 0xaa, 0xb2, 0xc4,
                0xa7, 0x27, 0x64, 0x00,
            ],
        },
        TestVector {
            sk: [
                0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
                0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
                0x09, 0x09, 0x09, 0x09,
            ],
            ask: [
                0x18, 0x01, 0xaa, 0xcd, 0x5b, 0xc2, 0xcc, 0xe9, 0x18, 0x3d, 0xf7, 0xba, 0xb4, 0x2c,
                0xff, 0xc6, 0xf7, 0xb6, 0xa6, 0x47, 0x5d, 0x51, 0x85, 0xc9, 0xd0, 0x0c, 0xa4, 0xf1,
                0x5e, 0x8d, 0xdb, 0x0b,
            ],
            nsk: [
                0x0c, 0xde, 0x2c, 0x34, 0x8f, 0x4c, 0x4f, 0xd6, 0xb7, 0xa8, 0x63, 0x6a, 0xd8, 0xfd,
                0x36, 0x09, 0x10, 0x4a, 0xf7, 0x73, 0x10, 0xbc, 0x53, 0x3b, 0x39, 0xdc, 0x1e, 0xf0,
                0xd9, 0xdc, 0xe6, 0x08,
            ],
            ovk: [
                0xa5, 0xaf, 0x3b, 0xdc, 0x0c, 0x32, 0xb6, 0x51, 0x85, 0x90, 0xce, 0x04, 0x9a, 0x3d,
                0x7b, 0xb2, 0x35, 0x7b, 0x0f, 0x24, 0x58, 0x4e, 0xd7, 0x8d, 0x36, 0xde, 0x49, 0xbe,
                0x7c, 0xed, 0xb2, 0x84,
            ],
            ak: [
                0x8c, 0x36, 0xc0, 0xd8, 0x9c, 0xbe, 0x48, 0x55, 0xed, 0x44, 0xff, 0xb9, 0x81, 0x50,
                0x86, 0xea, 0xd2, 0xad, 0xc4, 0x9b, 0xba, 0xee, 0x75, 0xf5, 0x90, 0x03, 0xd5, 0x96,
                0xbe, 0x0f, 0x85, 0x34,
            ],
            nk: [
                0xc2, 0xef, 0xb4, 0x1a, 0x6d, 0x45, 0x99, 0x20, 0x7c, 0x3f, 0x73, 0x7d, 0x52, 0xb6,
                0xae, 0xaa, 0xc8, 0xb2, 0x91, 0xb9, 0xe3, 0xe3, 0xba, 0xa2, 0x6b, 0xeb, 0xf9, 0x45,
                0x4f, 0x1d, 0x16, 0x1e,
            ],
            ivk: [
                0x43, 0x98, 0x29, 0xc6, 0x7e, 0x0b, 0x12, 0xd6, 0xb5, 0x8d, 0x03, 0x17, 0x7e, 0x7b,
                0x98, 0xf2, 0x01, 0x78, 0x9c, 0x43, 0xfc, 0x76, 0x6e, 0x41, 0xd8, 0x8a, 0x49, 0x40,
                0x4d, 0x6b, 0x88, 0x07,
            ],
            default_d: [
                0x0d, 0xaa, 0x3c, 0x1b, 0xcf, 0xda, 0xda, 0x95, 0x7e, 0x46, 0xb6,
            ],
            default_pk_d: [
                0x2a, 0x9f, 0xbb, 0x3b, 0xac, 0xd1, 0x7c, 0x47, 0xa8, 0xe1, 0x57, 0x2f, 0xc5, 0x1b,
                0xa4, 0x9e, 0xb4, 0x65, 0x1c, 0x6d, 0x90, 0xb0, 0x4a, 0x27, 0x4c, 0xe1, 0xb4, 0xaf,
                0xc8, 0x93, 0x29, 0xcb,
            ],
            note_v: 17811330145809239872,
            note_r: [
                0x6e, 0xbb, 0xed, 0x74, 0x36, 0x19, 0xa2, 0x56, 0xf9, 0xad, 0x2e, 0x85, 0x88, 0x0c,
                0xfa, 0xa9, 0x09, 0x8a, 0x5f, 0xdb, 0x16, 0x29, 0x99, 0x0d, 0x9a, 0x7d, 0x3b, 0xb9,
                0x3f, 0xc9, 0x00, 0x03,
            ],
            note_cm: [
                0xc4, 0x21, 0x6e, 0xb7, 0xa7, 0x14, 0xb7, 0xb4, 0xdc, 0x9a, 0x89, 0xc1, 0xa9, 0xee,
                0xfb, 0x62, 0x7b, 0x79, 0xbe, 0xd6, 0xac, 0xd3, 0x45, 0x83, 0x4b, 0xf3, 0xd6, 0x72,
                0x99, 0x28, 0x77, 0x66,
            ],
            note_pos: 2578461368,
            note_nf: [
                0xe4, 0xba, 0x26, 0xd7, 0xce, 0x67, 0xa8, 0xef, 0x09, 0x85, 0xad, 0x82, 0x97, 0x3d,
                0x45, 0x6e, 0x73, 0x15, 0x73, 0x66, 0x88, 0xcb, 0xce, 0x97, 0x0b, 0xc4, 0x67, 0xa0,
                0x46, 0x23, 0x76, 0x70,
            ],
        },
    ];
    
    let asset_identifier =
        b"sO\x0e\xc5os\x1e\x02\xccs~ki=\xb5+\x82\x1fonL\xd7\xfe<vCS\xf2cf\x9f\xbe"; // b'default' under repeated hashing

    for tv in test_vectors {
        // Compute commitment and compare with test vector
        let mut result = [0u8; 32];
        assert!(libmasp_sapling_compute_cmu(
            &tv.default_d,
            &tv.default_pk_d,
            asset_identifier,
            tv.note_v,
            &tv.note_r,
            &mut result
        ));
        assert_eq!(&result, &tv.note_cm);

        // Compute nullifier and compare with test vector
        assert!(libmasp_sapling_compute_nf(
            &tv.default_d,
            &tv.default_pk_d,
            asset_identifier,
            tv.note_v,
            &tv.note_r,
            &tv.ak,
            &tv.nk,
            tv.note_pos,
            &mut result
        ));
        assert_eq!(&result, &tv.note_nf);
    }
}
