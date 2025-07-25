//payload from https://github.com/ava-labs/avalanchego/blob/master/vms/platformvm/warp/message/payload_test.go
pub const SET_L1_VALIDATOR_WEIGHT_DATA: &[u8] = &[
    0x00, 0x00, 0x00, 0x25, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x21, 0xe6, 0x73, 0x17,
    0xcb, 0xc4, 0xbe, 0x2a, 0xeb, 0x00, 0x67, 0x7a, 0xd6, 0x46, 0x27, 0x78, 0xa8, 0xf5, 0x22, 0x74,
    0xb9, 0xd6, 0x05, 0xdf, 0x25, 0x91, 0xb2, 0x30, 0x27, 0xa8, 0x7d, 0xff, 0x00, 0x00, 0x00, 0x16,
    0x00, 0x00, 0x00, 0x00, 0x05, 0x39, 0x7f, 0xb1, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbc, 0x61, 0x4e, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x99, 0x77, 0x55, 0x77, 0x11, 0x33, 0x55, 0x31, 0x99, 0x77, 0x55, 0x77,
    0x11, 0x33, 0x55, 0x31, 0x99, 0x77, 0x55, 0x77, 0x11, 0x33, 0x55, 0x31, 0x99, 0x77, 0x55, 0x77,
    0x11, 0x33, 0x55, 0x31, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x34, 0x3e, 0xfc, 0xea,
    0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x3b, 0x9a, 0xca, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x44, 0x55, 0x66, 0x77,
    0x00, 0x00, 0x00, 0x02, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0xff, 0xee, 0xdd, 0xcc,
    0xbb, 0xaa, 0x99, 0x88, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0xff, 0xee, 0xdd, 0xcc,
    0xbb, 0xaa, 0x99, 0x88, 0x00, 0x00, 0x00, 0x01, 0x21, 0xe6, 0x73, 0x17, 0xcb, 0xc4, 0xbe, 0x2a,
    0xeb, 0x00, 0x67, 0x7a, 0xd6, 0x46, 0x27, 0x78, 0xa8, 0xf5, 0x22, 0x74, 0xb9, 0xd6, 0x05, 0xdf,
    0x25, 0x91, 0xb2, 0x30, 0x27, 0xa8, 0x7d, 0xff, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00,
    0x3b, 0x9a, 0xca, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x05,
    0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
    0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
    0x00, 0x00, 0x00, 0x02, 0x99, 0x77, 0x55, 0x77, 0x11, 0x33, 0x55, 0x31, 0x99, 0x77, 0x55, 0x77,
    0x11, 0x33, 0x55, 0x31, 0x99, 0x77, 0x55, 0x77, 0x11, 0x33, 0x55, 0x31, 0x99, 0x77, 0x55, 0x77,
    0x11, 0x33, 0x55, 0x31, 0x00, 0x00, 0x00, 0x05, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0xf0, 0x9f, 0x98, 0x85, 0x0a, 0x77, 0x65, 0x6c,
    0x6c, 0x20, 0x74, 0x68, 0x61, 0x74, 0x27, 0x73, 0x01, 0x23, 0x45, 0x21, 0x00, 0x00, 0x00, 0x70,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0xe9, 0x02, 0xa9, 0xa8, 0x66, 0x40, 0xbf, 0xdb, 0x1c, 0xd0,
    0xe3, 0x6c, 0x0c, 0xc9, 0x82, 0xb8, 0x3e, 0x57, 0x65, 0xfa, 0xd5, 0xf6, 0xbb, 0xe6, 0xab, 0xdc,
    0xce, 0x7b, 0x5a, 0xe7, 0xd7, 0xc7, 0x00, 0x00, 0x00, 0x46, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x02, 0xfa, 0xce, 0x00, 0x00, 0x00, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
    0x3d, 0x0a, 0xd1, 0x2b, 0x8e, 0xe8, 0x92, 0x8e, 0xdf, 0x24, 0x8c, 0xa9, 0x1c, 0xa5, 0x56, 0x00,
    0xfb, 0x38, 0x3f, 0x07, 0xc3, 0x2b, 0xff, 0x1d, 0x6d, 0xec, 0x47, 0x2b, 0x25, 0xcf, 0x59, 0xa7,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0xd0,
];
