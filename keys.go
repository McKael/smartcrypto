package smartcrypto

var wbKey = []byte{
	0xab, 0xbb, 0x12, 0x0c, 0x09, 0xe7, 0x11, 0x42,
	0x43, 0xd1, 0xfa, 0x01, 0x02, 0x16, 0x3b, 0x27,
}

var transKey = []byte{
	0x6c, 0x94, 0x74, 0x46, 0x9d, 0xdf, 0x75, 0x78,
	0xf3, 0xe5, 0xad, 0x8a, 0x4c, 0x70, 0x3d, 0x99,
}

var publicKey = []byte{
	0x2c, 0xb1, 0x2b, 0xb2, 0xcb, 0xf7, 0xce, 0xc7, 0x13, 0xc0, 0xff, 0xf7,
	0xb5, 0x9a, 0xe6, 0x8a, 0x96, 0x78, 0x4a, 0xe5, 0x17, 0xf4, 0x1d, 0x25,
	0x9a, 0x45, 0xd2, 0x05, 0x56, 0x17, 0x7c, 0x0f, 0xfe, 0x95, 0x1c, 0xa6,
	0x0e, 0xc0, 0x3a, 0x99, 0x0c, 0x94, 0x12, 0x61, 0x9d, 0x1b, 0xee, 0x30,
	0xad, 0xc7, 0x77, 0x30, 0x88, 0xc5, 0x72, 0x16, 0x64, 0xcf, 0xfc, 0xed,
	0xac, 0xf6, 0xd2, 0x51, 0xcb, 0x4b, 0x76, 0xe2, 0xfd, 0x7a, 0xef, 0x09,
	0xb3, 0xae, 0x9f, 0x94, 0x96, 0xac, 0x8d, 0x94, 0xed, 0x2b, 0x26, 0x2e,
	0xee, 0x37, 0x29, 0x1c, 0x8b, 0x23, 0x7e, 0x88, 0x0c, 0xc7, 0xc0, 0x21,
	0xfb, 0x1b, 0xe0, 0x88, 0x1f, 0x3d, 0x0b, 0xff, 0xa4, 0x23, 0x4d, 0x3b,
	0x8e, 0x6a, 0x61, 0x53, 0x0c, 0x00, 0x47, 0x3c, 0xe1, 0x69, 0xc0, 0x25,
	0xf4, 0x7f, 0xcc, 0x00, 0x1d, 0x9b, 0x80, 0x51,
}

var privateKey = []byte{
	0x2f, 0xd6, 0x33, 0x47, 0x13, 0x81, 0x6f, 0xae, 0x01, 0x8c, 0xde, 0xe4,
	0x65, 0x6c, 0x50, 0x33, 0xa8, 0xd6, 0xb0, 0x0e, 0x8e, 0xae, 0xa0, 0x7b,
	0x36, 0x24, 0x99, 0x92, 0x42, 0xe9, 0x62, 0x47, 0x11, 0x2d, 0xcd, 0x01,
	0x9c, 0x41, 0x91, 0xf4, 0x64, 0x3c, 0x3c, 0xe1, 0x60, 0x50, 0x02, 0xb2,
	0xe5, 0x06, 0xe7, 0xf1, 0xd1, 0xef, 0x8d, 0x9b, 0x80, 0x44, 0xe4, 0x6d,
	0x37, 0xc0, 0xd5, 0x26, 0x32, 0x16, 0xa8, 0x7c, 0xd7, 0x83, 0xaa, 0x18,
	0x54, 0x90, 0x43, 0x6c, 0x4a, 0x0c, 0xb2, 0xc5, 0x24, 0xe1, 0x5b, 0xc1,
	0xbf, 0xea, 0xe7, 0x03, 0xbc, 0xbc, 0x4b, 0x74, 0xa0, 0x54, 0x02, 0x02,
	0xe8, 0xd7, 0x9c, 0xad, 0xaa, 0xe8, 0x5c, 0x6f, 0x9c, 0x21, 0x8b, 0xc1,
	0x10, 0x7d, 0x1f, 0x5b, 0x4b, 0x9b, 0xd8, 0x71, 0x60, 0xe7, 0x82, 0xf4,
	0xe4, 0x36, 0xee, 0xb1, 0x74, 0x85, 0xab, 0x4d,
}

var prime = []byte{
	0xb3, 0x61, 0xeb, 0x0a, 0xb0, 0x1c, 0x34, 0x39, 0xf2, 0xc1, 0x6f, 0xfd,
	0xa7, 0xb0, 0x5e, 0x3e, 0x32, 0x07, 0x01, 0xeb, 0xee, 0x3e, 0x24, 0x91,
	0x23, 0xc3, 0x58, 0x67, 0x65, 0xfd, 0x5b, 0xf6, 0xc1, 0xdf, 0xa8, 0x8b,
	0xb6, 0xbb, 0x5d, 0xa3, 0xfd, 0xe7, 0x47, 0x37, 0xcd, 0x88, 0xb6, 0xa2,
	0x6c, 0x5c, 0xa3, 0x1d, 0x81, 0xd1, 0x8e, 0x35, 0x15, 0x53, 0x3d, 0x08,
	0xdf, 0x61, 0x93, 0x17, 0x06, 0x32, 0x24, 0xcf, 0x09, 0x43, 0xa2, 0xf2,
	0x9a, 0x5f, 0xe6, 0x0c, 0x1c, 0x31, 0xdd, 0xf2, 0x83, 0x34, 0xed, 0x76,
	0xa6, 0x47, 0x8a, 0x11, 0x22, 0xfb, 0x24, 0xc4, 0xa9, 0x4c, 0x87, 0x11,
	0x61, 0x7d, 0xdf, 0xe9, 0x0c, 0xf0, 0x2e, 0x64, 0x3c, 0xd8, 0x2d, 0x47,
	0x48, 0xd6, 0xd4, 0xa7, 0xca, 0x2f, 0x47, 0xd8, 0x85, 0x63, 0xaa, 0x2b,
	0xaf, 0x64, 0x82, 0xe1, 0x24, 0xac, 0xd7, 0xdd,
}