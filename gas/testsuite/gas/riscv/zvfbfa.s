target:
	vsetvli  a0, a1,  e8alt, mf8, tu, ma
	vsetvli  a0, a1,  e16alt, mf8, tu, ma
	vsetivli a0, 0xb, e8alt, mf8, tu, ma
	vsetivli a0, 0xb, e16alt, mf8, tu, ma
