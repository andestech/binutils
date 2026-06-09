target:
	vle4.v v4, (a0)
	vle4.v v4, 0(a0)
	vfwcvt.f.n.v v4, v8
	vfwcvt.f.n.v v4, v8, v0.t
	vfwcvt.f.nu.v v4, v8
	vfwcvt.f.nu.v v4, v8, v0.t
	vfwcvt.f.b.v v4, v8
	vfwcvt.f.b.v v4, v8, v0.t
	vfwcvt.f.bu.v v4, v8
	vfwcvt.f.bu.v v4, v8, v0.t
