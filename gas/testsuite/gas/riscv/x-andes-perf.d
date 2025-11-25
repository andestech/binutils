#as: -march=rv64i_xandesperf
#source: x-andes-perf.s
#objdump: -dr

.*:[ 	]+file format .*


Disassembly of section .text:

0+000 <.*>:
[ 	]+[0-9a-f]+:[ 	]+0005705b[ 	]+nds\.bbc[ 	]+a0,0,0x0 <target>
[ 	]+[0-9a-f]+:[ 	]+R_RISCV_RELAX_ENTRY[ 	]\*ABS\*
[ 	]+[0-9a-f]+:[ 	]+R_RISCV_10_PCREL[ 	]target
[ 	]+[0-9a-f]+:[ 	]+fe057e5b[ 	]+nds\.bbs[ 	]+a0,0,0x0 <target>
[ 	]+[0-9a-f]+:[ 	]+R_RISCV_10_PCREL[ 	]target
[ 	]+[0-9a-f]+:[ 	]+be055c5b[ 	]+nds\.beqc[ 	]+a0,0,0x0 <target>
[ 	]+[0-9a-f]+:[ 	]+R_RISCV_10_PCREL[ 	]target
[ 	]+[0-9a-f]+:[ 	]+be056a5b[ 	]+nds\.bnec[ 	]+a0,0,0x0 <target>
[ 	]+[0-9a-f]+:[ 	]+R_RISCV_10_PCREL[ 	]target
[ 	]+[0-9a-f]+:[ 	]+0005b55b[ 	]+nds\.bfos[ 	]+a0,a1,0,0
[ 	]+[0-9a-f]+:[ 	]+0005a55b[ 	]+nds\.bfoz[ 	]+a0,a1,0,0
[ 	]+[0-9a-f]+:[ 	]+0ac5855b[ 	]+nds\.lea\.h[ 	]+a0,a1,a2
[ 	]+[0-9a-f]+:[ 	]+0cc5855b[ 	]+nds\.lea\.w[ 	]+a0,a1,a2
[ 	]+[0-9a-f]+:[ 	]+0ec5855b[ 	]+nds\.lea\.d[ 	]+a0,a1,a2
[ 	]+[0-9a-f]+:[ 	]+10c5855b[ 	]+nds\.lea\.b\.ze[ 	]+a0,a1,a2
[ 	]+[0-9a-f]+:[ 	]+12c5855b[ 	]+nds\.lea\.h\.ze[ 	]+a0,a1,a2
[ 	]+[0-9a-f]+:[ 	]+14c5855b[ 	]+nds\.lea\.w\.ze[ 	]+a0,a1,a2
[ 	]+[0-9a-f]+:[ 	]+16c5855b[ 	]+nds\.lea\.d\.ze[ 	]+a0,a1,a2
[ 	]+[0-9a-f]+:[ 	]+0000150b[ 	]+nds\.addigp[ 	]+a0,0
[ 	]+[0-9a-f]+:[ 	]+R_RISCV_LGP18S0[ 	]target
[ 	]+[0-9a-f]+:[ 	]+0000050b[ 	]+nds\.lbgp[ 	]+a0,0
[ 	]+[0-9a-f]+:[ 	]+R_RISCV_LGP18S0[ 	]target
[ 	]+[0-9a-f]+:[ 	]+0000250b[ 	]+nds\.lbugp[ 	]+a0,0
[ 	]+[0-9a-f]+:[ 	]+R_RISCV_LGP18S0[ 	]target
[ 	]+[0-9a-f]+:[ 	]+0000152b[ 	]+nds\.lhgp[ 	]+a0,0
[ 	]+[0-9a-f]+:[ 	]+R_RISCV_LGP17S1[ 	]target
[ 	]+[0-9a-f]+:[ 	]+0000552b[ 	]+nds\.lhugp[ 	]+a0,0
[ 	]+[0-9a-f]+:[ 	]+R_RISCV_LGP17S1[ 	]target
[ 	]+[0-9a-f]+:[ 	]+0000252b[ 	]+nds\.lwgp[ 	]+a0,0
[ 	]+[0-9a-f]+:[ 	]+R_RISCV_LGP17S2[ 	]target
[ 	]+[0-9a-f]+:[ 	]+0000652b[ 	]+nds\.lwugp[ 	]+a0,0
[ 	]+[0-9a-f]+:[ 	]+R_RISCV_LGP17S2[ 	]target
[ 	]+[0-9a-f]+:[ 	]+0000352b[ 	]+nds\.ldgp[ 	]+a0,0
[ 	]+[0-9a-f]+:[ 	]+R_RISCV_LGP17S3[ 	]target
[ 	]+[0-9a-f]+:[ 	]+00a0300b[ 	]+nds\.sbgp[ 	]+a0,0
[ 	]+[0-9a-f]+:[ 	]+R_RISCV_SGP18S0[ 	]target
[ 	]+[0-9a-f]+:[ 	]+00a0002b[ 	]+nds\.shgp[ 	]+a0,0
[ 	]+[0-9a-f]+:[ 	]+R_RISCV_SGP17S1[ 	]target
[ 	]+[0-9a-f]+:[ 	]+00a0402b[ 	]+nds\.swgp[ 	]+a0,0
[ 	]+[0-9a-f]+:[ 	]+R_RISCV_SGP17S2[ 	]target
[ 	]+[0-9a-f]+:[ 	]+00a0702b[ 	]+nds\.sdgp[ 	]+a0,0
[ 	]+[0-9a-f]+:[ 	]+R_RISCV_SGP17S3[ 	]target
[ 	]+[0-9a-f]+:[ 	]+20c5855b[ 	]+nds\.ffb[ 	]+a0,a1,a2
[ 	]+[0-9a-f]+:[ 	]+22c5855b[ 	]+nds\.ffzmism[ 	]+a0,a1,a2
[ 	]+[0-9a-f]+:[ 	]+24c5855b[ 	]+nds\.ffmism[ 	]+a0,a1,a2
[ 	]+[0-9a-f]+:[ 	]+26c5855b[ 	]+nds\.flmism[ 	]+a0,a1,a2
