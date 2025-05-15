#as: -march=rv64i_xandes
#source: x-andes-perf-alias.s
#objdump: -dr

.*:[ 	]+file format .*


Disassembly of section .text:

0+000 <.*>:
[ 	]+[0-9a-f]+:[ 	]+4015745b[ 	]+nds\.bbs[ 	]+a0,1,0x8 <target\+0x8>
[ 	]+[0-9a-f]+:[ 	]+R_RISCV_RELAX_ENTRY[ 	]\*ABS\*
[ 	]+[0-9a-f]+:[ 	]+R_RISCV_10_PCREL[ 	]\.L0 
[ 	]+[0-9a-f]+:[ 	]+0000006f[ 	]+j[ 	]+0x4 <target\+0x4>
[ 	]+[0-9a-f]+:[ 	]+R_RISCV_JAL[ 	]\*ABS\*\+0x2
[ 	]+[0-9a-f]+:[ 	]+0015745b[ 	]+nds\.bbc[ 	]+a0,1,0x10 <target\+0x10>
[ 	]+[0-9a-f]+:[ 	]+R_RISCV_10_PCREL[ 	]\.L0 
[ 	]+[0-9a-f]+:[ 	]+0000006f[ 	]+j[ 	]+0xc <target\+0xc>
[ 	]+[0-9a-f]+:[ 	]+R_RISCV_JAL[ 	]\*ABS\*\+0x2
[ 	]+[0-9a-f]+:[ 	]+0015645b[ 	]+nds\.bnec[ 	]+a0,1,0x18 <target\+0x18>
[ 	]+[0-9a-f]+:[ 	]+R_RISCV_10_PCREL[ 	]\.L0 
[ 	]+[0-9a-f]+:[ 	]+0000006f[ 	]+j[ 	]+0x14 <target\+0x14>
[ 	]+[0-9a-f]+:[ 	]+R_RISCV_JAL[ 	]\*ABS\*\+0x2
[ 	]+[0-9a-f]+:[ 	]+0015545b[ 	]+nds\.beqc[ 	]+a0,1,0x20 <target\+0x20>
[ 	]+[0-9a-f]+:[ 	]+R_RISCV_10_PCREL[ 	]\.L0 
[ 	]+[0-9a-f]+:[ 	]+0000006f[ 	]+j[ 	]+0x1c <.*>
[ 	]+[0-9a-f]+:[ 	]+R_RISCV_JAL[ 	]\*ABS\*\+0x2
[ 	]+[0-9a-f]+:[ 	]+0c45b55b[ 	]+nds\.bfos[ 	]+a0,a1,3,4
[ 	]+[0-9a-f]+:[ 	]+0c45a55b[ 	]+nds\.bfoz[ 	]+a0,a1,3,4
[ 	]+[0-9a-f]+:[ 	]+0ac5855b[ 	]+nds\.lea\.h[ 	]+a0,a1,a2
[ 	]+[0-9a-f]+:[ 	]+0cc5855b[ 	]+nds\.lea\.w[ 	]+a0,a1,a2
[ 	]+[0-9a-f]+:[ 	]+0ec5855b[ 	]+nds\.lea\.d[ 	]+a0,a1,a2
[ 	]+[0-9a-f]+:[ 	]+10c5855b[ 	]+nds\.lea\.b\.ze[ 	]+a0,a1,a2
[ 	]+[0-9a-f]+:[ 	]+12c5855b[ 	]+nds\.lea\.h\.ze[ 	]+a0,a1,a2
[ 	]+[0-9a-f]+:[ 	]+14c5855b[ 	]+nds\.lea\.w\.ze[ 	]+a0,a1,a2
[ 	]+[0-9a-f]+:[ 	]+16c5855b[ 	]+nds\.lea\.d\.ze[ 	]+a0,a1,a2
[ 	]+[0-9a-f]+:[ 	]+0080150b[ 	]+nds\.addigp[ 	]+a0,8
[ 	]+[0-9a-f]+:[ 	]+0080050b[ 	]+nds\.lbgp[ 	]+a0,8
[ 	]+[0-9a-f]+:[ 	]+0080250b[ 	]+nds\.lbugp[ 	]+a0,8
[ 	]+[0-9a-f]+:[ 	]+0080152b[ 	]+nds\.lhgp[ 	]+a0,8
[ 	]+[0-9a-f]+:[ 	]+0080552b[ 	]+nds\.lhugp[ 	]+a0,8
[ 	]+[0-9a-f]+:[ 	]+0080252b[ 	]+nds\.lwgp[ 	]+a0,8
[ 	]+[0-9a-f]+:[ 	]+0080652b[ 	]+nds\.lwugp[ 	]+a0,8
[ 	]+[0-9a-f]+:[ 	]+0080352b[ 	]+nds\.ldgp[ 	]+a0,8
[ 	]+[0-9a-f]+:[ 	]+00a0340b[ 	]+nds\.sbgp[ 	]+a0,8
[ 	]+[0-9a-f]+:[ 	]+00a0042b[ 	]+nds\.shgp[ 	]+a0,8
[ 	]+[0-9a-f]+:[ 	]+00a0442b[ 	]+nds\.swgp[ 	]+a0,8
[ 	]+[0-9a-f]+:[ 	]+00a0742b[ 	]+nds\.sdgp[ 	]+a0,8
[ 	]+[0-9a-f]+:[ 	]+20c5855b[ 	]+nds\.ffb[ 	]+a0,a1,a2
[ 	]+[0-9a-f]+:[ 	]+22c5855b[ 	]+nds\.ffzmism[ 	]+a0,a1,a2
[ 	]+[0-9a-f]+:[ 	]+24c5855b[ 	]+nds\.ffmism[ 	]+a0,a1,a2
[ 	]+[0-9a-f]+:[ 	]+26c5855b[ 	]+nds\.flmism[ 	]+a0,a1,a2
