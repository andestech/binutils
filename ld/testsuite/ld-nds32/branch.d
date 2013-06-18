#as: -Os
#ld: -static --relax -T	$srcdir/$subdir/branch.ld
#objdump: -d --prefix-addresses -j .text

.*:     file format .*nds32.*


Disassembly of section .text:
0+0000.*<[^>]*>.*beq.*\$r0,.*\$r1,.*00000024.*<main>
0+0004.*<[^>]*>.*bne.*\$r0,.*\$r1,.*00000024.*<main>
0+0008.*<[^>]*>.*beqz38.*\$r0,.*00000024.*<main>
0+000a.*<[^>]*>.*bnez38.*\$r0,.*00000024.*<main>
0+000c.*<[^>]*>.*bgez.*\$r0,.*00000024.*<main>
0+0010.*<[^>]*>.*bgezal.*\$r0,.*00000024.*<main>
0+0014.*<[^>]*>.*bgtz.*\$r0,.*00000024.*<main>
0+0018.*<[^>]*>.*blez.*\$r0,.*00000024.*<main>
0+001c.*<[^>]*>.*bltz.*\$r0,.*00000024.*<main>
0+0020.*<[^>]*>.*bltzal.*\$r0,.*00000024.*<main>
0+0024.*<main>.*
