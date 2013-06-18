#as: -march=v3f
#ld: --relax -T $srcdir/$subdir/relax_flsi.ld
#objdump: -d

.*:\s+file format .*nds32.*


Disassembly of section .text:

...00000 <_start>:
...00000:\s+3e 0f c0 00\s+addi.gp \$r0,#-16384
...00004:\s+34 00 07 ff\s+fldi \$fd0,\[\$r0\+#0x1ffc\]
...00008:\s+34 0e 8c 00\s+fldi \$fd0,\[\$gp\+#-4096\]
...0000c:\s+34 0e 8c 00\s+fldi \$fd0,\[\$gp\+#-4096\]
...00010:\s+34 0e 87 ff\s+fldi \$fd0,\[\$gp\+#0x1ffc\]
...00014:\s+34 0e 87 ff\s+fldi \$fd0,\[\$gp\+#0x1ffc\]
...00018:\s+40 00 00 09\s+nop
...0001c:\s+40 00 00 09\s+nop
...00020:\s+3e 0f c0 00\s+addi.gp \$r0,#-16384
...00024:\s+34 00 07 ff\s+fldi \$fd0,\[\$r0\+#0x1ffc\]
...00028:\s+3e 0f e0 00\s+addi.gp \$r0,#-8192
...0002c:\s+34 00 03 ff\s+fldi \$fd0,\[\$r0\+#0xffc\]
...00030:\s+3e 08 00 00\s+addi.gp \$r0,#0x0
...00034:\s+34 00 0b ff\s+fldi \$fd0,\[\$r0\+#-4100\]
...00038:\s+34 0e 80 00\s+fldi \$fd0,\[\$gp\+#0x0\]
...0003c:\s+3e 08 20 00\s+addi.gp \$r0,#0x2000
...00040:\s+34 00 00 00\s+fldi \$fd0,\[\$r0\+#0x0\]
