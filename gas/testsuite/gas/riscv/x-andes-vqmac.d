#as: -march=rv32i_xandesvqmac
#source: x-andes-vqmac.s
#objdump: -d

.*:[ 	]+file format .*


Disassembly of section .text:

0+000 <target>:
[ 	]+[0-9a-f]+:[ 	]+f2860257[ 	]+nds\.vqmaccu\.vv[ 	]+v4,v12,v8
[ 	]+[0-9a-f]+:[ 	]+f0860257[ 	]+nds\.vqmaccu\.vv[ 	]+v4,v12,v8,v0\.t
[ 	]+[0-9a-f]+:[ 	]+f285c257[ 	]+nds\.vqmaccu\.vx[ 	]+v4,a1,v8
[ 	]+[0-9a-f]+:[ 	]+f085c257[ 	]+nds\.vqmaccu\.vx[ 	]+v4,a1,v8,v0\.t
[ 	]+[0-9a-f]+:[ 	]+f6860257[ 	]+nds\.vqmacc\.vv[ 	]+v4,v12,v8
[ 	]+[0-9a-f]+:[ 	]+f4860257[ 	]+nds\.vqmacc\.vv[ 	]+v4,v12,v8,v0\.t
[ 	]+[0-9a-f]+:[ 	]+f685c257[ 	]+nds\.vqmacc\.vx[ 	]+v4,a1,v8
[ 	]+[0-9a-f]+:[ 	]+f485c257[ 	]+nds\.vqmacc\.vx[ 	]+v4,a1,v8,v0\.t
[ 	]+[0-9a-f]+:[ 	]+fe860257[ 	]+nds\.vqmaccsu\.vv[ 	]+v4,v12,v8
[ 	]+[0-9a-f]+:[ 	]+fc860257[ 	]+nds\.vqmaccsu\.vv[ 	]+v4,v12,v8,v0\.t
[ 	]+[0-9a-f]+:[ 	]+fe85c257[ 	]+nds\.vqmaccsu\.vx[ 	]+v4,a1,v8
[ 	]+[0-9a-f]+:[ 	]+fc85c257[ 	]+nds\.vqmaccsu\.vx[ 	]+v4,a1,v8,v0\.t
[ 	]+[0-9a-f]+:[ 	]+fa85c257[ 	]+nds\.vqmaccus\.vx[ 	]+v4,a1,v8
[ 	]+[0-9a-f]+:[ 	]+f885c257[ 	]+nds\.vqmaccus\.vx[ 	]+v4,a1,v8,v0\.t
