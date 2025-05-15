#as: -march=rv32iv_xandes
#source: x-andes-vpackfph.s
#objdump: -d

.*:[ 	]+file format .*


Disassembly of section .text:

0+000 <target>:
[ 	]+[0-9a-f]+:[ 	]+0a80c25b[ 	]+nds\.vfpmadt\.vf[ 	]+v4,ft1,v8
[ 	]+[0-9a-f]+:[ 	]+0e80c25b[ 	]+nds\.vfpmadb\.vf[ 	]+v4,ft1,v8
[ 	]+[0-9a-f]+:[ 	]+0880c25b[ 	]+nds\.vfpmadt\.vf[ 	]+v4,ft1,v8,v0\.t
[ 	]+[0-9a-f]+:[ 	]+0c80c25b[ 	]+nds\.vfpmadb\.vf[ 	]+v4,ft1,v8,v0\.t
