#as: -march=rv32ic_zihintntl
#objdump: -d

.*:[ 	]+file format .*

Disassembly of section .text:

0+000 <target>:
[ 	]+[0-9a-f]+:[ 	]+00200033[ 	]+ntl\.p1
[ 	]+[0-9a-f]+:[ 	]+00300033[ 	]+ntl\.pall
[ 	]+[0-9a-f]+:[ 	]+00400033[ 	]+ntl\.s1
[ 	]+[0-9a-f]+:[ 	]+00500033[ 	]+ntl\.all
[ 	]+[0-9a-f]+:[ 	]+900a[ 	]+c\.ntl\.p1
[ 	]+[0-9a-f]+:[ 	]+900e[ 	]+c\.ntl\.pall
[ 	]+[0-9a-f]+:[ 	]+9012[ 	]+c\.ntl\.s1
[ 	]+[0-9a-f]+:[ 	]+9016[ 	]+c\.ntl\.all
