# source: float.s
# objdump: -sj .data
# as: -march=rv32i -mbig-endian

.*:[ 	]+file format .*bigriscv

Contents of section \.data:
 0000 3f8ccccd 40019999 9999999a.*
