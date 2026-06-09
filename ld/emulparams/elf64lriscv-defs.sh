source_sh ${srcdir}/emulparams/elf32lriscv-defs.sh 64
# ELFSIZE=64
SEPARATE_GOTPLT="SIZEOF (.got.plt) >= 16 ? 16 : 0"
