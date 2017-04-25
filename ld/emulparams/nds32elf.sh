TEXT_START_ADDR=0x500000
# This sets the stack to the top of simulator memory (48MB).
OTHER_END_SYMBOLS='PROVIDE (_stack = 0x3000000);'

SCRIPT_NAME=nds32elf
TEMPLATE_NAME=elf32
EXTRA_EM_FILE=nds32elf
BIG_OUTPUT_FORMAT="elf32-nds32be"
LITTLE_OUTPUT_FORMAT="elf32-nds32le"
OUTPUT_FORMAT="$LITTLE_OUTPUT_FORMAT"
ARCH=nds32
MACHINE=
MAXPAGESIZE=0x20
EMBEDDED=yes
COMMONPAGESIZE=0x20

# Instruct genscripts.sh not to compile scripts in by COMPILE_IN
# in order to use external linker scripts files.
EMULATION_LIBPATH=

GENERATE_SHLIB_SCRIPT=yes
GENERATE_PIE_SCRIPT=yes
