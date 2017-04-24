#readelf: -h
#name: Option checking: -mfpu-freg=2 (nds32 FPU configuration 2)
#as: -mfpu-freg=2 -mfpu-sp-ext

ELF Header:
  Magic:.*
  Class:.*
  Data:.*
  Version:.*
  OS/ABI:.*
  ABI Version:.*
  Type:.*
  Machine:.*
  Version:.*
  Entry point address:.*
  Start of program headers:.*
  Start of section headers:.*
  Flags:.*FPU_REG:32/16.*
  Size of this header:.*
  Size of program headers:.*
  Number of program headers:.*
  Size of section headers:.*
  Number of section headers:.*
  Section header string table index:.*
