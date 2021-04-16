#readelf: -h
#name: Option checking: -mabi=v1 (nds32 abi v1)
#as: -mabi=v1

# Test abi

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
  Flags:.*ABI v1.*
  Size of this header:.*
  Size of program headers:.*
  Number of program headers:.*
  Size of section headers:.*
  Number of section headers:.*
  Section header string table index:.*
