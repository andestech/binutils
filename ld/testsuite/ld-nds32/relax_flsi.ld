SECTIONS
{
  .text 0x100000 : {
    * (.text .text.*);
  }

  .data : ALIGN(0x1000) {
    * (.data .data.*);
  }
}
