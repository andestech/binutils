#include "sysdep.h"
#include <stdio.h>
#include "ansidecl.h"
#include "dis-asm.h"
#include "bfd.h"
#include "symcat.h"
#include "libiberty.h"
#include "opintl.h"
#include "bfd_stdint.h"
#include "hashtab.h"
#include "nds32-asm.h"
#include "opcode/nds32.h"
#define MASK_OP(insn,mask) ((insn) & (0x3f << 25 | (mask)))
enum map_type
{
  MAP_DATA0,
  MAP_DATA1,
  MAP_DATA2,
  MAP_DATA3,
  MAP_DATA4,
  MAP_CODE,
};
struct nds32_private_data
{
  int has_mapping_symbols;
  enum map_type last_mapping_type;
  int last_symbol_index;
  bfd_vma last_addr;
};
#define UNKNOWN_INSN_MSG _("*unknown*")
#define NDS32_PARSE_INSN16 0x01
#define NDS32_PARSE_INSN32 0x02
static void print_insn16 (bfd_vma pc, disassemble_info *info,
     uint32_t insn, uint32_t parse_mode);
static void print_insn32 (bfd_vma pc, disassemble_info *info, uint32_t insn,
     uint32_t parse_mode);
static uint32_t nds32_mask_opcode (uint32_t);
static void nds32_special_opcode (uint32_t, struct nds32_opcode **);
static int get_mapping_symbol_type (struct disassemble_info *info, int n,
        enum map_type *map_type);
static int is_mapping_symbol (struct disassemble_info *info, int n,
         enum map_type *map_type);
extern const field_t *nds32_field_table[NDS32_CORE_COUNT];
extern opcode_t *nds32_opcode_table[NDS32_CORE_COUNT];
extern keyword_t **nds32_keyword_table[NDS32_CORE_COUNT];
extern struct nds32_opcode nds32_opcodes[];
extern const field_t operand_fields[];
extern keyword_t *keywords[];
extern const keyword_t keyword_gpr[];
struct objdump_disasm_info
{
  bfd * abfd;
  asection * sec;
  bfd_boolean require_sec;
  arelent ** dynrelbuf;
  long dynrelcount;
  disassembler_ftype disassemble_fn;
  arelent * reloc;
};
static htab_t opcode_htab;
static keyword_t *
nds32_find_reg_keyword (keyword_t *reg, int value)
{
  if (!reg)
    return NULL;
  while (reg->name != NULL && reg->value != value)
    {
      reg++;
    }
  if (reg->name == NULL)
    return NULL;
  return reg;
}
static void
nds32_parse_audio_ext (const field_t *pfd,
         disassemble_info *info, uint32_t insn)
{
  fprintf_ftype func = info->fprintf_func;
  void *stream = info->stream;
  keyword_t *psys_reg;
  int int_value, new_value;
  if (pfd->hw_res == HW_INT || pfd->hw_res == HW_UINT)
    {
      if (pfd->hw_res == HW_INT)
 int_value =
   N32_IMMS ((insn >> pfd->bitpos), pfd->bitsize) << pfd->shift;
      else
 int_value = __GF (insn, pfd->bitpos, pfd->bitsize) << pfd->shift;
      if (int_value < 0)
 func (stream, "#%d", int_value);
      else
 func (stream, "#0x%x", int_value);
      return;
    }
  int_value =
    __GF (insn, pfd->bitpos, pfd->bitsize) << pfd->shift;
  new_value = int_value;
  psys_reg = (keyword_t*) keywords[pfd->hw_res];
  if (strcmp (pfd->name, "im5_i") == 0)
    {
      new_value = int_value & 0x03;
      new_value |= ((int_value & 0x10) >> 2);
    }
  else if (strcmp (pfd->name, "im5_m") == 0)
    {
      new_value = ((int_value & 0x1C) >> 2);
    }
  else if (strcmp (pfd->name, "im6_iq") == 0)
    {
      new_value |= 0x04;
    }
  else if (strcmp (pfd->name, "im6_ms") == 0)
    {
      new_value |= 0x04;
    }
  else if (strcmp (pfd->name, "a_rt21") == 0)
    {
      new_value = (insn & 0x00000020) >> 5;
      new_value |= (insn & 0x00000C00) >> 9;
      new_value |= (insn & 0x00008000) >> 12;
    }
  else if (strcmp (pfd->name, "a_rte") == 0)
    {
      new_value = (insn & 0x00000C00) >> 9;
      new_value |= (insn & 0x00008000) >> 12;
    }
  else if (strcmp (pfd->name, "a_rte1") == 0)
    {
      new_value = (insn & 0x00000C00) >> 9;
      new_value |= (insn & 0x00008000) >> 12;
      new_value |= 0x01;
    }
  else if (strcmp (pfd->name, "a_rte69") == 0)
    {
      new_value = int_value << 1;
    }
  else if (strcmp (pfd->name, "a_rte69_1") == 0)
    {
      new_value = int_value << 1;
      new_value |= 0x01;
    }
  psys_reg = nds32_find_reg_keyword (psys_reg, new_value);
  if (!psys_reg)
    func (stream, "???");
  else
    func (stream, "$%s", psys_reg->name);
}
static field_t *
match_field (char *name)
{
  field_t *pfd;
  int k;
  for (k = 0; k < NDS32_CORE_COUNT; k++)
    {
      pfd = (field_t *) nds32_field_table[k];
      while (1)
 {
   if (pfd->name == NULL)
     break;
   if (strcmp (name, pfd->name) == 0)
     return pfd;
   pfd++;
 }
    }
  return NULL;
}
static void
nds32_parse_opcode (struct nds32_opcode *opc, bfd_vma pc ATTRIBUTE_UNUSED,
      disassemble_info *info, uint32_t insn, uint32_t parse_mode)
{
  int op = 0;
  fprintf_ftype func = info->fprintf_func;
  void *stream = info->stream;
  const char *pstr_src;
  char *pstr_tmp;
  char tmp_string[16];
  unsigned int push25gpr = 0, lsmwRb, lsmwRe, lsmwEnb4, checkbit, i;
  int int_value, ifthe1st = 1;
  const field_t *pfd;
  keyword_t *psys_reg;
  if (opc == NULL)
    {
      func (stream, UNKNOWN_INSN_MSG);
      return;
    }
  pstr_src = opc->instruction;
  if (*pstr_src == 0)
    {
      func (stream, "%s", opc->opcode);
      return;
    }
  if (parse_mode & NDS32_PARSE_INSN16)
    {
      func (stream, "%s ", opc->opcode);
    }
  else
    {
      op = N32_OP6 (insn);
      if (op == N32_OP6_LSMW)
 func (stream, "%s.", opc->opcode);
      else if (strstr (opc->instruction, "tito"))
 func (stream, "%s", opc->opcode);
      else
 func (stream, "%s ", opc->opcode);
    }
  while (*pstr_src)
    {
      switch (*pstr_src)
 {
 case '%':
 case '=':
 case '&':
   pstr_src++;
   pstr_tmp = &tmp_string[0];
   while (*pstr_src)
     {
       if ((*pstr_src == ',') || (*pstr_src == ' ')
    || (*pstr_src == '{') || (*pstr_src == '}')
    || (*pstr_src == '[') || (*pstr_src == ']')
    || (*pstr_src == '(') || (*pstr_src == ')')
    || (*pstr_src == '+') || (*pstr_src == '<'))
  break;
       *pstr_tmp++ = *pstr_src++;
     }
   *pstr_tmp = 0;
          if ((pfd = match_field (&tmp_string[0])) == NULL)
            return;
   if (parse_mode & NDS32_PARSE_INSN16)
     {
       if (pfd->hw_res == HW_GPR)
  {
    int_value =
      __GF (insn, pfd->bitpos, pfd->bitsize) << pfd->shift;
    if ((opc->value == 0xfc00) || (opc->value == 0xfc80))
      {
        if (int_value == 0)
   int_value = 6;
        else
   int_value = (6 + (0x01 << int_value));
        push25gpr = int_value;
      }
    else if (strcmp (pfd->name, "rt4") == 0)
      {
        int_value = nds32_r45map[int_value];
      }
    func (stream, "$%s", keyword_gpr[int_value].name);
  }
       else if ((pfd->hw_res == HW_INT) || (pfd->hw_res == HW_UINT))
  {
    if (pfd->hw_res == HW_INT)
      int_value =
        N32_IMMS ((insn >> pfd->bitpos),
    pfd->bitsize) << pfd->shift;
    else
      int_value =
        __GF (insn, pfd->bitpos, pfd->bitsize) << pfd->shift;
    if (opc->value == 0xfa00)
      {
        int_value += 16;
        func (stream, "#0x%x", int_value);
      }
    else if (opc->value == 0xb200)
      {
        int_value = 0 - (128 - int_value);
        func (stream, "#%d", int_value);
      }
    else if ((opc->value == 0xc000) || (opc->value == 0xc800)
      || (opc->value == 0xd000) || (opc->value == 0xd800)
      || (opc->value == 0xd500) || (opc->value == 0xe800)
      || (opc->value == 0xe900))
      {
        info->print_address_func (int_value + pc, info);
      }
    else if ((opc->value == 0xfc00) || (opc->value == 0xfc80))
      {
        func (stream, "#%d    ! {$r6", int_value);
        if (push25gpr != 6)
   func (stream, "~$%s", keyword_gpr[push25gpr].name);
        func (stream, ", $fp, $gp, $lp}");
      }
    else if (pfd->hw_res == HW_INT)
      {
        if (int_value < 0)
   func (stream, "#%d", int_value);
        else
   func (stream, "#0x%x", int_value);
      }
    else
      func (stream, "#0x%x", int_value);
  }
     }
   else if (op == N32_OP6_AEXT)
     {
       nds32_parse_audio_ext (pfd, info, insn);
     }
   else if (pfd->hw_res < HW_INT)
     {
       int_value =
  __GF (insn, pfd->bitpos, pfd->bitsize) << pfd->shift;
       psys_reg = *(nds32_keyword_table[pfd->hw_res >> 8]
      + (pfd->hw_res & 0xff));
       psys_reg = nds32_find_reg_keyword (psys_reg, int_value);
       if (!psys_reg && pfd->hw_res == HW_SR)
  func (stream, "%d", int_value);
       else if (!psys_reg)
  func (stream, "???");
       else
  {
    if (pfd->hw_res == HW_GPR || pfd->hw_res == HW_CPR
        || pfd->hw_res == HW_FDR || pfd->hw_res == HW_FSR
        || pfd->hw_res == HW_DXR || pfd->hw_res == HW_SR
        || pfd->hw_res == HW_USR)
      func (stream, "$%s", psys_reg->name);
    else if (pfd->hw_res == HW_DTITON
      || pfd->hw_res == HW_DTITOFF)
      func (stream, ".%s", psys_reg->name);
    else
      func (stream, "%s", psys_reg->name);
  }
     }
   else if ((pfd->hw_res == HW_INT) || (pfd->hw_res == HW_UINT))
     {
       if (pfd->hw_res == HW_INT)
  int_value =
    N32_IMMS ((insn >> pfd->bitpos), pfd->bitsize) << pfd->shift;
       else
  int_value =
    __GF (insn, pfd->bitpos, pfd->bitsize) << pfd->shift;
       if ((op == N32_OP6_BR1) || (op == N32_OP6_BR2))
  {
    info->print_address_func (int_value + pc, info);
  }
       else if ((op == N32_OP6_BR3) && (pfd->bitpos == 0))
  {
    info->print_address_func (int_value + pc, info);
  }
       else if (op == N32_OP6_JI)
  {
    if (info->flags & INSN_HAS_RELOC)
      pc = 0;
    info->print_address_func (int_value + pc, info);
  }
       else if (op == N32_OP6_LSMW)
  {
    func (stream, "#0x%x    ! {", int_value);
    lsmwEnb4 = int_value;
    lsmwRb = ((insn >> 20) & 0x1F);
    lsmwRe = ((insn >> 10) & 0x1F);
    if (lsmwRb != 31 || lsmwRe != 31)
      {
        func (stream, "$%s", keyword_gpr[lsmwRb].name);
        if (lsmwRb != lsmwRe)
   func (stream, "~$%s", keyword_gpr[lsmwRe].name);
        ifthe1st = 0;
      }
    if (lsmwEnb4 != 0)
      {
        checkbit = 0x08;
        for (i = 0; i < 4; i++)
   {
     if (lsmwEnb4 & checkbit)
       {
         if (ifthe1st == 1)
    {
      ifthe1st = 0;
      func (stream, "$%s", keyword_gpr[28 + i].name);
    }
         else
    func (stream, ", $%s", keyword_gpr[28 + i].name);
       }
     checkbit >>= 1;
   }
      }
    func (stream, "}");
  }
       else if (pfd->hw_res == HW_INT)
  {
    if (int_value < 0)
      func (stream, "#%d", int_value);
    else
      func (stream, "#0x%x", int_value);
  }
       else
  {
    func (stream, "#0x%x", int_value);
  }
     }
   break;
 case '{':
 case '}':
   pstr_src++;
   break;
 default:
   func (stream, "%c", *pstr_src++);
   break;
 }
    }
  return;
}
static void
nds32_filter_unknown_insn (uint32_t insn, struct nds32_opcode **opc)
{
  if (!(*opc))
    return;
  switch ((*opc)->value)
    {
    case JREG (JR):
    case JREG (JRNEZ):
      if (__GF (insn, 6, 2) != 0 || __GF (insn, 15, 10) != 0)
        *opc = NULL;
      break;
    case MISC (STANDBY):
      if (__GF (insn, 7, 18) != 0)
        *opc = NULL;
      break;
    case SIMD (PBSAD):
    case SIMD (PBSADA):
      if (__GF (insn, 5, 5) != 0)
        *opc = NULL;
      break;
    case BR2 (SOP0):
      if (__GF (insn, 20, 5) != 0)
        *opc = NULL;
      break;
    case JREG (JRAL):
      if (__GF (insn, 5, 3) != 0 || __GF (insn, 15, 5) != 0)
        *opc = NULL;
      break;
    case ALU1 (NOR):
    case ALU1 (SLT):
    case ALU1 (SLTS):
    case ALU1 (SLLI):
    case ALU1 (SRLI):
    case ALU1 (SRAI):
    case ALU1 (ROTRI):
    case ALU1 (SLL):
    case ALU1 (SRL):
    case ALU1 (SRA):
    case ALU1 (ROTR):
    case ALU1 (SEB):
    case ALU1 (SEH):
    case ALU1 (ZEH):
    case ALU1 (WSBH):
    case ALU1 (SVA):
    case ALU1 (SVS):
    case ALU1 (CMOVZ):
    case ALU1 (CMOVN):
      if (__GF (insn, 5, 5) != 0)
        *opc = NULL;
      break;
    case MISC (IRET):
    case MISC (ISB):
    case MISC (DSB):
      if (__GF (insn, 5, 20) != 0)
        *opc = NULL;
      break;
    }
}
static void
print_insn32 (bfd_vma pc, disassemble_info *info, uint32_t insn,
       uint32_t parse_mode)
{
  struct nds32_opcode *opc;
  uint32_t opcode = nds32_mask_opcode (insn);
  opc = (struct nds32_opcode *) htab_find (opcode_htab, &opcode);
  nds32_special_opcode (insn, &opc);
  nds32_filter_unknown_insn (insn, &opc);
  nds32_parse_opcode (opc, pc, info, insn, parse_mode);
}
static void
print_insn16 (bfd_vma pc, disassemble_info *info,
       uint32_t insn, uint32_t parse_mode)
{
  struct nds32_opcode *opc;
  uint32_t opcode;
  unsigned int mask = 0xfe00;
  switch (__GF (insn, 13, 2))
    {
    case 0x0:
      if (__GF (insn, 11, 2) == 0)
 {
   mask = 0xfc00;
   if (__GF (insn, 0, 11) == 0x3ff)
     mask = 0xffff;
 }
      else if (__GF (insn, 9, 4) == 0xb)
 mask = 0xfe07;
      break;
    case 0x1:
      if (__GF (insn, 11, 2) == 0x3)
 mask = 0xf880;
      break;
    case 0x2:
      mask = 0xf800;
      if (__GF (insn, 12, 1) == 0x1
   && __GF (insn, 8, 3) == 0x5)
 {
   if (__GF (insn, 11, 1) == 0x0)
     mask = 0xff00;
   else
     mask = 0xffe0;
 }
      break;
    case 0x3:
      switch (__GF (insn, 11, 2))
 {
 case 0x1:
   if (__GF (insn, 9, 2) == 0x0)
     mask = 0xff00;
   else if (__GF(insn, 10, 1) == 0x1)
     mask = 0xfc00;
   break;
 case 0x2:
   mask = 0xf880;
   break;
 case 0x3:
   if (__GF (insn, 8, 3) == 0x5)
     mask = 0xff00;
   else if (__GF (insn, 8, 3) == 0x4)
     mask = 0xff80;
   else if (__GF (insn, 9 , 2) == 0x3)
     mask = 0xfe07;
   break;
 }
      break;
    }
  opcode = insn & mask;
  opc = (struct nds32_opcode *) htab_find (opcode_htab, &opcode);
  nds32_special_opcode (insn, &opc);
  nds32_parse_opcode (opc, pc, info, insn, parse_mode);
}
static hashval_t
htab_hash_hash (const void *p)
{
  return (*(unsigned int *) p) % 49;
}
static int
htab_hash_eq (const void *p, const void *q)
{
  uint32_t pinsn = ((struct nds32_opcode *) p)->value;
  uint32_t qinsn = *((uint32_t *) q);
  return (pinsn == qinsn);
}
static uint32_t
mask_CEXT (uint32_t insn)
{
  opcode_t *opc = nds32_opcode_table[NDS32_ACE], *max_opc = NULL;
  for (; opc != NULL && opc->opcode != NULL; opc++)
    {
      if ((insn & opc->value) == opc->value
   && (max_opc == NULL || opc->value > max_opc->value))
   max_opc = opc;
    }
  return max_opc ? max_opc->value : insn;
}
static uint32_t
nds32_mask_opcode (uint32_t insn)
{
  uint32_t opcode = N32_OP6 (insn);
  switch (opcode)
    {
    case N32_OP6_LBI:
    case N32_OP6_LHI:
    case N32_OP6_LWI:
    case N32_OP6_LDI:
    case N32_OP6_LBI_BI:
    case N32_OP6_LHI_BI:
    case N32_OP6_LWI_BI:
    case N32_OP6_LDI_BI:
    case N32_OP6_SBI:
    case N32_OP6_SHI:
    case N32_OP6_SWI:
    case N32_OP6_SDI:
    case N32_OP6_SBI_BI:
    case N32_OP6_SHI_BI:
    case N32_OP6_SWI_BI:
    case N32_OP6_SDI_BI:
    case N32_OP6_LBSI:
    case N32_OP6_LHSI:
    case N32_OP6_LWSI:
    case N32_OP6_LBSI_BI:
    case N32_OP6_LHSI_BI:
    case N32_OP6_LWSI_BI:
    case N32_OP6_MOVI:
    case N32_OP6_SETHI:
    case N32_OP6_ADDI:
    case N32_OP6_SUBRI:
    case N32_OP6_ANDI:
    case N32_OP6_XORI:
    case N32_OP6_ORI:
    case N32_OP6_SLTI:
    case N32_OP6_SLTSI:
    case N32_OP6_BITCI:
      return MASK_OP (insn, 0);
    case N32_OP6_CEXT:
      return mask_CEXT (insn);
    case N32_OP6_ALU2:
      if (__GF (insn, 0, 7) == (N32_ALU2_FFBI | __BIT (6)))
 return MASK_OP (insn, 0x7f);
      else if (__GF (insn, 0, 10) == (N32_ALU2_MFUSR | __BIT (6))
        || __GF (insn, 0, 10) == (N32_ALU2_MTUSR | __BIT (6)))
 return MASK_OP (insn, 0xf81ff);
      else if (__GF (insn, 0, 10) == (N32_ALU2_ONEOP | __BIT (7)))
 {
   if (__GF (insn, 12, 3) == 4)
     return MASK_OP (insn, 0x73ff);
   return MASK_OP (insn, 0x7fff);
 }
      return MASK_OP (insn, 0x3ff);
    case N32_OP6_ALU1:
    case N32_OP6_SIMD:
      return MASK_OP (insn, 0x1f);
    case N32_OP6_MEM:
      return MASK_OP (insn, 0xff);
    case N32_OP6_JREG:
      return MASK_OP (insn, 0x7f);
    case N32_OP6_LSMW:
      return MASK_OP (insn, 0x23);
    case N32_OP6_SBGP:
    case N32_OP6_LBGP:
      return MASK_OP (insn, 0x1 << 19);
    case N32_OP6_HWGP:
      if (__GF (insn, 18, 2) == 0x3)
 return MASK_OP (insn, 0x7 << 17);
      return MASK_OP (insn, 0x3 << 18);
    case N32_OP6_DPREFI:
      return MASK_OP (insn, 0x1 << 24);
    case N32_OP6_LWC:
    case N32_OP6_SWC:
    case N32_OP6_LDC:
    case N32_OP6_SDC:
      return MASK_OP (insn, 0x1 << 12);
    case N32_OP6_JI:
      return MASK_OP (insn, 0x1 << 24);
    case N32_OP6_BR1:
      return MASK_OP (insn, 0x1 << 14);
    case N32_OP6_BR2:
      if (__GF (insn, 16, 4) == 0)
 return MASK_OP (insn, 0x1ff << 16);
      else
 return MASK_OP (insn, 0xf << 16);
    case N32_OP6_BR3:
      return MASK_OP (insn, 0x1 << 19);
    case N32_OP6_MISC:
    switch (__GF (insn, 0, 5))
    {
    case N32_MISC_MTSR:
      if (__GF (insn, 5, 5) == 0x1 || __GF (insn, 5, 5) == 0x2)
 return MASK_OP (insn, 0x1fffff);
      return MASK_OP (insn, 0x1f);
    case N32_MISC_TLBOP:
      if (__GF (insn, 5, 5) == 5 || __GF (insn, 5, 5) == 7)
 return MASK_OP (insn, 0x3ff);
      return MASK_OP (insn, 0x1f);
    default:
      return MASK_OP (insn, 0x1f);
    }
    case N32_OP6_COP:
    if (__GF (insn, 4, 2) == 0)
      {
 switch (__GF (insn, 0, 4))
   {
   case 0x0:
   case 0x8:
     if (__GF (insn, 6, 4) == 0xf)
       return MASK_OP (insn, 0x7fff);
     return MASK_OP (insn, 0x3ff);
   case 0x4:
   case 0xc:
     return MASK_OP (insn, 0x3ff);
   case 0x1:
   case 0x9:
     if (__GF (insn, 6, 4) == 0xc)
       return MASK_OP (insn, 0x7fff);
     return MASK_OP (insn, 0x3ff);
   default:
     return MASK_OP (insn, 0xff);
   }
      }
    else if (__GF (insn, 0, 2) == 0)
      return MASK_OP (insn, 0xf);
    return MASK_OP (insn, 0xcf);
    case N32_OP6_AEXT:
    switch (__GF (insn, 23, 2))
      {
      case 0x0:
 if (__GF (insn, 5, 4) == 0)
   return MASK_OP (insn, (0x1f << 20) | 0x1ff);
 else if (__GF (insn, 5, 4) == 1)
   return MASK_OP (insn, (0x1f << 20) | (0xf << 5));
 else if (__GF (insn, 20, 3) == 0 && __GF (insn, 6, 3) == 1)
   return MASK_OP (insn, (0x1f << 20) | (0x7 << 6));
 else if (__GF (insn, 20 ,3) == 2 && __GF (insn, 6, 3) == 1)
   return MASK_OP (insn, (0x1f << 20) | (0xf << 5));
 else if (__GF (insn, 20 ,3) == 3 && __GF (insn, 6, 3) == 1)
   return MASK_OP (insn, (0x1f << 20) | (0x1f << 5));
 else if (__GF (insn, 7, 2) == 3)
   return MASK_OP (insn, (0x1f << 20) | (0x3 << 7));
 else if (__GF (insn, 6, 3) == 2)
   return MASK_OP (insn, (0x1f << 20) | (0xf << 5));
 else
   return MASK_OP (insn, (0x1f << 20) | (0x7 << 6));
      case 0x1:
 if (__GF (insn, 20, 3) == 0)
   return MASK_OP (insn, (0x1f << 20) | (0x1 << 5));
 else if (__GF (insn, 20, 3) == 1)
   return MASK_OP (insn, (0x1f << 20));
 else if (__GF (insn, 6, 3) == 2)
   return MASK_OP (insn, (0x1f << 20) | (0xf << 5));
 else if (__GF (insn, 7, 2) == 3)
   return MASK_OP (insn, (0x1f << 20) | (0x3 << 7));
 else
   return MASK_OP (insn, (0x1f << 20) | (0x7 << 6));
      case 0x2:
 if (__GF (insn, 6, 3) == 2)
   return MASK_OP (insn, (0x1f << 20) | (0xf << 5));
 else if (__GF (insn, 7, 2) == 3)
   return MASK_OP (insn, (0x1f << 20) | (0x3 << 7));
 else
   return MASK_OP (insn, (0x1f << 20) | (0x7 << 6));
      }
    return MASK_OP (insn, 0x1f << 20);
    default:
      return (1 << 31);
    }
}
static char *cctl_subtype [] =
{
  "st0", "st0", "st0", "st2", "st2", "st3", "st3", "st4",
  "st1", "st1", "st1", "st0", "st0", NULL, NULL, "st5",
  "st0", NULL, NULL, "st2", "st2", "st3", "st3", NULL,
  "st1", NULL, NULL, "st0", "st0", NULL, NULL, NULL
};
static void
nds32_special_opcode (uint32_t insn, struct nds32_opcode **opc)
{
  char *string = NULL;
  uint32_t op;
  if (!(*opc))
    return;
  switch ((*opc)->value)
    {
    case OP6 (LWC):
    case OP6 (SWC):
    case OP6 (LDC):
    case OP6 (SDC):
    case FPU_RA_IMMBI (LWC):
    case FPU_RA_IMMBI (SWC):
    case FPU_RA_IMMBI (LDC):
    case FPU_RA_IMMBI (SDC):
      if (__GF (insn, 13, 2) == 0)
      {
 while (!((*opc)->attr & ATTR (FPU)) && (*opc)->next)
   *opc = (*opc)->next;
      }
      break;
    case ALU1 (ADD):
    case ALU1 (SUB):
    case ALU1 (AND):
    case ALU1 (XOR):
    case ALU1 (OR):
      if (N32_SH5(insn) != 0)
        string = "sh";
      break;
    case ALU1 (SRLI):
      if (__GF (insn, 10, 15) == 0)
        string = "nop";
      break;
    case MISC (CCTL):
      string = cctl_subtype [__GF (insn, 5, 5)];
      break;
    case JREG (JR):
    case JREG (JRAL):
    case JREG (JR) | JREG_RET:
      if (__GF (insn, 8, 2) != 0)
 string = "tit";
    break;
    case N32_OP6_COP:
    break;
    case 0xea00:
      if (__GF (insn, 5, 4) != 0)
 string = "ex9";
      break;
    case 0x9200:
      if (__GF (insn, 0, 9) == 0)
 string = "nop16";
      break;
    }
  if (string)
    {
      while (strstr ((*opc)->opcode, string) == NULL
      && strstr ((*opc)->instruction, string) == NULL && (*opc)->next)
 *opc = (*opc)->next;
      return;
    }
  op = N32_OP6 (insn);
  if (op == N32_OP6_COP && __GF (insn, 4, 2) != 0)
    {
      while (((*opc)->attr & ATTR (FPU)) != 0 && (*opc)->next)
 *opc = (*opc)->next;
    }
}
int
print_insn_nds32 (bfd_vma pc, disassemble_info * info)
{
  int status;
  bfd_byte buf[4];
  bfd_byte buf_data[16];
  long long given;
  long long given1;
  uint32_t insn;
  int n;
  int last_symbol_index = -1;
  bfd_vma addr;
  int is_data = FALSE;
  bfd_boolean found = FALSE;
  struct nds32_private_data *private_data;
  unsigned int size = 16;
  enum map_type mapping_type = MAP_CODE;
  if (info->private_data == NULL)
    {
      static struct nds32_private_data private;
      private.has_mapping_symbols = -1;
      private.last_symbol_index = -1;
      private.last_addr = 0;
      info->private_data = &private;
    }
  private_data = info->private_data;
  if (info->symtab_size != 0)
    {
      int start;
      if (pc == 0)
 start = 0;
      else
 {
   start = info->symtab_pos;
   if (start < private_data->last_symbol_index)
     start = private_data->last_symbol_index;
 }
      if (0 > start)
 start = 0;
      if (private_data->has_mapping_symbols != 0
   && ((strncmp (".text", info->section->name, 5) == 0)))
 {
   for (n = start; n < info->symtab_size; n++)
     {
       addr = bfd_asymbol_value (info->symtab[n]);
       if (addr > pc)
  break;
       if (get_mapping_symbol_type (info, n, &mapping_type))
  {
    last_symbol_index = n;
    found = TRUE;
  }
     }
   if (found)
     private_data->has_mapping_symbols = 1;
   else if (!found && private_data->has_mapping_symbols == -1)
     {
       for (n = 0; n < info->symtab_size; n++)
  {
    if (is_mapping_symbol (info, n, &mapping_type))
      {
        private_data->has_mapping_symbols = -1;
        break;
      }
  }
       if (private_data->has_mapping_symbols == -1)
  private_data->has_mapping_symbols = 0;
     }
   private_data->last_symbol_index = last_symbol_index;
   private_data->last_mapping_type = mapping_type;
   is_data = (private_data->last_mapping_type == MAP_DATA0
       || private_data->last_mapping_type == MAP_DATA1
       || private_data->last_mapping_type == MAP_DATA2
       || private_data->last_mapping_type == MAP_DATA3
       || private_data->last_mapping_type == MAP_DATA4);
 }
    }
  if (is_data)
    {
      unsigned int i1;
      if (last_symbol_index + 1 >= info->symtab_size)
        {
          if (mapping_type == MAP_DATA0)
            size = 1;
          if (mapping_type == MAP_DATA1)
            size = 2;
          if (mapping_type == MAP_DATA2)
            size = 4;
          if (mapping_type == MAP_DATA3)
            size = 8;
          if (mapping_type == MAP_DATA4)
            size = 16;
        }
      for (n = last_symbol_index + 1; n < info->symtab_size; n++)
 {
   addr = bfd_asymbol_value (info->symtab[n]);
          enum map_type fake_mapping_type;
   if (get_mapping_symbol_type (info, n, &fake_mapping_type))
     {
       if (addr > pc
    && ((info->section == NULL)
        || (info->section == info->symtab[n]->section)))
  {
    if (addr - pc < size)
      {
        size = addr - pc;
        break;
      }
  }
     }
 }
      if (size == 3)
 size = (pc & 1) ? 1 : 2;
      info->read_memory_func (pc, (bfd_byte *) buf_data, size, info);
      given = 0;
      given1 = 0;
      if (info->endian == BFD_ENDIAN_LITTLE)
 {
   for (i1 = size - 1;; i1--)
     {
              if (i1 >= 8)
         given1 = buf_data[i1] | (given1 << 8);
              else
         given = buf_data[i1] | (given << 8);
       if (i1 == 0)
  break;
     }
 }
      else
 {
   for (i1 = 0; i1 < size; i1++) {
            if (i1 <= 7)
       given = buf_data[i1] | (given << 8);
            else
       given1 = buf_data[i1] | (given1 << 8);
          }
 }
      info->bytes_per_line = 4;
      if (size == 16)
        {
          info->fprintf_func (info->stream, ".qword\t0x%016llx%016llx",
                                given, given1);
        }
      else if (size == 8)
        {
          info->fprintf_func (info->stream, ".dword\t0x%016llx", given);
        }
      else if (size == 4)
        {
          info->fprintf_func (info->stream, ".word\t0x%08llx", given);
        }
      else if (size == 2)
        {
          if (mapping_type == MAP_DATA0)
     info->fprintf_func (info->stream, ".byte\t0x%02llx", given & 0xFF);
          else
            info->fprintf_func (info->stream, ".short\t0x%04llx", given);
        }
      else
        {
          info->fprintf_func (info->stream, ".byte\t0x%02llx", given);
        }
      return size;
    }
  status = info->read_memory_func (pc, (bfd_byte *) buf, 4, info);
  if (status)
    {
      status = info->read_memory_func (pc, (bfd_byte *) buf, 2, info);
      if (status)
 {
   (*info->memory_error_func)(status, pc, info);
   return -1;
 }
    }
  insn = bfd_getb32 (buf);
  if (insn & 0x80000000)
    {
      print_insn16 (pc, info, (insn >> 16), NDS32_PARSE_INSN16);
      return 2;
    }
  else
    {
      print_insn32 (pc, info, insn, NDS32_PARSE_INSN32);
      return 4;
    }
}
bfd_boolean
nds32_symbol_is_valid (asymbol *sym,
         struct disassemble_info *info ATTRIBUTE_UNUSED)
{
  const char *name;
  if (sym == NULL)
    return FALSE;
  name = bfd_asymbol_name (sym);
  if (name[0] == '$' || (strstr (name, "$nds32ifc_") != NULL))
    return FALSE;
  return TRUE;
}
void
nds32_add_opcode_hash_table (unsigned indx)
{
  opcode_t *opc;
  opc = nds32_opcode_table[indx];
  if (opc == NULL)
    return;
  while (opc->opcode != NULL)
    {
      opcode_t **slot;
      slot = (opcode_t **) htab_find_slot (opcode_htab, &opc->value, INSERT);
      if (*slot == NULL)
 {
   *slot = opc;
 }
      else
 {
   opcode_t *tmp;
   tmp = *slot;
   while (tmp->next)
     tmp = tmp->next;
   tmp->next = opc;
          opc->next = NULL;
 }
      opc++;
    }
}
void
disassemble_init_for_nds32 (struct disassemble_info *info)
{
  static unsigned init_done = 0;
  const char *ptr;
  unsigned k;
  info->symbol_is_valid = nds32_symbol_is_valid;
  if (init_done)
    return;
  nds32_keyword_table[NDS32_MAIN_CORE] = &keywords[0];
  nds32_opcode_table[NDS32_MAIN_CORE] = &nds32_opcodes[0];
  nds32_field_table[NDS32_MAIN_CORE] = &operand_fields[0];
  ptr = info->disassembler_options;
  if (ptr != NULL)
    {
      const char *start, *end;
      do
 {
   char name[256];
   start = strchr(ptr, '=');
   end = strchr(ptr, ',');
   if (start == NULL)
     fprintf (stderr, "Unknown nds32 disassembler option: %s\n", ptr);
   else
     {
       start++;
       if (end == NULL)
  strcpy (name, start);
       else
  strncpy (name, start, end - start);
       if (strncmp (ptr, "ace=", 4) == 0)
  nds32_parse_udi (name);
       else if (strncmp (ptr, "cop0=", 5) == 0)
  nds32_parse_cop0 (name);
       else if (strncmp (ptr, "cop1=", 5) == 0)
  nds32_parse_cop1 (name);
       else if (strncmp (ptr, "cop2=", 5) == 0)
  nds32_parse_cop2 (name);
       else if (strncmp (ptr, "cop3=", 5) == 0)
  nds32_parse_cop3 (name);
       else
  fprintf (stderr, "Unknown nds32 disassembler option: %s\n",
    ptr);
       if (end == NULL)
  break;
       ptr = end + 1;
     }
 } while (1);
    }
  opcode_htab = htab_create_alloc (1024, htab_hash_hash, htab_hash_eq, NULL,
       xcalloc, free);
  for (k = 0; k < NDS32_CORE_COUNT; k++)
    {
      nds32_add_opcode_hash_table (k);
    }
  init_done = 1;
}
static int
is_mapping_symbol (struct disassemble_info *info, int n,
     enum map_type *map_type)
{
  const char *name = NULL;
  name = bfd_asymbol_name (info->symtab[n]);
  if (name[1] == 'c')
    {
      *map_type = MAP_CODE;
      return TRUE;
    }
  else if (name[1] == 'd' && name[2] == '0')
    {
      *map_type = MAP_DATA0;
      return TRUE;
    }
  else if (name[1] == 'd' && name[2] == '1')
    {
      *map_type = MAP_DATA1;
      return TRUE;
    }
  else if (name[1] == 'd' && name[2] == '2')
    {
      *map_type = MAP_DATA2;
      return TRUE;
    }
  else if (name[1] == 'd' && name[2] == '3')
    {
      *map_type = MAP_DATA3;
      return TRUE;
    }
  else if (name[1] == 'd' && name[2] == '4')
    {
      *map_type = MAP_DATA4;
      return TRUE;
    }
  return FALSE;
}
static int
get_mapping_symbol_type (struct disassemble_info *info, int n,
    enum map_type *map_type)
{
  if (info->section != NULL && info->section != info->symtab[n]->section)
    return FALSE;
  return is_mapping_symbol (info, n, map_type);
}
void
print_nds32_disassembler_options (FILE *stream)
{
  fprintf (stream, _("\n\
The following Andes specific disassembler options are supported for use with\n\
the -M switch:\n"));
  fprintf (stream, "  ace=<shrlibfile>         Support user defined instruction extension\n");
  fprintf (stream, "  cop0=<shrlibfile>        Support coprocessor 0 extension\n");
  fprintf (stream, "  cop1=<shrlibfile>        Support coprocessor 1 extension\n");
  fprintf (stream, "  cop2=<shrlibfile>        Support coprocessor 2 extension\n");
  fprintf (stream, "  cop3=<shrlibfile>        Support coprocessor 3 extension\n\n");
}
