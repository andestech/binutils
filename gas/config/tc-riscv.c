/* tc-riscv.c -- RISC-V assembler
   Copyright (C) 2011-2019 Free Software Foundation, Inc.

   Contributed by Andrew Waterman (andrew@sifive.com).
   Based on MIPS target.

   This file is part of GAS.

   GAS is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   GAS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; see the file COPYING3. If not,
   see <http://www.gnu.org/licenses/>.  */

#include "as.h"
#include "config.h"
#include "subsegs.h"
#include "safe-ctype.h"

#include "itbl-ops.h"
#include "dwarf2dbg.h"
#include "dw2gencfi.h"

#include "bfd/elfxx-riscv.h"
#include "elf/riscv.h"
#include "opcode/riscv.h"

#include <stdint.h>
#ifndef __MINGW32__
#include <dlfcn.h>
#endif

/* Information about an instruction, including its format, operands
   and fixups.  */
struct riscv_cl_insn
{
  /* The opcode's entry in riscv_opcodes.  */
  const struct riscv_opcode *insn_mo;

  /* The encoded instruction bits.  */
  insn_t insn_opcode;

  /* The frag that contains the instruction.  */
  struct frag *frag;

  /* The offset into FRAG of the first instruction byte.  */
  long where;

  /* The relocs associated with the instruction, if any.  */
  fixS *fixp;

  struct
    {
      int method;
      int state;
      int type;
      int index;
      int offset;
    } cmodel;
};

#ifndef DEFAULT_ARCH
#define DEFAULT_ARCH "riscv64"
#endif

#ifndef DEFAULT_RISCV_ATTR
#define DEFAULT_RISCV_ATTR 0
#endif

enum riscv_cl_insn_method
{
  METHOD_DEFAULT,
  METHOD_VARIABLE,
};

enum cmodel_subtype_index
{
  CSI_INDIRECT_SYMBOL = 0,
  CSI_REFERENCE_SYMBOL = 1,
  CSI_LARGE_CODE = 2,
  CSI_DEFAULT_CODE = 3,
};

static const char default_arch[] = DEFAULT_ARCH;

static unsigned xlen = 0; /* width of an x-register */
static unsigned abi_xlen = 0; /* width of a pointer in the ABI */
static bfd_boolean rve_abi = FALSE;

#define LOAD_ADDRESS_INSN (abi_xlen == 64 ? "ld" : "lw")
#define ADD32_INSN (xlen == 64 ? "addiw" : "addi")

static int attributes_set_explicitly[NUM_KNOWN_OBJ_ATTRIBUTES + NUM_KNOWN_OBJ_ATTRIBUTES_V5];

static unsigned elf_flags = 0;
static int optimize = 0;
static int optimize_for_space = 0;
static const char *m_ict_model = NULL;

/* This is the set of options which the .option pseudo-op may modify.  */

struct riscv_set_options
{
  int pic; /* Generate position-independent code.  */
  int rvc; /* Generate RVC code.  */
  int rve; /* Generate RVE code.  */
  int relax; /* Emit relocs the linker is allowed to relax.  */
  int arch_attr; /* Emit arch attribute.  */
  int no_16_bit;
  int execit;
  int atomic;
  int verbatim;
  int dsp;
  int efhw;
  int vector;
  int cmodel;
};

enum CMODEL_TYPES {
  CMODEL_DEFAULT,
  CMODEL_LARGE,
};

static struct riscv_set_options riscv_opts =
{
  0,	/* pic */
  0,	/* rvc */
  0,	/* rve */
  1,	/* relax */
  DEFAULT_RISCV_ATTR, /* arch_attr */
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  CMODEL_DEFAULT,	/* cmodel */
};

static void
riscv_set_rvc (bfd_boolean rvc_value)
{
  if (riscv_opts.no_16_bit)
    return;

  if (rvc_value)
    elf_flags |= EF_RISCV_RVC;

  riscv_opts.rvc = rvc_value;
}

static void
riscv_set_rve (bfd_boolean rve_value)
{
  if (rve_value)
    elf_flags |= EF_RISCV_RVE;

  riscv_opts.rve = rve_value;
}

struct riscv_subset
{
  const char *name;

  struct riscv_subset *next;
};

static riscv_subset_list_t riscv_subsets;

static bfd_boolean
riscv_subset_supports (const char *feature)
{
  if (riscv_opts.rvc && (strcasecmp (feature, "c") == 0))
    return TRUE;

  return riscv_lookup_subset (&riscv_subsets, feature) != NULL;
}

static bfd_boolean
riscv_multi_subset_supports (const char *features[])
{
  unsigned i = 0;
  bfd_boolean supported = TRUE;

  for (;features[i]; ++i)
    supported = supported && riscv_subset_supports (features[i]);

  return supported;
}

/* Set which ISA and extensions are available.  */

ATTRIBUTE_UNUSED static void
riscv_set_arch (const char *s)
{
  riscv_parse_subset_t rps;
  rps.subset_list = &riscv_subsets;
  rps.error_handler = as_fatal;
  rps.xlen = &xlen;

  riscv_release_subset_list (&riscv_subsets);
  riscv_parse_subset (&rps, s);

  if (riscv_lookup_subset (rps.subset_list, "e"))
    {
      riscv_set_rve (TRUE);
    }

  if (riscv_lookup_subset_version (&riscv_subsets, "xv5-", 0, 0))
    {
      if (!riscv_lookup_subset (rps.subset_list, "xefhw"))
        riscv_add_subset (&riscv_subsets, "xefhw", 1, 0);
    }
}

/* Handle of the OPCODE hash table.  */
static struct hash_control *op_hash = NULL;

/* Handle of the type of .insn hash table.  */
static struct hash_control *insn_type_hash = NULL;

/* This array holds the chars that always start a comment.  If the
    pre-processor is disabled, these aren't very useful */
const char comment_chars[] = "#";

/* This array holds the chars that only start a comment at the beginning of
   a line.  If the line seems to have the form '# 123 filename'
   .line and .file directives will appear in the pre-processed output */
/* Note that input_file.c hand checks for '#' at the beginning of the
   first line of the input file.  This is because the compiler outputs
   #NO_APP at the beginning of its output.  */
/* Also note that C style comments are always supported.  */
const char line_comment_chars[] = "#";

/* This array holds machine specific line separator characters.  */
const char line_separator_chars[] = ";";

/* Chars that can be used to separate mant from exp in floating point nums */
const char EXP_CHARS[] = "eE";

/* Chars that mean this number is a floating point constant */
/* As in 0f12.456 */
/* or    0d1.2345e12 */
const char FLT_CHARS[] = "rRsSfFdDxXpP";

/* Indicate we are already assemble any instructions or not.  */
static bfd_boolean start_assemble = FALSE;

/* Indicate arch attribute is explictly set.  */
static bfd_boolean explicit_arch_attr = FALSE;

/* Macros for encoding relaxation state for RVC branches and far jumps.  */
#define RELAX_BRANCH_ENCODE(uncond, rvc, length, range)	\
  ((relax_substateT) 					\
   (0xc0000000						\
    | ((uncond) ? 1 : 0)				\
    | ((rvc) ? 2 : 0)					\
    | ((length) << 2)					\
    | ((range) << 6)))
#define RELAX_BRANCH_P(i) (((i) & 0xf0000000) == 0xc0000000)
#define RELAX_BRANCH_LENGTH(i) (((i) >> 2) & 0xF)
#define RELAX_BRANCH_RVC(i) (((i) & 2) != 0)
#define RELAX_BRANCH_UNCOND(i) (((i) & 1) != 0)
#define RELAX_BRANCH_RANGE(i) (((i) >> 6) & 0xF)

#define RELAX_CMODEL_ENCODE(type, length, index)	\
  ((relax_substateT) 					\
   (0xd0000000						\
    | ((type) << 0)					\
    | ((length) << 8)					\
    | ((index) << 16)))
#define RELAX_CMODEL_P(i) (((i) & 0xf0000000) == 0xd0000000)
#define RELAX_CMODEL_TYPE(i) ((i) & 0xff)
#define RELAX_CMODEL_LENGTH(i) (((i) >> 8) & 0xff)
#define RELAX_CMODEL_INDEX(i) (((i) >> 16) & 0xff)

enum cmodel_type
{
  TYPE_JX = 0,
  TYPE_LA,
  TYPE_LD,
  TYPE_ST,
  TYPE_IS, /* indirect symbol  */
};

enum branch_range
{
  RANGE_JMP = 1,
  RANGE_BRANCH = 2,
  RANGE_10_PCREL = 3
};

#define ENUM_BRANCH_RANGE(reloc)					\
  ((reloc == BFD_RELOC_RISCV_JMP) ? RANGE_JMP				\
    : ((reloc == BFD_RELOC_12_PCREL) ? RANGE_BRANCH			\
      : (reloc == BFD_RELOC_RISCV_10_PCREL) ? RANGE_10_PCREL : 0))

/* Is the given value a sign-extended 32-bit value?  */
#define IS_SEXT_32BIT_NUM(x)						\
  (((x) &~ (offsetT) 0x7fffffff) == 0					\
   || (((x) &~ (offsetT) 0x7fffffff) == ~ (offsetT) 0x7fffffff))

/* Is the given value a zero-extended 32-bit value?  Or a negated one?  */
#define IS_ZEXT_32BIT_NUM(x)						\
  (((x) &~ (offsetT) 0xffffffff) == 0					\
   || (((x) &~ (offsetT) 0xffffffff) == ~ (offsetT) 0xffffffff))

/* Change INSN's opcode so that the operand given by FIELD has value VALUE.
   INSN is a riscv_cl_insn structure and VALUE is evaluated exactly once.  */
#define INSERT_OPERAND(FIELD, INSN, VALUE) \
  INSERT_BITS ((INSN).insn_opcode, VALUE, OP_MASK_##FIELD, OP_SH_##FIELD)

/* Determine if an instruction matches an opcode.  */
#define OPCODE_MATCHES(OPCODE, OP) \
  (((OPCODE) & MASK_##OP) == MATCH_##OP)

static char *expr_end;

/* The default target format to use.  */

const char *
riscv_target_format (void)
{
  return xlen == 64 ? "elf64-littleriscv" : "elf32-littleriscv";
}

/* Return the length of instruction INSN.  */

static inline unsigned int
insn_length (const struct riscv_cl_insn *insn)
{
  return riscv_insn_length (insn->insn_opcode);
}

/* Initialise INSN from opcode entry MO.  Leave its position unspecified.  */

static void
create_insn (struct riscv_cl_insn *insn, const struct riscv_opcode *mo)
{
  insn->insn_mo = mo;
  insn->insn_opcode = mo->match;
  insn->frag = NULL;
  insn->where = 0;
  insn->fixp = NULL;
}

/* Install INSN at the location specified by its "frag" and "where" fields.  */

static void
install_insn (const struct riscv_cl_insn *insn)
{
  char *f = insn->frag->fr_literal + insn->where;
  md_number_to_chars (f, insn->insn_opcode, insn_length (insn));
}

/* Move INSN to offset WHERE in FRAG.  Adjust the fixups accordingly
   and install the opcode in the new location.  */

static void
move_insn (struct riscv_cl_insn *insn, fragS *frag, long where)
{
  insn->frag = frag;
  insn->where = where;
  if (insn->fixp != NULL)
    {
      insn->fixp->fx_frag = frag;
      insn->fixp->fx_where = where;
    }
  install_insn (insn);
}

/* Add INSN to the end of the output.  */

static void
add_fixed_insn (struct riscv_cl_insn *insn)
{
  char *f = frag_more (insn_length (insn));
  move_insn (insn, frag_now, f - frag_now->fr_literal);
}

static void
add_relaxed_insn (struct riscv_cl_insn *insn, int max_chars, int var,
      relax_substateT subtype, symbolS *symbol, offsetT offset)
{
  frag_grow (max_chars);
  move_insn (insn, frag_now, frag_more (0) - frag_now->fr_literal);
  frag_var (rs_machine_dependent, max_chars, var,
	    subtype, symbol, offset, NULL);
}

static void
add_insn_grow (struct riscv_cl_insn *insn)
{
  frag_grow (insn_length (insn));
  move_insn (insn, frag_now, frag_more (0) - frag_now->fr_literal + insn->cmodel.offset);
}

static inline void
add_insn_grow_done (struct riscv_cl_insn *insn ATTRIBUTE_UNUSED, int max_chars, int var,
      relax_substateT subtype, symbolS *symbol, offsetT offset)
{
  frag_var (rs_machine_dependent, max_chars, var,
	    subtype, symbol, offset, NULL);
}

static inline
bfd_boolean is_cmodel_large (void)
{
  return riscv_opts.cmodel == CMODEL_LARGE;
}

static inline
bfd_boolean is_same_section_symbol (symbolS *sym, asection *sec)
{
  return (sym != NULL
	  && S_IS_DEFINED (sym)
	  && !S_IS_WEAK (sym)
	  && sec == S_GET_SEGMENT (sym));
}

static inline
bfd_boolean is_cmodel_relaxable (symbolS *sym, asection *sec)
{
  return (abi_xlen >= 64
	  && is_cmodel_large ()
	  && !is_same_section_symbol (sym, sec));
}

/* Compute the length of a branch sequence, and adjust the stored length
   accordingly.  If FRAGP is NULL, the worst-case length is returned.  */

static unsigned
relaxed_branch_length (fragS *fragp, asection *sec, int update)
{
  int jump, rvc, length = 8;
  enum branch_range range;

  if (!fragp)
    return length;

  jump = RELAX_BRANCH_UNCOND (fragp->fr_subtype);
  rvc = RELAX_BRANCH_RVC (fragp->fr_subtype);
  length = RELAX_BRANCH_LENGTH (fragp->fr_subtype);
  range = RELAX_BRANCH_RANGE (fragp->fr_subtype);

  /* Assume jumps are in range; the linker will catch any that aren't.  */
  length = jump ? 4 : 8;

  if (fragp->fr_symbol != NULL
      && S_IS_DEFINED (fragp->fr_symbol)
      && !S_IS_WEAK (fragp->fr_symbol)
      && sec == S_GET_SEGMENT (fragp->fr_symbol))
    {
      offsetT val = S_GET_VALUE (fragp->fr_symbol) + fragp->fr_offset;
      bfd_vma rvc_range = jump ? RVC_JUMP_REACH : RVC_BRANCH_REACH;
      val -= fragp->fr_address + fragp->fr_fix;

      if (rvc && (bfd_vma)(val + rvc_range/2) < rvc_range)
	length = 2;
      else if (range == RANGE_BRANCH
	       && (bfd_vma)(val + RISCV_BRANCH_REACH/2) < RISCV_BRANCH_REACH)
	length = 4;
      else if  ((bfd_vma)(val + RISCV_10_PCREL_REACH/2) < RISCV_10_PCREL_REACH)
	length = 4;
      else if (!jump && rvc)
	length = 6;
    }

  if (update)
    fragp->fr_subtype = RELAX_BRANCH_ENCODE (jump, rvc, length, range);

  return length;
}

/* Compute the length of a CModel sequence, and adjust the stored length
   accordingly.  */
static unsigned
relaxed_cmodel_length (fragS *fragp, asection *sec)
{
  int type = RELAX_CMODEL_TYPE (fragp->fr_subtype);
  int length = RELAX_CMODEL_LENGTH (fragp->fr_subtype);
  int index = RELAX_CMODEL_INDEX (fragp->fr_subtype);
  int is_same_sec = is_same_section_symbol (fragp->fr_symbol, sec);

  gas_assert (fragp);

  switch (index)
    {
    case CSI_INDIRECT_SYMBOL:
      switch (type)
	{
	case TYPE_JX ... TYPE_ST:
	  length = 0;
	  break;
	case TYPE_IS:
	  if (is_same_sec)
	    length = 0;
	  else
	    gas_assert (length == 8);
	  break;
	default:
	  as_fatal (_("internal error: invalid CModel type!"));
	}
      break;
    case CSI_REFERENCE_SYMBOL:
      switch (type)
	{
	case TYPE_JX ... TYPE_ST:
	  length = 0;
	  break;
	default:
	  as_fatal (_("internal error: invalid CModel type!"));
	}
      break;
    case CSI_LARGE_CODE:
      switch (type)
	{
	case TYPE_JX:
	  if (is_same_sec)
	    length = 0;
	  break;
	case TYPE_LA:
	    length = 8;
	    break;
	case TYPE_LD... TYPE_ST:
	  if (is_same_sec)
	    length = 8;
	  break;
	default:
	  as_fatal (_("internal error: invalid CModel type!"));
	}
      break;
    case CSI_DEFAULT_CODE:
      switch (type)
	{
	case TYPE_JX:
	  if (!is_same_sec)
	    length = 0;
	  break;
	default:
	  as_fatal (_("internal error: invalid CModel type!"));
	}
      break;
    default:
      as_fatal (_("internal error: invalid CModel index!"));
    }

  fragp->fr_subtype = RELAX_CMODEL_ENCODE (type, length, index);
  return length;
}

/* Information about an opcode name, mnemonics and its value.  */
struct opcode_name_t
{
  const char *name;
  unsigned int val;
};

/* List for all supported opcode name.  */
static const struct opcode_name_t opcode_name_list[] =
{
  {"C0",        0x0},
  {"C1",        0x1},
  {"C2",        0x2},

  {"LOAD",      0x03},
  {"LOAD_FP",   0x07},
  {"CUSTOM_0",  0x0b},
  {"MISC_MEM",  0x0f},
  {"OP_IMM",    0x13},
  {"AUIPC",     0x17},
  {"OP_IMM_32", 0x1b},
  /* 48b        0x1f.  */

  {"STORE",     0x23},
  {"STORE_FP",  0x27},
  {"CUSTOM_1",  0x2b},
  {"AMO",       0x2f},
  {"OP",        0x33},
  {"LUI",       0x37},
  {"OP_32",     0x3b},
  /* 64b        0x3f.  */

  {"MADD",      0x43},
  {"MSUB",      0x47},
  {"NMADD",     0x4f},
  {"NMSUB",     0x4b},
  {"OP_FP",     0x53},
  /*reserved    0x57.  */
  {"CUSTOM_2",  0x5b},
  /* 48b        0x5f.  */

  {"BRANCH",    0x63},
  {"JALR",      0x67},
  /*reserved    0x5b.  */
  {"JAL",       0x6f},
  {"SYSTEM",    0x73},
  /*reserved    0x77.  */
  {"CUSTOM_3",  0x7b},
  /* >80b       0x7f.  */

  {NULL, 0}
};

/* Hash table for lookup opcode name.  */
static struct hash_control *opcode_names_hash = NULL;

/* Initialization for hash table of opcode name.  */
static void
init_opcode_names_hash (void)
{
  const char *retval;
  const struct opcode_name_t *opcode;

  for (opcode = &opcode_name_list[0]; opcode->name != NULL; ++opcode)
    {
      retval = hash_insert (opcode_names_hash, opcode->name, (void *)opcode);

      if (retval != NULL)
	as_fatal (_("internal error: can't hash `%s': %s"),
		  opcode->name, retval);
    }
}

/* Find `s` is a valid opcode name or not,
   return the opcode name info if found.  */
static const struct opcode_name_t *
opcode_name_lookup (char **s)
{
  char *e;
  char save_c;
  struct opcode_name_t *o;

  /* Find end of name.  */
  e = *s;
  if (is_name_beginner (*e))
    ++e;
  while (is_part_of_name (*e))
    ++e;

  /* Terminate name.  */
  save_c = *e;
  *e = '\0';

  o = (struct opcode_name_t *) hash_find (opcode_names_hash, *s);

  /* Advance to next token if one was recognized.  */
  if (o)
    *s = e;

  *e = save_c;
  expr_end = e;

  return o;
}

struct regname
{
  const char *name;
  unsigned int num;
};

enum reg_class
{
  RCLASS_GPR,
  RCLASS_FPR,
  RCLASS_CSR,
  RCLASS_VECR,
  RCLASS_VECM,
  RCLASS_MAX
};

static struct hash_control *reg_names_hash = NULL;

#define ENCODE_REG_HASH(cls, n) \
  ((void *)(uintptr_t)((n) * RCLASS_MAX + (cls) + 1))
#define DECODE_REG_CLASS(hash) (((uintptr_t)(hash) - 1) % RCLASS_MAX)
#define DECODE_REG_NUM(hash) (((uintptr_t)(hash) - 1) / RCLASS_MAX)

static void
hash_reg_name (enum reg_class class, const char *name, unsigned n)
{
  void *hash = ENCODE_REG_HASH (class, n);
  const char *retval = hash_insert (reg_names_hash, name, hash);

  if (retval != NULL)
    as_fatal (_("internal error: can't hash `%s': %s"), name, retval);
}

static void
hash_reg_names (enum reg_class class, const char * const names[], unsigned n)
{
  unsigned i;

  for (i = 0; i < n; i++)
    hash_reg_name (class, names[i], i);
}

static bfd_boolean
riscv_support_e_set_p (void)
{
  return (riscv_lookup_subset (&riscv_subsets, "e")) ? TRUE : FALSE;
}

static unsigned int
reg_lookup_internal (const char *s, enum reg_class class)
{
  struct regname *r = (struct regname *) hash_find (reg_names_hash, s);

  if (r == NULL || DECODE_REG_CLASS (r) != class)
    return -1;

  if (riscv_opts.rve && class == RCLASS_GPR && DECODE_REG_NUM (r) > 15)
    return -1;

  if (riscv_support_e_set_p ()
      && class != RCLASS_CSR
      && DECODE_REG_NUM (r) > 15)
    return -1;

  return DECODE_REG_NUM (r);
}

static bfd_boolean
reg_lookup (char **s, enum reg_class class, unsigned int *regnop)
{
  char *e;
  char save_c;
  int reg = -1;

  /* Find end of name.  */
  e = *s;
  if (is_name_beginner (*e))
    ++e;
  while (is_part_of_name (*e))
    ++e;

  /* Terminate name.  */
  save_c = *e;
  *e = '\0';

  /* Look for the register.  Advance to next token if one was recognized.  */
  if ((reg = reg_lookup_internal (*s, class)) >= 0)
    *s = e;

  *e = save_c;
  if (regnop)
    *regnop = reg;
  return reg >= 0;
}

static bfd_boolean
arg_lookup (char **s, const char *const *array, size_t size, unsigned *regnop)
{
  const char *p = strchr (*s, ',');
  size_t i, len = p ? (size_t)(p - *s) : strlen (*s);

  if (len == 0)
    return FALSE;

  for (i = 0; i < size; i++)
    if (array[i] != NULL && strncmp (array[i], *s, len) == 0)
      {
	*regnop = i;
	*s += len;
	return TRUE;
      }

  return FALSE;
}

#define MAX_KEYWORD_LEN 32

static bfd_boolean
parse_nds_v5_field (const char **str, char name[MAX_KEYWORD_LEN])
{
  char *p = name;
  const char *str_t;

  str_t = *str;
  str_t--;
  while (ISALNUM (*str_t) || *str_t == '.' || *str_t == '_')
    *p++ = *str_t++;
  *p = '\0';

  if (strncmp (name, "nds_", 4) == 0)
    {
      *str = str_t;
      return TRUE;
    }
  else
    return FALSE;
}

/* For consistency checking, verify that all bits are specified either
   by the match/mask part of the instruction definition, or by the
   operand list.

   `length` could be 0, 4 or 8, 0 for auto detection.  */
static bfd_boolean
validate_riscv_insn (const struct riscv_opcode *opc, int length)
{
  const char *p = opc->args;
  char c;
  insn_t used_bits = opc->mask;
  int insn_width;
  insn_t required_bits;

  if (length == 0)
    insn_width = 8 * riscv_insn_length (opc->match);
  else
    insn_width = 8 * length;

  required_bits = ~0ULL >> (64 - insn_width);

  if ((used_bits & opc->match) != (opc->match & required_bits))
    {
      as_bad (_("internal: bad RISC-V opcode (mask error): %s %s"),
	      opc->name, opc->args);
      return FALSE;
    }

#define USE_BITS(mask,shift)	(used_bits |= ((insn_t)(mask) << (shift)))
  while (*p)
    switch (c = *p++)
      {
      case 'C': /* RVC */
	switch (c = *p++)
	  {
	  case 'a': used_bits |= ENCODE_RVC_J_IMM (-1U); break;
	  case 'c': break; /* RS1, constrained to equal sp */
	  case 'i': used_bits |= ENCODE_RVC_SIMM3(-1U); break;
	  case 'j': used_bits |= ENCODE_RVC_IMM (-1U); break;
	  case 'e':
	    switch (c = *p++)
	      {
	      case 'i':
		used_bits |= ENCODE_RVC_EX9IT_IMM (-1U); break;
	      case 't':
		used_bits |= ENCODE_RVC_EXECIT_IMM (-1U); break;
	      default:
		break;
	      }
	  case 'o': used_bits |= ENCODE_RVC_IMM (-1U); break;
	  case 'k': used_bits |= ENCODE_RVC_LW_IMM (-1U); break;
	  case 'l': used_bits |= ENCODE_RVC_LD_IMM (-1U); break;
	  case 'm': used_bits |= ENCODE_RVC_LWSP_IMM (-1U); break;
	  case 'n': used_bits |= ENCODE_RVC_LDSP_IMM (-1U); break;
	  case 'p': used_bits |= ENCODE_RVC_B_IMM (-1U); break;
	  case 's': USE_BITS (OP_MASK_CRS1S, OP_SH_CRS1S); break;
	  case 't': USE_BITS (OP_MASK_CRS2S, OP_SH_CRS2S); break;
	  case 'u': used_bits |= ENCODE_RVC_IMM (-1U); break;
	  case 'v': used_bits |= ENCODE_RVC_IMM (-1U); break;
	  case 'w': break; /* RS1S, constrained to equal RD */
	  case 'x': break; /* RS2S, constrained to equal RD */
	  case 'z': break; /* RS1, constrained to equal zero. */
	  case 'K': used_bits |= ENCODE_RVC_ADDI4SPN_IMM (-1U); break;
	  case 'L': used_bits |= ENCODE_RVC_ADDI16SP_IMM (-1U); break;
	  case 'M': used_bits |= ENCODE_RVC_SWSP_IMM (-1U); break;
	  case 'N': used_bits |= ENCODE_RVC_SDSP_IMM (-1U); break;
	  case 'U': break; /* RS1, constrained to equal RD */
	  case 'V': USE_BITS (OP_MASK_CRS2, OP_SH_CRS2); break;
	  case '<': used_bits |= ENCODE_RVC_IMM (-1U); break;
	  case '>': used_bits |= ENCODE_RVC_IMM (-1U); break;
	  case '8': used_bits |= ENCODE_RVC_UIMM8 (-1U); break;
	  case 'S': USE_BITS (OP_MASK_CRS1S, OP_SH_CRS1S); break;
	  case 'T': USE_BITS (OP_MASK_CRS2, OP_SH_CRS2); break;
	  case 'D': USE_BITS (OP_MASK_CRS2S, OP_SH_CRS2S); break;
	  case 'F': /* funct */
	    switch (c = *p++)
	      {
		case '6': USE_BITS (OP_MASK_CFUNCT6, OP_SH_CFUNCT6); break;
		case '4': USE_BITS (OP_MASK_CFUNCT4, OP_SH_CFUNCT4); break;
		case '3': USE_BITS (OP_MASK_CFUNCT3, OP_SH_CFUNCT3); break;
		case '2': USE_BITS (OP_MASK_CFUNCT2, OP_SH_CFUNCT2); break;
		default:
		  as_bad (_("internal: bad RISC-V opcode"
			    " (unknown operand type `CF%c'): %s %s"),
			  c, opc->name, opc->args);
		  return FALSE;
	      }
	    break;
	  default:
	    as_bad (_("internal: bad RISC-V opcode (unknown operand type `C%c'): %s %s"),
		    c, opc->name, opc->args);
	    return FALSE;
	  }
	break;
      case ',': break;
      case '+': break;
      case '(': break;
      case ')': break;
      case '<': USE_BITS (OP_MASK_SHAMTW,	OP_SH_SHAMTW);	break;
      case '>':	USE_BITS (OP_MASK_SHAMT,	OP_SH_SHAMT);	break;
      case 'A': break;
      case 'D':	USE_BITS (OP_MASK_RD,		OP_SH_RD);	break;
      case 'Z':	USE_BITS (OP_MASK_RS1,		OP_SH_RS1);	break;
      case 'E':	USE_BITS (OP_MASK_CSR,		OP_SH_CSR);	break;
      case 'I': break;
      case 'R':	USE_BITS (OP_MASK_RS3,		OP_SH_RS3);	break;
      case 'S':	USE_BITS (OP_MASK_RS1,		OP_SH_RS1);	break;
      case 'e': USE_BITS (OP_MASK_RS2,   	OP_SH_RS2);	break;
      case 'U':	USE_BITS (OP_MASK_RS1,		OP_SH_RS1);	/* fallthru */
      case 'T':	USE_BITS (OP_MASK_RS2,		OP_SH_RS2);	break;
      case 'd':	USE_BITS (OP_MASK_RD,		OP_SH_RD);	break;
      case 'm':	USE_BITS (OP_MASK_RM,		OP_SH_RM);	break;
      case 's':	USE_BITS (OP_MASK_RS1,		OP_SH_RS1);	break;
      case 't':	USE_BITS (OP_MASK_RS2,		OP_SH_RS2);	break;
      case 'r':	USE_BITS (OP_MASK_RS3,		OP_SH_RS3);	break;
      case 'P':	USE_BITS (OP_MASK_PRED,		OP_SH_PRED);	break;
      case 'Q':	USE_BITS (OP_MASK_SUCC,		OP_SH_SUCC);	break;
      case 'v': USE_BITS (OP_MASK_SV,		OP_SH_SV);	break;
      case 'o':
      case 'j': used_bits |= ENCODE_ITYPE_IMM (-1U); break;
      case 'a':	used_bits |= ENCODE_UJTYPE_IMM (-1U); break;
      case 'p':	used_bits |= ENCODE_SBTYPE_IMM (-1U); break;
      case 'q':	used_bits |= ENCODE_STYPE_IMM (-1U); break;
      case 'u':	used_bits |= ENCODE_UTYPE_IMM (-1U); break;
      case 'h': used_bits |= ENCODE_ITYPE_IMM (-1U); break;
      case 'l': used_bits |= ENCODE_ITYPE_IMM (-1U); break;
      case 'i': used_bits |= ENCODE_STYPE_IMM7 (-1U); break;
      case 'g': used_bits |= ENCODE_STYPE_IMM10 (-1U); break;
      case 'f': used_bits |= ENCODE_TYPE_IMM8 (-1U); break;
      case 'k': used_bits |= ENCODE_TYPE_CIMM6 (-1U); break;
      case 'z': break;
      case '[': break;
      case ']': break;
      case '0': break;
      case '1': break;
      case 'F': /* funct */
	switch (c = *p++)
	  {
	    case '7': USE_BITS (OP_MASK_FUNCT7, OP_SH_FUNCT7); break;
	    case '3': USE_BITS (OP_MASK_FUNCT3, OP_SH_FUNCT3); break;
	    case '2': USE_BITS (OP_MASK_FUNCT2, OP_SH_FUNCT2); break;
	    default:
	      as_bad (_("internal: bad RISC-V opcode"
			" (unknown operand type `F%c'): %s %s"),
		      c, opc->name, opc->args);
	    return FALSE;
	  }
	break;
      case 'O': /* opcode */
	switch (c = *p++)
	  {
	    case '4': USE_BITS (OP_MASK_OP, OP_SH_OP); break;
	    case '2': USE_BITS (OP_MASK_OP2, OP_SH_OP2); break;
	    default:
	      as_bad (_("internal: bad RISC-V opcode"
			" (unknown operand type `F%c'): %s %s"),
		      c, opc->name, opc->args);
	     return FALSE;
	  }
	break;

      case 'V': /* RVV */
	switch (c = *p++)
	  {
	  case 'd':
	  case 'f': USE_BITS (OP_MASK_VD, OP_SH_VD); break;
	  case 'e': USE_BITS (OP_MASK_VWD, OP_SH_VWD); break;
	  case 's': USE_BITS (OP_MASK_VS1, OP_SH_VS1); break;
	  case 't': USE_BITS (OP_MASK_VS2, OP_SH_VS2); break;
	  case 'u': USE_BITS (OP_MASK_VS1, OP_SH_VS1);
		    USE_BITS (OP_MASK_VS2, OP_SH_VS2); break;
	  case 'v': USE_BITS (OP_MASK_VD, OP_SH_VD);
		    USE_BITS (OP_MASK_VS1, OP_SH_VS1);
		    USE_BITS (OP_MASK_VS2, OP_SH_VS2); break;
	  case '0': break;
	  case 'c': used_bits |= ENCODE_RVV_VC_IMM (-1U); break;
	  case 'i':
	  case 'j':
	  case 'k': USE_BITS (OP_MASK_VIMM, OP_SH_VIMM); break;
	  case 'm': USE_BITS (OP_MASK_VMASK, OP_SH_VMASK); break;
	  default:
	    as_bad (_("internal: bad RISC-V opcode (unknown operand type `V%c'): %s %s"),
		    c, opc->name, opc->args);
	  }
	break;

      case 'H':
	switch (c = *p++)
	  {
	    case 'b': used_bits |= ENCODE_GPTYPE_SB_IMM (-1U); break;
	    case 'h': used_bits |= ENCODE_GPTYPE_SH_IMM (-1U); break;
	    case 'w': used_bits |= ENCODE_GPTYPE_SW_IMM (-1U); break;
	    case 'd': used_bits |= ENCODE_GPTYPE_SD_IMM (-1U); break;
	    default: break;
	  }
	break;
      case 'G':
	switch (c = *p++)
	  {
	    case 'b': used_bits |= ENCODE_GPTYPE_LB_IMM (-1U); break;
	    case 'h': used_bits |= ENCODE_GPTYPE_LH_IMM (-1U); break;
	    case 'w': used_bits |= ENCODE_GPTYPE_LW_IMM (-1U); break;
	    case 'd': used_bits |= ENCODE_GPTYPE_LD_IMM (-1U); break;
	    default: break;
	  }
	break;
      case 'n':
	{
	  char field_name[MAX_KEYWORD_LEN];
	  if (parse_nds_v5_field (&p, field_name))
	    {
	      if (strcmp (field_name, "nds_rc") == 0)
		USE_BITS (OP_MASK_RC, OP_SH_RC);
	      else if (strcmp (field_name, "nds_rdp") == 0)
		USE_BITS (OP_MASK_RD, OP_SH_RD);
	      else if (strcmp (field_name, "nds_rsp") == 0)
		USE_BITS (OP_MASK_RD, OP_SH_RS1);
	      else if (strcmp (field_name, "nds_rtp") == 0)
		USE_BITS (OP_MASK_RD, OP_SH_RS2);
	      else if (strcmp (field_name, "nds_i3u") == 0)
		used_bits |= ENCODE_PTYPE_IMM3U (-1U);
	      else if (strcmp (field_name, "nds_i4u") == 0)
		used_bits |= ENCODE_PTYPE_IMM4U (-1U);
	      else if (strcmp (field_name, "nds_i5u") == 0)
		used_bits |= ENCODE_PTYPE_IMM5U (-1U);
	      else if (strcmp (field_name, "nds_i6u") == 0)
		used_bits |= ENCODE_PTYPE_IMM6U (-1U);
	      else if (strcmp (field_name, "nds_i15s") == 0)
		used_bits |= ENCODE_PTYPE_IMM15S (-1U);
	      else
		as_bad (_("internal: bad RISC-V opcode "
			  "(unknown operand type `%s'): %s %s"),
			field_name, opc->name, opc->args);
	    }
	  else
	    as_bad (_("internal: bad RISC-V opcode "
		      "(unknown operand type `%c'): %s %s"),
		    c, opc->name, opc->args);
	}
	break;
      default:
	as_bad (_("internal: bad RISC-V opcode "
		  "(unknown operand type `%c'): %s %s"),
		c, opc->name, opc->args);
	return FALSE;
      }
#undef USE_BITS
  if (used_bits != required_bits)
    {
      as_bad (_("internal: bad RISC-V opcode (bits 0x%lx undefined): %s %s"),
	      ~(unsigned long)(used_bits & required_bits),
	      opc->name, opc->args);
      return FALSE;
    }
  return TRUE;
}

struct percent_op_match
{
  const char *str;
  bfd_reloc_code_real_type reloc;
};

/* Common hash table initialization function for
   instruction and .insn directive.  */
static struct hash_control *
init_opcode_hash (const struct riscv_opcode *opcodes,
		  bfd_boolean insn_directive_p)
{
  int i = 0;
  int length;
  struct hash_control *hash = hash_new ();
  while (opcodes[i].name)
    {
      const char *name = opcodes[i].name;
      const char *hash_error =
	hash_insert (hash, name, (void *) &opcodes[i]);

      if (hash_error)
	{
	  fprintf (stderr, _("internal error: can't hash `%s': %s\n"),
		   opcodes[i].name, hash_error);
	  /* Probably a memory allocation problem?  Give up now.  */
	  as_fatal (_("Broken assembler.  No assembly attempted."));
	}

      do
	{
	  if (opcodes[i].pinfo != INSN_MACRO)
	    {
	      if (insn_directive_p)
		length = ((name[0] == 'c') ? 2 : 4);
	      else
		length = 0; /* Let assembler determine the length. */
	      if (!validate_riscv_insn (&opcodes[i], length))
		as_fatal (_("Broken assembler.  No assembly attempted."));
	    }
	  else
	    gas_assert (!insn_directive_p);
	  ++i;
	}
      while (opcodes[i].name && !strcmp (opcodes[i].name, name));
    }

  return hash;
}

typedef struct ace_keyword
{
  const char *name;
  int value;
  uint64_t attr;
} ace_keyword_t;

typedef struct ace_operand
{
  const char *name;
  int bitpos;
  int bitsize;
  int shift;
  int hw_res;
  const char *hw_name;
} ace_op_t;

enum
{
  HW_GPR,
  HW_UINT,
  HW_INT,
  HW_ACR,
  HW_FPR,
  HW_VR
};

static struct hash_control *ace_keyword_hash = NULL;
static struct hash_control *ace_op_hash = NULL;
struct riscv_opcode *ace_opcs;
ace_keyword_t *ace_keys;
ace_op_t *ace_ops;
bfd_boolean ace_lib_load_success = FALSE;

static void
ace_encode_insn (unsigned int v, ace_op_t * ace_op, struct riscv_cl_insn *ip)
{
  unsigned int bit_value = v;

  bit_value <<= 32 - ace_op->bitsize;
  bit_value >>= 32 - ace_op->bitsize;

  bit_value <<= ace_op->bitpos - ace_op->bitsize + 1;

  ip->insn_opcode = (unsigned int) ip->insn_opcode | bit_value;
}

static void
ace_encode_insn_discrete (unsigned int v, char *op_name_discrete, const char *op, struct riscv_cl_insn *ip)
{
  bfd_boolean found_or_token = TRUE;
  unsigned bit_value = 0;
  char *psep, *pval = op_name_discrete + strlen(op);
  unsigned msb = 0, width = 0, width_acc = 0;

  while (found_or_token) {
	psep = strchr (pval, '_');
	*psep = '\0';
	msb = strtoul (pval, (char **) NULL, 10);
	pval = psep + 1;
	psep = strchr (pval, '|');
	if (psep)
	  *psep = '\0';
	else
	  found_or_token = FALSE;
	width = strtoul (pval, (char **) NULL, 10);

	bit_value = v >> width_acc;
	bit_value <<= 32 - width;
	bit_value >>= 32 - width;

	bit_value <<= msb - width + 1;

	ip->insn_opcode = (unsigned int) ip->insn_opcode | bit_value;
	width_acc += width;

	pval = psep + 1;
  }

}

static void
ace_ip (char **args, char **str, struct riscv_cl_insn *ip)
{
  bfd_boolean found_op_str_end = FALSE;
  char *pch = strchr (*args, ',');
  if (pch == NULL)
    {
      pch = strchr (*args, '\0');
      found_op_str_end = TRUE;
    }
  if (pch == NULL)
    as_fatal (_("Broken assembler.  No assembly attempted."));

  unsigned int op_name_size = pch - (*args + 1);
  char *op_name = malloc (op_name_size + 1);
  memcpy (op_name, *args + 1, op_name_size);
  memcpy (op_name + op_name_size, "\0", 1);

  bfd_boolean found_asm_end = FALSE;
  if (strchr (*str, ',') == NULL && strchr (*str, '\0') != NULL)
    found_asm_end = TRUE;

  bfd_boolean is_discrete = FALSE;
  char *por = strchr (op_name, '|');
  char *op_name_discrete = NULL;
  if (por != NULL)
    {
      is_discrete = TRUE;
      op_name_discrete = malloc (op_name_size + 1);
      strcpy (op_name_discrete, op_name);
      *por = '\0';
    }

  ace_op_t *ace_op = (ace_op_t *) hash_find (ace_op_hash, op_name);
  switch (ace_op->hw_res)
    {
    case HW_GPR:
	{
	  unsigned int regno;
	  if (reg_lookup (str, RCLASS_GPR, &regno))
	    ace_encode_insn (regno, ace_op, ip);

	  if (!found_asm_end)
	    *str += 1;
	}
      break;

    case HW_FPR:
	{
	  unsigned int regno;
	  if (reg_lookup (str, RCLASS_FPR, &regno))
	    ace_encode_insn (regno, ace_op, ip);

	  if (!found_asm_end)
	    *str += 1;
	}
      break;

    case HW_VR:
	{
	  unsigned int regno;
	  if (reg_lookup (str, RCLASS_VECR, &regno))
	    ace_encode_insn (regno, ace_op, ip);

	  if (!found_asm_end)
	    *str += 1;
	}
      break;

    case HW_UINT:
	{
	  char *p = strchr (*str, ',');
	  if (p == NULL)
	    p = strchr (*str, '\0');
	  if (p == NULL)
	    as_fatal (_("Broken assembler.  No IMM value is given."));
	  unsigned int imm_size = p - *str;
	  char *imm = malloc (imm_size + 1);
	  memcpy (imm, *str, imm_size);
	  memcpy (imm + imm_size, "\0", 1);
	  unsigned int imm_value = strtoul (imm, (char **) NULL, 0);

	  if (is_discrete)
	    ace_encode_insn_discrete (imm_value, op_name_discrete, "imm",  ip);
	  else
	    ace_encode_insn (imm_value, ace_op, ip);

	  if (found_asm_end)
	    *str += imm_size;
	  else
	    *str += imm_size + 1;
	}
      break;

    case HW_ACR:
	{
	  char *p = strchr (*str, ',');
	  if (p == NULL)
	    p = strchr (*str, '\0');
	  if (p == NULL)
	    as_fatal (_("No ACR register index is given."));
	  unsigned int reg_idx_size = p - *str;
	  char *reg_idx = malloc (reg_idx_size + 1);
	  memcpy (reg_idx, *str, reg_idx_size);
	  memcpy (reg_idx + reg_idx_size, "\0", 1);

	  ace_keyword_t *ace_reg =
	    (ace_keyword_t *) hash_find (ace_keyword_hash, reg_idx);
	  if (ace_reg != NULL)
	    if (is_discrete)
	      ace_encode_insn_discrete (ace_reg->value, op_name_discrete, ace_op->hw_name,  ip);
	    else
	      ace_encode_insn (ace_reg->value, ace_op, ip);
	  else
	    as_fatal (_("Wrong ACR register index (%s)) is given."), reg_idx);

	  if (found_asm_end)
	    *str += reg_idx_size;
	  else
	    *str += reg_idx_size + 1;
	}
      break;

    default:
      as_fatal (_("Broken assembler.  Cannot find field attribute."));
    }

  if (found_op_str_end == TRUE)
    *args = pch - 1;
  else
    *args = pch;
}

/* The information of architecture attribute.  */
struct arch_info
{
  const char *name;
  const char *v_major;
  const char *v_minor;
  int valid;
};

struct arch_info arch_info[] =
{
/* Standard arch info.  */
{"e", "1", "9", 0}, {"i", "2", "0", 0}, {"m", "2", "0", 0},
{"a", "2", "0", 0}, {"f", "2", "0", 0}, {"d", "2", "0", 0},
{"q", "2", "0", 0}, {"c", "2", "0", 0}, {"p", "2", "0", 0},

/* Terminate the list.  */
{0, 0, 0, 0}
};

const char *non_standard_arch_name[] = {"xv5"};

static struct hash_control *arch_info_hash = NULL;
#define DEFAULT_PRIV_SPEC 1
#define DEFAULT_PRIV_SPEC_MINOR 10
#define DEFAULT_PRIV_SPEC_REVISION 0
#define DEFAULT_STRICT_ALIGN 0
#define DEFAULT_STACK_ALIGN 0
#define DEFAULT_ICT_VERSION 1


/* This function is called once, at assembler startup time.  It should set up
   all the tables, etc. that the MD part of the assembler will need.  */

void
md_begin (void)
{
  unsigned long mach = xlen == 64 ? bfd_mach_riscv64 : bfd_mach_riscv32;

  if (! bfd_set_arch_mach (stdoutput, bfd_arch_riscv, mach))
    as_warn (_("Could not set architecture and machine"));

  op_hash = init_opcode_hash (riscv_opcodes, FALSE);
  insn_type_hash = init_opcode_hash (riscv_insn_types, TRUE);

  reg_names_hash = hash_new ();
  hash_reg_names (RCLASS_GPR, riscv_gpr_names_numeric, NGPR);
  hash_reg_names (RCLASS_GPR, riscv_gpr_names_abi, NGPR);
  hash_reg_names (RCLASS_GPR, riscv_gpr_names_standard, NGPR);
  hash_reg_names (RCLASS_FPR, riscv_fpr_names_numeric, NFPR);
  hash_reg_names (RCLASS_FPR, riscv_fpr_names_abi, NFPR);
  hash_reg_names (RCLASS_VECR, riscv_vecr_names_numeric, NVECR);
  hash_reg_names (RCLASS_VECM, riscv_vecm_names_numeric, NVECM);

  /* Add "fp" as an alias for "s0".  */
  hash_reg_name (RCLASS_GPR, "fp", 8);

  opcode_names_hash = hash_new ();
  init_opcode_names_hash ();

#define DECLARE_CSR(name, num) hash_reg_name (RCLASS_CSR, #name, num);
#define DECLARE_CSR_ALIAS(name, num) DECLARE_CSR(name, num);
#include "opcode/riscv-opc.h"
#undef DECLARE_CSR

  /* Set the default alignment for the text section.  */
  record_alignment (text_section, riscv_opts.rvc ? 1 : 2);

  if (ace_lib_load_success)
    {
      int i;
      riscv_add_subset (&riscv_subsets, "x", 0, 0);

      i = 0;
      while (ace_opcs[i].name)
	{
	  const char *name = ace_opcs[i].name;
	  const char *hash_error =
	    hash_insert (op_hash, name, (void *) &ace_opcs[i]);
	  if (hash_error)
	    {
	      fprintf (stderr, _("internal error: can't hash `%s': %s\n"),
		       name, hash_error);
	      as_fatal (_("Broken assembler.  No assembly attempted."));
	    }
	  i++;
	}

      ace_keyword_hash = hash_new ();
      i = 0;
      while (ace_keys[i].name)
	{
	  const char *name = ace_keys[i].name;
	  const char *hash_error =
	    hash_insert (ace_keyword_hash, name, (void *) &ace_keys[i]);
	  if (hash_error)
	    {
	      fprintf (stderr, _("internal error: can't hash `%s': %s\n"),
		       name, hash_error);
	      as_fatal (_("Broken assembler.  No assembly attempted."));
	    }
	  i++;
	}

      ace_op_hash = hash_new ();
      i = 0;
      while (ace_ops[i].name)
	{
	  const char *name = ace_ops[i].name;
	  const char *hash_error =
	    hash_insert (ace_op_hash, name, (void *) &ace_ops[i]);
	  if (hash_error)
	    {
	      fprintf (stderr, _("internal error: can't hash `%s': %s\n"),
		       name, hash_error);
	      as_fatal (_("Broken assembler.  No assembly attempted."));
	    }
	  i++;
	}
    }
}

static insn_t
riscv_apply_const_reloc (bfd_reloc_code_real_type reloc_type, bfd_vma value)
{
  switch (reloc_type)
    {
    case BFD_RELOC_32:
      return value;

    case BFD_RELOC_RISCV_HI20:
    case BFD_RELOC_RISCV_LALO_HI20:
    case BFD_RELOC_RISCV_ICT_HI20:
      return ENCODE_UTYPE_IMM (RISCV_CONST_HIGH_PART (value));

    case BFD_RELOC_RISCV_LO12_S:
      return ENCODE_STYPE_IMM (value);

    case BFD_RELOC_RISCV_LO12_I:
    case BFD_RELOC_RISCV_LALO_LO12_I:
    case BFD_RELOC_RISCV_ICT_LO12_I:
      return ENCODE_ITYPE_IMM (value);

    default:
      abort ();
    }
}

static void
riscv_make_nops (char *buf, bfd_vma bytes)
{
  bfd_vma i = 0;

  if (bytes % 2 == 1)
    buf[i++] = 0;

  if ((bytes - i) % 4 == 2)
    {
      md_number_to_chars (buf + i, RVC_NOP, 2);
      i += 2;
    }

  for ( ; i < bytes; i += 4)
    md_number_to_chars (buf + i, RISCV_NOP, 4);
}

static int align_call = 0;

static void
append_insn (struct riscv_cl_insn *ip, expressionS *address_expr,
	     bfd_reloc_code_real_type reloc_type)
{
  dwarf2_emit_insn (0);

  if (reloc_type != BFD_RELOC_UNUSED)
    {
      reloc_howto_type *howto;

      gas_assert (address_expr);
      if (reloc_type == BFD_RELOC_12_PCREL
	  || reloc_type == BFD_RELOC_RISCV_JMP
	  || reloc_type == BFD_RELOC_RISCV_10_PCREL)
	{
	  int j = reloc_type == BFD_RELOC_RISCV_JMP;
	  int best_case = riscv_insn_length (ip->insn_opcode);
	  int range = ENUM_BRANCH_RANGE (reloc_type);
	  unsigned worst_case = relaxed_branch_length (NULL, NULL, 0);
	  add_relaxed_insn (ip, worst_case, best_case,
			    RELAX_BRANCH_ENCODE (j, best_case == 2,
						 worst_case, range),
			    address_expr->X_add_symbol,
			    address_expr->X_add_number);
	  return;
	}
      else if (ip->cmodel.method == METHOD_DEFAULT)
	{
	  howto = bfd_reloc_type_lookup (stdoutput, reloc_type);
	  if (howto == NULL)
	    as_bad (_("Unsupported RISC-V relocation number %d"), reloc_type);

	  ip->fixp = fix_new_exp (ip->frag, ip->where,
				  bfd_get_reloc_size (howto),
				  address_expr, FALSE, reloc_type);

	  ip->fixp->fx_tcbit = riscv_opts.relax;
	}
    }

  if (ip->cmodel.method == METHOD_DEFAULT)
    add_fixed_insn (ip);
  else if  (ip->cmodel.method == METHOD_VARIABLE)
    {
      add_insn_grow (ip);
      if (ip->cmodel.state == 0)
	{
	  int length = ip->cmodel.offset + 4;
	  add_insn_grow_done (ip, length, 0,
			      RELAX_CMODEL_ENCODE (ip->cmodel.type, length, ip->cmodel.index),
			      address_expr->X_add_symbol,
			      address_expr->X_add_number);
	}
      return;
    }
  else
    as_fatal (_("internal error: invalid append_insn method!"));

  if (reloc_type == BFD_RELOC_RISCV_CALL
      || reloc_type == BFD_RELOC_RISCV_CALL_PLT
      || reloc_type == BFD_RELOC_RISCV_HI20
      || reloc_type == BFD_RELOC_RISCV_PCREL_HI20
      || reloc_type == BFD_RELOC_RISCV_TPREL_HI20
      || reloc_type == BFD_RELOC_RISCV_TPREL_ADD)
    {
      frag_wane (frag_now);
      frag_new (0);
    }

  if (optimize && riscv_opts.verbatim && riscv_opts.relax && riscv_opts.rvc
      && ((align_call && ((ip->insn_opcode >> 7 & 0x1f)) != 0)
	  || (!align_call && ((ip->insn_opcode & MASK_JALR) == MATCH_JALR))))
    {
      char *nops = frag_more (4);
      expressionS ex;
      ex.X_op = O_constant;
      ex.X_add_number = 4;

      riscv_make_nops (nops, 4);
      fix_new_exp (frag_now, nops - frag_now->fr_literal, 0,
		   &ex, FALSE, BFD_RELOC_RISCV_ALIGN_BTB);
    }
  align_call = 0;

  if (reloc_type == BFD_RELOC_RISCV_CALL)
    align_call = 1;
}

/* Build an instruction created by a macro expansion.  This is passed
   a pointer to the count of instructions created so far, an
   expression, the name of the instruction to build, an operand format
   string, and corresponding arguments.  */

static void
macro_build (expressionS *ep, const char *name, const char *fmt, ...)
{
  const struct riscv_opcode *mo;
  struct riscv_cl_insn insn;
  bfd_reloc_code_real_type r;
  va_list args;

  insn.cmodel.method = METHOD_DEFAULT;
  va_start (args, fmt);

  r = BFD_RELOC_UNUSED;
  mo = (struct riscv_opcode *) hash_find (op_hash, name);
  gas_assert (mo);

  /* Find a non-RVC variant of the instruction.  append_insn will compress
     it if possible.  */
  while (riscv_insn_length (mo->match) < 4)
    mo++;
  gas_assert (strcmp (name, mo->name) == 0);

  create_insn (&insn, mo);
  for (;;)
    {
      switch (*fmt++)
	{
	case 'd':
	  INSERT_OPERAND (RD, insn, va_arg (args, int));
	  continue;

	case 's':
	  INSERT_OPERAND (RS1, insn, va_arg (args, int));
	  continue;

	case 't':
	  INSERT_OPERAND (RS2, insn, va_arg (args, int));
	  continue;

	case '>':
	  INSERT_OPERAND (SHAMT, insn, va_arg (args, int));
	  continue;

	case 'j':
	case 'u':
	case 'q':
	  gas_assert (ep != NULL);
	  r = va_arg (args, int);
	  continue;

	case '\0':
	  break;
	case ',':
	  continue;

	case 'V': /* RVV */
	  {
	    switch (*fmt++)
	      {
	      case 'd':
		INSERT_OPERAND (VD, insn, va_arg (args, int));
		continue;

	      case 's':
		INSERT_OPERAND (VS1, insn, va_arg (args, int));
		continue;

	      case 't':
		INSERT_OPERAND (VS2, insn, va_arg (args, int));
		continue;

	      case 'm':
		{
		  int reg = va_arg (args, int);
		  if (reg == -1)
		    {
		      INSERT_OPERAND (VMASK, insn, 1);
		      continue;
		    }
		  else if (reg == 0)
		    {
		      INSERT_OPERAND (VMASK, insn, 0);
		      continue;
		    }
		}
		/* fallthru */
	      }
	  }
	  /* fallthru */

	case 'C':
	  insn.cmodel.method = METHOD_VARIABLE;
	  insn.cmodel.state = va_arg (args, int);
	  insn.cmodel.type = va_arg (args, int);
	  insn.cmodel.index = va_arg (args, int);
	  insn.cmodel.offset = va_arg (args, int);
	  continue;

	default:
	  as_fatal (_("internal error: invalid macro"));
	}
      break;
    }
  va_end (args);
  gas_assert (r == BFD_RELOC_UNUSED ? ep == NULL : ep != NULL);

  append_insn (&insn, ep, r);
}

/* Sign-extend 32-bit mode constants that have bit 31 set and all higher bits
   unset.  */
static void
normalize_constant_expr (expressionS *ex)
{
  if (xlen > 32)
    return;
  if ((ex->X_op == O_constant || ex->X_op == O_symbol)
      && IS_ZEXT_32BIT_NUM (ex->X_add_number))
    ex->X_add_number = (((ex->X_add_number & 0xffffffff) ^ 0x80000000)
			- 0x80000000);
}

/* Fail if an expression EX is not a constant.  IP is the instruction using EX.
   MAYBE_CSR is true if the symbol may be an unrecognized CSR name.  */

static void
check_absolute_expr (struct riscv_cl_insn *ip, expressionS *ex,
		     bfd_boolean maybe_csr)
{
  if (ex->X_op == O_big)
    as_bad (_("unsupported large constant"));
  else if (maybe_csr && ex->X_op == O_symbol)
    as_bad (_("unknown CSR `%s'"),
	    S_GET_NAME (ex->X_add_symbol));
  else if (ex->X_op != O_constant)
    as_bad (_("Instruction %s requires absolute expression"),
	    ip->insn_mo->name);
  normalize_constant_expr (ex);
}

static symbolS *
make_internal_label (void)
{
  return (symbolS *) local_symbol_make (FAKE_LABEL_NAME, now_seg,
					(valueT) frag_now_fix (), frag_now);
}

#define CMODEL_SUBSECTION 8100
#define CMODEL_SYMBOL_PREFIX ".Laddr"
#define CMODEL_SECTION_ALIGN 3
#define CMODEL_SECTION_ENTRY_SIZE (1u << CMODEL_SECTION_ALIGN)

static
void  make_indirect_symbol (expressionS *ep, expressionS *ep_ind)
{
  char buf[0x100];
  char isym_name[0x100];
  symbolS *isym;
  const char *seg_name = segment_name (now_seg);
  const char *sym_name = S_GET_NAME (ep->X_add_symbol);
  valueT sym_addend = ep->X_add_number;

  sprintf (isym_name, "%s_%s_%s_%lx", CMODEL_SYMBOL_PREFIX, seg_name,
	   sym_name, (unsigned long)sym_addend);
  isym = symbol_find (isym_name);
  if (isym == NULL)
    {
      const char *sec_name = segment_name (now_seg);
      char *save_in;
      sprintf (buf, "%s, %d", sec_name, CMODEL_SUBSECTION);
      save_in = input_line_pointer;
      input_line_pointer = buf;
      obj_elf_section (1);
      input_line_pointer = save_in;
      isym = colon (isym_name);
      frag_var (rs_machine_dependent, CMODEL_SECTION_ENTRY_SIZE, 0,
		RELAX_CMODEL_ENCODE (TYPE_IS, CMODEL_SECTION_ENTRY_SIZE, 0),
		ep->X_add_symbol, ep->X_add_number, NULL);
      obj_elf_popsection (0);
    }

  ep_ind->X_op = O_symbol;
  ep_ind->X_add_symbol = isym;
  ep_ind->X_add_number = 0;
  ep_ind->X_md = 0;
}

/* Load an entry from the GOT.  */
static void
pcrel_access (int destreg, int tempreg, expressionS *ep,
	      const char *lo_insn, const char *lo_pattern,
	      bfd_reloc_code_real_type hi_reloc,
	      bfd_reloc_code_real_type lo_reloc)
{
  if (hi_reloc == BFD_RELOC_RISCV_PCREL_HI20
      && is_cmodel_relaxable (ep->X_add_symbol, now_seg))
    {
      gas_assert (ep->X_op == O_symbol);
      char lo_pattern_ex[0x100];
      int index, type;
      expressionS ep_ind, ep_ref;
      bfd_boolean is_la = strcmp (lo_insn, "addi") == 0;
      bfd_boolean is_st = lo_reloc == BFD_RELOC_RISCV_PCREL_LO12_S;
      make_indirect_symbol (ep, &ep_ind);
      ep_ref.X_op = O_symbol;
      ep_ref.X_add_symbol = make_internal_label ();
      ep_ref.X_add_number = 0;
      ep_ref.X_md = 0;
      type = is_st ? TYPE_ST : is_la ? TYPE_LA : TYPE_LD;

      strcpy (lo_pattern_ex, lo_pattern);
      strcat (lo_pattern_ex, ",C");

      index = CSI_INDIRECT_SYMBOL;
      macro_build (&ep_ind, "nop", "j,C", hi_reloc, 0, type, index, 0);

      index++;
      macro_build (&ep_ref, "nop", "j,C", hi_reloc, 0, type, index, 0);

      index++;
      macro_build (&ep_ind, "auipc", "d,u,C", tempreg, hi_reloc, 1, type, index, 0);
      macro_build (&ep_ref, "ld", "d,s,j,C", tempreg, tempreg, hi_reloc, 1, type, index, 4);
      macro_build (ep, lo_insn, lo_pattern_ex, destreg, tempreg, lo_reloc, 0, type, index, 8);

    }
  else
    {
      expressionS ep2;
      ep2.X_op = O_symbol;
      ep2.X_add_symbol = make_internal_label ();
      ep2.X_add_number = 0;
      ep2.X_md = 0;

      macro_build (ep, "auipc", "d,u", tempreg, hi_reloc);
      macro_build (&ep2, lo_insn, lo_pattern, destreg, tempreg, lo_reloc);
    }
}

static void
pcrel_load (int destreg, int tempreg, expressionS *ep, const char *lo_insn,
	    bfd_reloc_code_real_type hi_reloc,
	    bfd_reloc_code_real_type lo_reloc)
{
  gas_assert (lo_reloc == BFD_RELOC_RISCV_PCREL_LO12_I);
  pcrel_access (destreg, tempreg, ep, lo_insn, "d,s,j", hi_reloc, lo_reloc);
}

static void
pcrel_store (int srcreg, int tempreg, expressionS *ep, const char *lo_insn,
	     bfd_reloc_code_real_type hi_reloc,
	     bfd_reloc_code_real_type lo_reloc)
{
  gas_assert (lo_reloc == BFD_RELOC_RISCV_PCREL_LO12_S);
  pcrel_access (srcreg, tempreg, ep, lo_insn, "t,s,q", hi_reloc, lo_reloc);
}

/* PC-relative function call using AUIPC/JALR, relaxed to JAL.  */
static void
 riscv_call (int destreg, int tempreg, expressionS *ep,
	    bfd_reloc_code_real_type reloc)
{
  if (reloc == BFD_RELOC_RISCV_CALL
      && is_cmodel_relaxable (ep->X_add_symbol, now_seg))
    {
      gas_assert (ep->X_op == O_symbol);
      int index;
      expressionS ep_ind, ep_ref;
      make_indirect_symbol (ep, &ep_ind);
      ep_ref.X_op = O_symbol;
      ep_ref.X_add_symbol = make_internal_label ();
      ep_ref.X_add_number = 0;
      ep_ref.X_md = 0;

      index = CSI_INDIRECT_SYMBOL;
      macro_build (&ep_ind, "nop", "j,C", reloc, 0, TYPE_JX, index, 0);

      index++;
      macro_build (&ep_ref, "nop", "j,C", reloc, 0, TYPE_JX, index, 0);

      index++;
      macro_build (&ep_ind, "auipc", "d,u,C", tempreg, reloc, 1, TYPE_JX, index, 0);
      macro_build (&ep_ref, "ld", "d,s,j,C", tempreg, tempreg, reloc, 1, TYPE_JX, index, 4);
      macro_build (ep, "jalr", "d,s,j,C", destreg, tempreg, reloc, 0, TYPE_JX, index, 8);

      index++;
      macro_build (ep, "auipc", "d,u,C", tempreg, reloc, 1, TYPE_JX, index, 0);
      macro_build (ep, "jalr", "d,s,j,C", destreg, tempreg, reloc, 0, TYPE_JX, index, 4);
    }
  else
    {
      macro_build (ep, "auipc", "d,u", tempreg, reloc);
      macro_build (NULL, "jalr", "d,s", destreg, tempreg);
    }
}

/* Load an integer constant into a register.  */

static void
load_const (int reg, expressionS *ep)
{
  int shift = RISCV_IMM_BITS;
  expressionS upper = *ep, lower = *ep;
  lower.X_add_number = (int32_t) ep->X_add_number << (32-shift) >> (32-shift);
  upper.X_add_number -= lower.X_add_number;

  if (ep->X_op != O_constant)
    {
      as_bad (_("unsupported large constant"));
      return;
    }

  if (xlen > 32 && !IS_SEXT_32BIT_NUM (ep->X_add_number))
    {
      /* Reduce to a signed 32-bit constant using SLLI and ADDI.  */
      while (((upper.X_add_number >> shift) & 1) == 0)
	shift++;

      upper.X_add_number = (int64_t) upper.X_add_number >> shift;
      load_const (reg, &upper);

      macro_build (NULL, "slli", "d,s,>", reg, reg, shift);
      if (lower.X_add_number != 0)
	macro_build (&lower, "addi", "d,s,j", reg, reg, BFD_RELOC_RISCV_LO12_I);
    }
  else
    {
      /* Simply emit LUI and/or ADDI to build a 32-bit signed constant.  */
      int hi_reg = 0;

      if (upper.X_add_number != 0)
	{
	  macro_build (ep, "lui", "d,u", reg, BFD_RELOC_RISCV_HI20);
	  hi_reg = reg;
	}

      if (lower.X_add_number != 0 || hi_reg == 0)
	macro_build (ep, ADD32_INSN, "d,s,j", reg, hi_reg,
		     BFD_RELOC_RISCV_LO12_I);
    }
}

/* Expand RISC-V Vector macros into one of more instructions.  */

static void
vector_macro (struct riscv_cl_insn *ip)
{
  int vd = (ip->insn_opcode >> OP_SH_VD) & OP_MASK_VD;
  int vs1 = (ip->insn_opcode >> OP_SH_VS1) & OP_MASK_VS1;
  int vs2 = (ip->insn_opcode >> OP_SH_VS2) & OP_MASK_VS2;
  int vm = (ip->insn_opcode >> OP_SH_VMASK) & OP_MASK_VMASK;
  int vtemp = (ip->insn_opcode >> OP_SH_VFUNCT6) & OP_MASK_VFUNCT6;
  int mask = ip->insn_mo->mask;

  switch (mask)
    {
    case M_VMSGE:
      if (vm)
	{
	  /* Unmasked.  */
	  macro_build (NULL, "vmslt.vx", "Vd,Vt,sVm", vd, vs2, vs1, -1);
	  macro_build (NULL, "vmnand.mm", "Vd,Vt,Vs", vd, vs2, vs1);
	}
      else
	{
	  /* Masked w/ v0.  */
	  if (vtemp != 0)
	    {
	      macro_build (NULL, "vmslt.vx", "Vd,Vt,s", vtemp, vs2, vs1);
	      macro_build (NULL, "vmandnot.mm", "Vd,Vt,Vs", vd, vm, vtemp);
	    }
	  else if (vd != vm)
	    {
	      macro_build (NULL, "vmslt.vx", "Vd,Vt,sVm", vd, vs2, vs1, vm);
	      macro_build (NULL, "vmxor.mm", "Vd,Vt,Vs", vd, vd, vm);
	    }
	  else
	    as_bad (_("must provide temp if destination overlaps mask"));
	}
      break;

    case M_VMSGEU:
      if (vm)
	{
	  /* Unmasked.  */
	  macro_build (NULL, "vmsltu.vx", "Vd,Vt,sVm", vd, vs2, vs1, -1);
	  macro_build (NULL, "vmnand.mm", "Vd,Vt,Vs", vd, vs2, vs1);
	}
      else
	{
	  /* Masked w/ v0.  */
	  if (vtemp != 0)
	    {
	      macro_build (NULL, "vmsltu.vx", "Vd,Vt,s", vtemp, vs2, vs1);
	      macro_build (NULL, "vmandnot.mm", "Vd,Vt,Vs", vd, vm, vtemp);
	    }
	  else if (vd != vm)
	    {
	      macro_build (NULL, "vmsltu.vx", "Vd,Vt,sVm", vd, vs2, vs1, vm);
	      macro_build (NULL, "vmxor.mm", "Vd,Vt,Vs", vd, vd, vm);
	    }
	  else
	    as_bad (_("must provide temp if destination overlaps mask"));
	}
      break;

    default:
      as_bad (_("Macro %s not implemented"), ip->insn_mo->name);
      break;
    }
}

/* Expand RISC-V assembly macros into one or more instructions.  */
static void
macro (struct riscv_cl_insn *ip, expressionS *imm_expr,
       bfd_reloc_code_real_type *imm_reloc)
{
  int rd = (ip->insn_opcode >> OP_SH_RD) & OP_MASK_RD;
  int rs1 = (ip->insn_opcode >> OP_SH_RS1) & OP_MASK_RS1;
  int rs2 = (ip->insn_opcode >> OP_SH_RS2) & OP_MASK_RS2;
  int mask = ip->insn_mo->mask;

  switch (mask)
    {
    case M_LI:
      load_const (rd, imm_expr);
      break;

    case M_LA:
    case M_LLA:
      /* Load the address of a symbol into a register.  */
      if (!IS_SEXT_32BIT_NUM (imm_expr->X_add_number))
	as_bad (_("offset too large"));

      if (rd == 2)
	as_warn (_("Load address into sp directly may let sp "
		   "unaligned for auipc insn.\n"
		   "Please load address into a temp register!\n"
		   "\"la/lla a0, value; mv sp, a0\""));

      if (imm_expr->X_op == O_constant)
	load_const (rd, imm_expr);
      else if (riscv_opts.pic && mask == M_LA) /* Global PIC symbol */
	pcrel_load (rd, rd, imm_expr, LOAD_ADDRESS_INSN,
		    BFD_RELOC_RISCV_GOT_HI20, BFD_RELOC_RISCV_PCREL_LO12_I);
      else /* Local PIC symbol, or any non-PIC symbol */
	pcrel_load (rd, rd, imm_expr, "addi",
		    BFD_RELOC_RISCV_PCREL_HI20, BFD_RELOC_RISCV_PCREL_LO12_I);
      break;

    case M_LA_LO:
      macro_build (imm_expr, "lui", "d,u", rd, BFD_RELOC_RISCV_LALO_HI20);
      macro_build (imm_expr, ADD32_INSN, "d,s,j", rd, rd, BFD_RELOC_RISCV_LALO_LO12_I);
      break;

    case M_LA_TLS_GD:
      pcrel_load (rd, rd, imm_expr, "addi",
		  BFD_RELOC_RISCV_TLS_GD_HI20, BFD_RELOC_RISCV_PCREL_LO12_I);
      break;

    case M_LA_TLS_IE:
      pcrel_load (rd, rd, imm_expr, LOAD_ADDRESS_INSN,
		  BFD_RELOC_RISCV_TLS_GOT_HI20, BFD_RELOC_RISCV_PCREL_LO12_I);
      break;

    case M_LB:
      pcrel_load (rd, rd, imm_expr, "lb",
		  BFD_RELOC_RISCV_PCREL_HI20, BFD_RELOC_RISCV_PCREL_LO12_I);
      break;

    case M_LBU:
      pcrel_load (rd, rd, imm_expr, "lbu",
		  BFD_RELOC_RISCV_PCREL_HI20, BFD_RELOC_RISCV_PCREL_LO12_I);
      break;

    case M_LH:
      pcrel_load (rd, rd, imm_expr, "lh",
		  BFD_RELOC_RISCV_PCREL_HI20, BFD_RELOC_RISCV_PCREL_LO12_I);
      break;

    case M_LHU:
      pcrel_load (rd, rd, imm_expr, "lhu",
		  BFD_RELOC_RISCV_PCREL_HI20, BFD_RELOC_RISCV_PCREL_LO12_I);
      break;

    case M_LW:
      pcrel_load (rd, rd, imm_expr, "lw",
		  BFD_RELOC_RISCV_PCREL_HI20, BFD_RELOC_RISCV_PCREL_LO12_I);
      break;

    case M_LWU:
      pcrel_load (rd, rd, imm_expr, "lwu",
		  BFD_RELOC_RISCV_PCREL_HI20, BFD_RELOC_RISCV_PCREL_LO12_I);
      break;

    case M_LD:
      pcrel_load (rd, rd, imm_expr, "ld",
		  BFD_RELOC_RISCV_PCREL_HI20, BFD_RELOC_RISCV_PCREL_LO12_I);
      break;

    case M_FLH:
      pcrel_load (rd, rs1, imm_expr, "flh",
		  BFD_RELOC_RISCV_PCREL_HI20, BFD_RELOC_RISCV_PCREL_LO12_I);
      break;

    case M_FLW:
      pcrel_load (rd, rs1, imm_expr, "flw",
		  BFD_RELOC_RISCV_PCREL_HI20, BFD_RELOC_RISCV_PCREL_LO12_I);
      break;

    case M_FLD:
      pcrel_load (rd, rs1, imm_expr, "fld",
		  BFD_RELOC_RISCV_PCREL_HI20, BFD_RELOC_RISCV_PCREL_LO12_I);
      break;

    case M_SB:
      pcrel_store (rs2, rs1, imm_expr, "sb",
		   BFD_RELOC_RISCV_PCREL_HI20, BFD_RELOC_RISCV_PCREL_LO12_S);
      break;

    case M_SH:
      pcrel_store (rs2, rs1, imm_expr, "sh",
		   BFD_RELOC_RISCV_PCREL_HI20, BFD_RELOC_RISCV_PCREL_LO12_S);
      break;

    case M_SW:
      pcrel_store (rs2, rs1, imm_expr, "sw",
		   BFD_RELOC_RISCV_PCREL_HI20, BFD_RELOC_RISCV_PCREL_LO12_S);
      break;

    case M_SD:
      pcrel_store (rs2, rs1, imm_expr, "sd",
		   BFD_RELOC_RISCV_PCREL_HI20, BFD_RELOC_RISCV_PCREL_LO12_S);
      break;

    case M_FSH:
      pcrel_store (rs2, rs1, imm_expr, "fsh",
		   BFD_RELOC_RISCV_PCREL_HI20, BFD_RELOC_RISCV_PCREL_LO12_S);
      break;

    case M_FSW:
      pcrel_store (rs2, rs1, imm_expr, "fsw",
		   BFD_RELOC_RISCV_PCREL_HI20, BFD_RELOC_RISCV_PCREL_LO12_S);
      break;

    case M_FSD:
      pcrel_store (rs2, rs1, imm_expr, "fsd",
		   BFD_RELOC_RISCV_PCREL_HI20, BFD_RELOC_RISCV_PCREL_LO12_S);
      break;

    case M_CALL:
      riscv_call (rd, rs1, imm_expr, *imm_reloc);
      break;

    case M_VMSGE:
    case M_VMSGEU:
      vector_macro (ip);
      break;

    default:
      as_bad (_("Macro %s not implemented"), ip->insn_mo->name);
      break;
    }
}

static const struct percent_op_match percent_op_utype[] =
{
  {"%tprel_hi", BFD_RELOC_RISCV_TPREL_HI20},
  {"%pcrel_hi", BFD_RELOC_RISCV_PCREL_HI20},
  {"%tls_ie_pcrel_hi", BFD_RELOC_RISCV_TLS_GOT_HI20},
  {"%tls_gd_pcrel_hi", BFD_RELOC_RISCV_TLS_GD_HI20},
  {"%hi", BFD_RELOC_RISCV_HI20},
  {"%got_hi", BFD_RELOC_RISCV_GOT_HI20},
  {0, 0}
};

static const struct percent_op_match percent_op_itype[] =
{
  {"%lo", BFD_RELOC_RISCV_LO12_I},
  {"%tprel_lo", BFD_RELOC_RISCV_TPREL_LO12_I},
  {"%pcrel_lo", BFD_RELOC_RISCV_PCREL_LO12_I},
  {0, 0}
};

static const struct percent_op_match percent_op_stype[] =
{
  {"%lo", BFD_RELOC_RISCV_LO12_S},
  {"%tprel_lo", BFD_RELOC_RISCV_TPREL_LO12_S},
  {"%pcrel_lo", BFD_RELOC_RISCV_PCREL_LO12_S},
  {0, 0}
};

static const struct percent_op_match percent_op_rtype[] =
{
  {"%tprel_add", BFD_RELOC_RISCV_TPREL_ADD},
  {0, 0}
};

static const struct percent_op_match percent_op_null[] =
{
  {0, 0}
};

/* Return true if *STR points to a relocation operator.  When returning true,
   move *STR over the operator and store its relocation code in *RELOC.
   Leave both *STR and *RELOC alone when returning false.  */

static bfd_boolean
parse_relocation (char **str, bfd_reloc_code_real_type *reloc,
		  const struct percent_op_match *percent_op)
{
  for ( ; percent_op->str; percent_op++)
    if (strncasecmp (*str, percent_op->str, strlen (percent_op->str)) == 0)
      {
	int len = strlen (percent_op->str);

	if (!ISSPACE ((*str)[len]) && (*str)[len] != '(')
	  continue;

	*str += strlen (percent_op->str);
	*reloc = percent_op->reloc;

	/* Check whether the output BFD supports this relocation.
	   If not, issue an error and fall back on something safe.  */
	if (*reloc != BFD_RELOC_UNUSED
	    && !bfd_reloc_type_lookup (stdoutput, *reloc))
	  {
	    as_bad ("relocation %s isn't supported by the current ABI",
		    percent_op->str);
	    *reloc = BFD_RELOC_UNUSED;
	  }
	return TRUE;
      }
  return FALSE;
}

static void
my_getExpression (expressionS *ep, char *str)
{
  char *save_in;

  save_in = input_line_pointer;
  input_line_pointer = str;
  expression (ep);
  expr_end = input_line_pointer;
  input_line_pointer = save_in;
}

/* Parse string STR as a 16-bit relocatable operand.  Store the
   expression in *EP and the relocation, if any, in RELOC.
   Return the number of relocation operators used (0 or 1).

   On exit, EXPR_END points to the first character after the expression.  */

static size_t
my_getSmallExpression (expressionS *ep, bfd_reloc_code_real_type *reloc,
		       char *str, const struct percent_op_match *percent_op)
{
  size_t reloc_index;
  unsigned crux_depth, str_depth, regno;
  char *crux;

  /* First, check for integer registers.  No callers can accept a reg, but
     we need to avoid accidentally creating a useless undefined symbol below,
     if this is an instruction pattern that can't match.  A glibc build fails
     if this is removed.  */
  if (reg_lookup (&str, RCLASS_GPR, &regno))
    {
      ep->X_op = O_register;
      ep->X_add_number = regno;
      expr_end = str;
      return 0;
    }

  /* Search for the start of the main expression.
     End the loop with CRUX pointing to the start
     of the main expression and with CRUX_DEPTH containing the number
     of open brackets at that point.  */
  reloc_index = -1;
  str_depth = 0;
  do
    {
      reloc_index++;
      crux = str;
      crux_depth = str_depth;

      /* Skip over whitespace and brackets, keeping count of the number
	 of brackets.  */
      while (*str == ' ' || *str == '\t' || *str == '(')
	if (*str++ == '(')
	  str_depth++;
    }
  while (*str == '%'
	 && reloc_index < 1
	 && parse_relocation (&str, reloc, percent_op));

  my_getExpression (ep, crux);
  str = expr_end;

  /* Match every open bracket.  */
  while (crux_depth > 0 && (*str == ')' || *str == ' ' || *str == '\t'))
    if (*str++ == ')')
      crux_depth--;

  if (crux_depth > 0)
    as_bad ("unclosed '('");

  expr_end = str;

  return reloc_index;
}

/* Parse string STR as a vsetvli operand.  Store the expression in *EP.
   On exit, EXPR_END points to the first character after the expression.  */

static void
my_getVsetvliExpression (expressionS *ep, char *str)
{
  unsigned int vsew_value = 0, vlen_value = 0, vediv_value = 0;
  int vsew_found = FALSE, vlen_found = FALSE, vediv_found = FALSE;

  if (arg_lookup (&str, riscv_vsew, ARRAY_SIZE (riscv_vsew), &vsew_value))
    {
      if (*str == ',')
	++str;
      if (vsew_found)
	as_bad (_("multiple vsew constants"));
      vsew_found = TRUE;
    }
  if (arg_lookup (&str, riscv_vlen, ARRAY_SIZE (riscv_vlen), &vlen_value))
    {
      if (*str == ',')
	++str;
      if (vlen_found)
	as_bad (_("multiple vlen constants"));
      vlen_found = TRUE;
    }
  if (arg_lookup (&str, riscv_vediv, ARRAY_SIZE (riscv_vediv), &vediv_value))
    {
      if (*str == ',')
	++str;
      if (vediv_found)
	as_bad (_("multiple vediv constants"));
      vediv_found = TRUE;
    }

  if (vsew_found || vlen_found || vediv_found)
    {
      ep->X_op = O_constant;
      ep->X_add_number = (vediv_value << 5) | (vsew_value << 2) | (vlen_value);
      expr_end = str;
      return;
    }

  my_getExpression (ep, str);
  str = expr_end;
}

/* Parse opcode name, could be an mnemonics or number.  */
static size_t
my_getOpcodeExpression (expressionS *ep, bfd_reloc_code_real_type *reloc,
			char *str, const struct percent_op_match *percent_op)
{
  const struct opcode_name_t *o = opcode_name_lookup (&str);

  if (o != NULL)
    {
      ep->X_op = O_constant;
      ep->X_add_number = o->val;
      return 0;
    }

  return my_getSmallExpression (ep, reloc, str, percent_op);
}

/* Detect and handle implicitly zero load-store offsets.  For example,
   "lw t0, (t1)" is shorthand for "lw t0, 0(t1)".  Return TRUE iff such
   an implicit offset was detected.  */

static bfd_boolean
riscv_handle_implicit_zero_offset (expressionS *ep, const char *s)
{
  /* Check whether there is only a single bracketed expression left.
     If so, it must be the base register and the constant must be zero.  */
  if (*s == '(' && strchr (s + 1, '(') == 0)
    {
      ep->X_op = O_constant;
      ep->X_add_number = 0;
      return TRUE;
    }

  return FALSE;
}

/* This routine assembles an instruction into its binary format.  As a
   side effect, it sets the global variable imm_reloc to the type of
   relocation to do if one of the operands is an address expression.  */

static const char *
riscv_ip (char *str, struct riscv_cl_insn *ip, expressionS *imm_expr,
	  bfd_reloc_code_real_type *imm_reloc, struct hash_control *hash)
{
  char *s;
  const char *args;
  char c = 0;
  struct riscv_opcode *insn;
  char *argsStart;
  unsigned int regno, save_regno = 0;
  char save_c = 0;
  int argnum;
  const struct percent_op_match *p;
  const char *error = "unrecognized opcode";

  /* Parse the name of the instruction.  Terminate the string if whitespace
     is found so that hash_find only sees the name part of the string.  */
  for (s = str; *s != '\0'; ++s)
    if (ISSPACE (*s))
      {
	save_c = *s;
	*s++ = '\0';
	break;
      }

  insn = (struct riscv_opcode *) hash_find (hash, str);

  argsStart = s;
  for ( ; insn && insn->name && strcmp (insn->name, str) == 0; insn++)
    {
      if ((insn->xlen_requirement != 0) && (xlen != insn->xlen_requirement))
	continue;

      if (ace_lib_load_success && !strcasecmp(insn->subset[0], "X"))
	;
      else if (!riscv_multi_subset_supports (insn->subset))
	continue;

      create_insn (ip, insn);
      argnum = 1;

      imm_expr->X_op = O_absent;
      *imm_reloc = BFD_RELOC_UNUSED;
      p = percent_op_itype;

      for (args = insn->args;; ++args)
	{
	  s += strspn (s, " \t");
	  switch (*args)
	    {
	    case '\0': 	/* End of args.  */
	      if (insn->pinfo != INSN_MACRO)
		{
		  if (!insn->match_func (insn, ip->insn_opcode))
		    break;

		  /* For .insn, insn->match and insn->mask are 0.  */
		  if (riscv_insn_length ((insn->match == 0 && insn->mask == 0)
					 ? ip->insn_opcode
					 : insn->match) == 2
		      && !riscv_opts.rvc)
		    break;
		}
	      if (*s != '\0')
		break;
	      /* Successful assembly.  */
	      error = NULL;
	      goto out;

	    case 'C': /* RVC */
	      switch (*++args)
		{
		case 's': /* RS1 x8-x15 */
		  if (!reg_lookup (&s, RCLASS_GPR, &regno)
		      || !(regno >= 8 && regno <= 15))
		    break;
		  INSERT_OPERAND (CRS1S, *ip, regno % 8);
		  continue;
		case 'w': /* RS1 x8-x15, constrained to equal RD x8-x15.  */
		  if (!reg_lookup (&s, RCLASS_GPR, &regno)
		      || EXTRACT_OPERAND (CRS1S, ip->insn_opcode) + 8 != regno)
		    break;
		  continue;
		case 't': /* RS2 x8-x15 */
		  if (!reg_lookup (&s, RCLASS_GPR, &regno)
		      || !(regno >= 8 && regno <= 15))
		    break;
		  INSERT_OPERAND (CRS2S, *ip, regno % 8);
		  continue;
		case 'x': /* RS2 x8-x15, constrained to equal RD x8-x15.  */
		  if (!reg_lookup (&s, RCLASS_GPR, &regno)
		      || EXTRACT_OPERAND (CRS2S, ip->insn_opcode) + 8 != regno)
		    break;
		  continue;
		case 'U': /* RS1, constrained to equal RD.  */
		  if (!reg_lookup (&s, RCLASS_GPR, &regno)
		      || EXTRACT_OPERAND (RD, ip->insn_opcode) != regno)
		    break;
		  continue;
		case 'V': /* RS2 */
		  if (!reg_lookup (&s, RCLASS_GPR, &regno))
		    break;
		  INSERT_OPERAND (CRS2, *ip, regno);
		  continue;
		case 'c': /* RS1, constrained to equal sp.  */
		  if (!reg_lookup (&s, RCLASS_GPR, &regno)
		      || regno != X_SP)
		    break;
		  continue;
		case 'z': /* RS1, constrained to equal zero. */
		  if (!reg_lookup (&s, RCLASS_GPR, &regno)
		      || (regno != 0))
		    break;
		  continue;

		case '>':
		  if (my_getSmallExpression (imm_expr, imm_reloc, s, p)
		      || imm_expr->X_op != O_constant
		      || imm_expr->X_add_number <= 0
		      || imm_expr->X_add_number >= 64)
		    break;
		  ip->insn_opcode |= ENCODE_RVC_IMM (imm_expr->X_add_number);
rvc_imm_done:
		  s = expr_end;
		  imm_expr->X_op = O_absent;
		  continue;
		case '<':
		  if (my_getSmallExpression (imm_expr, imm_reloc, s, p)
		      || imm_expr->X_op != O_constant
		      || !VALID_RVC_IMM (imm_expr->X_add_number)
		      || imm_expr->X_add_number <= 0
		      || imm_expr->X_add_number >= 32)
		    break;
		  ip->insn_opcode |= ENCODE_RVC_IMM (imm_expr->X_add_number);
		  goto rvc_imm_done;
		case '8':
		  if (my_getSmallExpression (imm_expr, imm_reloc, s, p)
		      || imm_expr->X_op != O_constant
		      || !VALID_RVC_UIMM8 (imm_expr->X_add_number)
		      || imm_expr->X_add_number < 0
		      || imm_expr->X_add_number >= 256)
		    break;
		  ip->insn_opcode |= ENCODE_RVC_UIMM8 (imm_expr->X_add_number);
		  goto rvc_imm_done;
		case 'i':
		  if (my_getSmallExpression (imm_expr, imm_reloc, s, p)
		      || imm_expr->X_op != O_constant
		      || imm_expr->X_add_number == 0
		      || !VALID_RVC_SIMM3 (imm_expr->X_add_number))
		    break;
		  ip->insn_opcode |= ENCODE_RVC_SIMM3 (imm_expr->X_add_number);
		  goto rvc_imm_done;
		case 'j':
		  if (my_getSmallExpression (imm_expr, imm_reloc, s, p)
		      || imm_expr->X_op != O_constant
		      || imm_expr->X_add_number == 0
		      || !VALID_RVC_IMM (imm_expr->X_add_number))
		    break;
		  ip->insn_opcode |= ENCODE_RVC_IMM (imm_expr->X_add_number);
		  goto rvc_imm_done;
		case 'e':
		  switch (*++args)
		    {
		    case 'i':
		      if (my_getSmallExpression (imm_expr, imm_reloc, s, p)
			  || imm_expr->X_op != O_constant
			  || imm_expr->X_add_number == 0
			  || !VALID_RVC_EX9IT_IMM (imm_expr->X_add_number << 2))
			break;
		      ip->insn_opcode |= ENCODE_RVC_EX9IT_IMM (imm_expr->X_add_number << 2);
		      goto rvc_imm_done;
		    case 't':
		      if (my_getSmallExpression (imm_expr, imm_reloc, s, p)
			  || imm_expr->X_op != O_constant
			  || imm_expr->X_add_number == 0
			  || !VALID_RVC_EXECIT_IMM (imm_expr->X_add_number << 2))
			break;
		      ip->insn_opcode |= ENCODE_RVC_EXECIT_IMM (imm_expr->X_add_number << 2);
		      goto rvc_imm_done;
		    default:
		      break;
		    }
		case 'k':
		  if (riscv_handle_implicit_zero_offset (imm_expr, s))
		    continue;
		  if (my_getSmallExpression (imm_expr, imm_reloc, s, p)
		      || imm_expr->X_op != O_constant
		      || !VALID_RVC_LW_IMM (imm_expr->X_add_number))
		    break;
		  ip->insn_opcode |= ENCODE_RVC_LW_IMM (imm_expr->X_add_number);
		  goto rvc_imm_done;
		case 'l':
		  if (riscv_handle_implicit_zero_offset (imm_expr, s))
		    continue;
		  if (my_getSmallExpression (imm_expr, imm_reloc, s, p)
		      || imm_expr->X_op != O_constant
		      || !VALID_RVC_LD_IMM (imm_expr->X_add_number))
		    break;
		  ip->insn_opcode |= ENCODE_RVC_LD_IMM (imm_expr->X_add_number);
		  goto rvc_imm_done;
		case 'm':
		  if (riscv_handle_implicit_zero_offset (imm_expr, s))
		    continue;
		  if (my_getSmallExpression (imm_expr, imm_reloc, s, p)
		      || imm_expr->X_op != O_constant
		      || !VALID_RVC_LWSP_IMM (imm_expr->X_add_number))
		    break;
		  ip->insn_opcode |=
		    ENCODE_RVC_LWSP_IMM (imm_expr->X_add_number);
		  goto rvc_imm_done;
		case 'n':
		  if (riscv_handle_implicit_zero_offset (imm_expr, s))
		    continue;
		  if (my_getSmallExpression (imm_expr, imm_reloc, s, p)
		      || imm_expr->X_op != O_constant
		      || !VALID_RVC_LDSP_IMM (imm_expr->X_add_number))
		    break;
		  ip->insn_opcode |=
		    ENCODE_RVC_LDSP_IMM (imm_expr->X_add_number);
		  goto rvc_imm_done;
		case 'o':
		  if (my_getSmallExpression (imm_expr, imm_reloc, s, p)
		      || imm_expr->X_op != O_constant
		      /* C.addiw, c.li, and c.andi allow zero immediate.
			 C.addi allows zero immediate as hint.  Otherwise this
			 is same as 'j'.  */
		      || !VALID_RVC_IMM (imm_expr->X_add_number))
		    break;
		  ip->insn_opcode |= ENCODE_RVC_IMM (imm_expr->X_add_number);
		  goto rvc_imm_done;
		case 'K':
		  if (my_getSmallExpression (imm_expr, imm_reloc, s, p)
		      || imm_expr->X_op != O_constant
		      || !VALID_RVC_ADDI4SPN_IMM (imm_expr->X_add_number)
		      || imm_expr->X_add_number == 0)
		    break;
		  ip->insn_opcode |=
		    ENCODE_RVC_ADDI4SPN_IMM (imm_expr->X_add_number);
		  goto rvc_imm_done;
		case 'L':
		  if (my_getSmallExpression (imm_expr, imm_reloc, s, p)
		      || imm_expr->X_op != O_constant
		      || !VALID_RVC_ADDI16SP_IMM (imm_expr->X_add_number)
		      || imm_expr->X_add_number == 0)
		    break;
		  ip->insn_opcode |=
		    ENCODE_RVC_ADDI16SP_IMM (imm_expr->X_add_number);
		  goto rvc_imm_done;
		case 'M':
		  if (riscv_handle_implicit_zero_offset (imm_expr, s))
		    continue;
		  if (my_getSmallExpression (imm_expr, imm_reloc, s, p)
		      || imm_expr->X_op != O_constant
		      || !VALID_RVC_SWSP_IMM (imm_expr->X_add_number))
		    break;
		  ip->insn_opcode |=
		    ENCODE_RVC_SWSP_IMM (imm_expr->X_add_number);
		  goto rvc_imm_done;
		case 'N':
		  if (riscv_handle_implicit_zero_offset (imm_expr, s))
		    continue;
		  if (my_getSmallExpression (imm_expr, imm_reloc, s, p)
		      || imm_expr->X_op != O_constant
		      || !VALID_RVC_SDSP_IMM (imm_expr->X_add_number))
		    break;
		  ip->insn_opcode |=
		    ENCODE_RVC_SDSP_IMM (imm_expr->X_add_number);
		  goto rvc_imm_done;
		case 'u':
		  p = percent_op_utype;
		  if (my_getSmallExpression (imm_expr, imm_reloc, s, p))
		    break;
rvc_lui:
		  if (imm_expr->X_op != O_constant
		      || imm_expr->X_add_number <= 0
		      || imm_expr->X_add_number >= RISCV_BIGIMM_REACH
		      || (imm_expr->X_add_number >= RISCV_RVC_IMM_REACH / 2
			  && (imm_expr->X_add_number <
			      RISCV_BIGIMM_REACH - RISCV_RVC_IMM_REACH / 2)))
		    break;
		  ip->insn_opcode |= ENCODE_RVC_IMM (imm_expr->X_add_number);
		  goto rvc_imm_done;
		case 'v':
		  if (my_getSmallExpression (imm_expr, imm_reloc, s, p)
		      || (imm_expr->X_add_number & (RISCV_IMM_REACH - 1))
		      || ((int32_t)imm_expr->X_add_number
			  != imm_expr->X_add_number))
		    break;
		  imm_expr->X_add_number =
		    ((uint32_t) imm_expr->X_add_number) >> RISCV_IMM_BITS;
		  goto rvc_lui;
		case 'p':
		  goto branch;
		case 'a':
		  goto jump;
		case 'S': /* Floating-point RS1 x8-x15.  */
		  if (!reg_lookup (&s, RCLASS_FPR, &regno)
		      || !(regno >= 8 && regno <= 15))
		    break;
		  INSERT_OPERAND (CRS1S, *ip, regno % 8);
		  continue;
		case 'D': /* Floating-point RS2 x8-x15.  */
		  if (!reg_lookup (&s, RCLASS_FPR, &regno)
		      || !(regno >= 8 && regno <= 15))
		    break;
		  INSERT_OPERAND (CRS2S, *ip, regno % 8);
		  continue;
		case 'T': /* Floating-point RS2.  */
		  if (!reg_lookup (&s, RCLASS_FPR, &regno))
		    break;
		  INSERT_OPERAND (CRS2, *ip, regno);
		  continue;
		case 'F':
		  switch (*++args)
		    {
		      case '6':
		        if (my_getSmallExpression (imm_expr, imm_reloc, s, p)
			    || imm_expr->X_op != O_constant
			    || imm_expr->X_add_number < 0
			    || imm_expr->X_add_number >= 64)
			  {
			    as_bad (_("bad value for funct6 field, "
				      "value must be 0...64"));
			    break;
			  }

			INSERT_OPERAND (CFUNCT6, *ip, imm_expr->X_add_number);
			imm_expr->X_op = O_absent;
			s = expr_end;
			continue;
		      case '4':
		        if (my_getSmallExpression (imm_expr, imm_reloc, s, p)
			    || imm_expr->X_op != O_constant
			    || imm_expr->X_add_number < 0
			    || imm_expr->X_add_number >= 16)
			  {
			    as_bad (_("bad value for funct4 field, "
				      "value must be 0...15"));
			    break;
			  }

			INSERT_OPERAND (CFUNCT4, *ip, imm_expr->X_add_number);
			imm_expr->X_op = O_absent;
			s = expr_end;
			continue;
		      case '3':
			if (my_getSmallExpression (imm_expr, imm_reloc, s, p)
			    || imm_expr->X_op != O_constant
			    || imm_expr->X_add_number < 0
			    || imm_expr->X_add_number >= 8)
			  {
			    as_bad (_("bad value for funct3 field, "
				      "value must be 0...7"));
			    break;
			  }
			INSERT_OPERAND (CFUNCT3, *ip, imm_expr->X_add_number);
			imm_expr->X_op = O_absent;
			s = expr_end;
			continue;
		      case '2':
			if (my_getSmallExpression (imm_expr, imm_reloc, s, p)
			    || imm_expr->X_op != O_constant
			    || imm_expr->X_add_number < 0
			    || imm_expr->X_add_number >= 4)
			  {
			    as_bad (_("bad value for funct2 field, "
				      "value must be 0...3"));
			    break;
			  }
			INSERT_OPERAND (CFUNCT2, *ip, imm_expr->X_add_number);
			imm_expr->X_op = O_absent;
			s = expr_end;
			continue;
		      default:
			as_bad (_("bad compressed FUNCT field"
				  " specifier 'CF%c'\n"),
				*args);
		    }
		  break;

		default:
		  as_bad (_("bad RVC field specifier 'C%c'\n"), *args);
		}
	      break;

	    case ',':
	    case '+':
	      ++argnum;
	      if (*s++ == *args)
		continue;
	      s--;
	      break;

	    case '(':
	    case ')':
	    case '[':
	    case ']':
	      if (*s++ == *args)
		continue;
	      break;

	    case '<':		/* Shift amount, 0 - 31.  */
	      my_getExpression (imm_expr, s);
	      check_absolute_expr (ip, imm_expr, FALSE);
	      if ((unsigned long) imm_expr->X_add_number > 31)
		as_bad (_("Improper shift amount (%lu)"),
			(unsigned long) imm_expr->X_add_number);
	      INSERT_OPERAND (SHAMTW, *ip, imm_expr->X_add_number);
	      imm_expr->X_op = O_absent;
	      s = expr_end;
	      continue;

	    case '>':		/* Shift amount, 0 - (XLEN-1).  */
	      my_getExpression (imm_expr, s);
	      check_absolute_expr (ip, imm_expr, FALSE);
	      if ((unsigned long) imm_expr->X_add_number >= xlen)
		as_bad (_("Improper shift amount (%lu)"),
			(unsigned long) imm_expr->X_add_number);
	      INSERT_OPERAND (SHAMT, *ip, imm_expr->X_add_number);
	      imm_expr->X_op = O_absent;
	      s = expr_end;
	      continue;

	    case 'Z':		/* CSRRxI immediate.  */
	      my_getExpression (imm_expr, s);
	      check_absolute_expr (ip, imm_expr, FALSE);
	      if ((unsigned long) imm_expr->X_add_number > 31)
		as_bad (_("Improper CSRxI immediate (%lu)"),
			(unsigned long) imm_expr->X_add_number);
	      INSERT_OPERAND (RS1, *ip, imm_expr->X_add_number);
	      imm_expr->X_op = O_absent;
	      s = expr_end;
	      continue;

	    case 'E':		/* Control register.  */
	      if (reg_lookup (&s, RCLASS_CSR, &regno))
		INSERT_OPERAND (CSR, *ip, regno);
	      else
		{
		  my_getExpression (imm_expr, s);
		  check_absolute_expr (ip, imm_expr, TRUE);
		  if ((unsigned long) imm_expr->X_add_number > 0xfff)
		    as_bad (_("Improper CSR address (%lu)"),
			    (unsigned long) imm_expr->X_add_number);
		  INSERT_OPERAND (CSR, *ip, imm_expr->X_add_number);
		  imm_expr->X_op = O_absent;
		  s = expr_end;
		}
	      continue;

	    case 'm':		/* Rounding mode.  */
	      if (arg_lookup (&s, riscv_rm, ARRAY_SIZE (riscv_rm), &regno))
		{
		  INSERT_OPERAND (RM, *ip, regno);
		  continue;
		}
	      break;

	    case 'P':
	    case 'Q':		/* Fence predecessor/successor.  */
	      if (arg_lookup (&s, riscv_pred_succ, ARRAY_SIZE (riscv_pred_succ),
			      &regno))
		{
		  if (*args == 'P')
		    INSERT_OPERAND (PRED, *ip, regno);
		  else
		    INSERT_OPERAND (SUCC, *ip, regno);
		  continue;
		}
	      break;

	    case 'd':		/* Destination register.  */
	    case 's':		/* Source register.  */
	    case 't':		/* Target register.  */
	    case 'r':		/* rs3.  */
	    case 'e':		/* Target register with check.  */
	      if (reg_lookup (&s, RCLASS_GPR, &regno))
		{
		  c = *args;
		  if (*s == ' ')
		    ++s;

		  /* Now that we have assembled one operand, we use the args
		     string to figure out where it goes in the instruction.  */
		  switch (c)
		    {
		    case 's':
		      save_regno = regno;
		      INSERT_OPERAND (RS1, *ip, regno);
		      break;
		    case 'd':
		      INSERT_OPERAND (RD, *ip, regno);
		      break;
		    case 'e':
		    case 't':
		      INSERT_OPERAND (RS2, *ip, regno);
		      break;
		    case 'r':
		      INSERT_OPERAND (RS3, *ip, regno);
		      break;
		    }
		  if (c == 'e' && regno < save_regno)
		    break;
		  continue;
		}
	      break;

	    case 'D':		/* Floating point rd.  */
	    case 'S':		/* Floating point rs1.  */
	    case 'T':		/* Floating point rs2.  */
	    case 'U':		/* Floating point rs1 and rs2.  */
	    case 'R':		/* Floating point rs3.  */
	      if (reg_lookup (&s, RCLASS_FPR, &regno))
		{
		  c = *args;
		  if (*s == ' ')
		    ++s;
		  switch (c)
		    {
		    case 'D':
		      INSERT_OPERAND (RD, *ip, regno);
		      break;
		    case 'S':
		      INSERT_OPERAND (RS1, *ip, regno);
		      break;
		    case 'U':
		      INSERT_OPERAND (RS1, *ip, regno);
		      /* fallthru */
		    case 'T':
		      INSERT_OPERAND (RS2, *ip, regno);
		      break;
		    case 'R':
		      INSERT_OPERAND (RS3, *ip, regno);
		      break;
		    }
		  continue;
		}

	      break;

	    case 'I':
	      my_getExpression (imm_expr, s);
	      if (imm_expr->X_op != O_big
		  && imm_expr->X_op != O_constant)
		break;
	      normalize_constant_expr (imm_expr);
	      s = expr_end;
	      continue;

	    case 'A':
	      my_getExpression (imm_expr, s);
	      normalize_constant_expr (imm_expr);
	      /* The 'A' format specifier must be a symbol.  */
	      if (imm_expr->X_op != O_symbol)
	        break;
	      *imm_reloc = BFD_RELOC_32;
	      s = expr_end;
	      continue;

	    case 'B':
	      my_getExpression (imm_expr, s);
	      normalize_constant_expr (imm_expr);
	      /* The 'B' format specifier must be a symbol or a constant.  */
	      if (imm_expr->X_op != O_symbol && imm_expr->X_op != O_constant)
	        break;
	      if (imm_expr->X_op == O_symbol)
	        *imm_reloc = BFD_RELOC_32;
	      s = expr_end;
	      continue;

	    case 'j': /* Sign-extended immediate.  */
	      p = percent_op_itype;
	      *imm_reloc = BFD_RELOC_RISCV_LO12_I;
	      goto alu_op;
	    case 'q': /* Store displacement.  */
	      p = percent_op_stype;
	      *imm_reloc = BFD_RELOC_RISCV_LO12_S;
	      goto load_store;
	    case 'o': /* Load displacement.  */
	      p = percent_op_itype;
	      *imm_reloc = BFD_RELOC_RISCV_LO12_I;
	      goto load_store;
	    case '1': /* 4-operand add, must be %tprel_add.  */
	      p = percent_op_rtype;
	      goto alu_op;
	    case '0': /* AMO "displacement," which must be zero.  */
	      p = percent_op_null;
load_store:
	      if (riscv_handle_implicit_zero_offset (imm_expr, s))
		continue;
alu_op:
	      /* If this value won't fit into a 16 bit offset, then go
		 find a macro that will generate the 32 bit offset
		 code pattern.  */
	      if (!my_getSmallExpression (imm_expr, imm_reloc, s, p))
		{
		  normalize_constant_expr (imm_expr);
		  if (imm_expr->X_op != O_constant
		      || (*args == '0' && imm_expr->X_add_number != 0)
		      || (*args == '1')
		      || imm_expr->X_add_number >= (signed)RISCV_IMM_REACH/2
		      || imm_expr->X_add_number < -(signed)RISCV_IMM_REACH/2)
		    break;
		}

	      s = expr_end;
	      continue;

	    case 'p':		/* PC-relative offset.  */
branch:
	      *imm_reloc = BFD_RELOC_12_PCREL;
	      my_getExpression (imm_expr, s);
	      s = expr_end;
	      continue;

	    case 'u':		/* Upper 20 bits.  */
	      p = percent_op_utype;
	      if (!my_getSmallExpression (imm_expr, imm_reloc, s, p)
		  && imm_expr->X_op == O_constant)
		{
		  if (imm_expr->X_add_number < 0
		      || imm_expr->X_add_number >= (signed)RISCV_BIGIMM_REACH)
		    as_bad (_("lui expression not in range 0..1048575"));

		  *imm_reloc = BFD_RELOC_RISCV_HI20;
		  imm_expr->X_add_number <<= RISCV_IMM_BITS;
		}
	      /* The 'u' format specifier must be a symbol or a constant.  */
	      if (imm_expr->X_op != O_symbol && imm_expr->X_op != O_constant)
	        break;
	      s = expr_end;
	      continue;

	    case 'a':		/* 20-bit PC-relative offset.  */
jump:
	      my_getExpression (imm_expr, s);
	      s = expr_end;
	      *imm_reloc = BFD_RELOC_RISCV_JMP;
	      continue;

	    case 'c':
	      my_getExpression (imm_expr, s);
	      s = expr_end;
	      if (strcmp (s, "@plt") == 0 || strcmp(s, "@PLT") == 0)
		{
		  *imm_reloc = BFD_RELOC_RISCV_CALL_PLT;
		  s += 4;
		}
	      else
		*imm_reloc = BFD_RELOC_RISCV_CALL;
	      continue;
	    case 'O':
	      switch (*++args)
		{
		case '4':
		  if (my_getOpcodeExpression (imm_expr, imm_reloc, s, p)
		      || imm_expr->X_op != O_constant
		      || imm_expr->X_add_number < 0
		      || imm_expr->X_add_number >= 128
		      || (imm_expr->X_add_number & 0x3) != 3)
		    {
		      as_bad (_("bad value for opcode field, "
				"value must be 0...127 and "
				"lower 2 bits must be 0x3"));
		      break;
		    }

		  INSERT_OPERAND (OP, *ip, imm_expr->X_add_number);
		  imm_expr->X_op = O_absent;
		  s = expr_end;
		  continue;
		case '2':
		  if (my_getOpcodeExpression (imm_expr, imm_reloc, s, p)
		      || imm_expr->X_op != O_constant
		      || imm_expr->X_add_number < 0
		      || imm_expr->X_add_number >= 3)
		    {
		      as_bad (_("bad value for opcode field, "
				"value must be 0...2"));
		      break;
		    }

		  INSERT_OPERAND (OP2, *ip, imm_expr->X_add_number);
		  imm_expr->X_op = O_absent;
		  s = expr_end;
		  continue;
		default:
		  as_bad (_("bad Opcode field specifier 'O%c'\n"), *args);
		}
	      break;

	    case 'F':
	      switch (*++args)
		{
		case '7':
		  if (my_getSmallExpression (imm_expr, imm_reloc, s, p)
		      || imm_expr->X_op != O_constant
		      || imm_expr->X_add_number < 0
		      || imm_expr->X_add_number >= 128)
		    {
		      as_bad (_("bad value for funct7 field, "
				"value must be 0...127"));
		      break;
		    }

		  INSERT_OPERAND (FUNCT7, *ip, imm_expr->X_add_number);
		  imm_expr->X_op = O_absent;
		  s = expr_end;
		  continue;
		case '3':
		  if (my_getSmallExpression (imm_expr, imm_reloc, s, p)
		      || imm_expr->X_op != O_constant
		      || imm_expr->X_add_number < 0
		      || imm_expr->X_add_number >= 8)
		    {
		      as_bad (_("bad value for funct3 field, "
			        "value must be 0...7"));
		      break;
		    }

		  INSERT_OPERAND (FUNCT3, *ip, imm_expr->X_add_number);
		  imm_expr->X_op = O_absent;
		  s = expr_end;
		  continue;
		case '2':
		  if (my_getSmallExpression (imm_expr, imm_reloc, s, p)
		      || imm_expr->X_op != O_constant
		      || imm_expr->X_add_number < 0
		      || imm_expr->X_add_number >= 4)
		    {
		      as_bad (_("bad value for funct2 field, "
			        "value must be 0...3"));
		      break;
		    }

		  INSERT_OPERAND (FUNCT2, *ip, imm_expr->X_add_number);
		  imm_expr->X_op = O_absent;
		  s = expr_end;
		  continue;

		default:
		  as_bad (_("bad FUNCT field specifier 'F%c'\n"), *args);
		}
	      break;

	    case 'z':
	      if (my_getSmallExpression (imm_expr, imm_reloc, s, p)
		  || imm_expr->X_op != O_constant
		  || imm_expr->X_add_number != 0)
		break;
	      s = expr_end;
	      imm_expr->X_op = O_absent;
	      continue;

	    case 'V': /* RVV */
	      switch (*++args)
		{
		case 'd': /* VD */
		  if (!reg_lookup (&s, RCLASS_VECR, &regno))
		    break;
		  INSERT_OPERAND (VD, *ip, regno);
		  continue;

		case 'e': /* AMO VD */
		  if (reg_lookup (&s, RCLASS_GPR, &regno) && regno == 0)
		    INSERT_OPERAND (VWD, *ip, 0);
		  else if (reg_lookup (&s, RCLASS_VECR, &regno))
		    {
		      INSERT_OPERAND (VWD, *ip, 1);
		      INSERT_OPERAND (VD, *ip, regno);
		    }
		  else
		    break;
		  continue;

		case 'f': /* AMO VS3 */
		  if (!reg_lookup (&s, RCLASS_VECR, &regno))
		    break;
		  if (!EXTRACT_OPERAND (VWD, ip->insn_opcode))
		    INSERT_OPERAND (VD, *ip, regno);
		  else
		    {
		      /* VS3 must match VD.  */
		      if (EXTRACT_OPERAND (VD, ip->insn_opcode) != regno)
			break;
		    }
		  continue;

		case 's': /* VS1 */
		  if (!reg_lookup (&s, RCLASS_VECR, &regno))
		    break;
		  INSERT_OPERAND (VS1, *ip, regno);
		  continue;

		case 't': /* VS2 */
		  if (!reg_lookup (&s, RCLASS_VECR, &regno))
		    break;
		  INSERT_OPERAND (VS2, *ip, regno);
		  continue;

		case 'u': /* VS1 == VS2 */
		  if (!reg_lookup (&s, RCLASS_VECR, &regno))
		    break;
		  INSERT_OPERAND (VS1, *ip, regno);
		  INSERT_OPERAND (VS2, *ip, regno);
		  continue;

		case 'v': /* VD == VS1 == VS2 */
		  if (!reg_lookup (&s, RCLASS_VECR, &regno))
		    break;
		  INSERT_OPERAND (VD, *ip, regno);
		  INSERT_OPERAND (VS1, *ip, regno);
		  INSERT_OPERAND (VS2, *ip, regno);
		  continue;

		case '0': /* required vector mask register without .t */
		  if (reg_lookup (&s, RCLASS_VECR, &regno) && regno == 0)
		    continue;
		  break;

		case 'c': /* vtypei for vsetvli */
		  my_getVsetvliExpression (imm_expr, s);
		  check_absolute_expr (ip, imm_expr, FALSE);
		  if (!VALID_RVV_VC_IMM (imm_expr->X_add_number))
		    as_bad (_("bad value for vsetvli immediate field, "
			      "value must be 0..2047"));
		  ip->insn_opcode
		    |= ENCODE_RVV_VC_IMM (imm_expr->X_add_number);
		  imm_expr->X_op = O_absent;
		  s = expr_end;
		  continue;

		case 'i': /* vector arith signed immediate */
		  my_getExpression (imm_expr, s);
		  check_absolute_expr (ip, imm_expr, FALSE);
		  if (imm_expr->X_add_number > 15
		      || imm_expr->X_add_number < -16)
		    as_bad (_("bad value for vector immediate field, "
			      "value must be -16...15"));
		  INSERT_OPERAND (VIMM, *ip, imm_expr->X_add_number);
		  imm_expr->X_op = O_absent;
		  s = expr_end;
		  continue;

		case 'j': /* vector arith unsigned immediate */
		  my_getExpression (imm_expr, s);
		  check_absolute_expr (ip, imm_expr, FALSE);
		  if (imm_expr->X_add_number < 0
		      || imm_expr->X_add_number >= 32)
		    as_bad (_("bad value for vector immediate field, "
			      "value must be 0...31"));
		  INSERT_OPERAND (VIMM, *ip, imm_expr->X_add_number);
		  imm_expr->X_op = O_absent;
		  s = expr_end;
		  continue;

		case 'k': /* vector arith signed immediate, minus 1 */
		  my_getExpression (imm_expr, s);
		  check_absolute_expr (ip, imm_expr, FALSE);
		  if (imm_expr->X_add_number > 16
		      || imm_expr->X_add_number < -15)
		    as_bad (_("bad value for vector immediate field, "
			      "value must be -15...16"));
		  INSERT_OPERAND (VIMM, *ip, imm_expr->X_add_number - 1);
		  imm_expr->X_op = O_absent;
		  s = expr_end;
		  continue;

		case 'm': /* optional vector mask */
		  if (*s == '\0')
		    {
		      INSERT_OPERAND (VMASK, *ip, 1);
		      continue;
		    }
		  else if (*s == ',' && s++
			   && reg_lookup (&s, RCLASS_VECM, &regno)
			   && regno == 0)
		    {
		      INSERT_OPERAND (VMASK, *ip, 0);
		      continue;
		    }
		  break;

		  /* The following ones are only used in macros.  */
		case 'M': /* required vector mask */
		  if (reg_lookup (&s, RCLASS_VECM, &regno) && regno == 0)
		    {
		      INSERT_OPERAND (VMASK, *ip, 0);
		      continue;
		    }
		  break;

		case 'T': /* vector macro temporary register */
		  if (!reg_lookup (&s, RCLASS_VECR, &regno) || regno == 0)
		    break;
		  /* Store it in the FUNCT6 field as we don't have anyplace
		     else to store it.  */
		  INSERT_OPERAND (VFUNCT6, *ip, regno);
		  continue;
		}
	      break;

	    case 'h':
	      my_getExpression (imm_expr, s);
	      if (imm_expr->X_op != O_constant
		  || imm_expr->X_add_number >= xlen
		  || imm_expr->X_add_number < 0)
		break;
	      s = expr_end;
	      ip->insn_opcode |= ENCODE_SBTYPE_IMM6H (imm_expr->X_add_number);
	      imm_expr->X_op = O_absent;
	      continue;

	    case 'l':
	      my_getExpression (imm_expr, s);
	      if (imm_expr->X_op != O_constant
		  || imm_expr->X_add_number >= xlen
		  || imm_expr->X_add_number < 0)
		break;
	      ip->insn_opcode |= ENCODE_SBTYPE_IMM6L (imm_expr->X_add_number);
	      s = expr_end;
	      imm_expr->X_op = O_absent;
	      continue;

	    case 'i':
	      my_getExpression (imm_expr, s);
	      if (imm_expr->X_op != O_constant
		  || imm_expr->X_add_number >= (signed) RISCV_IMM7_REACH
		  || imm_expr->X_add_number < 0)
		break;
	      ip->insn_opcode |= ENCODE_STYPE_IMM7 (imm_expr->X_add_number);
	      s = expr_end;
	      imm_expr->X_op = O_absent;
	      continue;

	    case 'g':
	      *imm_reloc = BFD_RELOC_RISCV_10_PCREL;
	      my_getExpression (imm_expr, s);
	      s = expr_end;
	      continue;

	    case 'k':
	      my_getExpression (imm_expr, s);
	      if (imm_expr->X_op != O_constant
		  || imm_expr->X_add_number >= xlen
		  || imm_expr->X_add_number < 0)
		break;
	      s = expr_end;
	      ip->insn_opcode |= ENCODE_TYPE_CIMM6 (imm_expr->X_add_number);
	      imm_expr->X_op = O_absent;
	      continue;

	    case 'v':
	      if (*s != '<' || *(s + 1) != '<')
		break;
	      s = s + 2;
	      my_getExpression (imm_expr, s);
	      if (imm_expr->X_op != O_constant
		  || imm_expr->X_add_number > 3
		  || imm_expr->X_add_number < 0)
		break;
	      INSERT_OPERAND (SV, *ip, imm_expr->X_add_number);
	      imm_expr->X_op = O_absent;
	      s = expr_end;
	      continue;

	    case 'f':
	      my_getExpression (imm_expr, s);
	      if (imm_expr->X_op != O_constant
		  || imm_expr->X_add_number >= (signed) RISCV_IMM8_REACH/2
		  || imm_expr->X_add_number < -(signed) RISCV_IMM8_REACH/2)
		break;
	      ip->insn_opcode |= ENCODE_TYPE_IMM8 (imm_expr->X_add_number);
	      s = expr_end;
	      imm_expr->X_op = O_absent;
	      continue;

	    case 'H':
	    case 'G':
	      {
		bfd_boolean store = FALSE;
		if (*args == 'H')
		  store = TRUE;

		my_getExpression (imm_expr, s);
		switch (*++args)
		  {
		  case 'b':
		    if (imm_expr->X_op == O_constant
			&& imm_expr->X_add_number < (signed) RISCV_IMM18_REACH/2
			&& imm_expr->X_add_number >= -(signed) RISCV_IMM18_REACH/2)
		      {
			if (store)
			  ip->insn_opcode |= ENCODE_GPTYPE_SB_IMM (imm_expr->X_add_number);
			else
			  ip->insn_opcode |= ENCODE_GPTYPE_LB_IMM (imm_expr->X_add_number);
			s = expr_end;
			continue;
		      }
		    else if (imm_expr->X_op == O_symbol)
		      {
			if (store)
			  *imm_reloc = BFD_RELOC_RISCV_SGP18S0;
			else
			  *imm_reloc = BFD_RELOC_RISCV_LGP18S0;
			s = expr_end;
			continue;
		      }
		    break;

		  case 'h':
		    if (imm_expr->X_op == O_constant
			&& imm_expr->X_add_number < (signed) RISCV_IMM18_REACH/2
			&& imm_expr->X_add_number >= -(signed) RISCV_IMM18_REACH/2
			&& (imm_expr->X_add_number & 0x1) == 0)
		      {
			if (store)
			  ip->insn_opcode |= ENCODE_GPTYPE_SH_IMM (imm_expr->X_add_number);
			else
			  ip->insn_opcode |= ENCODE_GPTYPE_LH_IMM (imm_expr->X_add_number);
			s = expr_end;
			continue;
		      }
		    else if (imm_expr->X_op == O_symbol)
		      {
			if (store)
			  *imm_reloc = BFD_RELOC_RISCV_SGP17S1;
			else
			  *imm_reloc = BFD_RELOC_RISCV_LGP17S1;
			s = expr_end;
			continue;
		      }
		    break;

		  case 'w':
		    if (imm_expr->X_op == O_constant
			&& imm_expr->X_add_number < (signed) RISCV_IMM19_REACH/2
			&& imm_expr->X_add_number >= -(signed) RISCV_IMM19_REACH/2
			&& (imm_expr->X_add_number & 0x3) == 0)
		      {
			if (store)
			  ip->insn_opcode |= ENCODE_GPTYPE_SW_IMM (imm_expr->X_add_number);
			else
			  ip->insn_opcode |= ENCODE_GPTYPE_LW_IMM (imm_expr->X_add_number);
			s = expr_end;
			continue;
		      }
		    else if (imm_expr->X_op == O_symbol)
		      {
			if (store)
			  *imm_reloc = BFD_RELOC_RISCV_SGP17S2;
			else
			  *imm_reloc = BFD_RELOC_RISCV_LGP17S2;
			s = expr_end;
			continue;
		      }
		    break;

		  case 'd':
		    if (imm_expr->X_op == O_constant
			&& imm_expr->X_add_number < (signed) RISCV_IMM20_REACH/2
			&& imm_expr->X_add_number >= -(signed) RISCV_IMM20_REACH/2
			&& (imm_expr->X_add_number & 0x7) == 0)
		      {
			if (store)
			  ip->insn_opcode |= ENCODE_GPTYPE_SD_IMM (imm_expr->X_add_number);
			else
			  ip->insn_opcode |= ENCODE_GPTYPE_LD_IMM (imm_expr->X_add_number);
			s = expr_end;
			continue;
		      }
		    else if (imm_expr->X_op == O_symbol)
		      {
			if (store)
			  *imm_reloc = BFD_RELOC_RISCV_SGP17S3;
			else
			  *imm_reloc = BFD_RELOC_RISCV_LGP17S3;
			s = expr_end;
			continue;
		      }
		    break;

		  default:
		    break;
		  }
		break;
	      }

	    case 'n':
	      {
		char field_name[MAX_KEYWORD_LEN];
		args++;
		if (parse_nds_v5_field (&args, field_name))
		  {
		    if (strcmp (field_name, "nds_rc") == 0
			&& reg_lookup (&s, RCLASS_GPR, &regno))
		      {
			INSERT_OPERAND (RC, *ip, regno);
			args--;
			continue;
		      }
		    else if (strcmp (field_name, "nds_rdp") == 0
			     && reg_lookup (&s, RCLASS_GPR, &regno))
		      {
			if (xlen == 32 && (regno % 2) != 0)
			  {
			    as_bad (_("The number of Rd must be even "
				      "(limitation of register pair)."));
			    break;
			  }
			INSERT_OPERAND (RD, *ip, regno);
			args--;
			continue;
		      }
		    else if (strcmp (field_name, "nds_rsp") == 0
			     && reg_lookup (&s, RCLASS_GPR, &regno))
		      {
			if (xlen == 32 && (regno % 2) != 0)
			  {
			    as_bad (_("The number of Rs1 must be even "
				      "(limitation of register pair)."));
			    break;
			  }
			INSERT_OPERAND (RS1, *ip, regno);
			args--;
			continue;
		      }
		    else if (strcmp (field_name, "nds_rtp") == 0
			     && reg_lookup (&s, RCLASS_GPR, &regno))
		      {
			if (xlen == 32 && (regno % 2) != 0)
			  {
			    as_bad (_("The number of Rs2 must be even "
				      "(limitation of register pair)."));
			    break;
			  }
			INSERT_OPERAND (RS2, *ip, regno);
			args--;
			continue;
		      }

		    my_getExpression (imm_expr, s);
		    if (imm_expr->X_op != O_constant
			|| imm_expr->X_add_number >= xlen
			|| imm_expr->X_add_number < 0)
		      break;

		    if (strcmp (field_name, "nds_i3u") == 0
			&& VALID_PTYPE_IMM3U (imm_expr->X_add_number))
		      ip->insn_opcode |= ENCODE_PTYPE_IMM3U (imm_expr->X_add_number);
		    else if (strcmp (field_name, "nds_i4u") == 0
			     && VALID_PTYPE_IMM4U (imm_expr->X_add_number))
		      ip->insn_opcode |= ENCODE_PTYPE_IMM4U (imm_expr->X_add_number);
		    else if (strcmp (field_name, "nds_i5u") == 0
			     && VALID_PTYPE_IMM5U (imm_expr->X_add_number))
		      ip->insn_opcode |= ENCODE_PTYPE_IMM5U (imm_expr->X_add_number);
		    else if (strcmp (field_name, "nds_i6u") == 0
			     && VALID_PTYPE_IMM6U (imm_expr->X_add_number))
		      ip->insn_opcode |= ENCODE_PTYPE_IMM6U (imm_expr->X_add_number);
		    else if (strcmp (field_name, "nds_i15s") == 0
			     && VALID_PTYPE_IMM15S (imm_expr->X_add_number))
		      ip->insn_opcode |= ENCODE_PTYPE_IMM15S (imm_expr->X_add_number);
		    else
		      break;

		    s = expr_end;
		    imm_expr->X_op = O_absent;
		    args--;
		    continue;
		  }
		break;
	      }

	    case 'X':
	      if (ace_lib_load_success)
		{
		  ace_ip ((char **) &args, &s, ip);
		  continue;
		}
	      else
		break;

	    default:
	      as_fatal (_("internal error: bad argument type %c"), *args);
	    }
	  break;
	}
      s = argsStart;
      error = _("illegal operands");
    }

out:
  /* Restore the character we might have clobbered above.  */
  if (save_c)
    *(argsStart - 1) = save_c;

  return error;
}

static int
riscv_parse_arch_version (const char **in_ver)
{
  int version, num, major_set, minor_set;
  const char *string = *in_ver;

  version = 0;
  num = 0;
  major_set = 0;
  minor_set = 0;
  while (string[0] != '\0'
	 && string[0] != 'p'
	 && (string[0] - 48) >= 0
	 && (string[0] - 48) <= 9)
    {
      num = num * 10 + (string[0] - 48);
      string++;
      major_set = 1;
    }
  version = num * 10000;
  if (major_set && string[0] == 'p')
    {
      num = 0;
      string++;
      while (string[0] != '\0'
	     && (string[0] - 48) >= 0
	     && (string[0] - 48) <= 9)
	{
	  num = num * 10 + (string[0] - 48);
	  string++;
	  if (num >= 10000)
	    as_fatal (".attribute: minor version can not "
		      "be larger than 9999.");
	  minor_set = 1;
	}
      version += num;

      if (major_set ^ minor_set)
	as_fatal (".attribute: major and minor versions must be "
		  "set when 'p' is used.");
    }
  *in_ver = string;

  if (version > 0 || major_set)
    return version;
  else
    return -1;
}

static void
riscv_parse_arch_name (const char **in_arch, int len, char **name)
{
  const char *string = *in_arch;
  if (!len)
    {
      int i = 0, j = 0;
      for (; non_standard_arch_name[j]; j++)
	{
	  if (strncmp (string, non_standard_arch_name[j],
		       strlen (non_standard_arch_name[j])) == 0)
	    {
	      i += strlen (non_standard_arch_name[j]);
	      break;
	    }
	}
      if (i == 0)
	while (string[i] != '\0'
	       && string[i] != '_'
	       && ((string[i] - 48) < 0
		   || (string[i] - 48) > 9))
	  i++;

      if (i == 1)
	as_fatal (".attribute %s: empty non standard ISA extension?",
		  *in_arch);
      else
	len = i;
    }

  *name = (char *) malloc ((len + 1) * sizeof (char));
  memcpy (*name, *in_arch, len);
  memcpy (*name + len, "\0", 1);
  *in_arch = string + len;
}


static void
riscv_arch_version_int2str (int version, char *str, int minor)
{
  if (minor)
    sprintf (str, "%d", version % 10000);
  else
    sprintf (str, "%d", version / 10000);
}

static void
riscv_update_arch_info_hash (const char *arch, int version,
			     bfd_boolean update)
{
  const char *key;
  struct arch_info *info;
  char str[32];

  if (!update)
    return;

  info = (struct arch_info *) hash_find (arch_info_hash, arch);
  if (info)
    {
      if (version != -1)
	{
	  riscv_arch_version_int2str (version, str, 0);
	  info->v_major = xstrdup (str);
	  riscv_arch_version_int2str (version, str, 1);
	  info->v_minor = xstrdup (str);
	}
      info->valid = 1;
    }
  else
    {
      if (version == -1)
	version = 0;
      struct arch_info *new = malloc (sizeof (struct arch_info));
      key = xstrdup (arch);
      new->name = key;
      riscv_arch_version_int2str (version, str, 0);
      new->v_major = xstrdup (str);
      riscv_arch_version_int2str (version, str, 1);
      new->v_minor = xstrdup (str);
      new->valid = 1;

      const char *hash_error =
	hash_insert (arch_info_hash, key, (void *) new);
      if (hash_error)
	{
	  fprintf (stderr, _("internal error: can't hash `%s': %s\n"),
		   new->name, hash_error);
	}
    }
}

static int
strincmp(char const *a, char const *b, size_t sz)
{
  size_t i;
  if (!a || !b)
    return -1;

  for (i = 0; i < sz; a++, b++, i++)
    {
      int d = TOLOWER((unsigned char)*a) - TOLOWER((unsigned char)*b);
      if (d != 0 || !*a || !*b)
        return d;
    }

  return 0;
}

static bfd_boolean
riscv_parse_arch_attribute (const char *in_arch, bfd_boolean update)
{
  const char *all_subsets = "imafdqcp";
  char *name;
  int version;
  int parse_non_standard = 0;
  const char *in_arch_p = in_arch;

  riscv_set_rvc (FALSE);

  if (strincmp (in_arch_p, "rv32", 4) == 0)
    {
      xlen = 32;
      in_arch_p += 4;
    }
  else if (strincmp (in_arch_p, "rv64", 4) == 0)
    {
      xlen = 64;
      in_arch_p += 4;
    }
  else
    as_fatal (".attribute %s: ISA string must begin with rv32/rv64",
	      in_arch_p);

  switch (TOLOWER(*in_arch_p))
    {
    case 'e':
      in_arch_p++;
      version = riscv_parse_arch_version (&in_arch_p);
      riscv_update_arch_info_hash ("e", version, update);
      riscv_add_subset (&riscv_subsets, "e", 0, 0);
      riscv_add_subset (&riscv_subsets, "i", 0, 0);

      riscv_set_rve (TRUE);
      break;
    case 'g':
      in_arch_p++;
      version = riscv_parse_arch_version (&in_arch_p);
      for ( ; *all_subsets != 'q'; all_subsets++)
	{
	  const char subset[] = {*all_subsets, '\0'};
	  riscv_update_arch_info_hash (subset, version, update);
	  riscv_add_subset (&riscv_subsets, subset, 0, 0);
	}
      if (!riscv_opts.no_16_bit)
	{
	  riscv_update_arch_info_hash ("c", version, update);
	  riscv_set_rvc (TRUE);
	}
      break;
    case 'i':
      break;
    default:
      as_fatal (".attribute %s: first ISA subset must be i/g/e",
		in_arch_p);
    }

  while (*in_arch_p)
    {
      switch (TOLOWER(*in_arch_p))
	{
	case 'c':
	  if (riscv_opts.no_16_bit)
	    {
	      name = NULL;
	      riscv_parse_arch_name (&in_arch_p, 1, &name);
	      version = riscv_parse_arch_version (&in_arch_p);
	      free ((char *) name);
	      break;
	    }
	  riscv_set_rvc (TRUE);
	  /* Fall through.  */
	case 'i':
	case 'm':
	case 'a':
	case 'f':
	case 'd':
	case 'q':
	case 'p':
	  /* Standard extensions.  */
	  if (!parse_non_standard)
	    {
	      name = NULL;
	      riscv_parse_arch_name (&in_arch_p, 1, &name);
	      version = riscv_parse_arch_version (&in_arch_p);
	      riscv_update_arch_info_hash (name, version, update);
	      riscv_add_subset (&riscv_subsets, name, 0, 0);

	      free ((char *) name);
	    }
	  else
	    as_fatal (".attribute %c: Standard ISA subset can not "
		      "be set after Non-standard ISA subset.",
		      *in_arch_p);
	  break;
	case 'x':
	  parse_non_standard = 1;
	  name = NULL;
	  riscv_parse_arch_name (&in_arch_p, 0, &name);
	  version = riscv_parse_arch_version (&in_arch_p);
	  if (strcmp (name, "xv5") == 0)
	    {
	      if (version == 0)
		riscv_opts.efhw = TRUE;
	      if (version == -1)
		version = 10001;
	      riscv_update_arch_info_hash ("xv5-", version, update);
	      riscv_add_subset (&riscv_subsets, "xv5-", version/10000, version%10000);
	    }
	  else
	    {
	      riscv_update_arch_info_hash (name, version, update);
	      riscv_add_subset (&riscv_subsets, name, version/10000, version%10000);
	    }

	  if (*in_arch_p == '_')
	    in_arch_p++;

	  free ((char *) name);
	  break;
	default:
	  as_fatal (".attribute %s: ISA subset is unsupported",
		    in_arch_p);
	}
    }

  if (riscv_opts.atomic)
    riscv_add_subset (&riscv_subsets, "a", 0, 0);

  if (riscv_opts.dsp)
    riscv_add_subset (&riscv_subsets, "xdsp", 0, 0);

  if (riscv_opts.efhw)
    riscv_add_subset (&riscv_subsets, "xefhw", 1, 0);

  riscv_add_subset (&riscv_subsets, "c", 0, 0);

  return TRUE;
}

static void
riscv_set_arch_attributes (const char *name)
{
  obj_attribute *attr;
  const char *string;
  bfd_boolean update;

  if (name)
    {
      string = name;
      update = TRUE;
    }
  else
    {
      attr = elf_known_obj_attributes_proc (stdoutput);
      string = attr[Tag_arch].s;
      update = TRUE;
    }

  if (string && !riscv_parse_arch_attribute (string, update))
    as_fatal ("internal error: cannot parse .attribute %s",
	      string);
}

static int start_assemble_insn = 0;

void
md_assemble (char *str)
{
  struct riscv_cl_insn insn;
  expressionS imm_expr;
  bfd_reloc_code_real_type imm_reloc = BFD_RELOC_UNUSED;
  insn.cmodel.method = 0;

  if (!frag_now->tc_frag_data.rvc)
    frag_now->tc_frag_data.rvc = riscv_opts.rvc ? 1 : -1;

  if (!start_assemble_insn)
    {
      riscv_set_arch_attributes (NULL);
      start_assemble_insn = 1;
    }

  const char *error = riscv_ip (str, &insn, &imm_expr, &imm_reloc, op_hash);

  start_assemble = TRUE;

  if (error)
    {
      as_bad ("%s `%s'", error, str);
      return;
    }

  if (insn.insn_mo->pinfo == INSN_MACRO)
    macro (&insn, &imm_expr, &imm_reloc);
  else
    append_insn (&insn, &imm_expr, imm_reloc);
}

const char *
md_atof (int type, char *litP, int *sizeP)
{
  return ieee_md_atof (type, litP, sizeP, TARGET_BYTES_BIG_ENDIAN);
}

void
md_number_to_chars (char *buf, valueT val, int n)
{
  number_to_chars_littleendian (buf, val, n);
}

const char *md_shortopts = "O::g::G:";

enum options
{
  OPTION_MARCH = OPTION_MD_BASE,
  OPTION_PIC,
  OPTION_NO_PIC,
  OPTION_MABI,
  OPTION_RELAX,
  OPTION_NO_RELAX,
  OPTION_ARCH_ATTR,
  OPTION_NO_ARCH_ATTR,
  OPTION_NO_16_BIT,
  OPTION_MATOMIC,
  OPTION_ACE,
  OPTION_OPTIMIZE,
  OPTION_OPTIMIZE_SPACE,
  OPTION_MEXT_DSP,
  OPTION_MEXT_EFHW,
  OPTION_MEXT_VECTOR,
  OPTION_MICT_MODEL,
  OPTION_MCMODEL,
  OPTION_END_OF_ENUM
};

struct option md_longopts[] =
{
  {"march", required_argument, NULL, OPTION_MARCH},
  {"fPIC", no_argument, NULL, OPTION_PIC},
  {"fpic", no_argument, NULL, OPTION_PIC},
  {"fno-pic", no_argument, NULL, OPTION_NO_PIC},
  {"mabi", required_argument, NULL, OPTION_MABI},
  {"mrelax", no_argument, NULL, OPTION_RELAX},
  {"mno-relax", no_argument, NULL, OPTION_NO_RELAX},
  {"march-attr", no_argument, NULL, OPTION_ARCH_ATTR},
  {"mno-arch-attr", no_argument, NULL, OPTION_NO_ARCH_ATTR},
  {"mno-16-bit", no_argument, NULL, OPTION_NO_16_BIT},
  {"matomic", no_argument, NULL, OPTION_MATOMIC},
  {"mace", required_argument, NULL, OPTION_ACE},
  {"O1", no_argument, NULL, OPTION_OPTIMIZE},
  {"Os", no_argument, NULL, OPTION_OPTIMIZE_SPACE},
  {"mext-dsp", no_argument, NULL, OPTION_MEXT_DSP},
  {"mext-efhw", no_argument, NULL, OPTION_MEXT_EFHW},
  {"mext-vector", no_argument, NULL, OPTION_MEXT_VECTOR},
  {"mict-model", required_argument, NULL, OPTION_MICT_MODEL},
  {"mcmodel", required_argument, NULL, OPTION_MCMODEL},

  {NULL, no_argument, NULL, 0}
};
size_t md_longopts_size = sizeof (md_longopts);

enum float_abi {
  FLOAT_ABI_DEFAULT = -1,
  FLOAT_ABI_SOFT,
  FLOAT_ABI_SINGLE,
  FLOAT_ABI_DOUBLE,
  FLOAT_ABI_QUAD
};
static enum float_abi float_abi = FLOAT_ABI_DEFAULT;

static void
riscv_set_abi (unsigned new_xlen, enum float_abi new_float_abi, bfd_boolean rve)
{
  abi_xlen = new_xlen;
  float_abi = new_float_abi;
  rve_abi = rve;
}

int
md_parse_option (int c, const char *arg)
{
  switch (c)
    {
    case OPTION_MARCH:
      riscv_set_arch (arg);
      break;

    case OPTION_NO_PIC:
      riscv_opts.pic = FALSE;
      break;

    case OPTION_PIC:
      riscv_opts.pic = TRUE;
      break;

    case OPTION_MABI:
      if (strcmp (arg, "ilp32") == 0)
	riscv_set_abi (32, FLOAT_ABI_SOFT, FALSE);
      else if (strcmp (arg, "ilp32e") == 0)
	riscv_set_abi (32, FLOAT_ABI_SOFT, TRUE);
      else if (strcmp (arg, "ilp32f") == 0)
	riscv_set_abi (32, FLOAT_ABI_SINGLE, FALSE);
      else if (strcmp (arg, "ilp32d") == 0)
	riscv_set_abi (32, FLOAT_ABI_DOUBLE, FALSE);
      else if (strcmp (arg, "ilp32q") == 0)
	riscv_set_abi (32, FLOAT_ABI_QUAD, FALSE);
      else if (strcmp (arg, "lp64") == 0)
	riscv_set_abi (64, FLOAT_ABI_SOFT, FALSE);
      else if (strcmp (arg, "lp64f") == 0)
	riscv_set_abi (64, FLOAT_ABI_SINGLE, FALSE);
      else if (strcmp (arg, "lp64d") == 0)
	riscv_set_abi (64, FLOAT_ABI_DOUBLE, FALSE);
      else if (strcmp (arg, "lp64q") == 0)
	riscv_set_abi (64, FLOAT_ABI_QUAD, FALSE);
      else
	return 0;
      break;

    case OPTION_RELAX:
      riscv_opts.relax = TRUE;
      break;

    case OPTION_NO_RELAX:
      riscv_opts.relax = FALSE;
      break;

    case OPTION_ARCH_ATTR:
      riscv_opts.arch_attr = TRUE;
      break;

    case OPTION_NO_ARCH_ATTR:
      riscv_opts.arch_attr = FALSE;
      break;

    case OPTION_ACE:
      {
#ifndef __MINGW32__
	void *dlc = dlopen (arg, RTLD_NOW | RTLD_LOCAL);
	char *err;

	if (dlc == NULL)
	  err = (char *) dlerror ();
	else
	  {
	    ace_opcs = (struct riscv_opcode *) dlsym (dlc, "ace_opcodes_2");
	    err = (char *) dlerror ();
	    if (err == NULL)
	      {
		ace_ops = (ace_op_t *) dlsym (dlc, "ace_operands");
		err = (char *) dlerror ();
	    }
	    if (err == NULL)
	      {
		ace_keys = (ace_keyword_t *) dlsym (dlc, "ace_keywords");
		err = (char *) dlerror ();
	      }
	  }

	if (err == NULL)
	  {
	    ace_lib_load_success = TRUE;
	    return 1;
	  }
	else
	  as_bad ("Fault to load ACE shared library: %s\n", err);
#endif
      }
      break;


    case OPTION_NO_16_BIT:
      riscv_opts.no_16_bit = TRUE;
      break;

    case OPTION_MATOMIC:
      riscv_opts.atomic = TRUE;
      break;

    case OPTION_OPTIMIZE:
      optimize = 1;
      optimize_for_space = 0;
      break;

    case OPTION_OPTIMIZE_SPACE:
      optimize = 0;
      optimize_for_space = 1;
      break;

    case OPTION_MEXT_DSP:
      riscv_opts.dsp = TRUE;
      break;

    case OPTION_MEXT_EFHW:
      riscv_opts.efhw = TRUE;
      break;

    case OPTION_MEXT_VECTOR:
      riscv_opts.vector = TRUE;
      break;

    case OPTION_MICT_MODEL:
      if (strcmp ("tiny", arg) == 0
	  || strcmp ("small", arg) == 0
	  || strcmp ("large", arg) == 0)
	m_ict_model = arg;
      else
	as_bad (_("invalid ICT model setting -mict-model=%s"), arg);
      break;

    case OPTION_MCMODEL:
      if (strcmp (arg, "large") == 0)
	riscv_opts.cmodel = CMODEL_LARGE;
      else if (strcmp (arg, "medany") == 0)
	riscv_opts.cmodel = CMODEL_DEFAULT;
      else if (strcmp (arg, "medlow") == 0)
	riscv_opts.cmodel = CMODEL_DEFAULT;
      else
	as_bad (_("invalid cmodel setting -mcmodel=%s"), arg);
      break;

    default:
      return 0;
    }

  return 1;
}

void
riscv_after_parse_args (void)
{
  int d4_arch_type = 0;
  if (xlen == 0)
    {
      if (strncmp (default_arch, "rv32", 4) == 0)
	{
	  xlen = 32;
	  d4_arch_type = 1;
	}
      else if (strncmp (default_arch, "rv64", 4) == 0)
	{
	  xlen = 64;
	  d4_arch_type = 1;
	}
      else if (strcmp (default_arch, "riscv32") == 0)
	xlen = 32;
      else if (strcmp (default_arch, "riscv64") == 0)
	xlen = 64;
      else
	as_bad ("unknown default architecture `%s'", default_arch);
    }

  if (riscv_subsets.head == NULL)
    riscv_set_arch(d4_arch_type == 1 ? default_arch
				     : xlen == 64 ? "rv64g" : "rv32g");

  if (riscv_opts.atomic)
    riscv_add_subset (&riscv_subsets, "a", 2, 0);

  if (riscv_opts.dsp)
    riscv_add_subset (&riscv_subsets, "xdsp", 2, 0);

  if (riscv_opts.efhw)
    riscv_add_subset (&riscv_subsets, "xefhw", 1, 0);

  if (riscv_opts.vector)
    riscv_add_subset (&riscv_subsets, "v", 0, 7);

  riscv_set_rvc (FALSE);
  if (riscv_subset_supports ("c"))
    riscv_set_rvc (TRUE);

  riscv_set_rve (FALSE);
  if (riscv_subset_supports ("e"))
    riscv_set_rve (TRUE);

  /* Infer ABI from ISA if not specified on command line.  */
  if (abi_xlen == 0)
    abi_xlen = xlen;
  else if (abi_xlen > xlen)
    as_bad ("can't have %d-bit ABI on %d-bit ISA", abi_xlen, xlen);
  else if (abi_xlen < xlen)
    as_bad ("%d-bit ABI not yet supported on %d-bit ISA", abi_xlen, xlen);

  if (float_abi == FLOAT_ABI_DEFAULT)
    {
      riscv_subset_t *subset;

      /* Assume soft-float unless D extension is present.  */
      float_abi = FLOAT_ABI_SOFT;

      for (subset = riscv_subsets.head; subset != NULL; subset = subset->next)
	{
	  if (strcasecmp (subset->name, "D") == 0)
	    float_abi = FLOAT_ABI_DOUBLE;
	  if (strcasecmp (subset->name, "Q") == 0)
	    float_abi = FLOAT_ABI_QUAD;
	}
    }

  if (rve_abi)
    elf_flags |= EF_RISCV_RVE;

  /* Insert float_abi into the EF_RISCV_FLOAT_ABI field of elf_flags.  */
  elf_flags |= float_abi * (EF_RISCV_FLOAT_ABI & ~(EF_RISCV_FLOAT_ABI << 1));

  if (riscv_opts.cmodel == CMODEL_LARGE && xlen <= 32)
	riscv_opts.cmodel = CMODEL_DEFAULT;
#ifdef DEBUG_CMODEL
  printf("%s: cmodel = %d\n", __func__, riscv_opts.cmodel);
#endif
}

long
md_pcrel_from (fixS *fixP)
{
  return fixP->fx_where + fixP->fx_frag->fr_address;
}

static void
riscv_convert_ict_relocs (fixS ** fix)
{
  if ((*fix)->tc_fix_data.ict == BFD_RELOC_RISCV_ICT_HI20)
    switch ((*fix)->fx_r_type)
      {
      case BFD_RELOC_RISCV_HI20:
	(*fix)->fx_r_type = BFD_RELOC_RISCV_ICT_HI20;
	break;
      case BFD_RELOC_RISCV_LO12_I:
	(*fix)->fx_r_type = BFD_RELOC_RISCV_ICT_LO12_I;
	break;
      case BFD_RELOC_RISCV_PCREL_HI20:
	(*fix)->fx_r_type = BFD_RELOC_RISCV_PCREL_ICT_HI20;
	break;
      case BFD_RELOC_RISCV_CALL:
	(*fix)->fx_r_type = BFD_RELOC_RISCV_CALL_ICT;
	break;
      case BFD_RELOC_64:
	(*fix)->fx_r_type = BFD_RELOC_RISCV_ICT_64;
	break;
      default:
	as_fatal (_("internal error: ICT suffix for #%d "
		    "is not supported"),
		  (*fix)->fx_r_type);
	break;
      }
}

/* Apply a fixup to the object file.  */

void
md_apply_fix (fixS *fixP, valueT *valP, segT seg ATTRIBUTE_UNUSED)
{
  unsigned int subtype;
  bfd_byte *buf = (bfd_byte *) (fixP->fx_frag->fr_literal + fixP->fx_where);
  bfd_boolean relaxable = FALSE;
  offsetT loc;
  segT sub_segment;

  /* Remember value for tc_gen_reloc.  */
  fixP->fx_addnumber = *valP;

  riscv_convert_ict_relocs (&fixP);

  switch (fixP->fx_r_type)
    {
    case BFD_RELOC_RISCV_HI20:
    case BFD_RELOC_RISCV_LO12_I:
    case BFD_RELOC_RISCV_LO12_S:
    case BFD_RELOC_RISCV_LALO_HI20:
    case BFD_RELOC_RISCV_LALO_LO12_I:
    case BFD_RELOC_RISCV_ICT_HI20:
    case BFD_RELOC_RISCV_ICT_LO12_I:
      bfd_putl32 (riscv_apply_const_reloc (fixP->fx_r_type, *valP)
		  | bfd_getl32 (buf), buf);
      if (fixP->fx_addsy == NULL)
	fixP->fx_done = TRUE;
      relaxable = TRUE;
      break;

    case BFD_RELOC_RISCV_GOT_HI20:
    case BFD_RELOC_RISCV_ADD8:
    case BFD_RELOC_RISCV_ADD16:
    case BFD_RELOC_RISCV_ADD32:
    case BFD_RELOC_RISCV_ADD64:
    case BFD_RELOC_RISCV_SUB6:
    case BFD_RELOC_RISCV_SUB8:
    case BFD_RELOC_RISCV_SUB16:
    case BFD_RELOC_RISCV_SUB32:
    case BFD_RELOC_RISCV_SUB64:
    case BFD_RELOC_RISCV_RELAX:
      break;

    case BFD_RELOC_RISCV_TPREL_HI20:
    case BFD_RELOC_RISCV_TPREL_LO12_I:
    case BFD_RELOC_RISCV_TPREL_LO12_S:
    case BFD_RELOC_RISCV_TPREL_ADD:
      relaxable = TRUE;
      /* Fall through.  */

    case BFD_RELOC_RISCV_TLS_GOT_HI20:
    case BFD_RELOC_RISCV_TLS_GD_HI20:
    case BFD_RELOC_RISCV_TLS_DTPREL32:
    case BFD_RELOC_RISCV_TLS_DTPREL64:
      if (fixP->fx_addsy != NULL)
	S_SET_THREAD_LOCAL (fixP->fx_addsy);
      else
	as_bad_where (fixP->fx_file, fixP->fx_line,
		      _("TLS relocation against a constant"));
      break;

    case BFD_RELOC_32:
      /* Use pc-relative relocation for FDE initial location.
	 The symbol address in .eh_frame may be adjusted in
	 _bfd_elf_discard_section_eh_frame, and the content of
	 .eh_frame will be adjusted in _bfd_elf_write_section_eh_frame.
	 Therefore, we cannot insert a relocation whose addend symbol is
	 in .eh_frame. Othrewise, the value may be adjusted twice.*/
      if (fixP->fx_addsy && fixP->fx_subsy
	  && (sub_segment = S_GET_SEGMENT (fixP->fx_subsy))
	  && strcmp (sub_segment->name, ".eh_frame") == 0
	  && S_GET_VALUE (fixP->fx_subsy)
	     == fixP->fx_frag->fr_address + fixP->fx_where)
	{
	  fixP->fx_r_type = BFD_RELOC_RISCV_32_PCREL;
	  fixP->fx_subsy = NULL;
	  break;
	}
      /* Fall through.  */
    case BFD_RELOC_64:
    case BFD_RELOC_16:
    case BFD_RELOC_8:
    case BFD_RELOC_RISCV_CFA:
      if (fixP->fx_addsy && fixP->fx_subsy)
	{
	  fixP->fx_next = xmemdup (fixP, sizeof (*fixP), sizeof (*fixP));
	  fixP->fx_next->fx_addsy = fixP->fx_subsy;
	  fixP->fx_next->fx_subsy = NULL;
	  fixP->fx_next->fx_offset = 0;
	  fixP->fx_subsy = NULL;

	  switch (fixP->fx_r_type)
	    {
	    case BFD_RELOC_64:
	      fixP->fx_r_type = BFD_RELOC_RISCV_ADD64;
	      fixP->fx_next->fx_r_type = BFD_RELOC_RISCV_SUB64;
	      break;

	    case BFD_RELOC_32:
	      fixP->fx_r_type = BFD_RELOC_RISCV_ADD32;
	      fixP->fx_next->fx_r_type = BFD_RELOC_RISCV_SUB32;
	      break;

	    case BFD_RELOC_16:
	      fixP->fx_r_type = BFD_RELOC_RISCV_ADD16;
	      fixP->fx_next->fx_r_type = BFD_RELOC_RISCV_SUB16;
	      break;

	    case BFD_RELOC_8:
	      fixP->fx_r_type = BFD_RELOC_RISCV_ADD8;
	      fixP->fx_next->fx_r_type = BFD_RELOC_RISCV_SUB8;
	      break;

	    case BFD_RELOC_RISCV_CFA:
	      /* Load the byte to get the subtype.  */
	      subtype = bfd_get_8 (NULL, &((fragS *) (fixP->fx_frag->fr_opcode))->fr_literal[fixP->fx_where]);
	      loc = fixP->fx_frag->fr_fix - (subtype & 7);
	      switch (subtype)
		{
		case DW_CFA_advance_loc1:
		  fixP->fx_where = loc + 1;
		  fixP->fx_next->fx_where = loc + 1;
		  fixP->fx_r_type = BFD_RELOC_RISCV_SET8;
		  fixP->fx_next->fx_r_type = BFD_RELOC_RISCV_SUB8;
		  break;

		case DW_CFA_advance_loc2:
		  fixP->fx_size = 2;
		  fixP->fx_next->fx_size = 2;
		  fixP->fx_where = loc + 1;
		  fixP->fx_next->fx_where = loc + 1;
		  fixP->fx_r_type = BFD_RELOC_RISCV_SET16;
		  fixP->fx_next->fx_r_type = BFD_RELOC_RISCV_SUB16;
		  break;

		case DW_CFA_advance_loc4:
		  fixP->fx_size = 4;
		  fixP->fx_next->fx_size = 4;
		  fixP->fx_where = loc;
		  fixP->fx_next->fx_where = loc;
		  fixP->fx_r_type = BFD_RELOC_RISCV_SET32;
		  fixP->fx_next->fx_r_type = BFD_RELOC_RISCV_SUB32;
		  break;

		default:
		  if (subtype < 0x80 && (subtype & 0x40))
		    {
		      /* DW_CFA_advance_loc */
		      fixP->fx_frag = (fragS *) fixP->fx_frag->fr_opcode;
		      fixP->fx_next->fx_frag = fixP->fx_frag;
		      fixP->fx_r_type = BFD_RELOC_RISCV_SET6;
		      fixP->fx_next->fx_r_type = BFD_RELOC_RISCV_SUB6;
		    }
		  else
		    as_fatal (_("internal error: bad CFA value #%d"), subtype);
		  break;
		}
	      break;

	    default:
	      /* This case is unreachable.  */
	      abort ();
	    }
	}
      /* Fall through.  */

    case BFD_RELOC_RVA:
      /* If we are deleting this reloc entry, we must fill in the
	 value now.  This can happen if we have a .word which is not
	 resolved when it appears but is later defined.  */
      if (fixP->fx_addsy == NULL)
	{
	  gas_assert (fixP->fx_size <= sizeof (valueT));
	  md_number_to_chars ((char *) buf, *valP, fixP->fx_size);
	  fixP->fx_done = 1;
	}
      break;

    case BFD_RELOC_RISCV_JMP:
      if (fixP->fx_addsy)
	{
	  bfd_vma target = S_GET_VALUE (fixP->fx_addsy) + *valP;
	  bfd_vma delta = target - md_pcrel_from (fixP);
	  bfd_putl32 (bfd_getl32 (buf) | ENCODE_UJTYPE_IMM (delta), buf);
	}
      break;

    case BFD_RELOC_12_PCREL:
      if (fixP->fx_addsy)
	{
	  /* Fill in a tentative value to improve objdump readability.  */
	  bfd_vma target = S_GET_VALUE (fixP->fx_addsy) + *valP;
	  bfd_vma delta = target - md_pcrel_from (fixP);
	  bfd_putl32 (bfd_getl32 (buf) | ENCODE_SBTYPE_IMM (delta), buf);
	}
      break;

    case BFD_RELOC_RISCV_RVC_BRANCH:
      if (fixP->fx_addsy)
	{
	  /* Fill in a tentative value to improve objdump readability.  */
	  bfd_vma target = S_GET_VALUE (fixP->fx_addsy) + *valP;
	  bfd_vma delta = target - md_pcrel_from (fixP);
	  bfd_putl16 (bfd_getl16 (buf) | ENCODE_RVC_B_IMM (delta), buf);
	}
      break;

    case BFD_RELOC_RISCV_RVC_JUMP:
      if (fixP->fx_addsy)
	{
	  /* Fill in a tentative value to improve objdump readability.  */
	  bfd_vma target = S_GET_VALUE (fixP->fx_addsy) + *valP;
	  bfd_vma delta = target - md_pcrel_from (fixP);
	  bfd_putl16 (bfd_getl16 (buf) | ENCODE_RVC_J_IMM (delta), buf);
	}
      break;

    case BFD_RELOC_RISCV_CALL:
    case BFD_RELOC_RISCV_CALL_PLT:
    case BFD_RELOC_RISCV_CALL_ICT:
      relaxable = TRUE;
      break;

    case BFD_RELOC_RISCV_PCREL_HI20:
    case BFD_RELOC_RISCV_PCREL_LO12_S:
    case BFD_RELOC_RISCV_PCREL_LO12_I:
    case BFD_RELOC_RISCV_PCREL_ICT_HI20:
      relaxable = riscv_opts.relax;
      break;

    case BFD_RELOC_RISCV_10_PCREL:
      if (fixP->fx_addsy)
	{
	  /* Fill in a tentative value to improve objdump readability.  */
	  bfd_vma target = S_GET_VALUE (fixP->fx_addsy) + *valP;
	  bfd_vma delta = target - md_pcrel_from (fixP);
	  bfd_putl32 (bfd_getl32 (buf) | ENCODE_STYPE_IMM10 (delta), buf);
	}
      break;

    case BFD_RELOC_RISCV_ALIGN:
      if (fixP->fx_frag->fr_var >= 2)
	fixP->fx_addnumber += 2;
      break;
    case BFD_RELOC_RISCV_ALIGN_BTB:
    case BFD_RELOC_RISCV_DATA:
    case BFD_RELOC_RISCV_ICT_64:
    case BFD_RELOC_RISCV_LGP18S0:
    case BFD_RELOC_RISCV_LGP17S1:
    case BFD_RELOC_RISCV_LGP17S2:
    case BFD_RELOC_RISCV_LGP17S3:
    case BFD_RELOC_RISCV_SGP18S0:
    case BFD_RELOC_RISCV_SGP17S1:
    case BFD_RELOC_RISCV_SGP17S2:
    case BFD_RELOC_RISCV_SGP17S3:
    case BFD_RELOC_RISCV_RELAX_REGION_BEGIN:
    case BFD_RELOC_RISCV_RELAX_REGION_END:
    case BFD_RELOC_RISCV_NO_RVC_REGION_BEGIN:
    case BFD_RELOC_RISCV_NO_RVC_REGION_END:
    case BFD_RELOC_RISCV_RELAX_ENTRY:
      break;

    default:
      /* We ignore generic BFD relocations we don't know about.  */
      if (bfd_reloc_type_lookup (stdoutput, fixP->fx_r_type) != NULL)
	as_fatal (_("internal error: bad relocation #%d"), fixP->fx_r_type);
    }

  if (fixP->fx_subsy != NULL)
    as_bad_where (fixP->fx_file, fixP->fx_line,
		  _("unsupported symbol subtraction"));

  /* Add an R_RISCV_RELAX reloc if the reloc is relaxable.  */
  if (relaxable && fixP->fx_tcbit && fixP->fx_addsy != NULL)
    {
      fixP->fx_next = xmemdup (fixP, sizeof (*fixP), sizeof (*fixP));
      fixP->fx_next->fx_addsy = fixP->fx_next->fx_subsy = NULL;
      fixP->fx_next->fx_r_type = BFD_RELOC_RISCV_RELAX;
      fixP->fx_next->tc_fix_data.ict = 0;
    }
}

/* Because the value of .cfi_remember_state may changed after relaxation,
   we insert a fix to relocate it again in link-time.  */

void
riscv_pre_output_hook (void)
{
  const frchainS *frch;
  const asection *s;

  for (s = stdoutput->sections; s; s = s->next)
    for (frch = seg_info (s)->frchainP; frch; frch = frch->frch_next)
      {
	fragS *frag;

	for (frag = frch->frch_root; frag; frag = frag->fr_next)
	  {
	    if (frag->fr_type == rs_cfa)
	      {
		expressionS exp;
		expressionS *symval;

		symval = symbol_get_value_expression (frag->fr_symbol);
		exp.X_op = O_subtract;
		exp.X_add_symbol = symval->X_add_symbol;
		exp.X_add_number = 0;
		exp.X_op_symbol = symval->X_op_symbol;

		fix_new_exp (frag, (int) frag->fr_offset, 1, &exp, 0,
			     BFD_RELOC_RISCV_CFA);
	      }
	  }
      }
}

static void
riscv_rvc_reloc_setting (int mode)
{
  if (!start_assemble_insn)
    return;

  if (mode)
    fix_new (frag_now, frag_now_fix (), 0, abs_section_sym,
	     0x1, 0, BFD_RELOC_RISCV_NO_RVC_REGION_BEGIN);
  else
    fix_new (frag_now, frag_now_fix (), 0, abs_section_sym,
	     0x0, 0, BFD_RELOC_RISCV_NO_RVC_REGION_BEGIN);
}

/* This structure is used to hold a stack of .option values.  */

struct riscv_option_stack
{
  struct riscv_option_stack *next;
  struct riscv_set_options options;
};

static struct riscv_option_stack *riscv_opts_stack;

/* Handle the .option pseudo-op.  */

static void
s_riscv_option (int x ATTRIBUTE_UNUSED)
{
  char *name = input_line_pointer, ch;

  while (!is_end_of_line[(unsigned char) *input_line_pointer])
    ++input_line_pointer;
  ch = *input_line_pointer;
  *input_line_pointer = '\0';

  if (strcmp (name, "rvc") == 0)
    {
      riscv_set_rvc (TRUE);
      riscv_rvc_reloc_setting (1);
    }
  else if (strcmp (name, "norvc") == 0)
    {
      /* Force to set the 4-byte aligned when converting
	 rvc to norvc.  The repeated alignment setting is
	 fine since linker will remove the redundant nops.  */
      if (riscv_opts.rvc)
	riscv_frag_align_code (2);
      riscv_set_rvc (FALSE);
      riscv_rvc_reloc_setting (0);
    }
  else if (strcmp (name, "pic") == 0)
    riscv_opts.pic = TRUE;
  else if (strcmp (name, "nopic") == 0)
    riscv_opts.pic = FALSE;
  else if (strcmp (name, "relax") == 0)
    riscv_opts.relax = TRUE;
  else if (strcmp (name, "norelax") == 0)
    riscv_opts.relax = FALSE;
  else if (strcmp (name, "push") == 0)
    {
      struct riscv_option_stack *s;

      s = (struct riscv_option_stack *) xmalloc (sizeof *s);
      s->next = riscv_opts_stack;
      s->options = riscv_opts;
      riscv_opts_stack = s;
    }
  else if (strcmp (name, "pop") == 0)
    {
      struct riscv_option_stack *s;
      int pre_rvc;

      s = riscv_opts_stack;
      pre_rvc = riscv_opts.rvc;
      if (s == NULL)
	as_bad (_(".option pop with no .option push"));
      else
	{
	  riscv_opts = s->options;
	  riscv_opts_stack = s->next;
	  free (s);
	}

      /* Deal with the rvc setting.  */
      if (riscv_opts.rvc && !pre_rvc)
	/* norvc to rvc.  */
	riscv_rvc_reloc_setting (1);
      else if (!riscv_opts.rvc && pre_rvc)
	{
	  /* rvc to norvc.  */
	  riscv_opts.rvc = 1;
	  riscv_frag_align_code (2);
	  riscv_opts.rvc = 0;
	  riscv_rvc_reloc_setting (0);
	}
    }
  else if (strcmp (name, "execit") == 0
	   || strcmp (name, "ex9") == 0)
    riscv_opts.execit = TRUE;
  else if (strcmp (name, "verbatim") == 0)
    riscv_opts.verbatim = TRUE;
  else if (strncmp (name, "cmodel_[large|medany]", 6) == 0)
    {
      if (strcmp (name+6, "_large") == 0 && xlen > 32)
	riscv_opts.cmodel = CMODEL_LARGE;
      else if (strcmp (name+6, "_medany") == 0)
	riscv_opts.cmodel = CMODEL_DEFAULT;
      else if (strcmp (name+6, "_medlow") == 0)
	riscv_opts.cmodel = CMODEL_DEFAULT;
#ifdef DEBUG_CMODEL
      printf("%s: cmodel = %d\n", __func__, riscv_opts.cmodel);
#endif
    }
  else
    {
      as_warn (_("Unrecognized .option directive: %s\n"), name);
    }
  *input_line_pointer = ch;
  demand_empty_rest_of_line ();
}

/* Handle the .dtprelword and .dtpreldword pseudo-ops.  They generate
   a 32-bit or 64-bit DTP-relative relocation (BYTES says which) for
   use in DWARF debug information.  */

static void
s_dtprel (int bytes)
{
  expressionS ex;
  char *p;

  expression (&ex);

  if (ex.X_op != O_symbol)
    {
      as_bad (_("Unsupported use of %s"), (bytes == 8
					   ? ".dtpreldword"
					   : ".dtprelword"));
      ignore_rest_of_line ();
    }

  p = frag_more (bytes);
  md_number_to_chars (p, 0, bytes);
  fix_new_exp (frag_now, p - frag_now->fr_literal, bytes, &ex, FALSE,
	       (bytes == 8
		? BFD_RELOC_RISCV_TLS_DTPREL64
		: BFD_RELOC_RISCV_TLS_DTPREL32));

  demand_empty_rest_of_line ();
}

/* Handle the .bss pseudo-op.  */

static void
s_bss (int ignore ATTRIBUTE_UNUSED)
{
  subseg_set (bss_section, 0);
  demand_empty_rest_of_line ();
}

/* Called from md_do_align.  Used to create an alignment frag in a
   code section by emitting a worst-case NOP sequence that the linker
   will later relax to the correct number of NOPs.  We can't compute
   the correct alignment now because of other linker relaxations.  */

bfd_boolean
riscv_frag_align_code (int n)
{
  /* TODO: Review this.  */
  expressionS exp;
  bfd_vma alignment_power = riscv_opts.rvc ? 1 : 2;
  bfd_vma bytes = (bfd_vma) 1 << n;
  bfd_vma insn_alignment = riscv_opts.rvc ? 2 : 4;
  bfd_vma worst_case_bytes = bytes - insn_alignment;
  fragS* fragP = frag_now;
  char *p;

  unsigned fragP_fix = (frag_now_fix() + 1) >> 1 << 1;

  /* When not relaxing, riscv_handle_align handles code alignment.  */
  if (!riscv_opts.relax)
    return FALSE;

  if (bytes <= insn_alignment)
    return FALSE;

  frag_align_code (alignment_power, 0);

  exp.X_op = O_constant;
  /* Just set the worst value temporarily.  */
  exp.X_add_number = worst_case_bytes;
  fix_new_exp (fragP, fragP_fix, 0, &exp, 0, BFD_RELOC_RISCV_ALIGN);
  p = frag_more (worst_case_bytes);
  /* zero contents for Andes bug20178.  */
  md_number_to_chars (p, 0, worst_case_bytes);

  return TRUE;
}

/* Implement HANDLE_ALIGN.  */

void
riscv_handle_align (fragS *fragP)
{
  bfd_signed_vma bytes ;

  if (fragP->fr_type != rs_align_code)
    return;

  bytes = fragP->fr_next->fr_address - fragP->fr_address - fragP->fr_fix;
  bfd_signed_vma size = 4;
  bfd_signed_vma excess = bytes % size;
  char *p = fragP->fr_literal + fragP->fr_fix;

  if (bytes <= 0)
    return;

  if (excess)
    {
      riscv_make_nops (p, excess);
      fragP->fr_fix += excess;
      p += excess;
      if (excess >= 2)
	fragP->fr_var = 2;
    }

  if (bytes > size)
    {
      riscv_make_nops (p, size);
      fragP->fr_var = size;
    }
}

int
md_estimate_size_before_relax (fragS *fragp, asection *segtype)
{
  if (RELAX_BRANCH_P (fragp->fr_subtype))
    fragp->fr_var = relaxed_branch_length (fragp, segtype, FALSE);
  else if (RELAX_CMODEL_P (fragp->fr_subtype))
    fragp->fr_var = relaxed_cmodel_length (fragp, segtype);
  else
    gas_assert (0);

  return fragp->fr_var;
}

/* Translate internal representation of relocation info to BFD target
   format.  */

arelent *
tc_gen_reloc (asection *section ATTRIBUTE_UNUSED, fixS *fixp)
{
  arelent *reloc = (arelent *) xmalloc (sizeof (arelent));

  reloc->sym_ptr_ptr = (asymbol **) xmalloc (sizeof (asymbol *));
  *reloc->sym_ptr_ptr = symbol_get_bfdsym (fixp->fx_addsy);
  reloc->address = fixp->fx_frag->fr_address + fixp->fx_where;
  reloc->addend = fixp->fx_addnumber;

  reloc->howto = bfd_reloc_type_lookup (stdoutput, fixp->fx_r_type);
  if (reloc->howto == NULL)
    {
      if ((fixp->fx_r_type == BFD_RELOC_16 || fixp->fx_r_type == BFD_RELOC_8)
	  && fixp->fx_addsy != NULL && fixp->fx_subsy != NULL)
	{
	  /* We don't have R_RISCV_8/16, but for this special case,
	     we can use R_RISCV_ADD8/16 with R_RISCV_SUB8/16.  */
	  return reloc;
	}

      as_bad_where (fixp->fx_file, fixp->fx_line,
		    _("cannot represent %s relocation in object file"),
		    bfd_get_reloc_code_name (fixp->fx_r_type));
      return NULL;
    }

  switch (fixp->fx_r_type)
    {
    default:
      reloc->addend = fixp->fx_addnumber;
      break;

    case BFD_RELOC_RISCV_DATA:
      /* Prevent linker from optimizing data in text sections.
	 For example, jump table.  */
      reloc->addend = fixp->fx_size;
      break;
    }

  return reloc;
}

int
riscv_relax_frag (asection *sec, fragS *fragp, long stretch ATTRIBUTE_UNUSED)
{
  if (RELAX_BRANCH_P (fragp->fr_subtype))
    {
      offsetT old_var = fragp->fr_var;
      fragp->fr_var = relaxed_branch_length (fragp, sec, TRUE);
      return fragp->fr_var - old_var;
    }

  return 0;
}

/* Expand far branches to multi-instruction sequences.  */

static void
md_convert_frag_branch (fragS *fragp, segT sec)
{
  bfd_byte *buf;
  expressionS exp;
  fixS *fixp;
  insn_t insn;
  int rs1, reloc;

  buf = (bfd_byte *)fragp->fr_literal + fragp->fr_fix;

  exp.X_op = O_symbol;
  exp.X_add_symbol = fragp->fr_symbol;
  exp.X_add_number = fragp->fr_offset;

  gas_assert (fragp->fr_var == RELAX_BRANCH_LENGTH (fragp->fr_subtype));

  if (RELAX_BRANCH_RVC (fragp->fr_subtype))
    {
      switch (RELAX_BRANCH_LENGTH (fragp->fr_subtype))
	{
	  case 8:
	  case 4:
	    insn = bfd_getl16 (buf);
	    rs1 = 8 + ((insn >> OP_SH_CRS1S) & OP_MASK_CRS1S);
	    if ((insn & MASK_C_J) == MATCH_C_J)
	      insn = MATCH_JAL;
	    else if ((insn & MASK_C_JAL) == MATCH_C_JAL)
	      insn = MATCH_JAL | (X_RA << OP_SH_RD);
	    else if ((insn & MASK_C_BEQZ) == MATCH_C_BEQZ)
	      insn = MATCH_BEQ | (rs1 << OP_SH_RS1);
	    else if ((insn & MASK_C_BNEZ) == MATCH_C_BNEZ)
	      insn = MATCH_BNE | (rs1 << OP_SH_RS1);
	    else
	      abort ();
	    bfd_putl32 (insn, buf);
	    break;

	  case 6:
	    insn = bfd_getl16 (buf);
	    insn ^= MATCH_C_BEQZ ^ MATCH_C_BNEZ;
	    insn |= ENCODE_RVC_B_IMM (6);
	    bfd_putl16 (insn, buf);
	    exp.X_add_symbol = symbol_temp_new (sec, 0, fragp->fr_next);
	    exp.X_add_number = 0;
	    reloc = BFD_RELOC_RISCV_RVC_BRANCH;
	    fixp = fix_new_exp (fragp, buf - (bfd_byte *)fragp->fr_literal,
				2, &exp, FALSE, reloc);
	    buf += 2;
	    goto jump;

	  case 2:
	    /* Just keep the RVC branch.  */
	    reloc = RELAX_BRANCH_UNCOND (fragp->fr_subtype)
		    ? BFD_RELOC_RISCV_RVC_JUMP : BFD_RELOC_RISCV_RVC_BRANCH;
	    fixp = fix_new_exp (fragp, buf - (bfd_byte *)fragp->fr_literal,
				2, &exp, FALSE, reloc);
	    buf += 2;
	    goto done;

	  default:
	    abort ();
	}
    }

  switch (RELAX_BRANCH_LENGTH (fragp->fr_subtype))
    {
    case 8:
      gas_assert (!RELAX_BRANCH_UNCOND (fragp->fr_subtype));

      /* Invert the branch condition.  Branch over the jump.  */
      insn = bfd_getl32 (buf);
      if (((insn & MASK_BEQC) == MATCH_BEQC)
	  || ((insn & MASK_BNEC) == MATCH_BNEC))
	{
	  insn ^= MATCH_BEQC ^ MATCH_BNEC;
	  insn |= ENCODE_STYPE_IMM10 (8);
	  reloc = BFD_RELOC_RISCV_10_PCREL;
	}
      else if (((insn & MASK_BBC) == MATCH_BBC)
	       || ((insn & MASK_BBS) == MATCH_BBS))
	{
	  insn ^= MATCH_BBC ^ MATCH_BBS;
	  insn |= ENCODE_STYPE_IMM10 (8);
	  reloc = BFD_RELOC_RISCV_10_PCREL;
	}
      else
	{
	  insn ^= MATCH_BEQ ^ MATCH_BNE;
	  insn |= ENCODE_SBTYPE_IMM (8);
	  reloc = BFD_RELOC_12_PCREL;
	}
      md_number_to_chars ((char *) buf, insn, 4);
      /* Keep the relocation for the branch.  */
      exp.X_add_symbol = symbol_temp_new (sec, 0, fragp->fr_next);
      exp.X_add_number = 0;
      fixp = fix_new_exp (fragp, buf - (bfd_byte *)fragp->fr_literal,
			  4, &exp, FALSE, reloc);
      buf += 4;

jump:
      /* Jump to the target.  */
      exp.X_add_symbol = fragp->fr_symbol;
      exp.X_add_number = fragp->fr_offset;
      fixp = fix_new_exp (fragp, buf - (bfd_byte *)fragp->fr_literal,
			  4, &exp, FALSE, BFD_RELOC_RISCV_JMP);
      md_number_to_chars ((char *) buf, MATCH_JAL, 4);
      buf += 4;
      break;

    case 4:
      switch (RELAX_BRANCH_RANGE (fragp->fr_subtype))
	{
	case RANGE_JMP:
	  reloc = BFD_RELOC_RISCV_JMP;
	  break;
	case RANGE_BRANCH:
	    reloc = BFD_RELOC_12_PCREL;
	    break;
	case RANGE_10_PCREL:
	    reloc = BFD_RELOC_RISCV_10_PCREL;
	    break;
	default:
	    reloc = RELAX_BRANCH_UNCOND (fragp->fr_subtype)
	      ? BFD_RELOC_RISCV_JMP : BFD_RELOC_12_PCREL;
	    break;
	}
      fixp = fix_new_exp (fragp, buf - (bfd_byte *)fragp->fr_literal,
			  4, &exp, FALSE, reloc);
      buf += 4;
      break;

    default:
      abort ();
    }

done:
  fixp->fx_file = fragp->fr_file;
  fixp->fx_line = fragp->fr_line;

  gas_assert (buf == (bfd_byte *)fragp->fr_literal
	      + fragp->fr_fix + fragp->fr_var);

  fragp->fr_fix += fragp->fr_var;
}

static void
md_convert_frag_cmodel (fragS *fragp, segT sec)
{
  static expressionS exp_ind, exp_ref;
  bfd_byte *buf;
  expressionS exp;
  fixS *fixp = NULL;
  int reloc;
  int type = RELAX_CMODEL_TYPE (fragp->fr_subtype);
  int length = RELAX_CMODEL_LENGTH (fragp->fr_subtype);
  int index = RELAX_CMODEL_INDEX (fragp->fr_subtype);
  int is_same_sec = is_same_section_symbol (fragp->fr_symbol, sec);

  gas_assert (fragp->fr_var == RELAX_CMODEL_LENGTH (fragp->fr_subtype));

  buf = (bfd_byte *)fragp->fr_literal + fragp->fr_fix;

  exp.X_op = O_symbol;
  exp.X_add_symbol = fragp->fr_symbol;
  exp.X_add_number = fragp->fr_offset;

  switch (index)
  {
  case CSI_INDIRECT_SYMBOL:
    exp_ind = exp;
    switch (type)
    {
    case TYPE_JX ... TYPE_ST:
      break;
    case TYPE_IS:
      if (is_same_sec)
	gas_assert (length == 0);
      else
	{
	  gas_assert (length == 8);
	  reloc = BFD_RELOC_64;
	  fix_new_exp (fragp, buf - (bfd_byte *)fragp->fr_literal,
		       CMODEL_SECTION_ENTRY_SIZE, &exp, FALSE, reloc);
	}
      break;
    default:
      as_fatal (_("internal error: invalid CModel type!"));
    }
    break;
  case CSI_REFERENCE_SYMBOL:
    exp_ref = exp;
    break;
  case CSI_LARGE_CODE:
    reloc = 0;
    switch (type)
    {
    case TYPE_JX:
      if (is_same_sec)
        gas_assert (length == 0);
      else
	{
	  reloc = BFD_RELOC_RISCV_PCREL_HI20;
	  fix_new_exp (fragp, buf - (bfd_byte *)fragp->fr_literal,
		       4, &exp_ind, FALSE, reloc);
	  reloc = BFD_RELOC_RISCV_RELAX;
	  fix_new (fragp, buf - (bfd_byte *)fragp->fr_literal,
		   0, abs_section_sym, 0, FALSE, reloc);

	  reloc = BFD_RELOC_RISCV_PCREL_LO12_I;
	  fix_new_exp (fragp, buf - (bfd_byte *)fragp->fr_literal + 4,
		       4, &exp_ref, FALSE, reloc);
	  reloc = BFD_RELOC_RISCV_RELAX;
	  fix_new (fragp, buf - (bfd_byte *)fragp->fr_literal +4,
		   0, abs_section_sym, 0, FALSE, reloc);

	  /* TODO: relax jalr to c.jalr  */
	}
      break;
    case TYPE_LA:
      gas_assert (length == 8);
      if (is_same_sec)
	{
	  int32_t *bin = (int32_t *) buf;
	  bin[1] = bin[2];

	  reloc = BFD_RELOC_RISCV_PCREL_HI20;
	  fix_new_exp (fragp, buf - (bfd_byte *)fragp->fr_literal,
		       4, &exp, FALSE, reloc);
	  reloc = BFD_RELOC_RISCV_RELAX;
	  fix_new (fragp, buf - (bfd_byte *)fragp->fr_literal,
		   0, abs_section_sym, 0, FALSE, reloc);

	  reloc = BFD_RELOC_RISCV_PCREL_LO12_I;
	  fix_new_exp (fragp, buf - (bfd_byte *)fragp->fr_literal + 4,
		       4, &exp_ref, FALSE, reloc);
	  reloc = BFD_RELOC_RISCV_RELAX;
	  fix_new (fragp, buf - (bfd_byte *)fragp->fr_literal +4,
		   0, abs_section_sym, 0, FALSE, reloc);
	}
      else
	{
	  reloc = BFD_RELOC_RISCV_PCREL_HI20;
	  fix_new_exp (fragp, buf - (bfd_byte *)fragp->fr_literal,
		       4, &exp_ind, FALSE, reloc);
	  reloc = BFD_RELOC_RISCV_RELAX;
	  fix_new (fragp, buf - (bfd_byte *)fragp->fr_literal,
		   0, abs_section_sym, 0, FALSE, reloc);

	  reloc = BFD_RELOC_RISCV_PCREL_LO12_I;
	  fix_new_exp (fragp, buf - (bfd_byte *)fragp->fr_literal + 4,
		       4, &exp_ref, FALSE, reloc);
	  reloc = BFD_RELOC_RISCV_RELAX;
	  fix_new (fragp, buf - (bfd_byte *)fragp->fr_literal +4,
		   0, abs_section_sym, 0, FALSE, reloc);
	}
      break;
    case TYPE_LD:
      if (is_same_sec)
	{
	  gas_assert (length == 8);
	  int32_t *bin = (int32_t *) buf;
	  bin[1] = bin[2];

	  reloc = BFD_RELOC_RISCV_PCREL_HI20;
	  fix_new_exp (fragp, buf - (bfd_byte *)fragp->fr_literal,
		       4, &exp, FALSE, reloc);
	  reloc = BFD_RELOC_RISCV_RELAX;
	  fix_new (fragp, buf - (bfd_byte *)fragp->fr_literal,
		   0, abs_section_sym, 0, FALSE, reloc);

	  reloc = BFD_RELOC_RISCV_PCREL_LO12_I;
	  fix_new_exp (fragp, buf - (bfd_byte *)fragp->fr_literal + 4,
		       4, &exp_ref, FALSE, reloc);
	  reloc = BFD_RELOC_RISCV_RELAX;
	  fix_new (fragp, buf - (bfd_byte *)fragp->fr_literal +4,
		   0, abs_section_sym, 0, FALSE, reloc);
	}
      else
	{
	  gas_assert (length == 12);
	  reloc = BFD_RELOC_RISCV_PCREL_HI20;
	  fix_new_exp (fragp, buf - (bfd_byte *)fragp->fr_literal,
		       4, &exp_ind, FALSE, reloc);
	  reloc = BFD_RELOC_RISCV_RELAX;
	  fix_new (fragp, buf - (bfd_byte *)fragp->fr_literal,
		   0, abs_section_sym, 0, FALSE, reloc);

	  reloc = BFD_RELOC_RISCV_PCREL_LO12_I;
	  fix_new_exp (fragp, buf - (bfd_byte *)fragp->fr_literal + 4,
		       4, &exp_ref, FALSE, reloc);
	  reloc = BFD_RELOC_RISCV_RELAX;
	  fix_new (fragp, buf - (bfd_byte *)fragp->fr_literal +4,
		   0, abs_section_sym, 0, FALSE, reloc);
	}
      break;
    case TYPE_ST:
      if (is_same_sec)
	{
	  gas_assert (length == 8);
	  int32_t *bin = (int32_t *) buf;
	  bin[1] = bin[2];

	  reloc = BFD_RELOC_RISCV_PCREL_HI20;
	  fix_new_exp (fragp, buf - (bfd_byte *)fragp->fr_literal,
		       4, &exp, FALSE, reloc);
	  reloc = BFD_RELOC_RISCV_RELAX;
	  fix_new (fragp, buf - (bfd_byte *)fragp->fr_literal,
		   0, abs_section_sym, 0, FALSE, reloc);

	  reloc = BFD_RELOC_RISCV_PCREL_LO12_S;
	  fix_new_exp (fragp, buf - (bfd_byte *)fragp->fr_literal + 4,
		       4, &exp_ref, FALSE, reloc);
	  reloc = BFD_RELOC_RISCV_RELAX;
	  fix_new (fragp, buf - (bfd_byte *)fragp->fr_literal +4,
		   0, abs_section_sym, 0, FALSE, reloc);
	}
      else
	{
	  gas_assert (length == 12);
	  reloc = BFD_RELOC_RISCV_PCREL_HI20;
	  fix_new_exp (fragp, buf - (bfd_byte *)fragp->fr_literal,
		       4, &exp_ind, FALSE, reloc);
	  reloc = BFD_RELOC_RISCV_RELAX;
	  fix_new (fragp, buf - (bfd_byte *)fragp->fr_literal,
		   0, abs_section_sym, 0, FALSE, reloc);

	  reloc = BFD_RELOC_RISCV_PCREL_LO12_I;
	  fix_new_exp (fragp, buf - (bfd_byte *)fragp->fr_literal + 4,
		       4, &exp_ref, FALSE, reloc);
	  reloc = BFD_RELOC_RISCV_RELAX;
	  fix_new (fragp, buf - (bfd_byte *)fragp->fr_literal +4,
		   0, abs_section_sym, 0, FALSE, reloc);
	}
      break;
    default:
      as_fatal (_("internal error: invalid CModel type!"));
    }
    break;
  case CSI_DEFAULT_CODE:
    reloc = 0;
    switch (type)
    {
    case TYPE_JX:
      if (!is_same_sec)
        gas_assert (length == 0);
      else
	{
	  reloc = BFD_RELOC_RISCV_CALL;
	  fix_new_exp (fragp, buf - (bfd_byte *)fragp->fr_literal,
		       4, &exp, FALSE, reloc);
	  reloc = BFD_RELOC_RISCV_RELAX;
	  fix_new (fragp, buf - (bfd_byte *)fragp->fr_literal,
		   0, abs_section_sym, 0, FALSE, reloc);
	}
      break;
    default:
      as_fatal (_("internal error: invalid CModel type!"));
    }
    break;
  default:
    as_fatal (_("internal error: invalid CModel index!"));
  }

  buf += length;

  if (fixp)
    {
      fixp->fx_file = fragp->fr_file;
      fixp->fx_line = fragp->fr_line;
    }

  gas_assert (buf == (bfd_byte *)fragp->fr_literal
	      + fragp->fr_fix + fragp->fr_var);

  fragp->fr_fix += fragp->fr_var;
}

/* Relax a machine dependent frag.  This returns the amount by which
   the current size of the frag should change.  */

void
md_convert_frag (bfd *abfd ATTRIBUTE_UNUSED, segT asec, fragS *fragp)
{
  gas_assert (RELAX_BRANCH_P (fragp->fr_subtype)
	      || RELAX_CMODEL_P (fragp->fr_subtype));
  if (RELAX_BRANCH_P (fragp->fr_subtype))
    md_convert_frag_branch (fragp, asec);
  else if (RELAX_CMODEL_P (fragp->fr_subtype))
    md_convert_frag_cmodel (fragp, asec);
}

void
md_show_usage (FILE *stream)
{
  fprintf (stream, _("\
RISC-V options:\n\
  -fpic          generate position-independent code\n\
  -fPIC          same as -fpic\n\
  -fno-pic       don't generate position-independent code (default)\n\
  -march=ISA     set the RISC-V architecture\n\
  -mabi=ABI      set the RISC-V ABI\n\
  -mrelax        enable relax (default)\n\
  -mno-relax     disable relax\n\
  -march-attr    generate RISC-V arch attribute\n\
  -mno-arch-attr don't generate RISC-V arch attribute\n\
\nNDS specific command line options:\n\
  -mno-16-bit    don't generate rvc instructions\n\
  -matomic       enable atomic extension\n\
  -mace          Support user defined instruction extension\n\
  -O1            optimize for performance\n\
  -Os            optimize for space\n\
  -mext-dsp      enable dsp extension\n\
  -mext-efhw     enable efhw extension\n\
  -mext-vector   enable vector extension\n\
  -mexecit-noji  disable execit relaxation for jump instructions\n\
  -mexecit-nols  disable execit relaxation for load/store instructions\n\
  -mexecit-norel disable execit relaxation for instructions with reloaction\n\
  -mcmodel=TYPE  set cmodel type\n\
"));
}

/* Standard calling conventions leave the CFA at SP on entry.  */
void
riscv_cfi_frame_initial_instructions (void)
{
  cfi_add_CFA_def_cfa_register (X_SP);
}

int
tc_riscv_regname_to_dw2regnum (char *regname)
{
  int reg;

  if ((reg = reg_lookup_internal (regname, RCLASS_GPR)) >= 0)
    return reg;

  if ((reg = reg_lookup_internal (regname, RCLASS_FPR)) >= 0)
    return reg + 32;

  as_bad (_("unknown register `%s'"), regname);
  return -1;
}

/* We don't allow the overlapped NO_RVC_REGION_BEGIN and NO_RVC_REGION_END.
   Therefore, we choose the last NO_RVC_REGION as the effective setting
   at the same address.  */

static void
riscv_find_next_effective_rvc_region (fixS **fixp)
{
  fixS *effective_fixp = NULL;

  while (*fixp && (*fixp)->fx_r_type != BFD_RELOC_RISCV_NO_RVC_REGION_BEGIN)
    *fixp = (*fixp)->fx_next;
  effective_fixp = *fixp;
  if (!effective_fixp)
    return;

  *fixp = (*fixp)->fx_next;
  while (*fixp
	 && (*fixp)->fx_frag == effective_fixp->fx_frag
	 && (*fixp)->fx_where == effective_fixp->fx_where)
    {
      if ((*fixp)->fx_r_type == BFD_RELOC_RISCV_NO_RVC_REGION_BEGIN)
	{
	  effective_fixp->fx_offset = 2;
	  effective_fixp->fx_done = 1;
	  effective_fixp = *fixp;
	}
      *fixp = (*fixp)->fx_next;
    }
  *fixp = effective_fixp;
}


static void
riscv_final_no_rvc_region (bfd *abfd ATTRIBUTE_UNUSED, asection *sec,
			   void *xxx ATTRIBUTE_UNUSED)
{
  segment_info_type *seginfo;
  frchainS *frch;
  fixS *fixp, *pre_fixp_begin;
  int current_rvc = 0;

  seginfo = seg_info (sec);
  if (!seginfo || !symbol_rootP || !subseg_text_p (sec) || sec->size == 0)
    return;

  subseg_change (sec, 0);

  frch = seginfo->frchainP;
  pre_fixp_begin = NULL;
  current_rvc = frch->frch_root->tc_frag_data.rvc;
  if (current_rvc == -1)
    {
      fixp = fix_at_start (frch->frch_root, 0, abs_section_sym, 0x2,
			   0, BFD_RELOC_RISCV_NO_RVC_REGION_BEGIN);
      pre_fixp_begin = fixp;
      fixp = seginfo->fix_root->fx_next;
    }
  else
    fixp = seginfo->fix_root;

  for (; fixp; fixp = fixp->fx_next)
    {
      riscv_find_next_effective_rvc_region (&fixp);
      if (!fixp)
	break;

      if (fixp->fx_offset == 0)
	{
	  if (current_rvc == -1)
	    fixp->fx_done = 1;
	  else
	    {
	      current_rvc = -1;
	      pre_fixp_begin = fixp;
	    }
	}
      else if (fixp->fx_offset == 1)
	{
	  if (!pre_fixp_begin
	      || current_rvc == 1)
	    fixp->fx_done = 1;
	  else
	    {
	      current_rvc = 1;
	      pre_fixp_begin = NULL;
	      fixp->fx_r_type = BFD_RELOC_RISCV_NO_RVC_REGION_END;
	    }
	}
      fixp->fx_offset = 2;
    }
}

static void
riscv_final_no_execit_region (bfd *abfd ATTRIBUTE_UNUSED, asection *sec,
			      void *xxx ATTRIBUTE_UNUSED)
{
  segment_info_type *seginfo;
  fixS *fixp;
  int no_execit_count;
  int innermost_loop_count;

  seginfo = seg_info (sec);
  if (!seginfo || !symbol_rootP || !subseg_text_p (sec) || sec->size == 0)
    return;

  subseg_change (sec, 0);

  fixp = seginfo->fix_root;
  for (; fixp; fixp = fixp->fx_next)
    {
      if (fixp->fx_r_type == BFD_RELOC_RISCV_NO_RVC_REGION_BEGIN)
	fix_new (fixp->fx_frag, fixp->fx_where, 0, abs_section_sym,
		 R_RISCV_RELAX_REGION_NO_EXECIT_FLAG, 0,
		 BFD_RELOC_RISCV_RELAX_REGION_BEGIN);
      else if (fixp->fx_r_type == BFD_RELOC_RISCV_NO_RVC_REGION_END)
	fix_new (fixp->fx_frag, fixp->fx_where, 0, abs_section_sym,
		 R_RISCV_RELAX_REGION_NO_EXECIT_FLAG, 0,
		 BFD_RELOC_RISCV_RELAX_REGION_END);
    }

  no_execit_count = 0;
  innermost_loop_count = 0;
  fixp = seginfo->fix_root;
  for (; fixp; fixp = fixp->fx_next)
    {
      if (fixp->fx_r_type == BFD_RELOC_RISCV_RELAX_REGION_BEGIN)
	{
	  if (fixp->fx_offset == R_RISCV_RELAX_REGION_NO_EXECIT_FLAG)
	    {
	      if (no_execit_count > 0)
		fixp->fx_done = 1;
	      no_execit_count++;
	    }
	  else if (fixp->fx_offset == R_RISCV_RELAX_REGION_INNERMOST_LOOP_FLAG)
	    {
	      if (innermost_loop_count > 0)
		fixp->fx_done = 1;
	      innermost_loop_count++;
	    }
	}
      else if (fixp->fx_r_type == BFD_RELOC_RISCV_RELAX_REGION_END)
        {
	  if (fixp->fx_offset == R_RISCV_RELAX_REGION_NO_EXECIT_FLAG)
	    {
	      no_execit_count--;
	      if (no_execit_count > 0)
		fixp->fx_done = 1;
	      else if (no_execit_count < 0)
		{
		  no_execit_count++;
		  fixp->fx_done = 1;
		}
	    }
	  else if (fixp->fx_offset == R_RISCV_RELAX_REGION_INNERMOST_LOOP_FLAG)
	    {
	      innermost_loop_count--;
	      if (innermost_loop_count > 0)
		fixp->fx_done = 1;
	      else if (innermost_loop_count < 0)
		{
		  innermost_loop_count++;
		  fixp->fx_done = 1;
		}
	    }
	}
    }

  if (no_execit_count > 0)
    {
    }
}

static void
riscv_insert_relax_entry (bfd *abfd ATTRIBUTE_UNUSED, asection *sec,
			  void *xxx ATTRIBUTE_UNUSED)
{
  segment_info_type *seginfo;
  frchainS *frch;
  fixS *fixp;
  offsetT X_add_number;

  seginfo = seg_info (sec);
  if (!seginfo || !symbol_rootP || !subseg_text_p (sec) || sec->size == 0)
    return;

  subseg_change (sec, 0);

  frch = seginfo->frchainP;
  X_add_number = 0;

  if (!riscv_opts.relax)
    X_add_number |= R_RISCV_RELAX_ENTRY_DISABLE_RELAX_FLAG;
  else
    {
      if (riscv_opts.execit)
	X_add_number |= R_RISCV_RELAX_ENTRY_EXECIT_FLAG;
    }

  fixp = fix_at_start (frch->frch_root, 0, abs_section_sym, X_add_number,
		       0, BFD_RELOC_RISCV_RELAX_ENTRY);
  fixp->fx_no_overflow = 1;
}

void
riscv_post_relax_hook (void)
{
  bfd_map_over_sections (stdoutput, riscv_final_no_rvc_region, NULL);
  bfd_map_over_sections (stdoutput, riscv_final_no_execit_region, NULL);
  bfd_map_over_sections (stdoutput, riscv_insert_relax_entry, NULL);
}

void
riscv_elf_final_processing (void)
{
  elf_elfheader (stdoutput)->e_flags |= elf_flags;
}

static void
riscv_aligned_cons (int idx)
{
  cons (1 << idx);
  if (now_seg->flags & SEC_CODE
      && now_seg->flags & SEC_ALLOC && now_seg->flags & SEC_RELOC)
    {
      /* Use BFD_RELOC_RISCV_DATA to avoid EXECIT optimization replacing data.  */
      expressionS exp;

      exp.X_add_number = 0;
      exp.X_op = O_constant;
      fix_new_exp (frag_now, frag_now_fix () - (1 << idx), 1 << idx,
		   &exp, 0, BFD_RELOC_RISCV_DATA);
    }
}

/* Parse the .sleb128 and .uleb128 pseudos.  Only allow constant expressions,
   since these directives break relaxation when used with symbol deltas.  */

static void
s_riscv_leb128 (int sign)
{
  expressionS exp;
  char *save_in = input_line_pointer;

  expression (&exp);
  if (exp.X_op != O_constant)
    as_bad (_("non-constant .%cleb128 is not supported"), sign ? 's' : 'u');
  demand_empty_rest_of_line ();

  input_line_pointer = save_in;
  return s_leb128 (sign);
}

/* Parse the .insn directive.  */

static void
s_riscv_insn (int x ATTRIBUTE_UNUSED)
{
  char *str = input_line_pointer;
  struct riscv_cl_insn insn;
  expressionS imm_expr;
  bfd_reloc_code_real_type imm_reloc = BFD_RELOC_UNUSED;
  char save_c;

  while (!is_end_of_line[(unsigned char) *input_line_pointer])
    ++input_line_pointer;

  save_c = *input_line_pointer;
  *input_line_pointer = '\0';

  const char *error = riscv_ip (str, &insn, &imm_expr,
				&imm_reloc, insn_type_hash);

  if (error)
    {
      as_bad ("%s `%s'", error, str);
    }
  else
    {
      gas_assert (insn.insn_mo->pinfo != INSN_MACRO);
      append_insn (&insn, &imm_expr, imm_reloc);
    }

  *input_line_pointer = save_c;
  demand_empty_rest_of_line ();
}

/* Update arch attributes.  */

static void
riscv_write_out_arch_attr (void)
{
  const char *arch_str = riscv_arch_str (xlen, &riscv_subsets);

  bfd_elf_add_proc_attr_string (stdoutput, Tag_RISCV_arch, arch_str);

  xfree ((void *)arch_str);
}

/* Add the default contents for the .riscv.attributes section.  */
static void
andes_riscv_set_public_attributes (void);

#if 0
static void
riscv_set_public_attributes (void)
{
  if (riscv_opts.arch_attr || explicit_arch_attr)
    /* Re-write arch attribute to normalize the arch string.  */
    riscv_write_out_arch_attr ();
}
#endif

/* Called after all assembly has been done.  */

void
riscv_md_end (void)
{
/*riscv_set_public_attributes (); */
  andes_riscv_set_public_attributes ();
}

/* Given a symbolic attribute NAME, return the proper integer value.
   Returns -1 if the attribute is not known.  */

int
riscv_convert_symbolic_attribute (const char *name)
{
  static const struct
  {
    const char * name;
    const int    tag;
  }
  attribute_table[] =
    {
      /* When you modify this table you should
	 also modify the list in doc/c-riscv.texi.  */
#define T(tag) {#tag, Tag_RISCV_##tag},  {"Tag_RISCV_" #tag, Tag_RISCV_##tag}
      T(arch),
      T(priv_spec),
      T(priv_spec_minor),
      T(priv_spec_revision),
      T(unaligned_access),
      T(stack_align),
      T(strict_align),
      T(ict_version),
      T(ict_model),
#undef T
    };

  unsigned int i;

  if (name == NULL)
    return -1;

  for (i = 0; i < ARRAY_SIZE (attribute_table); i++)
    if (strcmp (name, attribute_table[i].name) == 0)
      return attribute_table[i].tag;

  return -1;
}

/* Parse a .attribute directive.  */
static void andes_pre_s_riscv_attribute (void);
static void andes_post_s_riscv_attribute (int tag);

static void
s_riscv_attribute (int ignored ATTRIBUTE_UNUSED)
{
  andes_pre_s_riscv_attribute();

  int tag = obj_elf_vendor_attribute (OBJ_ATTR_PROC);

  if (tag == Tag_RISCV_arch)
    {
      unsigned old_xlen = xlen;

      explicit_arch_attr = TRUE;
      obj_attribute *attr;
      attr = elf_known_obj_attributes_proc (stdoutput);
      if (!start_assemble)
	riscv_set_arch (attr[Tag_RISCV_arch].s);
      else
	as_fatal (_(".attribute arch must set before any instructions"));

      if (old_xlen != xlen)
	{
	  /* We must re-init bfd again if xlen is changed.  */
	  unsigned long mach = xlen == 64 ? bfd_mach_riscv64 : bfd_mach_riscv32;
	  bfd_find_target (riscv_target_format (), stdoutput);

	  if (! bfd_set_arch_mach (stdoutput, bfd_arch_riscv, mach))
	    as_warn (_("Could not set architecture and machine"));
	}
    }

  andes_post_s_riscv_attribute(tag);
}

static void
riscv_no_execit (int mode)
{
  expressionS exp;

  exp.X_op = O_symbol;
  exp.X_add_symbol = abs_section_sym;
  if (mode == 1)
    {
      exp.X_add_number = R_RISCV_RELAX_REGION_NO_EXECIT_FLAG;
      fix_new_exp (frag_now, frag_now_fix (), 0, &exp, 0,
		   BFD_RELOC_RISCV_RELAX_REGION_BEGIN);
    }
  else
    {
      exp.X_add_number = R_RISCV_RELAX_REGION_NO_EXECIT_FLAG;
      fix_new_exp (frag_now, frag_now_fix (), 0, &exp, 0,
		   BFD_RELOC_RISCV_RELAX_REGION_END);
    }
}


static void
riscv_innermost_loop (int mode)
{
  expressionS exp;

  exp.X_op = O_symbol;
  exp.X_add_symbol = abs_section_sym;
  if (mode == 1)
    {
      exp.X_add_number = R_RISCV_RELAX_REGION_INNERMOST_LOOP_FLAG;
      fix_new_exp (frag_now, frag_now_fix (), 0, &exp, 0,
		   BFD_RELOC_RISCV_RELAX_REGION_BEGIN);
    }
  else
    {
      exp.X_add_number = R_RISCV_RELAX_REGION_INNERMOST_LOOP_FLAG;
      fix_new_exp (frag_now, frag_now_fix (), 0, &exp, 0,
		   BFD_RELOC_RISCV_RELAX_REGION_END);
    }
}

#ifdef DEBUG_ARCH_INFO_HASH
static void
riscv_print_arch_info_hash (const char *key, void *value)
{
  struct arch_info *data = (struct arch_info *) value;
  printf ("(key, name, v_major, v_minor, valid): (%s, %s, %s, %s, %d)\n",
	  key, data->name, data->v_major, data->v_minor, data->valid);
}
#endif

#if 0
static void
riscv_count_arch_attr_strlen (const char *key ATTRIBUTE_UNUSED,
			      void *value)
{
  struct arch_info *data = (struct arch_info *) value;
  if (data->valid)
    {
      arch_attr_strlen += strlen (data->name)
	+ strlen (data->v_major)
	+ strlen (data->v_minor)
	+ 1; /* for 'p'  */
      if (*(data->name) == 'x')
	{
	  first_X_arch = 0;
	  arch_attr_strlen++; /* for '_'  */
	}
    }
}
#endif

/* Update standard arch attributes.  */

#if 0
static void
riscv_update_non_standard_arch_attr (const char *key ATTRIBUTE_UNUSED,
				     void *value)
{
  struct arch_info *data = (struct arch_info *) value;
  if (data->valid)
    {
      if (first_X_arch)
	first_X_arch = 0;
      else
	strncat (out_arch, "_", 1);

      strncat (out_arch, data->name, strlen (data->name));
      strncat (out_arch, data->v_major, strlen (data->v_major));
      strncat (out_arch, "p", 1);
      strncat (out_arch, data->v_minor, strlen (data->v_minor));
      data->valid = 0;
    }
}
#endif
#if 0
static void
andes_riscv_write_out_arch_attr (void)
{
  unsigned int i;
  obj_attribute *attr;
  bfd_boolean e_ext;

  /* If we can't find any attribute directive, update the arch hash
     table according to the `all_subsets' set by the `-march' option
     or `default_arch'.  */
  attr = elf_known_obj_attributes_proc (stdoutput);
  if (!attr[Tag_arch].s)
    {
      while (riscv_subsets != NULL)
	{
	  struct riscv_subset *next = riscv_subsets->next;
	  /* Since riscv_subsets does not save the version so far,
	     1. Standard arch version: default setting
	     2. Non standard arch version: zero.  */
	  for (i = 0; arch_info[i].name; i++)
	    if (strcmp (riscv_subsets->name, arch_info[i].name) == 0)
	      {
		if (strcmp (arch_info[i].name, "c") != 0)
		  riscv_update_arch_info_hash (riscv_subsets->name, -1, TRUE);
		break;
	      }
	  /* Can not find the matched standard arch, regard it as
	     non-standard one.  */
	  if (!arch_info[i].name)
	    riscv_update_arch_info_hash (riscv_subsets->name, -1, TRUE);
	  riscv_subsets = next;
	}
    }

  /* Check the `elf_flags' rather than `riscv_subsets' and `riscv_opts'
     since .option rvc/norvc may occur at any place (after parsing
     attribute and -march).  */
  if (elf_flags & EF_RISCV_RVC)
    riscv_update_arch_info_hash ("c", -1, TRUE);

  arch_attr_strlen = 0;
  hash_traverse (arch_info_hash, riscv_count_arch_attr_strlen);
  /* Arch attribute is not set up.  */
  if (arch_attr_strlen == 0)
    return;
  if (!first_X_arch)
    arch_attr_strlen--; /* first x do not need '_'.  */
  first_X_arch = 1;
  arch_attr_strlen += 4; /* rv32/rv64.  */

  out_arch = (char *) malloc
    ((arch_attr_strlen + 1) * sizeof (char));
  out_arch[0] = '\0';
  if (attr[Tag_arch].s)
    strncat (out_arch, attr[Tag_arch].s, 4);
  else if (xlen == 32)
    strncat (out_arch, "rv32", 4);
  else
    strncat (out_arch, "rv64", 4);

  /* Update standard arch attributes.  */
  e_ext = FALSE;
  for (i = 0; arch_info[i].name; i++)
    {
      struct arch_info *info;

      info = (struct arch_info *) hash_find
	(arch_info_hash, arch_info[i].name);
      if (info && info->valid)
	{
	  if (strcmp(info->name, "e") == 0)
	    e_ext = TRUE;

	  if ((strcmp(info->name, "i") == 0) && e_ext)
	    {
	      info->valid = 0;
	      continue;
	    }

	  strncat(out_arch, info->name, strlen (info->name));
	  strncat(out_arch, info->v_major, strlen (info->v_major));
	  strncat(out_arch, "p", 1);
	  strncat(out_arch, info->v_minor, strlen (info->v_minor));
	  info->valid = 0;
	}
    }

  /* Update non-standard arch attributes.  */
  hash_traverse (arch_info_hash, riscv_update_non_standard_arch_attr);

  bfd_elf_add_proc_attr_string (stdoutput, Tag_arch, out_arch);

  if (strlen (out_arch) > arch_attr_strlen)
    as_fatal ("Not enough spaces for the architecture attribute name");

  /* Clean the unused items.  */
  first_X_arch = 1;
  free (out_arch);
  out_arch = NULL;
}
#endif

static void
andes_riscv_set_public_attributes (void)
{
  if (!riscv_opts.arch_attr && !explicit_arch_attr)
    return;

#ifdef DEBUG_ARCH_INFO_HASH
  printf ("===== Contents of arch attribute hash table =====\n");
  hash_traverse (arch_info_hash, riscv_print_arch_info_hash);
  printf ("\n");
#endif

  if (!start_assemble_insn)
    riscv_set_arch_attributes (NULL);

  riscv_write_out_arch_attr ();

#if 0
  if (!attributes_set_explicitly[Tag_RISCV_priv_spec])
    bfd_elf_add_proc_attr_int (stdoutput, Tag_RISCV_priv_spec,
			       DEFAULT_PRIV_SPEC);
  if (!attributes_set_explicitly[Tag_RISCV_priv_spec_minor])
    bfd_elf_add_proc_attr_int (stdoutput, Tag_RISCV_priv_spec_minor,
			       DEFAULT_PRIV_SPEC_MINOR);
  if (!attributes_set_explicitly[Tag_RISCV_priv_spec_revision])
    bfd_elf_add_proc_attr_int (stdoutput, Tag_RISCV_priv_spec_revision,
			       DEFAULT_PRIV_SPEC_REVISION);
  if (!attributes_set_explicitly[Tag_RISCV_strict_align])
    bfd_elf_add_proc_attr_int (stdoutput, Tag_RISCV_strict_align,
			       DEFAULT_STRICT_ALIGN);
  if (!attributes_set_explicitly[Tag_RISCV_stack_align])
    bfd_elf_add_proc_attr_int (stdoutput, Tag_RISCV_stack_align,
			       DEFAULT_STACK_ALIGN);
#endif

  if (m_ict_model
      && !attributes_set_explicitly[Tag_RISCV_ict_version
      + NUM_KNOWN_OBJ_ATTRIBUTES
      - TAG_VALUE_BEGIN_V5])
    bfd_elf_add_proc_attr_int (stdoutput, Tag_RISCV_ict_version,
			       DEFAULT_ICT_VERSION);
  if (m_ict_model
      && !attributes_set_explicitly[Tag_RISCV_ict_model
      + NUM_KNOWN_OBJ_ATTRIBUTES
      - TAG_VALUE_BEGIN_V5])
    bfd_elf_add_proc_attr_string (stdoutput, Tag_RISCV_ict_model,
				  m_ict_model);
}

static void
andes_pre_s_riscv_attribute (void)
{
  char *s = input_line_pointer;
  if (strncmp(s, "strict_align,", 13) != 0)
    return;

  s = input_line_pointer + 13;
  *s ^= 1; /* '0' <-> '1' */
}

static void
andes_post_s_riscv_attribute (int tag)
{
  if (tag < NUM_KNOWN_OBJ_ATTRIBUTES)
    attributes_set_explicitly[tag] = 1;
  else if (tag >= TAG_VALUE_BEGIN_V5 &&
	   tag < (TAG_VALUE_BEGIN_V5 + NUM_KNOWN_OBJ_ATTRIBUTES_V5))
    attributes_set_explicitly[tag + NUM_KNOWN_OBJ_ATTRIBUTES -
			      TAG_VALUE_BEGIN_V5] = 1;
}

/* Pseudo-op table.  */

static const pseudo_typeS riscv_pseudo_table[] =
{
  /* RISC-V-specific pseudo-ops.  */
  {"option", s_riscv_option, 0},
  {"byte", riscv_aligned_cons, 0},
  {"short", riscv_aligned_cons, 1},
  {"half", riscv_aligned_cons, 1},
  {"hword", riscv_aligned_cons, 1},
  {"int", riscv_aligned_cons, 2},
  {"long", riscv_aligned_cons, 2},
  {"word", riscv_aligned_cons, 2},
  {"dword", riscv_aligned_cons, 3},
  {"quad", riscv_aligned_cons, 3},
  {"octa", riscv_aligned_cons, 4},
  {"qword", riscv_aligned_cons, 4},
  {"dtprelword", s_dtprel, 4},
  {"dtpreldword", s_dtprel, 8},
  {"bss", s_bss, 0},
  {"sleb128", s_riscv_leb128, 1},
  {"insn", s_riscv_insn, 0},
  {"attribute", s_riscv_attribute, 0},
  {"no_ex9_begin", riscv_no_execit, 1},
  {"no_ex9_end", riscv_no_execit, 0},
  {"no_execit_begin", riscv_no_execit, 1},
  {"no_execit_end", riscv_no_execit, 0},
  {"innermost_loop_begin", riscv_innermost_loop, 1},
  {"innermost_loop_end", riscv_innermost_loop, 0},

  { NULL, NULL, 0 },
};

void
riscv_pop_insert (void)
{
  extern void pop_insert (const pseudo_typeS *);

  pop_insert (riscv_pseudo_table);
}

int
riscv_parse_name (char const *name, expressionS *exprP,
                  enum expr_mode mode ATTRIBUTE_UNUSED,
                  char *nextcharP)
{
  segT segment;
  char *next;

  if (*nextcharP != '@'
      || (strncasecmp (input_line_pointer + 1, "ICT", 3) != 0
	  && strncasecmp (input_line_pointer + 1, "ict", 3) != 0))
    return 0;

  exprP->X_op_symbol = NULL;
  exprP->X_md = BFD_RELOC_UNUSED;

  exprP->X_add_symbol = symbol_find_or_make (name);
  exprP->X_op = O_symbol;
  exprP->X_add_number = 0;

  segment = S_GET_SEGMENT (exprP->X_add_symbol);
  if ((segment != undefined_section) && (*nextcharP != '@'))
    return 0;

  next = input_line_pointer + 1 + 3;

  if (!is_part_of_name (*next))
    {
      exprP->X_md = BFD_RELOC_RISCV_ICT_HI20;
      *input_line_pointer = *nextcharP;
      input_line_pointer = next;
      *nextcharP = *input_line_pointer;
      *input_line_pointer = '\0';
    }

  return 1;
}

void riscv_andes_md_cleanup (void)
{
}

