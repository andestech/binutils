/* tc-riscv.c -- RISC-V assembler
   Copyright (C) 2011-2022 Free Software Foundation, Inc.

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
#include <stdlib.h>

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

  /* { Andes */
  /* The cmodel parameters.  */
  struct
    {
      int method;
      int state;
      int type;
      int relax;
      int index;
      int offset;
    } cmodel;
  /* } Andes */
};

/* All RISC-V CSR belong to one of these classes.  */
enum riscv_csr_class
{
  CSR_CLASS_NONE,

  CSR_CLASS_I,
  CSR_CLASS_I_32,	/* rv32 only */
  CSR_CLASS_F,		/* f-ext only */
  CSR_CLASS_ZKR,	/* zkr only */
  CSR_CLASS_V,		/* rvv only */
  CSR_CLASS_SSCOFPMF,	/* sscofpmf only */
  /* { Andes  */
  CSR_CLASS_P,
  CSR_CLASS_XANDES,
  /* } Andes  */
  CSR_CLASS_ZCMT,	/* zcmt only */
  CSR_CLASS_DEBUG	/* debug CSR */
};

/* This structure holds all restricted conditions for a CSR.  */
struct riscv_csr_extra
{
  /* Class to which this CSR belongs.  Used to decide whether or
     not this CSR is legal in the current -march context.  */
  enum riscv_csr_class csr_class;

  /* CSR may have differnet numbers in the previous priv spec.  */
  unsigned address;

  /* Record the CSR is defined/valid in which versions.  */
  enum riscv_spec_class define_version;

  /* Record the CSR is aborted/invalid from which versions.  If it isn't
     aborted in the current version, then it should be PRIV_SPEC_CLASS_DRAFT.  */
  enum riscv_spec_class abort_version;

  /* The CSR may have more than one setting.  */
  struct riscv_csr_extra *next;
};

#ifndef DEFAULT_ARCH
#define DEFAULT_ARCH "riscv64"
#endif

#ifndef DEFAULT_RISCV_ATTR
#define DEFAULT_RISCV_ATTR 0
#endif

/* Let riscv_after_parse_args set the default value according to xlen.  */
#ifndef DEFAULT_RISCV_ARCH_WITH_EXT
#define DEFAULT_RISCV_ARCH_WITH_EXT NULL
#endif

/* Need to sync the version with RISC-V compiler.  */
#ifndef DEFAULT_RISCV_ISA_SPEC
/* #define DEFAULT_RISCV_ISA_SPEC "20191213" */
#define DEFAULT_RISCV_ISA_SPEC "2.2"
#endif

#ifndef DEFAULT_RISCV_PRIV_SPEC
#define DEFAULT_RISCV_PRIV_SPEC "1.11"
#endif

/* Instruction pair combiner check function. */
typedef bfd_boolean (*riscv_combine_check) (const struct riscv_cl_insn*,
    const expressionS*, const bfd_reloc_code_real_type);

typedef bfd_boolean (*riscv_combine_avail) (void);

/* A matcher defines a rule to combine an instruction pair. */
struct riscv_combiner_matcher
{
  /* Func to check the first/second insn in insn pair. */
  riscv_combine_check check_1;
  riscv_combine_check check_2;

  /* Func to write the combined insn after check_2 passes.
    The combined insn is written to the cached field in
    riscv_combiner.  */
  riscv_combine_check update;

  /* Rturn TRUE if this matcher is available. */
  riscv_combine_avail avail;
};

struct riscv_combiner
{
  /* Matcher list */
  struct riscv_combiner_matcher *matcher;

  /* idx is 0 if no insn is cached. If idx is not 0,
    then an insn is cached through the matcher(check_1)
    at the index idx-1 in matcher list. */
  int idx;

  /* Holding a cached insn information,
     insn symbol, info and reloc type */
  expressionS imm_expr;
  struct riscv_cl_insn insn;
  bfd_reloc_code_real_type imm_reloc;
};

static const char default_arch[] = DEFAULT_ARCH;
static const char *default_arch_with_ext = DEFAULT_RISCV_ARCH_WITH_EXT;
static enum riscv_spec_class default_isa_spec = ISA_SPEC_CLASS_NONE;
static enum riscv_spec_class default_priv_spec = PRIV_SPEC_CLASS_NONE;

static unsigned xlen = 0; /* The width of an x-register.  */
static unsigned abi_xlen = 0; /* The width of a pointer in the ABI.  */
static bool rve_abi = false;
enum float_abi
{
  FLOAT_ABI_DEFAULT = -1,
  FLOAT_ABI_SOFT,
  FLOAT_ABI_SINGLE,
  FLOAT_ABI_DOUBLE,
  FLOAT_ABI_QUAD
};
static enum float_abi float_abi = FLOAT_ABI_DEFAULT;

#define LOAD_ADDRESS_INSN (abi_xlen == 64 ? "ld" : "lw")
#define ADD32_INSN (xlen == 64 ? "addiw" : "addi")

static unsigned elf_flags = 0;

/* { Andes  */
enum riscv_cl_insn_method
{
  METHOD_DEFAULT,
  METHOD_VARIABLE,
};

enum cmodel_types {
  CMODEL_DEFAULT,
  CMODEL_LARGE,
};

enum cmodel_subtype_index
{
  CSI_INDIRECT_SYMBOL = 0,
  CSI_REFERENCE_SYMBOL = 1,
  CSI_LARGE_CODE = 2,
  CSI_DEFAULT_CODE = 3,
  /* workaround borrow variable frag used by cmodel.  */
  CSI_B22827,
  CSI_B22827_1,
};
/* } Andes  */

/* { Andes  */
/* Save option -O1 for perfomance.  */
static int optimize = 0;
/* Save option -Os for code size.  */
static int optimize_for_space = 0;
/* Save option -mict-model for ICT model setting.  */
static const char *m_ict_model = NULL;
static bool pre_insn_is_a_cond_br = false;
static struct andes_as_states
{
  /* CONS (RISCV_DATA) */
  int cons_count;
  /* ICT */
  expressionS *ict_exp;
  /* b22827 */
  struct riscv_cl_insn prev_insn;
  fragS *frag_b22827;
} nsta;
/* } Andes  */

/* { Andes ACE */
extern char *andes_ace_load_hooks (const char *arg);
/* Hash table for storing symbols from shared library */
static htab_t ace_keyword_hash = NULL;
static htab_t ace_op_hash = NULL;
/* Pointers for storing symbols from ACE shared library */
extern struct riscv_opcode *ace_opcs;
extern ace_keyword_t *ace_keys;
extern ace_op_t *ace_ops;
/* Represent whether ACE shared library is loaded successfully */
extern bool ace_lib_load_success;

static void
ace_ip (char **args, char **str, struct riscv_cl_insn *ip);
/* } Andes ACE */

/* { Andes */
static void
riscv_rvc_reloc_setting (int mode);
static bool
is_b19758_associated_insn (struct riscv_opcode *insn);
static bool
is_indirect_jump (struct riscv_opcode *insn);
static bool
is_conditional_branch (struct riscv_opcode *insn);
static bool
is_insn_fdiv_or_fsqrt (const struct riscv_opcode *insn);
static bool
is_insn_in_b22827_list (const struct riscv_opcode *insn,
			insn_t prev, insn_t curr);
static inline int insn_fp_rd (insn_t insn);
static inline bool is_insn_fmt_s (insn_t insn);
static inline bool is_insn_fshw (const struct riscv_opcode *insn);
static bool
is_insn_of_std_type (const struct riscv_opcode *insn, const char *type);
static bool
is_insn_of_fp_types (const struct riscv_opcode *insn);
static void
andes_insert_btb_reloc (struct riscv_cl_insn *ip);

static void
riscv_aligned_cons (int idx);
static void
macro_build (expressionS *ep, const char *name, const char *fmt, ...);
static void
riscv_make_nops (char *buf, bfd_vma bytes);
/* } Andes */

/* Set the default_isa_spec.  Return 0 if the spec isn't supported.
   Otherwise, return 1.  */

static int
riscv_set_default_isa_spec (const char *s)
{
  enum riscv_spec_class class = ISA_SPEC_CLASS_NONE;
  RISCV_GET_ISA_SPEC_CLASS (s, class);
  if (class == ISA_SPEC_CLASS_NONE)
    {
      as_bad ("unknown default ISA spec `%s' set by "
	      "-misa-spec or --with-isa-spec", s);
      return 0;
    }
  else
    default_isa_spec = class;
  return 1;
}

/* Set the default_priv_spec.  Find the privileged elf attributes when
   the input string is NULL.  Return 0 if the spec isn't supported.
   Otherwise, return 1.  */

static int
riscv_set_default_priv_spec (const char *s)
{
  enum riscv_spec_class class = PRIV_SPEC_CLASS_NONE;
  unsigned major, minor, revision;
  obj_attribute *attr;

  RISCV_GET_PRIV_SPEC_CLASS (s, class);
  if (class != PRIV_SPEC_CLASS_NONE)
    {
      default_priv_spec = class;
      return 1;
    }

  if (s != NULL)
    {
      as_bad (_("unknown default privileged spec `%s' set by "
		"-mpriv-spec or --with-priv-spec"), s);
      return 0;
    }

  /* Set the default_priv_spec by the privileged elf attributes.  */
  attr = elf_known_obj_attributes_proc (stdoutput);
  major = (unsigned) attr[Tag_RISCV_priv_spec].i;
  minor = (unsigned) attr[Tag_RISCV_priv_spec_minor].i;
  revision = (unsigned) attr[Tag_RISCV_priv_spec_revision].i;
  /* Version 0.0.0 is the default value and meningless.  */
  if (major == 0 && minor == 0 && revision == 0)
    return 1;

  riscv_get_priv_spec_class_from_numbers (major, minor, revision, &class);
  if (class != PRIV_SPEC_CLASS_NONE)
    {
      default_priv_spec = class;
      return 1;
    }

  /* Still can not find the privileged spec class.  */
  as_bad (_("unknown default privileged spec `%d.%d.%d' set by "
	    "privileged elf attributes"), major, minor, revision);
  return 0;
}

/* This is the set of options which the .option pseudo-op may modify.  */
struct riscv_set_options
{
  int pic; /* Generate position-independent code.  */
  int rvc; /* Generate RVC code.  */
  int relax; /* Emit relocs the linker is allowed to relax.  */
  int arch_attr; /* Emit architecture and privileged elf attributes.  */
  int csr_check; /* Enable the CSR checking.  */
  /* { Andes  */
  int no_16_bit; /* Do not emit any 16 bit instructions.  */
  int execit; /* Enable EXECIT relaxation.  */
  int verbatim; /* Code is generated by compiler.  */
  int cmodel; /* cmodel type.  */
  int atomic; /* RVA */
  int dsp; /* RVP */
  int nexecit_op; /* Enable nexec.it opcode. */
  int vector; /* RVV */
  int efhw; /* RVXefhw (flhw/fshw) */
  int workaround; /* Enable Andes workarounds.  */
  /* { workaround */
  int b19758_effect;
  int b19758;
  int b25057; /* alias of b19758 */
  int b20282;
  int b22827;
  int b22827_1;
  /* } workaround */
  int full_arch;
  int no_branch_relax;
  int no_rvc_convert;
  int is_linux;
  /* } Andes  */
};

static struct riscv_set_options riscv_opts =
{
  0, /* pic */
  0, /* rvc */
  1, /* relax */
  DEFAULT_RISCV_ATTR, /* arch_attr */
  0, /* csr_check */
  /* { Andes  */
  0, /* no_16_bit */
  0, /* execit */
  0, /* verbatim */
  CMODEL_DEFAULT, /* cmodel */
  0, /* atomic */
  0, /* dsp */
  0, /* nexec.it opcode */
  0, /* vector */
  0, /* efhw */
  1, /* workaround */
  1, /* b19758_effect */
  1, /* b19758 */
  1, /* b25057 */
  0, /* b20282 */
  0, /* b22827 */
  0, /* b22827_1 */
  0, /* full arch */
  0, /* no_branch_relax */
  0, /* no_rvc_convert */
  0, /* is_linux */
  /* } Andes  */
};

/* Enable or disable the rvc flags for riscv_opts.  Turn on the rvc flag
   for elf_flags once we have enabled c extension.  */

static void
riscv_set_rvc (bool rvc_value)
{
  /* Always close the rvc when -mno-16-bit option is set.  */
  if (riscv_opts.no_16_bit)
    return;

  if (rvc_value)
    elf_flags |= EF_RISCV_RVC;

  riscv_opts.rvc = rvc_value;
}

/* This linked list records all enabled extensions, which are parsed from
   the architecture string.  The architecture string can be set by the
   -march option, the elf architecture attributes, and the --with-arch
   configure option.  */
static riscv_subset_list_t *riscv_subsets = NULL;
static riscv_parse_subset_t riscv_rps_as =
{
  NULL,			/* subset_list, we will set it later once
			   riscv_opts_stack is created or updated.  */
  as_bad,		/* error_handler.  */
  as_warn,		/* warning_handler.  */
  &xlen,		/* xlen.  */
  &default_isa_spec,	/* isa_spec.  */
  true,			/* check_unknown_prefixed_ext.  */
  STATE_ASSEMBLE,	/* state.  */
  false,		/* exec.it enabled? */
};

/* This structure is used to hold a stack of .option values.  */
struct riscv_option_stack
{
  struct riscv_option_stack *next;
  struct riscv_set_options options;
  riscv_subset_list_t *subset_list;
};

static struct riscv_option_stack *riscv_opts_stack = NULL;

/* Set which ISA and extensions are available.  */

static void
riscv_set_arch (const char *s)
{
  if (s != NULL && strcmp (s, "") == 0)
    {
      as_bad (_("the architecture string of -march and elf architecture "
		"attributes cannot be empty"));
      return;
    }

  if (riscv_subsets == NULL)
    {
      riscv_subsets = XNEW (riscv_subset_list_t);
      riscv_subsets->head = NULL;
      riscv_subsets->tail = NULL;
      riscv_subsets->last = NULL;
      riscv_rps_as.subset_list = riscv_subsets;
    }
  riscv_release_subset_list (riscv_subsets);
  riscv_parse_subset (&riscv_rps_as, s);

  riscv_set_rvc (false);
  if (riscv_subset_supports (&riscv_rps_as, "c")
      || riscv_subset_supports (&riscv_rps_as, "zca"))
    riscv_set_rvc (true);
}

/* Indicate -mabi option is explictly set.  */
static bool explicit_mabi = false;

/* Set the abi information.  */

static void
riscv_set_abi (unsigned new_xlen, enum float_abi new_float_abi, bool rve)
{
  abi_xlen = new_xlen;
  float_abi = new_float_abi;
  rve_abi = rve;
}

/* If the -mabi option isn't set, then set the abi according to the
   ISA string.  Otherwise, check if there is any conflict.  */

static void
riscv_set_abi_by_arch (void)
{
  if (!explicit_mabi)
    {
      if (riscv_subset_supports (&riscv_rps_as, "q"))
	riscv_set_abi (xlen, FLOAT_ABI_QUAD, false);
      else if (riscv_subset_supports (&riscv_rps_as, "d"))
	riscv_set_abi (xlen, FLOAT_ABI_DOUBLE, false);
      else if (riscv_subset_supports (&riscv_rps_as, "e"))
	riscv_set_abi (xlen, FLOAT_ABI_SOFT, true);
      else
	riscv_set_abi (xlen, FLOAT_ABI_SOFT, false);
    }
  else
    {
      gas_assert (abi_xlen != 0 && xlen != 0 && float_abi != FLOAT_ABI_DEFAULT);
      if (abi_xlen > xlen)
	as_bad ("can't have %d-bit ABI on %d-bit ISA", abi_xlen, xlen);
      else if (abi_xlen < xlen)
	as_bad ("%d-bit ABI not yet supported on %d-bit ISA", abi_xlen, xlen);

      if (riscv_subset_supports (&riscv_rps_as, "e") && !rve_abi)
	as_bad ("only the ilp32e ABI is supported for e extension");

      if (float_abi == FLOAT_ABI_SINGLE
	  && !riscv_subset_supports (&riscv_rps_as, "f"))
	as_bad ("ilp32f/lp64f ABI can't be used when f extension "
		"isn't supported");
      else if (float_abi == FLOAT_ABI_DOUBLE
	       && !riscv_subset_supports (&riscv_rps_as, "d"))
	as_bad ("ilp32d/lp64d ABI can't be used when d extension "
		"isn't supported");
      else if (float_abi == FLOAT_ABI_QUAD
	       && !riscv_subset_supports (&riscv_rps_as, "q"))
	as_bad ("ilp32q/lp64q ABI can't be used when q extension "
		"isn't supported");
    }

  /* Update the EF_RISCV_FLOAT_ABI field of elf_flags.  */
  elf_flags &= ~EF_RISCV_FLOAT_ABI;
  elf_flags |= float_abi << 1;

  if (rve_abi)
    elf_flags |= EF_RISCV_RVE;
}

/* Handle of the OPCODE hash table.  */
static htab_t op_hash = NULL;

/* Handle of the type of .insn hash table.  */
static htab_t insn_type_hash = NULL;

/* This array holds the chars that always start a comment.  If the
   pre-processor is disabled, these aren't very useful.  */
const char comment_chars[] = "#";

/* This array holds the chars that only start a comment at the beginning of
   a line.  If the line seems to have the form '# 123 filename'
   .line and .file directives will appear in the pre-processed output

   Note that input_file.c hand checks for '#' at the beginning of the
   first line of the input file.  This is because the compiler outputs
   #NO_APP at the beginning of its output.

   Also note that C style comments are always supported.  */
const char line_comment_chars[] = "#";

/* This array holds machine specific line separator characters.  */
const char line_separator_chars[] = ";";

/* Chars that can be used to separate mant from exp in floating point nums.  */
const char EXP_CHARS[] = "eE";

/* Chars that mean this number is a floating point constant.
   As in 0f12.456 or 0d1.2345e12.  */
const char FLT_CHARS[] = "rRsSfFdDxXpPhH";

/* Indicate we are already assemble any instructions or not.  */
static bool start_assemble = false;

/* Indicate ELF attributes are explicitly set.  */
static bool explicit_attr = false;

/* Indicate CSR or priv instructions are explicitly used.  */
static bool explicit_priv_attr = false;

static char *expr_end;

/* Instruction pair combiner */
static struct riscv_combiner *insn_combiner;

/* Macros for encoding relaxation state for RVC branches and far jumps.  */
#define RELAX_BRANCH_ENCODE(uncond, rvc, length)	\
  ((relax_substateT) 					\
   (0xc0000000						\
    | ((uncond) ? 1 : 0)				\
    | ((rvc) ? 2 : 0)					\
    | ((length) << 2)))
#define RELAX_BRANCH_P(i) (((i) & 0xf0000000) == 0xc0000000)
#define RELAX_BRANCH_LENGTH(i) (((i) >> 2) & 0xF)
#define RELAX_BRANCH_RVC(i) (((i) & 2) != 0)
#define RELAX_BRANCH_UNCOND(i) (((i) & 1) != 0)
/* { Andes */
#define RELAX_BRANCH_ENCODE_EX(uncond, rvc, length, range) \
  (RELAX_BRANCH_ENCODE(uncond, rvc, length) \
  | ((range) << 6))
#define RELAX_BRANCH_RANGE(i) (((i) >> 6) & 0xF)

#define RELAX_CMODEL_ENCODE(type, relax, length, index)	\
  ((relax_substateT) 					\
   (0xd0000000						\
    | ((type) << 0)					\
    | ((relax) << 7)					\
    | ((length) << 8)					\
    | ((index) << 16)))
#define RELAX_CMODEL_P(i) (((i) & 0xf0000000) == 0xd0000000)
#define RELAX_CMODEL_TYPE(i) ((i) & 0x7f)
#define RELAX_CMODEL_RELAX(i) (((i) >> 7) & 0x01)
#define RELAX_CMODEL_LENGTH(i) (((i) >> 8) & 0xff)
#define RELAX_CMODEL_INDEX(i) (((i) >> 16) & 0xff)

enum cmodel_type
{
  TYPE_JX = 0,
  TYPE_LA,
  TYPE_LD,
  TYPE_ST,
  TYPE_ALIGN,
  TYPE_IS, /* indirect symbol  */
  /* workaround borrow variable frag used by cmodel.  */
  TYPE_B22827,
  TYPE_B22827_1,
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

/* } Andes */


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

/* Create a new mapping symbol for the transition to STATE.  */

static void
make_mapping_symbol (enum riscv_seg_mstate state,
		     valueT value,
		     fragS *frag)
{
  const char *name;
  switch (state)
    {
    case MAP_DATA:
      name = "$d";
      break;
    case MAP_INSN:
      name = "$x";
      break;
    default:
      abort ();
    }

  symbolS *symbol = symbol_new (name, now_seg, frag, value);
  symbol_get_bfdsym (symbol)->flags |= (BSF_NO_FLAGS | BSF_LOCAL);

  /* If .fill or other data filling directive generates zero sized data,
     or we are adding odd alignemnts, then the mapping symbol for the
     following code will have the same value.  */
  if (value == 0)
    {
       if (frag->tc_frag_data.first_map_symbol != NULL)
	{
	  know (S_GET_VALUE (frag->tc_frag_data.first_map_symbol)
		== S_GET_VALUE (symbol));
	  /* Remove the old one.  */
	  symbol_remove (frag->tc_frag_data.first_map_symbol,
			 &symbol_rootP, &symbol_lastP);
	}
      frag->tc_frag_data.first_map_symbol = symbol;
    }
  if (frag->tc_frag_data.last_map_symbol != NULL)
    {
      /* The mapping symbols should be added in offset order.  */
      know (S_GET_VALUE (frag->tc_frag_data.last_map_symbol)
			 <= S_GET_VALUE (symbol));
      /* Remove the old one.  */
      if (S_GET_VALUE (frag->tc_frag_data.last_map_symbol)
	  == S_GET_VALUE (symbol))
	symbol_remove (frag->tc_frag_data.last_map_symbol,
		       &symbol_rootP, &symbol_lastP);
    }
  frag->tc_frag_data.last_map_symbol = symbol;
}

/* Set the mapping state for frag_now.  */

void
riscv_mapping_state (enum riscv_seg_mstate to_state,
		     int max_chars)
{
  enum riscv_seg_mstate from_state =
	seg_info (now_seg)->tc_segment_info_data.map_state;

  if (!SEG_NORMAL (now_seg)
      /* For now I only add the mapping symbols to text sections.
	 Therefore, the dis-assembler only show the actual contents
	 distribution for text.  Other sections will be shown as
	 data without the details.  */
      || !subseg_text_p (now_seg))
    return;

  /* The mapping symbol should be emitted if not in the right
     mapping state  */
  if (from_state == to_state)
    return;

  valueT value = (valueT) (frag_now_fix () - max_chars);
  seg_info (now_seg)->tc_segment_info_data.map_state = to_state;
  make_mapping_symbol (to_state, value, frag_now);
}

/* Add the odd bytes of paddings for riscv_handle_align.  */

static void
riscv_add_odd_padding_symbol (fragS *frag)
{
  /* If there was already a mapping symbol, it should be
     removed in the make_mapping_symbol.  */
  make_mapping_symbol (MAP_DATA, frag->fr_fix, frag);
  make_mapping_symbol (MAP_INSN, frag->fr_fix + 1, frag);
}

/* Remove any excess mapping symbols generated for alignment frags in
   SEC.  We may have created a mapping symbol before a zero byte
   alignment; remove it if there's a mapping symbol after the
   alignment.  */

static void
riscv_check_mapping_symbols (bfd *abfd ATTRIBUTE_UNUSED,
			     asection *sec,
			     void *dummy ATTRIBUTE_UNUSED)
{
  segment_info_type *seginfo = seg_info (sec);
  fragS *fragp;

  if (seginfo == NULL || seginfo->frchainP == NULL)
    return;

  for (fragp = seginfo->frchainP->frch_root;
       fragp != NULL;
       fragp = fragp->fr_next)
    {
      symbolS *last = fragp->tc_frag_data.last_map_symbol;
      fragS *next = fragp->fr_next;

      if (last == NULL || next == NULL)
	continue;

      /* Check the last mapping symbol if it is at the boundary of
	 fragment.  */
      if (S_GET_VALUE (last) < next->fr_address)
	continue;
      know (S_GET_VALUE (last) == next->fr_address);

      do
	{
	  if (next->tc_frag_data.first_map_symbol != NULL)
	    {
	      /* The last mapping symbol overlaps with another one
		 which at the start of the next frag.  */
	      symbol_remove (last, &symbol_rootP, &symbol_lastP);
	      break;
	    }

	  if (next->fr_next == NULL)
	    {
	      /* The last mapping symbol is at the end of the section.  */
	      know (next->fr_fix == 0 && next->fr_var == 0);
	      symbol_remove (last, &symbol_rootP, &symbol_lastP);
	      break;
	    }

	  /* Since we may have empty frags without any mapping symbols,
	     keep looking until the non-empty frag.  */
	  if (next->fr_address != next->fr_next->fr_address)
	    break;

	  next = next->fr_next;
	}
      while (next != NULL);
    }
}

/* The default target format to use.  */

const char *
riscv_target_format (void)
{
  if (target_big_endian)
    return xlen == 64 ? "elf64-bigriscv" : "elf32-bigriscv";
  else
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
  number_to_chars_littleendian (f, insn->insn_opcode, insn_length (insn));
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

/* { Andes */
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

static inline bool
is_cmodel_large (void)
{
  return riscv_opts.cmodel == CMODEL_LARGE;
}

static inline bool
is_same_section_symbol (symbolS *sym, asection *sec)
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
/* } Andes */

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
  if (!riscv_opts.no_branch_relax)
    length = jump ? 4 : 8;

  if (!riscv_opts.no_branch_relax
      && fragp->fr_symbol != NULL
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
    fragp->fr_subtype = RELAX_BRANCH_ENCODE_EX (jump, rvc, length, range);

  return length;
}

/* { Andes */
/* Compute the length of a CModel sequence, and adjust the stored length
   accordingly.  */
static unsigned
relaxed_cmodel_length (fragS *fragp, asection *sec)
{
  int type = RELAX_CMODEL_TYPE (fragp->fr_subtype);
  int relax = RELAX_CMODEL_RELAX (fragp->fr_subtype);
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
	case TYPE_ALIGN:
	  if (is_same_sec)
	    length = 0;
	  else
	    gas_assert (length == 6);
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
	    length = 8; /* -= 4 is NG, might do more than time.  */
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
    case CSI_B22827:
    case CSI_B22827_1:
      if (fragp->fr_var == 0) length = 0;
      else if (fragp->fr_var == 1) length = 4;
      break;
    default:
      as_fatal (_("internal error: invalid CModel index!"));
    }

  fragp->fr_subtype = RELAX_CMODEL_ENCODE (type, relax, length, index);
  return length;
}
/* } Andes */

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
static htab_t opcode_names_hash = NULL;

/* Initialization for hash table of opcode name.  */

static void
init_opcode_names_hash (void)
{
  const struct opcode_name_t *opcode;

  for (opcode = &opcode_name_list[0]; opcode->name != NULL; ++opcode)
    if (str_hash_insert (opcode_names_hash, opcode->name, opcode, 0) != NULL)
      as_fatal (_("internal: duplicate %s"), opcode->name);
}

/* Find `s` is a valid opcode name or not, return the opcode name info
   if found.  */

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

  o = (struct opcode_name_t *) str_hash_find (opcode_names_hash, *s);

  /* Advance to next token if one was recognized.  */
  if (o)
    *s = e;

  *e = save_c;
  expr_end = e;

  return o;
}

/* All RISC-V registers belong to one of these classes.  */
enum reg_class
{
  RCLASS_GPR,
  RCLASS_FPR,
  RCLASS_VECR,
  RCLASS_VECM,
  RCLASS_MAX,

  RCLASS_CSR
};

static htab_t reg_names_hash = NULL;
static htab_t csr_extra_hash = NULL;

#define ENCODE_REG_HASH(cls, n) \
  ((void *)(uintptr_t)((n) * RCLASS_MAX + (cls) + 1))
#define DECODE_REG_CLASS(hash) (((uintptr_t)(hash) - 1) % RCLASS_MAX)
#define DECODE_REG_NUM(hash) (((uintptr_t)(hash) - 1) / RCLASS_MAX)

static void
hash_reg_name (enum reg_class class, const char *name, unsigned n)
{
  void *hash = ENCODE_REG_HASH (class, n);
  if (str_hash_insert (reg_names_hash, name, hash, 0) != NULL)
    as_fatal (_("internal: duplicate %s"), name);
}

static void
hash_reg_names (enum reg_class class, const char * const names[], unsigned n)
{
  unsigned i;

  for (i = 0; i < n; i++)
    hash_reg_name (class, names[i], i);
}

/* Init hash table csr_extra_hash to handle CSR.  */

static void
riscv_init_csr_hash (const char *name,
		     unsigned address,
		     enum riscv_csr_class class,
		     enum riscv_spec_class define_version,
		     enum riscv_spec_class abort_version)
{
  struct riscv_csr_extra *entry, *pre_entry;
  bool need_enrty = true;

  pre_entry = NULL;
  entry = (struct riscv_csr_extra *) str_hash_find (csr_extra_hash, name);
  while (need_enrty && entry != NULL)
    {
      if (entry->csr_class == class
	  && entry->address == address
	  && entry->define_version == define_version
	  && entry->abort_version == abort_version)
	need_enrty = false;
      pre_entry = entry;
      entry = entry->next;
    }

  /* Duplicate CSR.  */
  if (!need_enrty)
    return;

  entry = XNEW (struct riscv_csr_extra);
  entry->csr_class = class;
  entry->address = address;
  entry->define_version = define_version;
  entry->abort_version = abort_version;
  entry->next = NULL;

  if (pre_entry == NULL)
    str_hash_insert (csr_extra_hash, name, entry, 0);
  else
    pre_entry->next = entry;
}

/* Return the CSR address after checking the ISA dependency and
   the privileged spec version.

   There are one warning and two errors for CSR,

   Invalid CSR: the CSR was defined, but isn't allowed for the current ISA
   or the privileged spec, report warning only if -mcsr-check is set.
   Unknown CSR: the CSR has never been defined, report error.
   Improper CSR: the CSR number over the range (> 0xfff), report error.  */

static unsigned int
riscv_csr_address (const char *csr_name,
		   struct riscv_csr_extra *entry)
{
  struct riscv_csr_extra *saved_entry = entry;
  enum riscv_csr_class csr_class = entry->csr_class;
  bool need_check_version = true;
  bool result = true;

  switch (csr_class)
    {
    case CSR_CLASS_I:
      result = riscv_subset_supports (&riscv_rps_as, "i");
      break;
    case CSR_CLASS_I_32:
      result = (xlen == 32 && riscv_subset_supports (&riscv_rps_as, "i"));
      break;
    case CSR_CLASS_F:
      result = riscv_subset_supports (&riscv_rps_as, "f");
      need_check_version = false;
      break;
    case CSR_CLASS_ZKR:
      result = riscv_subset_supports (&riscv_rps_as, "zkr");
      need_check_version = false;
      break;
    case CSR_CLASS_V:
      result = riscv_subset_supports (&riscv_rps_as, "v");
      need_check_version = false;
      break;
    case CSR_CLASS_DEBUG:
      need_check_version = false;
      break;
    case CSR_CLASS_SSCOFPMF:
      need_check_version = false;
      break;
    /* { Andes  */
    case CSR_CLASS_P:
      result = riscv_subset_supports (&riscv_rps_as, "p");
      break;
    case CSR_CLASS_XANDES:
      result = riscv_subset_supports (&riscv_rps_as, "xandes");
      break;
    /* } Andes  */
    case CSR_CLASS_ZCMT:
      result = riscv_subset_supports (&riscv_rps_as, "zcmt");
      need_check_version = false;
      break;
    default:
      as_bad (_("internal: bad RISC-V CSR class (0x%x)"), csr_class);
    }

  if (riscv_opts.csr_check && !result)
    as_warn (_("invalid CSR `%s' for the current ISA"), csr_name);

  while (entry != NULL)
    {
      if (!need_check_version
	  || (default_priv_spec >= entry->define_version
	      && default_priv_spec < entry->abort_version))
       {
         /* Find the CSR according to the specific version.  */
         return entry->address;
       }
      entry = entry->next;
    }

  /* Can not find the CSR address from the chosen privileged version,
     so use the newly defined value.  */
  if (riscv_opts.csr_check)
    {
      const char *priv_name = NULL;
      RISCV_GET_PRIV_SPEC_NAME (priv_name, default_priv_spec);
      if (priv_name != NULL)
	as_warn (_("invalid CSR `%s' for the privileged spec `%s'"),
		 csr_name, priv_name);
    }

  return saved_entry->address;
}

/* Return -1 if the CSR has never been defined.  Otherwise, return
   the address.  */

static unsigned int
reg_csr_lookup_internal (const char *s)
{
  struct riscv_csr_extra *r =
    (struct riscv_csr_extra *) str_hash_find (csr_extra_hash, s);

  if (r == NULL)
    return -1U;

  return riscv_csr_address (s, r);
}

static unsigned int
reg_lookup_internal (const char *s, enum reg_class class)
{
  void *r;

  if (class == RCLASS_CSR)
    return reg_csr_lookup_internal (s);

  r = str_hash_find (reg_names_hash, s);
  if (r == NULL || DECODE_REG_CLASS (r) != class)
    return -1;

  if (riscv_subset_supports (&riscv_rps_as, "e")
      && class == RCLASS_GPR
      && DECODE_REG_NUM (r) > 15)
    return -1;

  return DECODE_REG_NUM (r);
}

static bool
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

static bool
arg_lookup (char **s, const char *const *array, size_t size, unsigned *regnop)
{
  const char *p = strchr (*s, ',');
  size_t i, len = p ? (size_t)(p - *s) : strlen (*s);

  if (len == 0)
    return false;

  for (i = 0; i < size; i++)
    if (array[i] != NULL && strncmp (array[i], *s, len) == 0)
      {
	*regnop = i;
	*s += len;
	return true;
      }

  return false;
}

/* Map ra and s-register to [4,15], so that we can check if the
    reg2 in register list reg1-reg2 or single reg2 is valid or not,
    and obtain the corresponding rlist value.

   ra - 4
   s0 - 5
   s1 - 6
    ....
  s10 - 0 (invalid)
  s11 - 15
*/

static int
regno_to_rlist (unsigned regno)
{
  if (regno == X_RA)
    return 4;
  else if (regno == X_S0 || regno == X_S1)
    return 5 + regno - X_S0;
  else if (regno >= X_S2 && regno < X_S10)
    return 7 + regno - X_S2;
  else if (regno == X_S11)
    return 15;

  return 0; /* invalid symbol */
}

/* Parse register list, and the parsed rlist value is stored in rlist
  argument.

  If ABI register names are used (e.g. ra and s0), the register
  list could be "{ra}", "{ra, s0}", "{ra, s0-sN}", where 0 < N < 10 or
  N == 11.

  If numeric register names are used (e.g. x1 and x8), the register list
  could be "{x1}", "{x1,x8}", "{x1,x8-x9}", "{x1,x8-x9, x18}" and
  "{x1,x8-x9,x18-xN}", where 19 < N < 25 or N == 27.

  It will fail if numeric register names and ABI register names are used
  at the same time.
  */

static bool
reglist_lookup (char **s, unsigned *rlist)
{
  unsigned regno;
  bool is_zcmpe = riscv_subset_supports (&riscv_rps_as, "zcmpe");
  /* Use to check if the register format is xreg.  */
  bool use_xreg = **s == 'x';

  /* The first register in register list should be ra.  */
  if (!reg_lookup (s, RCLASS_GPR, &regno)
      || !(*rlist = regno_to_rlist (regno)) /* update rlist */
      || regno != X_RA)
    return FALSE;

  /* Skip "whitespace, whitespace" pattern.  */
  while (ISSPACE (**s))
    ++ *s;
  if (**s == '}')
    return TRUE;
  else if (**s != ',')
    return FALSE;
  while (ISSPACE (*++*s))
    ++ *s;

  /* Do not use numeric and abi names at the same time.  */
  if (use_xreg && **s != 'x')
    return FALSE;

  /* Reg1 should be s0 or its numeric names x8. */
  if (!reg_lookup (s, RCLASS_GPR, &regno)
      || !(*rlist = regno_to_rlist (regno))
      || regno != X_S0)
    return FALSE;

  /* Skip "whitespace - whitespace" pattern.  */
  while (ISSPACE (**s))
    ++ *s;
  if (**s == '}')
    return TRUE;
  else if (**s != '-')
    return FALSE;
  while (ISSPACE (*++*s))
    ++ *s;

  if (use_xreg && **s != 'x')
    return FALSE;

  /* Reg2 is x9 if the numeric name is used or arch is zcmpe,
    otherwise, it could be any other sN register, where N > 0. */
  if (!reg_lookup (s, RCLASS_GPR, &regno)
      || !(*rlist = regno_to_rlist (regno))
      || regno <= X_S0
      || (use_xreg && regno != X_S1)
	  || (is_zcmpe && regno != X_S1))
    return FALSE;

   /* Skip whitespace */
  while (ISSPACE (**s))
    ++ *s;

  /* Check if it is the end of register list. */
  if (**s == '}')
    return TRUE;
  else if (!(use_xreg || is_zcmpe))
    return FALSE;

  /* Here is not reachable if the abi name is used. */
  gas_assert (use_xreg);

  /* If the numeric name is used, we need to parse extra
    register list, reg3 or reg3-reg4. */

  /* Skip ", white space" pattern.  */
  if (**s != ',')
    return FALSE;
  while (ISSPACE (*++*s))
    ++ *s;

  if (use_xreg && **s != 'x')
    return FALSE;

  /* Reg3 should be s2. */
    if (!reg_lookup (s, RCLASS_GPR, &regno)
	|| !(*rlist = regno_to_rlist (regno))
	|| regno != X_S2)
      return FALSE;

  /* skip "whitespace - whitespace" pattern.  */
  while (ISSPACE (**s))
    ++ *s;
  if (**s == '}')
    return TRUE;
  else if (**s != '-')
    return FALSE;
  while (ISSPACE (*++*s))
    ++ *s;

  /* Reg4 could be any other sN register, where N > 1. */
  if (!reg_lookup (s, RCLASS_GPR, &regno)
      || !(*rlist = regno_to_rlist (regno))
      || regno <= X_S2)
    return FALSE;

  return TRUE;
}

#define USE_BITS(mask,shift) (used_bits |= ((insn_t)(mask) << (shift)))

/* For consistency checking, verify that all bits are specified either
   by the match/mask part of the instruction definition, or by the
   operand list. The `length` could be 0, 4 or 8, 0 for auto detection.  */

static bool
validate_riscv_insn (const struct riscv_opcode *opc, int length)
{
  const char *oparg, *opargStart;
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
      return false;
    }

  for (oparg = opc->args; *oparg; ++oparg)
    {
      opargStart = oparg;
      switch (*oparg)
	{
	case 'C': /* RVC */
	  switch (*++oparg)
	    {
	    case 'U': break; /* CRS1, constrained to equal RD.  */
	    case 'c': break; /* CRS1, constrained to equal sp.  */
	    case 'T': /* CRS2, floating point.  */
	    case 'V': USE_BITS (OP_MASK_CRS2, OP_SH_CRS2); break;
	    case 'S': /* CRS1S, floating point.  */
	    case 's': USE_BITS (OP_MASK_CRS1S, OP_SH_CRS1S); break;
	    case 'w': break; /* CRS1S, constrained to equal RD.  */
	    case 'D': /* CRS2S, floating point.  */
	    case 't': USE_BITS (OP_MASK_CRS2S, OP_SH_CRS2S); break;
	    case 'x': break; /* CRS2S, constrained to equal RD.  */
	    case 'z': break; /* CRS2S, constrained to be x0.  */
	    case '>': /* CITYPE immediate, compressed shift.  */
	    case 'u': /* CITYPE immediate, compressed lui.  */
	    case 'v': /* CITYPE immediate, li to compressed lui.  */
	    case 'o': /* CITYPE immediate, allow zero.  */
	    case 'j': used_bits |= ENCODE_CITYPE_IMM (-1U); break;
	    case 'L': used_bits |= ENCODE_CITYPE_ADDI16SP_IMM (-1U); break;
	    case 'm': used_bits |= ENCODE_CITYPE_LWSP_IMM (-1U); break;
	    case 'n': used_bits |= ENCODE_CITYPE_LDSP_IMM (-1U); break;
	    case '6': used_bits |= ENCODE_CSSTYPE_IMM (-1U); break;
	    case 'M': used_bits |= ENCODE_CSSTYPE_SWSP_IMM (-1U); break;
	    case 'N': used_bits |= ENCODE_CSSTYPE_SDSP_IMM (-1U); break;
	    case '8': used_bits |= ENCODE_CIWTYPE_IMM (-1U); break;
	    case 'K': used_bits |= ENCODE_CIWTYPE_ADDI4SPN_IMM (-1U); break;
	    /* CLTYPE and CSTYPE have the same immediate encoding.  */
	    case '5': used_bits |= ENCODE_CLTYPE_IMM (-1U); break;
	    case 'k': used_bits |= ENCODE_CLTYPE_LW_IMM (-1U); break;
	    case 'l': used_bits |= ENCODE_CLTYPE_LD_IMM (-1U); break;
	    case 'p': used_bits |= ENCODE_CBTYPE_IMM (-1U); break;
	    case 'a': used_bits |= ENCODE_CJTYPE_IMM (-1U); break;
	    case 'F': /* Compressed funct for .insn directive.  */
	      switch (*++oparg)
		{
		case '6': USE_BITS (OP_MASK_CFUNCT6, OP_SH_CFUNCT6); break;
		case '4': USE_BITS (OP_MASK_CFUNCT4, OP_SH_CFUNCT4); break;
		case '3': USE_BITS (OP_MASK_CFUNCT3, OP_SH_CFUNCT3); break;
		case '2': USE_BITS (OP_MASK_CFUNCT2, OP_SH_CFUNCT2); break;
		default:
		  goto unknown_validate_operand;
		}
	      break;
	    /* { Andes  */
	    case 'e':
	      switch (*++oparg)
		{
		case 'i':
		  used_bits |= ENCODE_RVC_EX9IT_IMM (-1U); break;
		case 't':
		  used_bits |= ENCODE_RVC_EXECIT_IMM (-1U); break;
		case 'T':
		  used_bits |= ENCODE_RVC_NEXECIT_IMM (-1U); break;
		default:
		  goto unknown_validate_operand;
		}
	      break;
	    /* } Andes  */
	    case 'Z': /* ZC specific operators.  */
	      switch (*++oparg)
		{
		/* sreg operators in cm.mvsa01 and cm.mva01s. */
		case '1': USE_BITS (OP_MASK_SREG1, OP_SH_SREG1); break;
		case '2': USE_BITS (OP_MASK_SREG2, OP_SH_SREG2); break;
		/* byte immediate operators, load/store byte insns.  */
		case 'h': used_bits |= ENCODE_ZCB_HALFWORD_UIMM (-1U); break;
		/* halfword immediate operators, load/store halfword insns.  */
		case 'b': used_bits |= ENCODE_ZCB_BYTE_UIMM (-1U); break;
		/* byte immediate operators, load/store byte insns.  */
		case 'H': used_bits |= ENCODE_ZCMB_HALFWORD_UIMM (-1U); break;
		/* halfword immediate operators, load/store halfword insns.  */
		case 'B': used_bits |= ENCODE_ZCMB_BYTE_UIMM (-1U); break;
		/* immediate offset operand for cm.push and cm.pop.  */
		case 'p': used_bits |= ENCODE_ZCMP_SPIMM (-1U); break;
		/* register list operand for cm.push and cm.pop. */
		case 'r': USE_BITS (OP_MASK_RLIST, OP_SH_RLIST); break;
		/* table jump index operand.  */
		case 'i':
		case 'I': used_bits |= ENCODE_ZCMP_TABLE_JUMP_INDEX (-1U); break;
		default:
		  goto unknown_validate_operand;
		}
	      break;
	    default:
	      goto unknown_validate_operand;
	    }
	  break;  /* end RVC */
	/* { Andes  */
	case 'g': used_bits |= ENCODE_STYPE_IMM10 (-1U); break;
	case 'h': used_bits |= ENCODE_ITYPE_IMM (-1U); break;
	case 'i': used_bits |= ENCODE_STYPE_IMM7 (-1U); break;
	case 'k': used_bits |= ENCODE_TYPE_CIMM6 (-1U); break;
	case 'l': used_bits |= ENCODE_ITYPE_IMM (-1U); break;
	case 'H':
	  switch (*++oparg)
	    {
	    case 'b': used_bits |= ENCODE_GPTYPE_SB_IMM (-1U); break;
	    case 'h': used_bits |= ENCODE_GPTYPE_SH_IMM (-1U); break;
	    case 'w': used_bits |= ENCODE_GPTYPE_SW_IMM (-1U); break;
	    case 'd': used_bits |= ENCODE_GPTYPE_SD_IMM (-1U); break;
	    default:
	      goto unknown_validate_operand;
	    }
	  break;
	case 'G':
	  switch (*++oparg)
	    {
	    case 'b': used_bits |= ENCODE_GPTYPE_LB_IMM (-1U); break;
	    case 'h': used_bits |= ENCODE_GPTYPE_LH_IMM (-1U); break;
	    case 'w': used_bits |= ENCODE_GPTYPE_LW_IMM (-1U); break;
	    case 'd': used_bits |= ENCODE_GPTYPE_LD_IMM (-1U); break;
	    default:
	      goto unknown_validate_operand;
	    }
	  break;
	case 'N': /* Andes extensions: RVP  */
	  switch (*++oparg)
	    {
	      case 'c': /* rc */
		USE_BITS (OP_MASK_RC, OP_SH_RC); break;
	      case 'd': /* rdp */
		USE_BITS (OP_MASK_RD, OP_SH_RD); break;
	      case 's': /* rsp */
		USE_BITS (OP_MASK_RD, OP_SH_RS1); break;
	      case 't': /* rtp */
		USE_BITS (OP_MASK_RD, OP_SH_RS2); break;
	      case '3': /* i3u */
		used_bits |= ENCODE_PTYPE_IMM3U (-1U); break;
	      case '4': /* i4u */
		used_bits |= ENCODE_PTYPE_IMM4U (-1U); break;
	      case '5': /* i5u */
		used_bits |= ENCODE_PTYPE_IMM5U (-1U); break;
	      case '6': /* i6u */
		used_bits |= ENCODE_PTYPE_IMM6U (-1U); break;
	      case 'f': /* i15s */
		used_bits |= ENCODE_PTYPE_IMM15S (-1U); break;
	      default:
		goto unknown_validate_operand;
	    }
	  break;
	/* } Andes  */
	case 'V': /* RVV */
	  switch (*++oparg)
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
	    case 'b': used_bits |= ENCODE_RVV_VB_IMM (-1U); break;
	    case 'c': used_bits |= ENCODE_RVV_VC_IMM (-1U); break;
	    case 'i':
	    case 'j':
	    case 'k': USE_BITS (OP_MASK_VIMM, OP_SH_VIMM); break;
	    case 'm': USE_BITS (OP_MASK_VMASK, OP_SH_VMASK); break;
	    default:
	      goto unknown_validate_operand;
	    }
	  break; /* end RVV */
	case ',': break;
	case '(': break;
	case ')': break;
	case '{': break;
	case '}': break;
	case '!': break;
	case '<': USE_BITS (OP_MASK_SHAMTW, OP_SH_SHAMTW); break;
	case '>': USE_BITS (OP_MASK_SHAMT, OP_SH_SHAMT); break;
	case 'A': break; /* Macro operand, must be symbol.  */
	case 'B': break; /* Macro operand, must be symbol or constant.  */
	case 'I': break; /* Macro operand, must be constant.  */
	case 'D': /* RD, floating point.  */
	case 'd': USE_BITS (OP_MASK_RD, OP_SH_RD); break;
	case 'y': USE_BITS (OP_MASK_BS,	OP_SH_BS); break;
	case 'Y': USE_BITS (OP_MASK_RNUM, OP_SH_RNUM); break;
	case 'Z': /* RS1, CSR number.  */
	case 'S': /* RS1, floating point.  */
	case 's': USE_BITS (OP_MASK_RS1, OP_SH_RS1); break;
	case 'U': /* RS1 and RS2 are the same, floating point.  */
	  USE_BITS (OP_MASK_RS1, OP_SH_RS1);
	  /* Fall through.  */
	case 'T': /* RS2, floating point.  */
	case 't': USE_BITS (OP_MASK_RS2, OP_SH_RS2); break;
	case 'R': /* RS3, floating point.  */
	case 'r': USE_BITS (OP_MASK_RS3, OP_SH_RS3); break;
	case 'm': USE_BITS (OP_MASK_RM, OP_SH_RM); break;
	case 'E': USE_BITS (OP_MASK_CSR, OP_SH_CSR); break;
	case 'P': USE_BITS (OP_MASK_PRED, OP_SH_PRED); break;
	case 'Q': USE_BITS (OP_MASK_SUCC, OP_SH_SUCC); break;
	case 'o': /* ITYPE immediate, load displacement.  */
	case 'j': used_bits |= ENCODE_ITYPE_IMM (-1U); break;
	case 'a': used_bits |= ENCODE_JTYPE_IMM (-1U); break;
	case 'p': used_bits |= ENCODE_BTYPE_IMM (-1U); break;
	case 'q': used_bits |= ENCODE_STYPE_IMM (-1U); break;
	case 'f': used_bits |= ENCODE_STYPE_IMM (-1U); break;
	case 'u': used_bits |= ENCODE_UTYPE_IMM (-1U); break;
	case 'z': break; /* Zero immediate.  */
	case '[': break; /* Unused operand.  */
	case ']': break; /* Unused operand.  */
	case '0': break; /* AMO displacement, must to zero.  */
	case '1': break; /* Relaxation operand.  */
	case 'F': /* Funct for .insn directive.  */
	  switch (*++oparg)
	    {
	      case '7': USE_BITS (OP_MASK_FUNCT7, OP_SH_FUNCT7); break;
	      case '3': USE_BITS (OP_MASK_FUNCT3, OP_SH_FUNCT3); break;
	      case '2': USE_BITS (OP_MASK_FUNCT2, OP_SH_FUNCT2); break;
	      default:
		goto unknown_validate_operand;
	    }
	  break;
	case 'O': /* Opcode for .insn directive.  */
	  switch (*++oparg)
	    {
	      case '4': USE_BITS (OP_MASK_OP, OP_SH_OP); break;
	      case '2': USE_BITS (OP_MASK_OP2, OP_SH_OP2); break;
	      default:
		goto unknown_validate_operand;
	    }
	  break;
	case 'n': /* ZC */
	  switch (*++oparg)
	    {
	      case 'f': break;
	      default:
		goto unknown_validate_operand;
	    }
	  break;
	default:
	unknown_validate_operand:
	  as_bad (_("internal: bad RISC-V opcode "
		    "(unknown operand type `%s'): %s %s"),
		  opargStart, opc->name, opc->args);
	  return false;
	}
    }

  if (used_bits != required_bits)
    {
      as_bad (_("internal: bad RISC-V opcode "
		"(bits 0x%lx undefined): %s %s"),
	      ~(unsigned long)(used_bits & required_bits),
	      opc->name, opc->args);
      return false;
    }
  return true;
}

#undef USE_BITS

struct percent_op_match
{
  const char *str;
  bfd_reloc_code_real_type reloc;
};

/* Common hash table initialization function for instruction and .insn
   directive.  */

static htab_t
init_opcode_hash (const struct riscv_opcode *opcodes,
		  bool insn_directive_p)
{
  int i = 0;
  int length;
  htab_t hash = str_htab_create ();
  while (opcodes[i].name)
    {
      const char *name = opcodes[i].name;
      if (str_hash_insert (hash, name, &opcodes[i], 0) != NULL)
	as_fatal (_("internal: duplicate %s"), name);

      do
	{
	  if (opcodes[i].pinfo != INSN_MACRO)
	    {
	      if (insn_directive_p)
		length = ((name[0] == 'c') ? 2 : 4);
	      else
		length = 0; /* Let assembler determine the length.  */
	      if (!validate_riscv_insn (&opcodes[i], length))
		as_fatal (_("internal: broken assembler.  "
			    "No assembly attempted"));
	    }
	  else
	    gas_assert (!insn_directive_p);
	  ++i;
	}
      while (opcodes[i].name && !strcmp (opcodes[i].name, name));
    }

  return hash;
}

/* This function is called once, at assembler startup time.  It should set up
   all the tables, etc. that the MD part of the assembler will need.  */

void
md_begin (void)
{
  unsigned long mach = xlen == 64 ? bfd_mach_riscv64 : bfd_mach_riscv32;

  if (! bfd_set_arch_mach (stdoutput, bfd_arch_riscv, mach))
    as_warn (_("could not set architecture and machine"));

  op_hash = init_opcode_hash (riscv_opcodes, false);
  insn_type_hash = init_opcode_hash (riscv_insn_types, true);

  reg_names_hash = str_htab_create ();
  hash_reg_names (RCLASS_GPR, riscv_gpr_names_numeric, NGPR);
  hash_reg_names (RCLASS_GPR, riscv_gpr_names_abi, NGPR);
  hash_reg_names (RCLASS_FPR, riscv_fpr_names_numeric, NFPR);
  hash_reg_names (RCLASS_FPR, riscv_fpr_names_abi, NFPR);
  hash_reg_names (RCLASS_VECR, riscv_vecr_names_numeric, NVECR);
  hash_reg_names (RCLASS_VECM, riscv_vecm_names_numeric, NVECM);
  /* Add "fp" as an alias for "s0".  */
  hash_reg_name (RCLASS_GPR, "fp", 8);

  /* Create and insert CSR hash tables.  */
  csr_extra_hash = str_htab_create ();
#define DECLARE_CSR(name, num, class, define_version, abort_version) \
  riscv_init_csr_hash (#name, num, class, define_version, abort_version);
#define DECLARE_CSR_ALIAS(name, num, class, define_version, abort_version) \
  DECLARE_CSR(name, num, class, define_version, abort_version);
#include "opcode/riscv-opc.h"
#undef DECLARE_CSR

  opcode_names_hash = str_htab_create ();
  init_opcode_names_hash ();

  /* Set the default alignment for the text section.  */
  record_alignment (text_section, riscv_opts.rvc ? 1 : 2);

  /* { Andes ACE */
  /* Load symbols from ACE shared library if exists */
  if (ace_lib_load_success)
    {
      int i;

      /* Insert instruction information in a hash table */
      i = 0;
      while (ace_opcs[i].name)
	{
	  const char *name = ace_opcs[i].name;
	  struct riscv_opcode **hash_error = (struct riscv_opcode **)
	    str_hash_insert (op_hash, name, (void *) &ace_opcs[i], 0);
	  if (hash_error)
	    {
	      fprintf (stderr, _("internal error: can't hash `%s': %s\n"),
		       name, (*hash_error)->name);
	      as_fatal (_("Broken assembler.  No assembly attempted."));
	    }
	  i++;
	}

      /* Insert ACR index name in a hash table */
      ace_keyword_hash = str_htab_create ();
      i = 0;
      while (ace_keys[i].name)
	{
	  const char *name = ace_keys[i].name;
	  struct riscv_opcode **hash_error = (struct riscv_opcode **)
	    str_hash_insert (ace_keyword_hash, name, (void *) &ace_keys[i], 0);
	  if (hash_error)
	    {
	      fprintf (stderr, _("internal error: can't hash `%s': %s\n"),
		       name, (*hash_error)->name);
	      as_fatal (_("Broken assembler.  No assembly attempted."));
	    }
	  i++;
	}

      /* Insert operand field information in a hash table */
      ace_op_hash = str_htab_create ();
      i = 0;
      while (ace_ops[i].name)
	{
	  const char *name = ace_ops[i].name;
	  struct riscv_opcode **hash_error = (struct riscv_opcode **)
	    str_hash_insert (ace_op_hash, name, (void *) &ace_ops[i], 0);
	  if (hash_error)
	    {
	      fprintf (stderr, _("internal error: can't hash `%s': %s\n"),
		       name, (*hash_error)->name);
	      as_fatal (_("Broken assembler.  No assembly attempted."));
	    }
	  i++;
	}
    }
  /* } Andes ACE */
}

static insn_t
riscv_apply_const_reloc (bfd_reloc_code_real_type reloc_type, bfd_vma value)
{
  switch (reloc_type)
    {
    case BFD_RELOC_32:
      return value;

    case BFD_RELOC_RISCV_HI20:
    case BFD_RELOC_RISCV_ICT_HI20:
      return ENCODE_UTYPE_IMM (RISCV_CONST_HIGH_PART (value));

    case BFD_RELOC_RISCV_LO12_S:
      return ENCODE_STYPE_IMM (value);

    case BFD_RELOC_RISCV_LO12_I:
    case BFD_RELOC_RISCV_ICT_LO12_I:
      return ENCODE_ITYPE_IMM (value);

    default:
      abort ();
    }
}

/* Output an instruction.  IP is the instruction information.
   ADDRESS_EXPR is an operand of the instruction to be used with
   RELOC_TYPE.  */

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
          /* { Andes  */
	  || reloc_type == BFD_RELOC_RISCV_10_PCREL
	  /* } Andes  */
	  || reloc_type == BFD_RELOC_RISCV_JMP)
	{
	  int j = reloc_type == BFD_RELOC_RISCV_JMP;
	  int best_case = riscv_insn_length (ip->insn_opcode);
	  unsigned worst_case = relaxed_branch_length (NULL, NULL, 0);
	  int range = ENUM_BRANCH_RANGE (reloc_type);

	  if (riscv_opts.no_branch_relax)
	    worst_case = best_case;

	  if (now_seg == absolute_section)
	    {
	      as_bad (_("relaxable branches not supported in absolute section"));
	      return;
	    }

	  add_relaxed_insn (ip, worst_case, best_case,
			    RELAX_BRANCH_ENCODE_EX (j, best_case == 2,
						    worst_case, range),
			    address_expr->X_add_symbol,
			    address_expr->X_add_number);
	  if (reloc_type == BFD_RELOC_RISCV_JMP)
	    andes_insert_btb_reloc (ip);
	  return;
	}
      else if (ip->cmodel.method == METHOD_DEFAULT)
	{
	  howto = bfd_reloc_type_lookup (stdoutput, reloc_type);
	  if (howto == NULL)
	    as_bad (_("internal: unsupported RISC-V relocation number %d"),
		    reloc_type);

	  ip->fixp = fix_new_exp (ip->frag, ip->where,
				  bfd_get_reloc_size (howto),
				  address_expr, false, reloc_type);

	  ip->fixp->fx_tcbit = riscv_opts.relax;
	  /* { Andes */
	  if (address_expr == nsta.ict_exp)
	    {
	      nsta.ict_exp = NULL;
	      ip->fixp->tc_fix_data.ict = address_expr->X_md;
	    }
	  /* } Andes */
	}
    }

  if (ip->cmodel.method == METHOD_DEFAULT)
    {
      add_fixed_insn (ip);
      if (riscv_opts.workaround)
	{
	  if ((riscv_opts.b22827 || riscv_opts.b22827_1)
	      && !riscv_subset_supports (&riscv_rps_as, "v"))
	    {
	      const struct riscv_opcode *insn = ip->insn_mo;

	      /* insert “fclass.x x0, RD(FDIV/FSQRT)” after FDIV/FSQRT unless
	       * the next immediate instruction is
	       * “fsub/fadd/fmul/fmadd/fsqrt/fdiv/jal/ret and their 16bit variants”
	       * NOTE: by jal I mean jal and jral. Ret includes jr.
	       * If you can accept more complex conditions, RD(FDIV/FSQRT) has to be
	       * in fa0-7 to exclude jal/ret.
	       */
	      if (riscv_opts.b22827 && is_insn_fdiv_or_fsqrt (insn))
		{
		  const char *mne = "fclass.d";
		  if (is_insn_fmt_s (ip->insn_opcode))
		    mne = "fclass.s";
		  nsta.frag_b22827 = frag_now;
		  macro_build (NULL, mne, "d,s,C", 0, insn_fp_rd(ip->insn_opcode),
			       0, TYPE_B22827, 0, CSI_B22827, 0);
		}

	      /* to provide a separate flag to turn it off, with the following rule:
	       * If FSHW is followed by any floating-point instructions (including
	       * FSHW and FLHW), insert a NOP after it.
	       */
	      else if (riscv_opts.b22827_1 && is_insn_fshw (insn))
		{
		  nsta.frag_b22827 = frag_now;
		  macro_build (NULL, "nop", "C",
			       0, TYPE_B22827_1, 0, CSI_B22827_1, 0);
		}
	    }
	}
    }
  else if (ip->cmodel.method == METHOD_VARIABLE)
    {
      add_insn_grow (ip);
      if (ip->cmodel.state == 0)
	{
	  int length = ip->cmodel.offset + 4;
	  symbolS *symbol = address_expr ? address_expr->X_add_symbol : NULL;
	  offsetT offset = address_expr ? address_expr->X_add_number : 0;
	  add_insn_grow_done (ip, length, 0,
			      RELAX_CMODEL_ENCODE (ip->cmodel.type, ip->cmodel.relax,
						   length, ip->cmodel.index),
			      symbol, offset);
	  andes_insert_btb_reloc (ip);
	}
      return;
    }
  else
    as_fatal (_("internal error: invalid append_insn method!"));

  andes_insert_btb_reloc (ip);

  /* We need to start a new frag after any instruction that can be
     optimized away or compressed by the linker during relaxation, to prevent
     the assembler from computing static offsets across such an instruction.
     This is necessary to get correct EH info.  */
  if (reloc_type == BFD_RELOC_RISCV_HI20
      || reloc_type == BFD_RELOC_RISCV_PCREL_HI20
      || reloc_type == BFD_RELOC_RISCV_TPREL_HI20
      || reloc_type == BFD_RELOC_RISCV_TPREL_ADD)
    {
      frag_wane (frag_now);
      frag_new (0);
    }
}

/* Return TRUE if instruction combiner is available.  */

static bfd_boolean
use_insn_combiner (void)
{
  return riscv_subset_supports (&riscv_rps_as, "zcmp");
}

/* Return TRUE if the insn is valid for the first insn in
  instruction pair. */

static bfd_boolean
zcmp_mva01s_1 (const struct riscv_cl_insn *insn,
	const expressionS *imm_expr ATTRIBUTE_UNUSED,
	const bfd_reloc_code_real_type reloc_type ATTRIBUTE_UNUSED)
{
  int rd, rs2;

  /* mv is replaced by c.mv in C ext  */
  if (insn->insn_mo->match != MATCH_C_MV)
    return FALSE;

  rd = EXTRACT_OPERAND (RD, insn->insn_opcode);
  rs2 = EXTRACT_OPERAND (CRS2, insn->insn_opcode);

  return (rd == X_A0 || rd == X_A1)
      && RISCV_SREG_0_7 (rs2);
}

static bfd_boolean
zcmp_mvsa01_1 (const struct riscv_cl_insn *insn,
	const expressionS *imm_expr ATTRIBUTE_UNUSED,
	const bfd_reloc_code_real_type reloc_type ATTRIBUTE_UNUSED)
{
  int rd, rs2;

  /* mv is replaced by c.mv in C ext  */
  if (insn->insn_mo->match != MATCH_C_MV)
    return FALSE;

  rd = EXTRACT_OPERAND (RD, insn->insn_opcode);
  rs2 = EXTRACT_OPERAND (CRS2, insn->insn_opcode);

  return (rs2 == X_A0 || rs2 == X_A1)
      && RISCV_SREG_0_7 (rd);
}

/* Return TRUE if the insn is valid for the second insn in
  instruction pair. */

static bfd_boolean
zcmp_mva01s_2 (const struct riscv_cl_insn *insn,
	const expressionS *imm_expr ATTRIBUTE_UNUSED,
	const bfd_reloc_code_real_type reloc_type ATTRIBUTE_UNUSED)
{
  if (insn->insn_mo->match != MATCH_C_MV)
    return FALSE;

  int rd = EXTRACT_OPERAND (RD, insn->insn_opcode);
  int rs2 = EXTRACT_OPERAND (CRS2, insn->insn_opcode);
  int rd_cache = EXTRACT_OPERAND (RD, insn_combiner->insn.insn_opcode);

  /* First check if rd does not equal the rd of cached c.mv insn,
    and if rd is a0 or a1. */
  if ((rd == rd_cache)
      || (rd != X_A0 && rd != X_A1))
    return FALSE;

  /* Then we check if rs is s0-s7. */
  return RISCV_SREG_0_7 (rs2);
}

static bfd_boolean
zcmp_mvsa01_2 (const struct riscv_cl_insn *insn,
	const expressionS *imm_expr ATTRIBUTE_UNUSED,
	const bfd_reloc_code_real_type reloc_type ATTRIBUTE_UNUSED)
{
  if (insn->insn_mo->match != MATCH_C_MV)
    return FALSE;

  int rd = EXTRACT_OPERAND (RD, insn->insn_opcode);
  int rs2 = EXTRACT_OPERAND (CRS2, insn->insn_opcode);
  int rd_cache = EXTRACT_OPERAND (RD, insn_combiner->insn.insn_opcode);
  int rs2_cache = EXTRACT_OPERAND (CRS2, insn_combiner->insn.insn_opcode);

  /* First check if rs does not equal the rd of cached c.mv insn,
    and if rs is a0 or a1. */
  if ((rs2 == rs2_cache)
      || (rs2 != X_A0 && rs2 != X_A1))
    return FALSE;

  /* Then we check if rd is s0-s7 and does not equal the
    rd of cached c.mv insn.  */
  return (rd != rd_cache)
      && RISCV_SREG_0_7 (rd);
}

/* Write combined insn to the cached field in insn_combiner to append
  later. */

static bfd_boolean
zcmp_mva01s_update (const struct riscv_cl_insn *insn,
	const expressionS *imm_expr ATTRIBUTE_UNUSED,
	const bfd_reloc_code_real_type reloc_type ATTRIBUTE_UNUSED)
{
  unsigned sreg1, sreg2;
  struct riscv_cl_insn *cached_insn = &insn_combiner->insn;

  unsigned rd = EXTRACT_OPERAND (RD, insn->insn_opcode);
  unsigned rs2 = EXTRACT_OPERAND (CRS2, insn->insn_opcode);
  unsigned rs2_cache = EXTRACT_OPERAND (CRS2, cached_insn->insn_opcode);

  cached_insn->insn_opcode = MATCH_CM_MVA01S;

  sreg1 = (rd == X_A0 ? rs2 : rs2_cache) % 8;
  sreg2 = (rd == X_A0 ? rs2_cache : rs2) % 8;

  INSERT_OPERAND (SREG1, *cached_insn, sreg1);
  INSERT_OPERAND (SREG2, *cached_insn, sreg2);

  return TRUE;
}

static bfd_boolean
zcmp_mvsa01_update (const struct riscv_cl_insn *insn,
	const expressionS *imm_expr ATTRIBUTE_UNUSED,
	const bfd_reloc_code_real_type reloc_type ATTRIBUTE_UNUSED)
{
  unsigned sreg1, sreg2;
  struct riscv_cl_insn *cached_insn = &insn_combiner->insn;

  unsigned rd = EXTRACT_OPERAND (RD, insn->insn_opcode);
  unsigned rd_cache = EXTRACT_OPERAND (RD, cached_insn->insn_opcode);
  unsigned rs2 = EXTRACT_OPERAND (CRS2, insn->insn_opcode);

  cached_insn->insn_opcode = MATCH_CM_MVSA01;

  sreg1 = (rs2 == X_A0 ? rd : rd_cache) % 8;
  sreg2 = (rs2 == X_A0 ? rd_cache : rd) % 8;

  INSERT_OPERAND (SREG1, *cached_insn, sreg1);
  INSERT_OPERAND (SREG2, *cached_insn, sreg2);
  return TRUE;
}

/* Instruction pair matching table.  */

static struct riscv_combiner_matcher riscv_comb_matchers [] = {
  { zcmp_mva01s_1, zcmp_mva01s_2, zcmp_mva01s_update, use_insn_combiner },
  { zcmp_mvsa01_1, zcmp_mvsa01_2, zcmp_mvsa01_update, use_insn_combiner },
  { NULL, NULL, NULL, NULL },
};

/* Cache an instruction when it passes check function */

static void
cache_an_insn (struct riscv_cl_insn *insn,
		    expressionS *imm_expr,
		    bfd_reloc_code_real_type reloc_type)
{
  memcpy((void*)&(insn_combiner->imm_expr),
      (void*)imm_expr, sizeof(expressionS));
  memcpy((void*)&(insn_combiner->insn), (void*)insn,
      sizeof(struct riscv_cl_insn));
  insn_combiner->imm_reloc = reloc_type;
}

/* Initialize instruction pair combiner */

static void
init_insn_combiner (void)
{
  insn_combiner = (struct riscv_combiner *)
	xmalloc (sizeof (struct riscv_combiner));
  insn_combiner->idx = 0;
  insn_combiner->matcher = riscv_comb_matchers;
}

/* Return TRUE if combiner has cached one instruction.  */

static bfd_boolean
has_cached_insn (void)
{
  return use_insn_combiner ()
      && insn_combiner
      && insn_combiner->idx > 0;
}

/* Append a cached instruction.  */

static void
release_cached_insn (void)
{
  append_insn (&insn_combiner->insn,
		&insn_combiner->imm_expr,
		insn_combiner->imm_reloc);
  insn_combiner->idx = 0;
}

/* Build an instruction created by a macro expansion.  This is passed
   a pointer to the count of instructions created so far, an expression,
   the name of the instruction to build, an operand format string, and
   corresponding arguments.  */

static void
macro_build (expressionS *ep, const char *name, const char *fmt, ...)
{
  const struct riscv_opcode *mo;
  struct riscv_cl_insn insn;
  bfd_reloc_code_real_type r;
  va_list args;
  const char *fmtStart;

  insn.cmodel.method = METHOD_DEFAULT;
  va_start (args, fmt);

  r = BFD_RELOC_UNUSED;
  mo = (struct riscv_opcode *) str_hash_find (op_hash, name);
  gas_assert (mo);

  /* Find a non-RVC variant of the instruction.  append_insn will compress
     it if possible.  */
  while (riscv_insn_length (mo->match) < 4)
    mo++;
  gas_assert (strcmp (name, mo->name) == 0);

  create_insn (&insn, mo);
  for (;; ++fmt)
    {
      fmtStart = fmt;
      switch (*fmt)
	{
	case 'V': /* RVV */
	  switch (*++fmt)
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
		else
		  goto unknown_macro_argument;
	      }
	    default:
	      goto unknown_macro_argument;
	    }
	  break;

	case 'd':
	  INSERT_OPERAND (RD, insn, va_arg (args, int));
	  continue;
	case 's':
	  INSERT_OPERAND (RS1, insn, va_arg (args, int));
	  continue;
	case 't':
	  INSERT_OPERAND (RS2, insn, va_arg (args, int));
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

	/* { Andes */
	case 'C':
	  insn.cmodel.method = METHOD_VARIABLE;
	  insn.cmodel.state = va_arg (args, int);
	  insn.cmodel.type = va_arg (args, int);
	  insn.cmodel.relax = va_arg (args, int);
	  insn.cmodel.index = va_arg (args, int);
	  insn.cmodel.offset = va_arg (args, int);
	  continue;
	/* } Andes */

	case 'P':
	  INSERT_OPERAND (PRED, insn, va_arg (args, int));
	  continue;
	case 'Q':
	  INSERT_OPERAND (SUCC, insn, va_arg (args, int));
	  continue;

	default:
	unknown_macro_argument:
	  as_fatal (_("internal: invalid macro argument `%s'"), fmtStart);
	}
      break;
    }
  va_end (args);
  gas_assert (r == BFD_RELOC_UNUSED ? ep == NULL : ep != NULL);

  append_insn (&insn, ep, r);
}

/* Build an instruction created by a macro expansion.  Like md_assemble but
   accept a printf-style format string and arguments.  */

static void
md_assemblef (const char *format, ...)
{
  char *buf = NULL;
  va_list ap;
  int r;

  va_start (ap, format);

  r = vasprintf (&buf, format, ap);

  if (r < 0)
    as_fatal (_("internal: vasprintf failed"));

  md_assemble (buf);
  free(buf);

  va_end (ap);
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
		     bool maybe_csr)
{
  if (ex->X_op == O_big)
    as_bad (_("unsupported large constant"));
  else if (maybe_csr && ex->X_op == O_symbol)
    as_bad (_("unknown CSR `%s'"),
	    S_GET_NAME (ex->X_add_symbol));
  else if (ex->X_op != O_constant)
    as_bad (_("instruction %s requires absolute expression"),
	    ip->insn_mo->name);
  normalize_constant_expr (ex);
}

static symbolS *
make_internal_label (void)
{
  return (symbolS *) local_symbol_make (FAKE_LABEL_NAME, now_seg, frag_now,
					frag_now_fix ());
}

/* { Andes */
#define CMODEL_SUBSECTION 8100
#define CMODEL_SYMBOL_PREFIX ".Laddr"
#define CMODEL_SECTION_ALIGN 3
#define CMODEL_SECTION_ENTRY_SIZE (1u << CMODEL_SECTION_ALIGN)

static
void make_indirect_symbol (expressionS *ep, expressionS *ep_ind)
{
  char buf[0x100];
  char isym_name[0x100];
  symbolS *isym;
  const char *seg_name = segment_name (now_seg);
  const char *sym_name = S_GET_NAME (ep->X_add_symbol);
  valueT sym_addend = ep->X_add_number;

  /* make indirect symbol once  */
  sprintf (isym_name, "%s_%s_%s_%lx", CMODEL_SYMBOL_PREFIX, seg_name,
	   sym_name, (unsigned long)sym_addend);
  isym = symbol_find (isym_name);
  if (isym == NULL)
    {
      /* create indirect symbol:
       *   # NOTE! these data might eventually drop, don't put fix here!!
       *   # .pushsection subsection
       *   # make nops for align
       *   # make indirect symbol
       *   # new variable fragment (grow frag, pend reloc till md_convert)
       *   # .popsection
       */
      const char *sec_name = segment_name (now_seg);
      char *save_in;
      /* #  */
      sprintf (buf, "%s, %d", sec_name, CMODEL_SUBSECTION);
      save_in = input_line_pointer;
      input_line_pointer = buf;
      obj_elf_section (1); /* .pushsection  */
      input_line_pointer = save_in;
      /* #  */
      #define ALIGN_LEN (6)
      /* ALIGN */
      frag_grow (ALIGN_LEN);
      char *nops = frag_more (0);
      riscv_make_nops (nops, ALIGN_LEN);
      frag_var (rs_machine_dependent, ALIGN_LEN, 0,
		RELAX_CMODEL_ENCODE (TYPE_ALIGN, riscv_opts.relax, ALIGN_LEN, 0),
		ep->X_add_symbol, ep->X_add_number, NULL);
      /* SYMBOL */
      isym = colon (isym_name);
      #define DATA_LEN (8)
      frag_grow (DATA_LEN);
      frag_var (rs_machine_dependent, DATA_LEN, 0,
		RELAX_CMODEL_ENCODE (TYPE_IS, riscv_opts.relax, DATA_LEN, 0),
		ep->X_add_symbol, ep->X_add_number, NULL);
      /* #  */
      obj_elf_popsection (0); /* .popsection  */
    }

  ep_ind->X_op = O_symbol;
  ep_ind->X_add_symbol = isym;
  ep_ind->X_add_number = 0;
  ep_ind->X_md = 0; /* for ICT logic within fix_new_exp */
}
/* } Andes */

/* Load an entry from the GOT.  */

static void
pcrel_access (int destreg, int tempreg, expressionS *ep,
	      const char *lo_insn, const char *lo_pattern,
	      bfd_reloc_code_real_type hi_reloc,
	      bfd_reloc_code_real_type lo_reloc)
{
  /* only L[BHWD]/S[BHWD support cmodel large  */
  if (hi_reloc == BFD_RELOC_RISCV_PCREL_HI20
      && is_cmodel_relaxable (ep->X_add_symbol, now_seg))
    {
      gas_assert (ep->X_op == O_symbol);
      char lo_pattern_ex[0x100];
      int index, type, relax = riscv_opts.relax;
      expressionS ep_ind, ep_ref;
      bfd_boolean is_la = strcmp (lo_insn, "addi") == 0;
      bfd_boolean is_st = lo_reloc == BFD_RELOC_RISCV_PCREL_LO12_S;
      make_indirect_symbol (ep, &ep_ind);
      ep_ref.X_op = O_symbol;
      ep_ref.X_add_symbol = make_internal_label ();
      ep_ref.X_add_number = 0;
      ep_ref.X_md = 0; /* for ICT logic within fix_new_exp */
      type = is_st ? TYPE_ST : is_la ? TYPE_LA : TYPE_LD;

      strcpy (lo_pattern_ex, lo_pattern);
      strcat (lo_pattern_ex, ",C");

      /* index 0: argument, C: state, type, index, offset.  */
      index = CSI_INDIRECT_SYMBOL;
      macro_build (&ep_ind, "nop", "j,C", hi_reloc, 0, type, relax, index, 0);

      /* index 1: argument, C: state, type, index, offset.  */
      index++; /* CSI_REFERENCE_SYMBOL  */
      macro_build (&ep_ref, "nop", "j,C", hi_reloc, 0, type, relax, index, 0);

      /* index 2: generic form, C: state, type, index, offset.  */
      index++; /* CSI_LARGE_CODE  */
      frag_grow(4 * 3); /* ensure folloiwng instructions without frag bump.  */
      macro_build (&ep_ind, "auipc", "d,u,C", tempreg, hi_reloc, 1, type, relax, index, 0);
      macro_build (&ep_ref, "ld", "d,s,j,C", tempreg, tempreg, hi_reloc, 1, type, relax, index, 4);
      macro_build (ep, lo_insn, lo_pattern_ex, destreg, tempreg, lo_reloc, 0, type, relax, index, 8);

      /* CSI_DEFAULT_CODE can be extracted from CSI_LARGE_CODE  */
    }
  else
    {
      expressionS ep2;
      ep2.X_op = O_symbol;
      ep2.X_add_symbol = make_internal_label ();
      ep2.X_add_number = 0;

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
  /* { Andes */
  if (reloc == BFD_RELOC_RISCV_CALL
      && is_cmodel_relaxable (ep->X_add_symbol, now_seg))
    {
      gas_assert (ep->X_op == O_symbol);
      int index, relax = riscv_opts.relax;
      expressionS ep_ind, ep_ref;
      make_indirect_symbol (ep, &ep_ind);
      ep_ref.X_op = O_symbol;
      ep_ref.X_add_symbol = make_internal_label ();
      ep_ref.X_add_number = 0;
      ep_ref.X_md = 0; /* for ICT logic within fix_new_exp */

      /* index 0: argument, C: state, type, index, offset.  */
      index = CSI_INDIRECT_SYMBOL;
      macro_build (&ep_ind, "nop", "j,C", reloc, 0, TYPE_JX, relax, index, 0);

      /* index 1: argument, C: state, type, index, offset.  */
      index++; /* CSI_REFERENCE_SYMBOL  */
      macro_build (&ep_ref, "nop", "j,C", reloc, 0, TYPE_JX, relax, index, 0);

      /* index 2: generic form, C: state, type, index, offset.  */
      index++; /* CSI_LARGE_CODE  */
      frag_grow(4 * 3); /* ensure folloiwng instructions without frag bump.  */
      macro_build (&ep_ind, "auipc", "d,u,C", tempreg, reloc, 1, TYPE_JX, relax, index, 0);
      macro_build (&ep_ref, "ld", "d,s,j,C", tempreg, tempreg, reloc, 1, TYPE_JX, relax, index, 4);
      macro_build (ep, "jalr", "d,s,j,C", destreg, tempreg, reloc, 0, TYPE_JX, relax, index, 8);

      /* index 3: relaxed form  */
      index++; /* CSI_DEFAULT_CODE  */
      frag_grow(4 * 2); /* ensure folloiwng instructions without frag bump.  */
      macro_build (ep, "auipc", "d,u,C", tempreg, reloc, 1, TYPE_JX, relax, index, 0);
      macro_build (ep, "jalr", "d,s,j,C", destreg, tempreg, reloc, 0, TYPE_JX, relax, index, 4);
    }
  /* } Andes */
  else
    {
      /* Ensure the jalr is emitted to the same frag as the auipc.  */
      frag_grow (8);
      macro_build (ep, "auipc", "d,u", tempreg, reloc);
      macro_build (NULL, "jalr", "d,s", destreg, tempreg);
    }

  /* See comment at end of append_insn.  */
  frag_wane (frag_now);
  frag_new (0);
}

/* Load an integer constant into a register.  */

static void
load_const (int reg, expressionS *ep)
{
  int shift = RISCV_IMM_BITS;
  bfd_vma upper_imm, sign = (bfd_vma) 1 << (RISCV_IMM_BITS - 1);
  expressionS upper = *ep, lower = *ep;
  lower.X_add_number = ((ep->X_add_number & (sign + sign - 1)) ^ sign) - sign;
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

      md_assemblef ("slli x%d, x%d, 0x%x", reg, reg, shift);
      if (lower.X_add_number != 0)
	md_assemblef ("addi x%d, x%d, %" BFD_VMA_FMT "d", reg, reg,
		      lower.X_add_number);
    }
  else
    {
      /* Simply emit LUI and/or ADDI to build a 32-bit signed constant.  */
      int hi_reg = 0;

      if (upper.X_add_number != 0)
	{
	  /* Discard low part and zero-extend upper immediate.  */
	  upper_imm = ((uint32_t)upper.X_add_number >> shift);

	  md_assemblef ("lui x%d, 0x%" BFD_VMA_FMT "x", reg, upper_imm);
	  hi_reg = reg;
	}

      if (lower.X_add_number != 0 || hi_reg == 0)
	md_assemblef ("%s x%d, x%d, %" BFD_VMA_FMT "d", ADD32_INSN, reg, hi_reg,
		      lower.X_add_number);
    }
}

/* Zero extend and sign extend byte/half-word/word.  */

static void
riscv_ext (int destreg, int srcreg, unsigned shift, bool sign)
{
  if (sign)
    {
      md_assemblef ("slli x%d, x%d, 0x%x", destreg, srcreg, shift);
      md_assemblef ("srai x%d, x%d, 0x%x", destreg, destreg, shift);
    }
  else
    {
      md_assemblef ("slli x%d, x%d, 0x%x", destreg, srcreg, shift);
      md_assemblef ("srli x%d, x%d, 0x%x", destreg, destreg, shift);
    }
}

/* Expand RISC-V Vector macros into one or more instructions.  */

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
	  macro_build (NULL, "vmnand.mm", "Vd,Vt,Vs", vd, vd, vd);
	  break;
	}
      if (vtemp != 0)
	{
	  /* Masked.  Have vtemp to avoid overlap constraints.  */
	  if (vd == vm)
	    {
	      macro_build (NULL, "vmslt.vx", "Vd,Vt,s", vtemp, vs2, vs1);
	      macro_build (NULL, "vmandnot.mm", "Vd,Vt,Vs", vd, vm, vtemp);
	    }
	  else
	    {
	      /* Preserve the value of vd if not updating by vm.  */
	      macro_build (NULL, "vmslt.vx", "Vd,Vt,s", vtemp, vs2, vs1);
	      macro_build (NULL, "vmandnot.mm", "Vd,Vt,Vs", vtemp, vm, vtemp);
	      macro_build (NULL, "vmandnot.mm", "Vd,Vt,Vs", vd, vd, vm);
	      macro_build (NULL, "vmor.mm", "Vd,Vt,Vs", vd, vtemp, vd);
	    }
	}
      else if (vd != vm)
	{
	  /* Masked.  This may cause the vd overlaps vs2, when LMUL > 1.  */
	  macro_build (NULL, "vmslt.vx", "Vd,Vt,sVm", vd, vs2, vs1, vm);
	  macro_build (NULL, "vmxor.mm", "Vd,Vt,Vs", vd, vd, vm);
	}
      else
	as_bad (_("must provide temp if destination overlaps mask"));
      break;

    case M_VMSGEU:
      if (vm)
	{
	  /* Unmasked.  */
	  macro_build (NULL, "vmsltu.vx", "Vd,Vt,sVm", vd, vs2, vs1, -1);
	  macro_build (NULL, "vmnand.mm", "Vd,Vt,Vs", vd, vd, vd);
	  break;
	}
      if (vtemp != 0)
	{
	  /* Masked.  Have vtemp to avoid overlap constraints.  */
	  if (vd == vm)
	    {
	      macro_build (NULL, "vmsltu.vx", "Vd,Vt,s", vtemp, vs2, vs1);
	      macro_build (NULL, "vmandnot.mm", "Vd,Vt,Vs", vd, vm, vtemp);
	    }
	  else
	    {
	      /* Preserve the value of vd if not updating by vm.  */
	      macro_build (NULL, "vmsltu.vx", "Vd,Vt,s", vtemp, vs2, vs1);
	      macro_build (NULL, "vmandnot.mm", "Vd,Vt,Vs", vtemp, vm, vtemp);
	      macro_build (NULL, "vmandnot.mm", "Vd,Vt,Vs", vd, vd, vm);
	      macro_build (NULL, "vmor.mm", "Vd,Vt,Vs", vd, vtemp, vd);
	    }
	}
      else if (vd != vm)
	{
	  /* Masked.  This may cause the vd overlaps vs2, when LMUL > 1.  */
	  macro_build (NULL, "vmsltu.vx", "Vd,Vt,sVm", vd, vs2, vs1, vm);
	  macro_build (NULL, "vmxor.mm", "Vd,Vt,Vs", vd, vd, vm);
	}
      else
	as_bad (_("must provide temp if destination overlaps mask"));
      break;

    default:
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

      if (imm_expr->X_op == O_constant)
	load_const (rd, imm_expr);
      else if (riscv_opts.pic && mask == M_LA) /* Global PIC symbol.  */
	pcrel_load (rd, rd, imm_expr, LOAD_ADDRESS_INSN,
		    BFD_RELOC_RISCV_GOT_HI20, BFD_RELOC_RISCV_PCREL_LO12_I);
      else /* Local PIC symbol, or any non-PIC symbol.  */
	pcrel_load (rd, rd, imm_expr, "addi",
		    BFD_RELOC_RISCV_PCREL_HI20, BFD_RELOC_RISCV_PCREL_LO12_I);
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

    case M_ZEXTH:
      riscv_ext (rd, rs1, xlen - 16, false);
      break;

    case M_ZEXTW:
      riscv_ext (rd, rs1, xlen - 32, false);
      break;

    case M_SEXTB:
      riscv_ext (rd, rs1, xlen - 8, true);
      break;

    case M_SEXTH:
      riscv_ext (rd, rs1, xlen - 16, true);
      break;

    case M_VMSGE:
    case M_VMSGEU:
      vector_macro (ip);
      break;

    default:
      as_bad (_("internal: macro %s not implemented"), ip->insn_mo->name);
      break;
    }
}

static const struct percent_op_match percent_op_utype[] =
{
  {"%tprel_hi", BFD_RELOC_RISCV_TPREL_HI20},
  {"%pcrel_hi", BFD_RELOC_RISCV_PCREL_HI20},
  {"%got_pcrel_hi", BFD_RELOC_RISCV_GOT_HI20},
  {"%tls_ie_pcrel_hi", BFD_RELOC_RISCV_TLS_GOT_HI20},
  {"%tls_gd_pcrel_hi", BFD_RELOC_RISCV_TLS_GD_HI20},
  {"%hi", BFD_RELOC_RISCV_HI20},
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

static bool
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
	    as_bad ("internal: relocation %s isn't supported by the "
		    "current ABI", percent_op->str);
	    *reloc = BFD_RELOC_UNUSED;
	  }
	return true;
      }
  return false;
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

     End the loop with CRUX pointing to the start of the main expression and
     with CRUX_DEPTH containing the number of open brackets at that point.  */
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

/* Parse string STR as a vsetvli operand.  Store the expression in *EP.
   On exit, EXPR_END points to the first character after the expression.  */

static void
my_getVsetvliExpression (expressionS *ep, char *str)
{
  unsigned int vsew_value = 0, vlmul_value = 0;
  unsigned int vta_value = 0, vma_value = 0;
  bfd_boolean vsew_found = FALSE, vlmul_found = FALSE;
  bfd_boolean vta_found = FALSE, vma_found = FALSE;

  if (arg_lookup (&str, riscv_vsew, ARRAY_SIZE (riscv_vsew), &vsew_value))
    {
      if (*str == ',')
	++str;
      if (vsew_found)
	as_bad (_("multiple vsew constants"));
      vsew_found = TRUE;
    }
  if (arg_lookup (&str, riscv_vlmul, ARRAY_SIZE (riscv_vlmul), &vlmul_value))
    {
      if (*str == ',')
	++str;
      if (vlmul_found)
	as_bad (_("multiple vlmul constants"));
      vlmul_found = TRUE;
    }
  if (arg_lookup (&str, riscv_vta, ARRAY_SIZE (riscv_vta), &vta_value))
    {
      if (*str == ',')
	++str;
      if (vta_found)
	as_bad (_("multiple vta constants"));
      vta_found = TRUE;
    }
  if (arg_lookup (&str, riscv_vma, ARRAY_SIZE (riscv_vma), &vma_value))
    {
      if (*str == ',')
	++str;
      if (vma_found)
	as_bad (_("multiple vma constants"));
      vma_found = TRUE;
    }

  if (vsew_found || vlmul_found || vta_found || vma_found)
    {
      ep->X_op = O_constant;
      ep->X_add_number = (vlmul_value << OP_SH_VLMUL)
			 | (vsew_value << OP_SH_VSEW)
			 | (vta_value << OP_SH_VTA)
			 | (vma_value << OP_SH_VMA);
      expr_end = str;
    }
  else
    {
      my_getExpression (ep, str);
      str = expr_end;
    }
}

/* Detect and handle implicitly zero load-store offsets.  For example,
   "lw t0, (t1)" is shorthand for "lw t0, 0(t1)".  Return true if such
   an implicit offset was detected.  */

static bool
riscv_handle_implicit_zero_offset (expressionS *ep, const char *s)
{
  /* Check whether there is only a single bracketed expression left.
     If so, it must be the base register and the constant must be zero.  */
  if (*s == '(' && strchr (s + 1, '(') == 0)
    {
      ep->X_op = O_constant;
      ep->X_add_number = 0;
      return true;
    }

  return false;
}

/* All RISC-V CSR instructions belong to one of these classes.  */
enum csr_insn_type
{
  INSN_NOT_CSR,
  INSN_CSRRW,
  INSN_CSRRS,
  INSN_CSRRC
};

/* Return which CSR instruction is checking.  */

static enum csr_insn_type
riscv_csr_insn_type (insn_t insn)
{
  if (((insn ^ MATCH_CSRRW) & MASK_CSRRW) == 0
      || ((insn ^ MATCH_CSRRWI) & MASK_CSRRWI) == 0)
    return INSN_CSRRW;
  else if (((insn ^ MATCH_CSRRS) & MASK_CSRRS) == 0
	   || ((insn ^ MATCH_CSRRSI) & MASK_CSRRSI) == 0)
    return INSN_CSRRS;
  else if (((insn ^ MATCH_CSRRC) & MASK_CSRRC) == 0
	   || ((insn ^ MATCH_CSRRCI) & MASK_CSRRCI) == 0)
    return INSN_CSRRC;
  else
    return INSN_NOT_CSR;
}

/* CSRRW and CSRRWI always write CSR.  CSRRS, CSRRC, CSRRSI and CSRRCI write
   CSR when RS1 isn't zero.  The CSR is read only if the [11:10] bits of
   CSR address is 0x3.  */

static bool
riscv_csr_read_only_check (insn_t insn)
{
  int csr = (insn & (OP_MASK_CSR << OP_SH_CSR)) >> OP_SH_CSR;
  int rs1 = (insn & (OP_MASK_RS1 << OP_SH_RS1)) >> OP_SH_RS1;
  int readonly = (((csr & (0x3 << 10)) >> 10) == 0x3);
  enum csr_insn_type csr_insn = riscv_csr_insn_type (insn);

  if (readonly
      && (((csr_insn == INSN_CSRRS
	    || csr_insn == INSN_CSRRC)
	   && rs1 != 0)
	  || csr_insn == INSN_CSRRW))
    return false;

  return true;
}

/* Return true if it is a privileged instruction.  Otherwise, return false.

   uret is actually a N-ext instruction.  So it is better to regard it as
   an user instruction rather than the priv instruction.

   hret is used to return from traps in H-mode.  H-mode is removed since
   the v1.10 priv spec, but probably be added in the new hypervisor spec.
   Therefore, hret should be controlled by the hypervisor spec rather than
   priv spec in the future.

   dret is defined in the debug spec, so it should be checked in the future,
   too.  */

static bool
riscv_is_priv_insn (insn_t insn)
{
  return (((insn ^ MATCH_SRET) & MASK_SRET) == 0
	  || ((insn ^ MATCH_MRET) & MASK_MRET) == 0
	  || ((insn ^ MATCH_SFENCE_VMA) & MASK_SFENCE_VMA) == 0
	  || ((insn ^ MATCH_WFI) & MASK_WFI) == 0
  /* The sfence.vm is dropped in the v1.10 priv specs, but we still need to
     check it here to keep the compatible.  */
	  || ((insn ^ MATCH_SFENCE_VM) & MASK_SFENCE_VM) == 0);
}

/* This routine assembles an instruction into its binary format.  As a
   side effect, it sets the global variable imm_reloc to the type of
   relocation to do if one of the operands is an address expression.  */

static const char *
riscv_ip (char *str, struct riscv_cl_insn *ip, expressionS *imm_expr,
	  bfd_reloc_code_real_type *imm_reloc, htab_t hash)
{
  /* The operand string defined in the riscv_opcodes.  */
  const char *oparg, *opargStart;
  /* The parsed operands from assembly.  */
  char *asarg, *asargStart;
  char save_c = 0;
  struct riscv_opcode *insn;
  unsigned int regno;
  int argnum;
  const struct percent_op_match *p;
  const char *error = "unrecognized opcode";
  /* Indicate we are assembling instruction with CSR.  */
  bool insn_with_csr = false;

  /* Parse the name of the instruction.  Terminate the string if whitespace
     is found so that str_hash_find only sees the name part of the string.  */
  for (asarg = str; *asarg!= '\0'; ++asarg)
    if (ISSPACE (*asarg))
      {
	save_c = *asarg;
	*asarg++ = '\0';
	break;
      }

  insn = (struct riscv_opcode *) str_hash_find (hash, str);

  asargStart = asarg;
  for ( ; insn && insn->name && strcmp (insn->name, str) == 0; insn++)
    {
      if ((insn->xlen_requirement != 0) && (xlen != insn->xlen_requirement))
	continue;

      if (!riscv_multi_subset_supports (&riscv_rps_as, insn->insn_class))
	continue;

      /* VLSI mode desires AS IT conversion.  */
      if (riscv_opts.no_rvc_convert
	  && (insn->insn_class == INSN_CLASS_C
	      || insn->insn_class == INSN_CLASS_F_AND_C
	      || insn->insn_class == INSN_CLASS_D_AND_C)
	  && 0 != strncmp (insn->name, "c.", 2))
	continue;

      nsta.ict_exp = NULL;

      /* Reset error message of the previous round.  */
      error = _("illegal operands");
      create_insn (ip, insn);
      argnum = 1;

      imm_expr->X_op = O_absent;
      *imm_reloc = BFD_RELOC_UNUSED;
      p = percent_op_itype;

      for (oparg = insn->args;; ++oparg)
	{
	  opargStart = oparg;
	  asarg += strspn (asarg, " \t");
	  switch (*oparg)
	    {
	    case '\0': /* End of args.  */
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

		  if (riscv_is_priv_insn (ip->insn_opcode))
		    explicit_priv_attr = true;

		  /* Check if we write a read-only CSR by the CSR
		     instruction.  */
		  if (insn_with_csr
		      && riscv_opts.csr_check
		      && !riscv_csr_read_only_check (ip->insn_opcode))
		    {
		      /* Restore the character in advance, since we want to
			 report the detailed warning message here.  */
		      if (save_c)
			*(asargStart - 1) = save_c;
		      as_warn (_("read-only CSR is written `%s'"), str);
		      insn_with_csr = false;
		    }

		  /* The (segmant) load and store with EEW 64 cannot be used
		     when zve32x is enabled.  */
		  if (ip->insn_mo->pinfo & INSN_V_EEW64
		      && riscv_subset_supports (&riscv_rps_as, "zve32x")
		      && !riscv_subset_supports (&riscv_rps_as, "zve64x"))
		    {
		      error = _("illegal opcode for zve32x");
		      break;
		    }
		}
	      if (*asarg != '\0')
		break;

	      /* Convert "add rd, rs, zero" and "add rd, zero, rs"
		 to "mv rd, rs".  */
	      if (strcmp (insn->name, "add") == 0 && !riscv_opts.rvc)
		{
		  if (EXTRACT_OPERAND (RS2, ip->insn_opcode) == 0)
		    ip->insn_opcode &= ~(1 << 5);
		  else if (EXTRACT_OPERAND (RS1, ip->insn_opcode) == 0)
		    {
		      ip->insn_opcode &= ~(1 << 5);
		      INSERT_OPERAND (RS1, *ip, EXTRACT_OPERAND (RS2, ip->insn_opcode));
		      INSERT_OPERAND (RS2, *ip, 0);
		    }
		}

	      /* Successful assembly.  */
	      error = NULL;
	      insn_with_csr = false;
	      goto out;

	    case 'C': /* RVC */
	      switch (*++oparg)
		{
		case 's': /* RS1 x8-x15.  */
		  if (!reg_lookup (&asarg, RCLASS_GPR, &regno)
		      || !(regno >= 8 && regno <= 15))
		    break;
		  INSERT_OPERAND (CRS1S, *ip, regno % 8);
		  continue;
		case 'w': /* RS1 x8-x15, constrained to equal RD x8-x15.  */
		  if (!reg_lookup (&asarg, RCLASS_GPR, &regno)
		      || EXTRACT_OPERAND (CRS1S, ip->insn_opcode) + 8 != regno)
		    break;
		  continue;
		case 't': /* RS2 x8-x15.  */
		  if (!reg_lookup (&asarg, RCLASS_GPR, &regno)
		      || !(regno >= 8 && regno <= 15))
		    break;
		  INSERT_OPERAND (CRS2S, *ip, regno % 8);
		  continue;
		case 'x': /* RS2 x8-x15, constrained to equal RD x8-x15.  */
		  if (!reg_lookup (&asarg, RCLASS_GPR, &regno)
		      || EXTRACT_OPERAND (CRS2S, ip->insn_opcode) + 8 != regno)
		    break;
		  continue;
		case 'U': /* RS1, constrained to equal RD.  */
		  if (!reg_lookup (&asarg, RCLASS_GPR, &regno)
		      || EXTRACT_OPERAND (RD, ip->insn_opcode) != regno)
		    break;
		  continue;
		case 'V': /* RS2 */
		  if (!reg_lookup (&asarg, RCLASS_GPR, &regno))
		    break;
		  INSERT_OPERAND (CRS2, *ip, regno);
		  continue;
		case 'c': /* RS1, constrained to equal sp.  */
		  if (!reg_lookup (&asarg, RCLASS_GPR, &regno)
		      || regno != X_SP)
		    break;
		  continue;
		case 'z': /* RS2, constrained to equal x0.  */
		  if (!reg_lookup (&asarg, RCLASS_GPR, &regno)
		      || regno != 0)
		    break;
		  continue;
		case '>': /* Shift amount, 0 - (XLEN-1).  */
		  if (my_getSmallExpression (imm_expr, imm_reloc, asarg, p)
		      || imm_expr->X_op != O_constant
		      || (unsigned long) imm_expr->X_add_number >= xlen)
		    break;
		  ip->insn_opcode |= ENCODE_CITYPE_IMM (imm_expr->X_add_number);
		rvc_imm_done:
		  asarg = expr_end;
		  imm_expr->X_op = O_absent;
		  continue;
		case '5':
		  if (my_getSmallExpression (imm_expr, imm_reloc, asarg, p)
		      || imm_expr->X_op != O_constant
		      || imm_expr->X_add_number < 0
		      || imm_expr->X_add_number >= 32
		      || !VALID_CLTYPE_IMM ((valueT) imm_expr->X_add_number))
		    break;
		  ip->insn_opcode |= ENCODE_CLTYPE_IMM (imm_expr->X_add_number);
		  goto rvc_imm_done;
		case '6':
		  if (my_getSmallExpression (imm_expr, imm_reloc, asarg, p)
		      || imm_expr->X_op != O_constant
		      || imm_expr->X_add_number < 0
		      || imm_expr->X_add_number >= 64
		      || !VALID_CSSTYPE_IMM ((valueT) imm_expr->X_add_number))
		    break;
		  ip->insn_opcode |= ENCODE_CSSTYPE_IMM (imm_expr->X_add_number);
		  goto rvc_imm_done;
		case '8':
		  if (my_getSmallExpression (imm_expr, imm_reloc, asarg, p)
		      || imm_expr->X_op != O_constant
		      || imm_expr->X_add_number < 0
		      || imm_expr->X_add_number >= 256
		      || !VALID_CIWTYPE_IMM ((valueT) imm_expr->X_add_number))
		    break;
		  ip->insn_opcode |= ENCODE_CIWTYPE_IMM (imm_expr->X_add_number);
		  goto rvc_imm_done;
		case 'j':
		  if (my_getSmallExpression (imm_expr, imm_reloc, asarg, p)
		      || imm_expr->X_op != O_constant
		      || imm_expr->X_add_number == 0
		      || !VALID_CITYPE_IMM ((valueT) imm_expr->X_add_number))
		    break;
		  ip->insn_opcode |= ENCODE_CITYPE_IMM (imm_expr->X_add_number);
		  goto rvc_imm_done;
		case 'k':
		  if (riscv_handle_implicit_zero_offset (imm_expr, asarg))
		    continue;
		  if (my_getSmallExpression (imm_expr, imm_reloc, asarg, p)
		      || imm_expr->X_op != O_constant
		      || !VALID_CLTYPE_LW_IMM ((valueT) imm_expr->X_add_number))
		    break;
		  ip->insn_opcode |= ENCODE_CLTYPE_LW_IMM (imm_expr->X_add_number);
		  goto rvc_imm_done;
		case 'l':
		  if (riscv_handle_implicit_zero_offset (imm_expr, asarg))
		    continue;
		  if (my_getSmallExpression (imm_expr, imm_reloc, asarg, p)
		      || imm_expr->X_op != O_constant
		      || !VALID_CLTYPE_LD_IMM ((valueT) imm_expr->X_add_number))
		    break;
		  ip->insn_opcode |= ENCODE_CLTYPE_LD_IMM (imm_expr->X_add_number);
		  goto rvc_imm_done;
		case 'm':
		  if (riscv_handle_implicit_zero_offset (imm_expr, asarg))
		    continue;
		  if (my_getSmallExpression (imm_expr, imm_reloc, asarg, p)
		      || imm_expr->X_op != O_constant
		      || !VALID_CITYPE_LWSP_IMM ((valueT) imm_expr->X_add_number))
		    break;
		  ip->insn_opcode |=
		    ENCODE_CITYPE_LWSP_IMM (imm_expr->X_add_number);
		  goto rvc_imm_done;
		case 'n':
		  if (riscv_handle_implicit_zero_offset (imm_expr, asarg))
		    continue;
		  if (my_getSmallExpression (imm_expr, imm_reloc, asarg, p)
		      || imm_expr->X_op != O_constant
		      || !VALID_CITYPE_LDSP_IMM ((valueT) imm_expr->X_add_number))
		    break;
		  ip->insn_opcode |=
		    ENCODE_CITYPE_LDSP_IMM (imm_expr->X_add_number);
		  goto rvc_imm_done;
		case 'o':
		  if (my_getSmallExpression (imm_expr, imm_reloc, asarg, p)
		      || imm_expr->X_op != O_constant
		      /* C.addiw, c.li, and c.andi allow zero immediate.
			 C.addi allows zero immediate as hint.  Otherwise this
			 is same as 'j'.  */
		      || !VALID_CITYPE_IMM ((valueT) imm_expr->X_add_number))
		    break;
		  ip->insn_opcode |= ENCODE_CITYPE_IMM (imm_expr->X_add_number);
		  goto rvc_imm_done;
		case 'K':
		  if (my_getSmallExpression (imm_expr, imm_reloc, asarg, p)
		      || imm_expr->X_op != O_constant
		      || imm_expr->X_add_number == 0
		      || !VALID_CIWTYPE_ADDI4SPN_IMM ((valueT) imm_expr->X_add_number))
		    break;
		  ip->insn_opcode |=
		    ENCODE_CIWTYPE_ADDI4SPN_IMM (imm_expr->X_add_number);
		  goto rvc_imm_done;
		case 'L':
		  if (my_getSmallExpression (imm_expr, imm_reloc, asarg, p)
		      || imm_expr->X_op != O_constant
		      || !VALID_CITYPE_ADDI16SP_IMM ((valueT) imm_expr->X_add_number))
		    break;
		  ip->insn_opcode |=
		    ENCODE_CITYPE_ADDI16SP_IMM (imm_expr->X_add_number);
		  goto rvc_imm_done;
		case 'M':
		  if (riscv_handle_implicit_zero_offset (imm_expr, asarg))
		    continue;
		  if (my_getSmallExpression (imm_expr, imm_reloc, asarg, p)
		      || imm_expr->X_op != O_constant
		      || !VALID_CSSTYPE_SWSP_IMM ((valueT) imm_expr->X_add_number))
		    break;
		  ip->insn_opcode |=
		    ENCODE_CSSTYPE_SWSP_IMM (imm_expr->X_add_number);
		  goto rvc_imm_done;
		case 'N':
		  if (riscv_handle_implicit_zero_offset (imm_expr, asarg))
		    continue;
		  if (my_getSmallExpression (imm_expr, imm_reloc, asarg, p)
		      || imm_expr->X_op != O_constant
		      || !VALID_CSSTYPE_SDSP_IMM ((valueT) imm_expr->X_add_number))
		    break;
		  ip->insn_opcode |=
		    ENCODE_CSSTYPE_SDSP_IMM (imm_expr->X_add_number);
		  goto rvc_imm_done;
		case 'u':
		  p = percent_op_utype;
		  if (my_getSmallExpression (imm_expr, imm_reloc, asarg, p))
		    break;
		rvc_lui:
		  if (imm_expr->X_op != O_constant
		      || imm_expr->X_add_number <= 0
		      || imm_expr->X_add_number >= RISCV_BIGIMM_REACH
		      || (imm_expr->X_add_number >= RISCV_RVC_IMM_REACH / 2
			  && (imm_expr->X_add_number <
			      RISCV_BIGIMM_REACH - RISCV_RVC_IMM_REACH / 2)))
		    break;
		  ip->insn_opcode |= ENCODE_CITYPE_IMM (imm_expr->X_add_number);
		  goto rvc_imm_done;
		case 'v':
		  if (my_getSmallExpression (imm_expr, imm_reloc, asarg, p)
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
		  if (!reg_lookup (&asarg, RCLASS_FPR, &regno)
		      || !(regno >= 8 && regno <= 15))
		    break;
		  INSERT_OPERAND (CRS1S, *ip, regno % 8);
		  continue;
		case 'D': /* Floating-point RS2 x8-x15.  */
		  if (!reg_lookup (&asarg, RCLASS_FPR, &regno)
		      || !(regno >= 8 && regno <= 15))
		    break;
		  INSERT_OPERAND (CRS2S, *ip, regno % 8);
		  continue;
		case 'T': /* Floating-point RS2.  */
		  if (!reg_lookup (&asarg, RCLASS_FPR, &regno))
		    break;
		  INSERT_OPERAND (CRS2, *ip, regno);
		  continue;
		case 'F':
		  switch (*++oparg)
		    {
		      case '6':
		        if (my_getSmallExpression (imm_expr, imm_reloc, asarg, p)
			    || imm_expr->X_op != O_constant
			    || imm_expr->X_add_number < 0
			    || imm_expr->X_add_number >= 64)
			  {
			    as_bad (_("bad value for compressed funct6 "
				      "field, value must be 0...64"));
			    break;
			  }
			INSERT_OPERAND (CFUNCT6, *ip, imm_expr->X_add_number);
			imm_expr->X_op = O_absent;
			asarg = expr_end;
			continue;

		      case '4':
		        if (my_getSmallExpression (imm_expr, imm_reloc, asarg, p)
			    || imm_expr->X_op != O_constant
			    || imm_expr->X_add_number < 0
			    || imm_expr->X_add_number >= 16)
			  {
			    as_bad (_("bad value for compressed funct4 "
				      "field, value must be 0...15"));
			    break;
			  }
			INSERT_OPERAND (CFUNCT4, *ip, imm_expr->X_add_number);
			imm_expr->X_op = O_absent;
			asarg = expr_end;
			continue;

		      case '3':
			if (my_getSmallExpression (imm_expr, imm_reloc, asarg, p)
			    || imm_expr->X_op != O_constant
			    || imm_expr->X_add_number < 0
			    || imm_expr->X_add_number >= 8)
			  {
			    as_bad (_("bad value for compressed funct3 "
				      "field, value must be 0...7"));
			    break;
			  }
			INSERT_OPERAND (CFUNCT3, *ip, imm_expr->X_add_number);
			imm_expr->X_op = O_absent;
			asarg = expr_end;
			continue;

		      case '2':
			if (my_getSmallExpression (imm_expr, imm_reloc, asarg, p)
			    || imm_expr->X_op != O_constant
			    || imm_expr->X_add_number < 0
			    || imm_expr->X_add_number >= 4)
			  {
			    as_bad (_("bad value for compressed funct2 "
				      "field, value must be 0...3"));
			    break;
			  }
			INSERT_OPERAND (CFUNCT2, *ip, imm_expr->X_add_number);
			imm_expr->X_op = O_absent;
			asarg = expr_end;
			continue;

		      default:
			goto unknown_riscv_ip_operand;
		    }
		  break;
		/* { Andes  */
		case 'e': /* exec.it imm  */
		  switch (*++oparg)
		    {
		    case 'i':
		      if (my_getSmallExpression (imm_expr, imm_reloc, asarg, p)
			  || imm_expr->X_op != O_constant
			  || !VALID_RVC_EX9IT_IMM (imm_expr->X_add_number << 2))
			break;
		      ip->insn_opcode |= ENCODE_RVC_EX9IT_IMM (imm_expr->X_add_number << 2);
		      goto rvc_imm_done;
		    case 't':
		      if (my_getSmallExpression (imm_expr, imm_reloc, asarg, p)
			  || imm_expr->X_op != O_constant
			  || !VALID_RVC_EXECIT_IMM (imm_expr->X_add_number << 2))
			break;
		      ip->insn_opcode |= ENCODE_RVC_EXECIT_IMM (imm_expr->X_add_number << 2);
		      goto rvc_imm_done;
		    case 'T':
		      if (my_getSmallExpression (imm_expr, imm_reloc, asarg, p)
			  || imm_expr->X_op != O_constant
			  || !VALID_RVC_NEXECIT_IMM (imm_expr->X_add_number << 2))
			break;
		      ip->insn_opcode |= ENCODE_RVC_NEXECIT_IMM (imm_expr->X_add_number << 2);
		      goto rvc_imm_done;
		    default:
		      goto unknown_riscv_ip_operand;
		    }
		  break;
		/* } Andes  */

		case 'Z': /* ZC extension.  */
		  switch (*++oparg)
		    {
		    case 'h': /* immediate field for c.lh/c.lhu/c.sh.  */
		      /* handle cases, such as c.sh rs2', (rs1') */
		      if (riscv_handle_implicit_zero_offset (imm_expr, asarg))
			continue;
		      if (my_getSmallExpression (imm_expr, imm_reloc, asarg, p)
			|| imm_expr->X_op != O_constant
			|| !VALID_ZCB_HALFWORD_UIMM ((valueT) imm_expr->X_add_number))
			  break;
		      ip->insn_opcode |= ENCODE_ZCB_HALFWORD_UIMM (imm_expr->X_add_number);
		      goto rvc_imm_done;

		    case 'b': /* immediate field for c.lbu/c.sb.  */
		      /* handle cases, such as c.lbu rd', (rs1') */
		      if (riscv_handle_implicit_zero_offset (imm_expr, asarg))
			continue;
		      if (my_getSmallExpression (imm_expr, imm_reloc, asarg, p)
			|| imm_expr->X_op != O_constant
			|| !VALID_ZCB_BYTE_UIMM ((valueT) imm_expr->X_add_number))
			break;
		      ip->insn_opcode |= ENCODE_ZCB_BYTE_UIMM (imm_expr->X_add_number);
		      goto rvc_imm_done;

		    case 'H': /* immediate field for cm.lh/cm.lhu/cm.sh.  */
		      /* handle cases, such as cm.sh rs2', (rs1') */
		      if (riscv_handle_implicit_zero_offset (imm_expr, asarg))
			continue;
		      if (my_getSmallExpression (imm_expr, imm_reloc, asarg, p)
			|| imm_expr->X_op != O_constant
			|| !VALID_ZCMB_HALFWORD_UIMM ((valueT) imm_expr->X_add_number))
			  break;
		      ip->insn_opcode |= ENCODE_ZCMB_HALFWORD_UIMM (imm_expr->X_add_number);
		      goto rvc_imm_done;

		    case 'B': /* immediate field for cm.lbu/cm.sb.  */
		      /* handle cases, such as cm.lbu rd', (rs1') */
		      if (riscv_handle_implicit_zero_offset (imm_expr, asarg))
			continue;
		      if (my_getSmallExpression (imm_expr, imm_reloc, asarg, p)
			|| imm_expr->X_op != O_constant
			|| !VALID_ZCMB_BYTE_UIMM ((valueT) imm_expr->X_add_number))
			break;
		      ip->insn_opcode |= ENCODE_ZCMB_BYTE_UIMM (imm_expr->X_add_number);
		      goto rvc_imm_done;

		    case 'r':
		      /* we use regno to store reglist value here.  */
		      if (!reglist_lookup (&asarg, &regno))
			break;
		      INSERT_OPERAND (RLIST, *ip, regno);
		      continue;

		    case 'p':
		      if (my_getSmallExpression (imm_expr, imm_reloc, asarg, p)
			  || imm_expr->X_op != O_constant)
			break;
		      /* convert stack adjust of cm.push to a positive offset. */
		      if (ip->insn_mo->match == MATCH_CM_PUSH)
			imm_expr->X_add_number *= -1;
		      /* subtract base stack adjust. */
		      imm_expr->X_add_number -=
			  riscv_get_base_spimm (ip->insn_opcode, &riscv_rps_as);
		      if (!VALID_ZCMP_SPIMM (imm_expr->X_add_number))
			break;
		      ip->insn_opcode |=
			  ENCODE_ZCMP_SPIMM (imm_expr->X_add_number);
		      goto rvc_imm_done;

		    case '1':
		      if (!reg_lookup (&asarg, RCLASS_GPR, &regno)
			  || !RISCV_SREG_0_7 (regno))
			break;
		      INSERT_OPERAND (SREG1, *ip, regno % 8);
		      continue;

		    case '2':
		      if (!reg_lookup (&asarg, RCLASS_GPR, &regno)
			  || !RISCV_SREG_0_7 (regno))
			break;
		      INSERT_OPERAND (SREG2, *ip, regno % 8);
		      continue;

		    case 'I': /* index operand of cm.jt. The range is from 0 to 32. */
		      my_getExpression (imm_expr, asarg);
		      if (imm_expr->X_op != O_constant
			  || imm_expr->X_add_number < 0
			  || imm_expr->X_add_number > 31)
			{
			  as_bad ("bad index value for cm.jt, range: [0, 31]");
			  break;
			}
		      ip->insn_opcode |= ENCODE_ZCMP_TABLE_JUMP_INDEX (imm_expr->X_add_number);
		      goto rvc_imm_done;

		    case 'i': /* index operand of cm.jalt. The range is from 64 to 255. */
		      my_getExpression (imm_expr, asarg);
		      if (imm_expr->X_op != O_constant
			  || imm_expr->X_add_number < 32
			  || imm_expr->X_add_number > 255)
			{
			  as_bad ("bad index value for cm.jalt, range: [32, 255]");
			  break;
			}
		      ip->insn_opcode |= ENCODE_ZCMP_TABLE_JUMP_INDEX (imm_expr->X_add_number);
		      goto rvc_imm_done;

		    default:
		      goto unknown_riscv_ip_operand;
		    }
		  break;

		default:
		  goto unknown_riscv_ip_operand;
		}
	      break; /* end RVC */

	    case 'V': /* RVV */
	      switch (*++oparg)
		{
		case 'd': /* VD */
		  if (!reg_lookup (&asarg, RCLASS_VECR, &regno))
		    break;
		  INSERT_OPERAND (VD, *ip, regno);
		  continue;

		case 'e': /* AMO VD */
		  if (reg_lookup (&asarg, RCLASS_GPR, &regno) && regno == 0)
		    INSERT_OPERAND (VWD, *ip, 0);
		  else if (reg_lookup (&asarg, RCLASS_VECR, &regno))
		    {
		      INSERT_OPERAND (VWD, *ip, 1);
		      INSERT_OPERAND (VD, *ip, regno);
		    }
		  else
		    break;
		  continue;

		case 'f': /* AMO VS3 */
		  if (!reg_lookup (&asarg, RCLASS_VECR, &regno))
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
		  if (!reg_lookup (&asarg, RCLASS_VECR, &regno))
		    break;
		  INSERT_OPERAND (VS1, *ip, regno);
		  continue;

		case 't': /* VS2 */
		  if (!reg_lookup (&asarg, RCLASS_VECR, &regno))
		    break;
		  INSERT_OPERAND (VS2, *ip, regno);
		  continue;

		case 'u': /* VS1 == VS2 */
		  if (!reg_lookup (&asarg, RCLASS_VECR, &regno))
		    break;
		  INSERT_OPERAND (VS1, *ip, regno);
		  INSERT_OPERAND (VS2, *ip, regno);
		  continue;

		case 'v': /* VD == VS1 == VS2 */
		  if (!reg_lookup (&asarg, RCLASS_VECR, &regno))
		    break;
		  INSERT_OPERAND (VD, *ip, regno);
		  INSERT_OPERAND (VS1, *ip, regno);
		  INSERT_OPERAND (VS2, *ip, regno);
		  continue;

		/* The `V0` is carry-in register for v[m]adc and v[m]sbc,
		   and is used to choose vs1/rs1/frs1/imm or vs2 for
		   v[f]merge.  It use the same encoding as the vector mask
		   register.  */
		case '0':
		  if (reg_lookup (&asarg, RCLASS_VECR, &regno) && regno == 0)
		    continue;
		  break;

		case 'b': /* vtypei for vsetivli */
		  my_getVsetvliExpression (imm_expr, asarg);
		  check_absolute_expr (ip, imm_expr, FALSE);
		  if (!VALID_RVV_VB_IMM (imm_expr->X_add_number))
		    as_bad (_("bad value for vsetivli immediate field, "
			      "value must be 0..1023"));
		  ip->insn_opcode
		    |= ENCODE_RVV_VB_IMM (imm_expr->X_add_number);
		  imm_expr->X_op = O_absent;
		  asarg = expr_end;
		  continue;

		case 'c': /* vtypei for vsetvli */
		  my_getVsetvliExpression (imm_expr, asarg);
		  check_absolute_expr (ip, imm_expr, FALSE);
		  if (!VALID_RVV_VC_IMM (imm_expr->X_add_number))
		    as_bad (_("bad value for vsetvli immediate field, "
			      "value must be 0..2047"));
		  ip->insn_opcode
		    |= ENCODE_RVV_VC_IMM (imm_expr->X_add_number);
		  imm_expr->X_op = O_absent;
		  asarg = expr_end;
		  continue;

		case 'i': /* vector arith signed immediate */
		  my_getExpression (imm_expr, asarg);
		  check_absolute_expr (ip, imm_expr, FALSE);
		  if (imm_expr->X_add_number > 15
		      || imm_expr->X_add_number < -16)
		    as_bad (_("bad value for vector immediate field, "
			      "value must be -16...15"));
		  INSERT_OPERAND (VIMM, *ip, imm_expr->X_add_number);
		  imm_expr->X_op = O_absent;
		  asarg = expr_end;
		  continue;

		case 'j': /* vector arith unsigned immediate */
		  my_getExpression (imm_expr, asarg);
		  check_absolute_expr (ip, imm_expr, FALSE);
		  if (imm_expr->X_add_number < 0
		      || imm_expr->X_add_number >= 32)
		    as_bad (_("bad value for vector immediate field, "
			      "value must be 0...31"));
		  INSERT_OPERAND (VIMM, *ip, imm_expr->X_add_number);
		  imm_expr->X_op = O_absent;
		  asarg = expr_end;
		  continue;

		case 'k': /* vector arith signed immediate, minus 1 */
		  my_getExpression (imm_expr, asarg);
		  check_absolute_expr (ip, imm_expr, FALSE);
		  if (imm_expr->X_add_number > 16
		      || imm_expr->X_add_number < -15)
		    as_bad (_("bad value for vector immediate field, "
			      "value must be -15...16"));
		  INSERT_OPERAND (VIMM, *ip, imm_expr->X_add_number - 1);
		  imm_expr->X_op = O_absent;
		  asarg = expr_end;
		  continue;

		case 'm': /* optional vector mask */
		  if (*asarg == '\0')
		    {
		      INSERT_OPERAND (VMASK, *ip, 1);
		      continue;
		    }
		  else if (*asarg == ',' && asarg++
			   && reg_lookup (&asarg, RCLASS_VECM, &regno)
			   && regno == 0)
		    {
		      INSERT_OPERAND (VMASK, *ip, 0);
		      continue;
		    }
		  break;

		case 'M': /* required vector mask */
		  if (reg_lookup (&asarg, RCLASS_VECM, &regno) && regno == 0)
		    {
		      INSERT_OPERAND (VMASK, *ip, 0);
		      continue;
		    }
		  break;

		case 'T': /* vector macro temporary register */
		  if (!reg_lookup (&asarg, RCLASS_VECR, &regno) || regno == 0)
		    break;
		  /* Store it in the FUNCT6 field as we don't have anyplace
		     else to store it.  */
		  INSERT_OPERAND (VFUNCT6, *ip, regno);
		  continue;

		default:
		  goto unknown_riscv_ip_operand;
		}
	      break; /* end RVV */

	    case ',':
	      ++argnum;
	      if (*asarg++ == *oparg)
		continue;
	      asarg--;
	      break;

	    case '(':
	    case ')':
	    case '{':
	    case '}':
	    case '[':
	    case ']':
	      if (*asarg++ == *oparg)
		continue;
	      break;

	    case '<': /* Shift amount, 0 - 31.  */
	      my_getExpression (imm_expr, asarg);
	      check_absolute_expr (ip, imm_expr, false);
	      if ((unsigned long) imm_expr->X_add_number > 31)
		as_bad (_("improper shift amount (%lu)"),
			(unsigned long) imm_expr->X_add_number);
	      INSERT_OPERAND (SHAMTW, *ip, imm_expr->X_add_number);
	      imm_expr->X_op = O_absent;
	      asarg = expr_end;
	      continue;

	    case '>': /* Shift amount, 0 - (XLEN-1).  */
	      my_getExpression (imm_expr, asarg);
	      check_absolute_expr (ip, imm_expr, false);
	      if ((unsigned long) imm_expr->X_add_number >= xlen)
		as_bad (_("improper shift amount (%lu)"),
			(unsigned long) imm_expr->X_add_number);
	      INSERT_OPERAND (SHAMT, *ip, imm_expr->X_add_number);
	      imm_expr->X_op = O_absent;
	      asarg = expr_end;
	      continue;

	    case 'Z': /* CSRRxI immediate.  */
	      my_getExpression (imm_expr, asarg);
	      check_absolute_expr (ip, imm_expr, false);
	      if ((unsigned long) imm_expr->X_add_number > 31)
		as_bad (_("improper CSRxI immediate (%lu)"),
			(unsigned long) imm_expr->X_add_number);
	      INSERT_OPERAND (RS1, *ip, imm_expr->X_add_number);
	      imm_expr->X_op = O_absent;
	      asarg = expr_end;
	      continue;

	    case 'E': /* Control register.  */
	      insn_with_csr = true;
	      explicit_priv_attr = true;
	      if (reg_lookup (&asarg, RCLASS_CSR, &regno))
		INSERT_OPERAND (CSR, *ip, regno);
	      else
		{
		  my_getExpression (imm_expr, asarg);
		  check_absolute_expr (ip, imm_expr, true);
		  if ((unsigned long) imm_expr->X_add_number > 0xfff)
		    as_bad (_("improper CSR address (%lu)"),
			    (unsigned long) imm_expr->X_add_number);
		  INSERT_OPERAND (CSR, *ip, imm_expr->X_add_number);
		  imm_expr->X_op = O_absent;
		  asarg = expr_end;
		}
	      continue;

	    case 'm': /* Rounding mode.  */
	      if (arg_lookup (&asarg, riscv_rm,
			      ARRAY_SIZE (riscv_rm), &regno))
		{
		  INSERT_OPERAND (RM, *ip, regno);
		  continue;
		}
	      break;

	    case 'P':
	    case 'Q': /* Fence predecessor/successor.  */
	      if (arg_lookup (&asarg, riscv_pred_succ,
			      ARRAY_SIZE (riscv_pred_succ), &regno))
		{
		  if (*oparg == 'P')
		    INSERT_OPERAND (PRED, *ip, regno);
		  else
		    INSERT_OPERAND (SUCC, *ip, regno);
		  continue;
		}
	      break;

	    case 'd': /* Destination register.  */
	    case 's': /* Source register.  */
	    case 't': /* Target register.  */
	    case 'r': /* RS3 */
	      if (reg_lookup (&asarg, RCLASS_GPR, &regno))
		{
		  char c = *oparg;
		  if (*asarg == ' ')
		    ++asarg;

		  /* Now that we have assembled one operand, we use the args
		     string to figure out where it goes in the instruction.  */
		  switch (c)
		    {
		    case 's':
		      INSERT_OPERAND (RS1, *ip, regno);
		      break;
		    case 'd':
		      INSERT_OPERAND (RD, *ip, regno);
		      break;
		    case 't':
		      INSERT_OPERAND (RS2, *ip, regno);
		      break;
		    case 'r':
		      INSERT_OPERAND (RS3, *ip, regno);
		      break;
		    }
		  continue;
		}
	      break;

	    case 'D': /* Floating point RD.  */
	    case 'S': /* Floating point RS1.  */
	    case 'T': /* Floating point RS2.  */
	    case 'U': /* Floating point RS1 and RS2.  */
	    case 'R': /* Floating point RS3.  */
	      if (reg_lookup (&asarg,
			      (riscv_subset_supports (&riscv_rps_as, "zfinx")
			      ? RCLASS_GPR : RCLASS_FPR), &regno))
		{
		  char c = *oparg;
		  if (*asarg == ' ')
		    ++asarg;
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
		      /* Fall through.  */
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
	      my_getExpression (imm_expr, asarg);
	      if (imm_expr->X_op != O_big
		  && imm_expr->X_op != O_constant)
		break;
	      normalize_constant_expr (imm_expr);
	      asarg = expr_end;
	      continue;

	    case 'A':
	      my_getExpression (imm_expr, asarg);
	      normalize_constant_expr (imm_expr);
	      /* The 'A' format specifier must be a symbol.  */
	      if (imm_expr->X_op != O_symbol)
	        break;
	      *imm_reloc = BFD_RELOC_32;
	      asarg = expr_end;
	      continue;

	    case 'B':
	      my_getExpression (imm_expr, asarg);
	      normalize_constant_expr (imm_expr);
	      /* The 'B' format specifier must be a symbol or a constant.  */
	      if (imm_expr->X_op != O_symbol && imm_expr->X_op != O_constant)
	        break;
	      if (imm_expr->X_op == O_symbol)
	        *imm_reloc = BFD_RELOC_32;
	      asarg = expr_end;
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
	    case '1':
	      /* This is used for TLS, where the fourth operand is
		 %tprel_add, to get a relocation applied to an add
		 instruction, for relaxation to use.  */
	      p = percent_op_rtype;
	      goto alu_op;
	    case '0': /* AMO displacement, which must be zero.  */
	      p = percent_op_null;
	    load_store:
	      if (riscv_handle_implicit_zero_offset (imm_expr, asarg))
		continue;
	    alu_op:
	      /* If this value won't fit into a 16 bit offset, then go
		 find a macro that will generate the 32 bit offset
		 code pattern.  */
	      if (!my_getSmallExpression (imm_expr, imm_reloc, asarg, p))
		{
		  normalize_constant_expr (imm_expr);
		  if (imm_expr->X_op != O_constant
		      || (*oparg == '0' && imm_expr->X_add_number != 0)
		      || (*oparg == '1')
		      || imm_expr->X_add_number >= (signed)RISCV_IMM_REACH/2
		      || imm_expr->X_add_number < -(signed)RISCV_IMM_REACH/2)
		    break;
		}
	      asarg = expr_end;
	      continue;

	    case 'p': /* PC-relative offset.  */
	    branch:
	      *imm_reloc = BFD_RELOC_12_PCREL;
	      my_getExpression (imm_expr, asarg);
	      asarg = expr_end;
	      continue;

	    case 'u': /* Upper 20 bits.  */
	      p = percent_op_utype;
	      if (!my_getSmallExpression (imm_expr, imm_reloc, asarg, p))
		{
		  if (imm_expr->X_op != O_constant)
		    break;

		  if (imm_expr->X_add_number < 0
		      || imm_expr->X_add_number >= (signed)RISCV_BIGIMM_REACH)
		    as_bad (_("lui expression not in range 0..1048575"));

		  *imm_reloc = BFD_RELOC_RISCV_HI20;
		  imm_expr->X_add_number <<= RISCV_IMM_BITS;
		}
	      asarg = expr_end;
	      continue;

	    case 'a': /* 20-bit PC-relative offset.  */
	    jump:
	      my_getExpression (imm_expr, asarg);
	      asarg = expr_end;
	      *imm_reloc = BFD_RELOC_RISCV_JMP;
	      continue;

	    case 'c':
	      my_getExpression (imm_expr, asarg);
	      asarg = expr_end;
	      if (strcmp (asarg, "@plt") == 0)
		{
		  *imm_reloc = BFD_RELOC_RISCV_CALL_PLT;
		  asarg += 4;
		}
	      else
		*imm_reloc = BFD_RELOC_RISCV_CALL;
	      continue;

	    case 'O':
	      switch (*++oparg)
		{
		case '4':
		  if (my_getOpcodeExpression (imm_expr, imm_reloc, asarg, p)
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
		  asarg = expr_end;
		  continue;

		case '2':
		  if (my_getOpcodeExpression (imm_expr, imm_reloc, asarg, p)
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
		  asarg = expr_end;
		  continue;

		default:
		  goto unknown_riscv_ip_operand;
		}
	      break;

	    case 'F':
	      switch (*++oparg)
		{
		case '7':
		  if (my_getSmallExpression (imm_expr, imm_reloc, asarg, p)
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
		  asarg = expr_end;
		  continue;

		case '3':
		  if (my_getSmallExpression (imm_expr, imm_reloc, asarg, p)
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
		  asarg = expr_end;
		  continue;

		case '2':
		  if (my_getSmallExpression (imm_expr, imm_reloc, asarg, p)
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
		  asarg = expr_end;
		  continue;

		default:
		  goto unknown_riscv_ip_operand;
		}
	      break;

	    case 'y': /* bs immediate */
	      my_getExpression (imm_expr, asarg);
	      check_absolute_expr (ip, imm_expr, FALSE);
	      if ((unsigned long)imm_expr->X_add_number > 3)
		as_bad(_("Improper bs immediate (%lu)"),
		       (unsigned long)imm_expr->X_add_number);
	      INSERT_OPERAND(BS, *ip, imm_expr->X_add_number);
	      imm_expr->X_op = O_absent;
	      asarg = expr_end;
	      continue;

	    case 'Y': /* rnum immediate */
	      my_getExpression (imm_expr, asarg);
	      check_absolute_expr (ip, imm_expr, FALSE);
	      if ((unsigned long)imm_expr->X_add_number > 10)
		as_bad(_("Improper rnum immediate (%lu)"),
		       (unsigned long)imm_expr->X_add_number);
	      INSERT_OPERAND(RNUM, *ip, imm_expr->X_add_number);
	      imm_expr->X_op = O_absent;
	      asarg = expr_end;
	      continue;

	    case 'z':
	      if (my_getSmallExpression (imm_expr, imm_reloc, asarg, p)
		  || imm_expr->X_op != O_constant
		  || imm_expr->X_add_number != 0)
		break;
	      asarg = expr_end;
	      imm_expr->X_op = O_absent;
	      continue;

	    /* { zicbo */
	    case 'f': /* Prefetch offset, pseudo S-type but lower 5-bits zero.  */
	      if (riscv_handle_implicit_zero_offset (imm_expr, asarg))
		continue;
	      my_getExpression (imm_expr, asarg);
	      check_absolute_expr (ip, imm_expr, FALSE);
	      if (((unsigned) (imm_expr->X_add_number) & 0x1f)
		  || imm_expr->X_add_number >= (signed)RISCV_IMM_REACH/2
		  || imm_expr->X_add_number < -(signed)RISCV_IMM_REACH/2)
		as_bad (_("improper prefetch offset (%ld)"),
		        (long) imm_expr->X_add_number);
	      ip->insn_opcode |= ENCODE_STYPE_IMM (imm_expr->X_add_number);
	      ip->insn_opcode &= ~ ENCODE_STYPE_IMM (0x1fU);
	      imm_expr->X_op = O_absent;
	      asarg = expr_end;
	      continue;
	    /* } zicbo */

	    /* { Andes  */
	    case 'g': /* 10bits PC-relative offset.  */
	      *imm_reloc = BFD_RELOC_RISCV_10_PCREL;
	      my_getExpression (imm_expr, asarg);
	      asarg = expr_end;
	      continue;
	    case 'h': /* Upper unsigned 6-bit immediate.  */
	      my_getExpression (imm_expr, asarg);
	      if (imm_expr->X_op != O_constant
		  || imm_expr->X_add_number >= xlen
		  || imm_expr->X_add_number < 0)
		break;
	      asarg = expr_end;
	      ip->insn_opcode |= ENCODE_SBTYPE_IMM6H (imm_expr->X_add_number);
	      imm_expr->X_op = O_absent;
	      continue;
	    case 'i': /* Signed 7-bit immediate in [31:25].  */
	      my_getExpression (imm_expr, asarg);
	      if (imm_expr->X_op != O_constant
		  || imm_expr->X_add_number >= (signed) RISCV_IMM7_REACH
		  || imm_expr->X_add_number < 0)
		break;
	      ip->insn_opcode |= ENCODE_STYPE_IMM7 (imm_expr->X_add_number);
	      asarg = expr_end;
	      imm_expr->X_op = O_absent;
	      continue;
	    case 'k': /* Cimm unsigned 6-bit immediate.  */
	      my_getExpression (imm_expr, asarg);
	      if (imm_expr->X_op != O_constant
		  || imm_expr->X_add_number >= xlen
		  || imm_expr->X_add_number < 0)
		break;
	      asarg = expr_end;
	      ip->insn_opcode |= ENCODE_TYPE_CIMM6 (imm_expr->X_add_number);
	      imm_expr->X_op = O_absent;
	      continue;
	    case 'l': /* Lower unsigned 6-bit immediate.  */
	      my_getExpression (imm_expr, asarg);
	      if (imm_expr->X_op != O_constant
		  || imm_expr->X_add_number >= xlen
		  || imm_expr->X_add_number < 0)
		break;
	      ip->insn_opcode |= ENCODE_SBTYPE_IMM6L (imm_expr->X_add_number);
	      asarg = expr_end;
	      imm_expr->X_op = O_absent;
	      continue;
	    case 'H':
	    case 'G':
	      {
		bfd_boolean store = FALSE;
		if (*oparg == 'H')
		  store = TRUE;

		my_getExpression (imm_expr, asarg);
		switch (*++oparg)
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
			asarg = expr_end;
			continue;
		      }
		    else if (imm_expr->X_op == O_symbol)
		      {
			if (store)
			  *imm_reloc = BFD_RELOC_RISCV_SGP18S0;
			else
			  *imm_reloc = BFD_RELOC_RISCV_LGP18S0;
			asarg = expr_end;
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
			asarg = expr_end;
			continue;
		      }
		    else if (imm_expr->X_op == O_symbol)
		      {
			if (store)
			  *imm_reloc = BFD_RELOC_RISCV_SGP17S1;
			else
			  *imm_reloc = BFD_RELOC_RISCV_LGP17S1;
			asarg = expr_end;
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
			asarg = expr_end;
			continue;
		      }
		    else if (imm_expr->X_op == O_symbol)
		      {
			if (store)
			  *imm_reloc = BFD_RELOC_RISCV_SGP17S2;
			else
			  *imm_reloc = BFD_RELOC_RISCV_LGP17S2;
			asarg = expr_end;
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
			asarg = expr_end;
			continue;
		      }
		    else if (imm_expr->X_op == O_symbol)
		      {
			if (store)
			  *imm_reloc = BFD_RELOC_RISCV_SGP17S3;
			else
			  *imm_reloc = BFD_RELOC_RISCV_LGP17S3;
			asarg = expr_end;
			continue;
		      }
		    break;

		  default:
		    goto unknown_riscv_ip_operand;
		  }
		break;
	      }
	    case 'N': /* Andes extensions: RVP  */
	      ++oparg;
	      if ((*oparg == 'c') /* rc */
		  && reg_lookup (&asarg, RCLASS_GPR, &regno))
		{
		  INSERT_OPERAND (RC, *ip, regno);
		  continue;
		}
	      else if ((*oparg == 'd') /* rdp */
		       && reg_lookup (&asarg, RCLASS_GPR, &regno))
		{
		  if (xlen == 32 && (regno % 2) != 0)
		    {
		      as_bad (_("The number of Rd must be even "
				"(limitation of register pair)."));
		      break;
		    }
		  INSERT_OPERAND (RD, *ip, regno);
		  continue;
		}
	      else if ((*oparg == 's') /* rsp */
		       && reg_lookup (&asarg, RCLASS_GPR, &regno))
		{
		  if (xlen == 32 && (regno % 2) != 0)
		    {
		      as_bad (_("The number of Rs1 must be even "
				"(limitation of register pair)."));
		      break;
		    }
		  INSERT_OPERAND (RS1, *ip, regno);
		  continue;
		}
	      else if ((*oparg == 't') /* rtp */
		       && reg_lookup (&asarg, RCLASS_GPR, &regno))
		{
		  if (xlen == 32 && (regno % 2) != 0)
		    {
		      as_bad (_("The number of Rs2 must be even "
				"(limitation of register pair)."));
		      break;
		    }
		  INSERT_OPERAND (RS2, *ip, regno);
		  continue;
		}

	      my_getExpression (imm_expr, asarg);
	      if (imm_expr->X_op != O_constant
		  || imm_expr->X_add_number >= xlen
		  || imm_expr->X_add_number < 0)
		break;

	      if ((*oparg == '3') /* i3u */
		  && VALID_PTYPE_IMM3U (imm_expr->X_add_number))
		ip->insn_opcode |= ENCODE_PTYPE_IMM3U (imm_expr->X_add_number);
	      else if ((*oparg == '4') /* i4u */
		       && VALID_PTYPE_IMM4U (imm_expr->X_add_number))
		ip->insn_opcode |= ENCODE_PTYPE_IMM4U (imm_expr->X_add_number);
	      else if ((*oparg == '5') /* i5u */
		       && VALID_PTYPE_IMM5U (imm_expr->X_add_number))
		ip->insn_opcode |= ENCODE_PTYPE_IMM5U (imm_expr->X_add_number);
	      else if ((*oparg == '6') /* i6u */
		       && VALID_PTYPE_IMM6U (imm_expr->X_add_number))
		ip->insn_opcode |= ENCODE_PTYPE_IMM6U (imm_expr->X_add_number);
	      else if ((*oparg == 'f') /* i15 */
		       && VALID_PTYPE_IMM15S (imm_expr->X_add_number))
		ip->insn_opcode |= ENCODE_PTYPE_IMM15S (imm_expr->X_add_number);
	      else
		goto unknown_riscv_ip_operand;

	      asarg = expr_end;
	      imm_expr->X_op = O_absent;
	      continue;
	    /* } Andes  */

	    /* { Andes ACE */
	    /* Handle operand fields of ACE.  */
	    case 'X':
	      if (ace_lib_load_success)
		{
		  ace_ip ((char **) &oparg, &asarg, ip);
		  continue;
		}
	      else
		break;
	    /* } Andes ACE */

	    case 'n':
	      switch (*++oparg)
	        {
		case 'f': /* operand for matching immediate 255.  */
		  if (my_getSmallExpression (imm_expr, imm_reloc, asarg, p)
		      || imm_expr->X_op != O_constant
		      || imm_expr->X_add_number != 255)
		    break;
		  /* this operand is used for matching immediate 255, and
		  we do not write anything to encoding by this operand. */
		  asarg = expr_end;
		  imm_expr->X_op = O_absent;
		  continue;
		default:
		  goto unknown_riscv_ip_operand;
		}
	      break;

	    default:
	    unknown_riscv_ip_operand:
	      as_fatal (_("internal: unknown argument type `%s'"),
			opargStart);
	    }
	  break;
	}
      asarg = asargStart;
      insn_with_csr = false;
    }

 out:
  /* Restore the character we might have clobbered above.  */
  if (save_c)
    *(asargStart  - 1) = save_c;

  if (error == NULL && riscv_opts.workaround)
    {
      if (riscv_opts.b19758_effect)
	{
	  if (is_b19758_associated_insn (insn))
	    {
	      char *s = (char*) "iorw";
	      arg_lookup (&s, riscv_pred_succ, ARRAY_SIZE (riscv_pred_succ), &regno);
              macro_build (NULL, "fence", "P,Q", regno, regno);
	    }
	}

      if (riscv_opts.b20282)
	{
	  if (pre_insn_is_a_cond_br && is_indirect_jump (insn))
	    {
	      macro_build (NULL, "nop", "");
	      pre_insn_is_a_cond_br = false;
	    }
	  else
	    pre_insn_is_a_cond_br = is_conditional_branch (insn);
	}

      if ((riscv_opts.b22827 || riscv_opts.b22827_1)
	  && !riscv_subset_supports (&riscv_rps_as, "v"))
	{
	  const struct riscv_opcode *prev_insn = nsta.prev_insn.insn_mo;
	  insn_t prev_insn_co = nsta.prev_insn.insn_opcode;
	  insn_t curr_insn_co = ip->insn_opcode;

	  /* insert “fclass.x x0, RD(FDIV/FSQRT)” after FDIV/FSQRT unless 
	   * the next immediate instruction is 
	   * “fsub/fadd/fmul/fmadd/fsqrt/fdiv/jal/ret and their 16bit variants”
	   * NOTE: by jal I mean jal and jral. Ret includes jr. 
	   * If you can accept more complex conditions, RD(FDIV/FSQRT) has to be
	   * in fa0-7 to exclude jal/ret.
	   */
	  if (riscv_opts.b22827
	      && is_insn_fdiv_or_fsqrt (prev_insn)
	      && is_insn_in_b22827_list (insn, prev_insn_co, curr_insn_co))
	    {
	      nsta.frag_b22827->fr_var = 1;
	    }

	  /* to provide a separate flag to turn it off, with the following rule:
	   * If FSHW is followed by any floating-point instructions (including 
	   * FSHW and FLHW), insert a NOP after it.
	   */
	  else if (riscv_opts.b22827_1
	      && is_insn_fshw (prev_insn)
	      && is_insn_of_fp_types (insn))
	    {
	      nsta.frag_b22827->fr_var = 1;
	    }

	  /* update previous insns  */
	  nsta.prev_insn = *ip;
	}
    }

  return error;
}

/* Similar to riscv_ip, but assembles an instruction according to the
   hardcode values of .insn directive.  */

static const char *
riscv_ip_hardcode (char *str,
		   struct riscv_cl_insn *ip,
		   expressionS *imm_expr,
		   const char *error)
{
  struct riscv_opcode *insn;
  insn_t values[2] = {0, 0};
  unsigned int num = 0;

  input_line_pointer = str;
  do
    {
      expression (imm_expr);
      if (imm_expr->X_op != O_constant)
	{
	  /* The first value isn't constant, so it should be
	     .insn <type> <operands>.  We have been parsed it
	     in the riscv_ip.  */
	  if (num == 0)
	    return error;
	  return _("values must be constant");
	}
      values[num++] = (insn_t) imm_expr->X_add_number;
    }
  while (*input_line_pointer++ == ',' && num < 2);

  input_line_pointer--;
  if (*input_line_pointer != '\0')
    return _("unrecognized values");

  insn = XNEW (struct riscv_opcode);
  insn->match = values[num - 1];
  create_insn (ip, insn);
  unsigned int bytes = riscv_insn_length (insn->match);
  if (values[num - 1] >> (8 * bytes) != 0
      || (num == 2 && values[0] != bytes))
    return _("value conflicts with instruction length");

  return NULL;
}

static
void riscv_append_insn (struct riscv_cl_insn *insn, expressionS *imm_expr,
  bfd_reloc_code_real_type imm_reloc)
{
  if (insn->insn_mo->pinfo == INSN_MACRO)
    {
      if (has_cached_insn ())
        release_cached_insn ();
      macro (insn, imm_expr, &imm_reloc);
      return;
    }

  if (use_insn_combiner ())
    {
      struct riscv_combiner_matcher *matchers = insn_combiner->matcher;
      unsigned idx;

      /* if one insn is cached, we now check the second insn */
      if (insn_combiner->idx)
	{
	  idx = insn_combiner->idx - 1;

	  /* if successfully match a insn pair, we output the merged result */
	  if (matchers[idx].check_2 (insn, imm_expr, imm_reloc))
	    {
	      matchers[idx].update (insn, imm_expr, imm_reloc);
	      release_cached_insn ();
	      return;
	    }

	  release_cached_insn ();
	}

      gas_assert (insn_combiner->idx == 0);

      for (idx = 0; matchers[idx].check_1 != NULL; idx++)
	{
	  if (!matchers[idx].avail())
	    continue;
	  if (matchers[idx].check_1 (insn, imm_expr, imm_reloc))
	    {
	      cache_an_insn (insn, imm_expr, imm_reloc);
	      insn_combiner->idx = idx + 1;
	      return;
	    }
	}
    }

  append_insn (insn, imm_expr, imm_reloc);
}

void
md_assemble (char *str)
{
  struct riscv_cl_insn insn;
  expressionS imm_expr;
  bfd_reloc_code_real_type imm_reloc = BFD_RELOC_UNUSED;
  insn.cmodel.method = METHOD_DEFAULT;

  /* { Andes */
  /* Set the first rvc info for the the current fragmant.  */
  if (!frag_now->tc_frag_data.rvc)
    frag_now->tc_frag_data.rvc = riscv_opts.rvc ? 1 : -1;
  /* } Andes */

  /* The architecture and privileged elf attributes should be set
     before assembling.  */
  if (!start_assemble)
    {
      start_assemble = true;
      /* Initialize instruction pair combiner for cm.mva01s
	and cm.mvsa01*/
      if (use_insn_combiner ())
	init_insn_combiner ();

      riscv_set_abi_by_arch ();
      if (!riscv_set_default_priv_spec (NULL))
       return;

      /* { Andes */
      /* sync arch from source file; update riscv_opts.  */
      if (riscv_opts.efhw == 0)
	riscv_opts.efhw = riscv_subset_supports (&riscv_rps_as, "xefhw");
      /* determine exec.it opcode.  */
      if (riscv_subset_supports (&riscv_rps_as, "xnexecit"))
	riscv_opts.nexecit_op = 1;
      else if (riscv_opts.nexecit_op != 0)
	riscv_parse_add_subset (&riscv_rps_as, "xnexecit", RISCV_UNKNOWN_VERSION,
				RISCV_UNKNOWN_VERSION, false);
      /* } Andes */
    }

  riscv_mapping_state (MAP_INSN, 0);

  const char *error = riscv_ip (str, &insn, &imm_expr, &imm_reloc, op_hash);

  if (error)
    {
      as_bad ("%s `%s'", error, str);
      return;
    }

  riscv_append_insn (&insn, &imm_expr, imm_reloc);
}

const char *
md_atof (int type, char *litP, int *sizeP)
{
  return ieee_md_atof (type, litP, sizeP, TARGET_BYTES_BIG_ENDIAN);
}

void
md_number_to_chars (char *buf, valueT val, int n)
{
  if (target_big_endian)
    number_to_chars_bigendian (buf, val, n);
  else
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
  OPTION_CSR_CHECK,
  OPTION_NO_CSR_CHECK,
  OPTION_MISA_SPEC,
  OPTION_MPRIV_SPEC,
  OPTION_BIG_ENDIAN,
  OPTION_LITTLE_ENDIAN,
  /* { Andes  */
  OPTION_NO_16_BIT,
  OPTION_OPTIMIZE,
  OPTION_OPTIMIZE_SPACE,
  OPTION_MCMODEL,
  OPTION_MICT_MODEL,
  OPTION_ACE,
  OPTION_MATOMIC,
  OPTION_MEXT_DSP,
  OPTION_MEXT_VECTOR,
  OPTION_MEXT_EFHW,
  OPTION_MNO_WORKAROUND,
  OPTION_MB19758,
  OPTION_MNO_B19758,
  OPTION_MB25057,
  OPTION_MNO_B25057,
  OPTION_MB20282,
  OPTION_MB22827,
  OPTION_MB22827_1,
  OPTION_FULL_ARCH,
  OPTION_MNEXECIT_OP,
  OPTION_MNO_BRANCH_RELAX,
  OPTION_MNO_RVC_CONVERT,
  /* } Andes  */
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
  {"mcsr-check", no_argument, NULL, OPTION_CSR_CHECK},
  {"mno-csr-check", no_argument, NULL, OPTION_NO_CSR_CHECK},
  {"misa-spec", required_argument, NULL, OPTION_MISA_SPEC},
  {"mpriv-spec", required_argument, NULL, OPTION_MPRIV_SPEC},
  {"mbig-endian", no_argument, NULL, OPTION_BIG_ENDIAN},
  {"mlittle-endian", no_argument, NULL, OPTION_LITTLE_ENDIAN},

  /* { Andes  */
  {"mno-16-bit", no_argument, NULL, OPTION_NO_16_BIT},
  {"matomic", no_argument, NULL, OPTION_MATOMIC},
  {"mace", required_argument, NULL, OPTION_ACE},
  {"O1", no_argument, NULL, OPTION_OPTIMIZE},
  {"Os", no_argument, NULL, OPTION_OPTIMIZE_SPACE},
  {"mext-dsp", no_argument, NULL, OPTION_MEXT_DSP},
  {"mnexecitop", no_argument, NULL, OPTION_MNEXECIT_OP},
  /* hidden options */
  {"mext-efhw", no_argument, NULL, OPTION_MEXT_EFHW},
  {"mext-vector", no_argument, NULL, OPTION_MEXT_VECTOR},
  {"mcmodel", required_argument, NULL, OPTION_MCMODEL},
  {"mict-model", required_argument, NULL, OPTION_MICT_MODEL},
  {"mno-workaround", no_argument, NULL, OPTION_MNO_WORKAROUND},
  {"mb19758", no_argument, NULL, OPTION_MB19758},
  {"mno-b19758", no_argument, NULL, OPTION_MNO_B19758},
  {"mb25057", no_argument, NULL, OPTION_MB25057},
  {"mno-b25057", no_argument, NULL, OPTION_MNO_B25057},
  {"mb20282", no_argument, NULL, OPTION_MB20282},
  {"mb22827", no_argument, NULL, OPTION_MB22827},
  {"mb22827.1", no_argument, NULL, OPTION_MB22827_1},
  {"mfull-arch", no_argument, NULL, OPTION_FULL_ARCH},
  {"mno-branch-relax", no_argument, NULL, OPTION_MNO_BRANCH_RELAX},
  {"mno-rvc-convert", no_argument, NULL, OPTION_MNO_RVC_CONVERT},
  /* } Andes  */

  {NULL, no_argument, NULL, 0}
};
size_t md_longopts_size = sizeof (md_longopts);

int
md_parse_option (int c, const char *arg)
{
  switch (c)
    {
    case OPTION_MARCH:
      default_arch_with_ext = arg;
      break;

    case OPTION_NO_PIC:
      riscv_opts.pic = false;
      break;

    case OPTION_PIC:
      riscv_opts.pic = true;
      break;

    case OPTION_MABI:
      if (strcmp (arg, "ilp32") == 0)
	riscv_set_abi (32, FLOAT_ABI_SOFT, false);
      else if (strcmp (arg, "ilp32e") == 0)
	riscv_set_abi (32, FLOAT_ABI_SOFT, true);
      else if (strcmp (arg, "ilp32f") == 0)
	riscv_set_abi (32, FLOAT_ABI_SINGLE, false);
      else if (strcmp (arg, "ilp32d") == 0)
	riscv_set_abi (32, FLOAT_ABI_DOUBLE, false);
      else if (strcmp (arg, "ilp32q") == 0)
	riscv_set_abi (32, FLOAT_ABI_QUAD, false);
      else if (strcmp (arg, "lp64") == 0)
	riscv_set_abi (64, FLOAT_ABI_SOFT, false);
      else if (strcmp (arg, "lp64f") == 0)
	riscv_set_abi (64, FLOAT_ABI_SINGLE, false);
      else if (strcmp (arg, "lp64d") == 0)
	riscv_set_abi (64, FLOAT_ABI_DOUBLE, false);
      else if (strcmp (arg, "lp64q") == 0)
	riscv_set_abi (64, FLOAT_ABI_QUAD, false);
      else
	return 0;
      explicit_mabi = true;
      break;

    case OPTION_RELAX:
      riscv_opts.relax = true;
      break;

    case OPTION_NO_RELAX:
      riscv_opts.relax = false;
      break;

    case OPTION_ARCH_ATTR:
      riscv_opts.arch_attr = true;
      break;

    case OPTION_NO_ARCH_ATTR:
      riscv_opts.arch_attr = false;
      break;

    case OPTION_CSR_CHECK:
      riscv_opts.csr_check = true;
      break;

    case OPTION_NO_CSR_CHECK:
      riscv_opts.csr_check = false;
      break;

    case OPTION_MISA_SPEC:
      return riscv_set_default_isa_spec (arg);

    case OPTION_MPRIV_SPEC:
      return riscv_set_default_priv_spec (arg);

    case OPTION_BIG_ENDIAN:
      target_big_endian = 1;
      break;

    case OPTION_LITTLE_ENDIAN:
      target_big_endian = 0;
      break;

    /* { Andes  */
    case OPTION_NO_16_BIT:
      riscv_opts.no_16_bit = true;
      break;

    case OPTION_OPTIMIZE:
      optimize = 1;
      optimize_for_space = 0;
      break;

    case OPTION_OPTIMIZE_SPACE:
      optimize = 0;
      optimize_for_space = 1;
      break;

    case OPTION_MCMODEL:
      if (strcmp (arg, "large") == 0)
	riscv_opts.cmodel = CMODEL_LARGE;
      else if (strcmp (arg, "medany") == 0)
	riscv_opts.cmodel = CMODEL_DEFAULT;
      else if (strcmp (arg, "medlow") == 0)
	riscv_opts.cmodel = CMODEL_DEFAULT;
      else
	return 0;
      break;

    case OPTION_MICT_MODEL:
      if (strcmp ("tiny", arg) == 0
	  || strcmp ("small", arg) == 0
	  || strcmp ("large", arg) == 0)
	m_ict_model = arg;
      else
	as_bad (_("invalid ICT model setting -mict-model=%s"), arg);
      break;

    case OPTION_MATOMIC:
      riscv_opts.atomic = true;
      break;

    case OPTION_MEXT_DSP:
      riscv_opts.dsp = true;
      break;

    case OPTION_MNEXECIT_OP:
      riscv_opts.nexecit_op = true;
      break;

    case OPTION_MEXT_VECTOR:
      riscv_opts.vector = true;
      break;

    case OPTION_MEXT_EFHW:
      riscv_opts.efhw = true;
      break;

    case OPTION_MNO_BRANCH_RELAX:
      riscv_opts.no_branch_relax = true;
      break;

    case OPTION_MNO_RVC_CONVERT:
      riscv_opts.no_rvc_convert = true;
      break;
    /* } Andes  */

    /* { Andes ACE */
    /* Load ACE shared library if ACE option is enable */
    case OPTION_ACE:
      {
#ifndef __MINGW32__
	char *err = andes_ace_load_hooks (arg);
	if (err)
	  as_bad ("Fault to load ACE shared library: %s\n", err);
#endif
      }
      break;
    /* } Andes ACE */

    case OPTION_MNO_WORKAROUND:
	riscv_opts.workaround = 0;
      break;

    case OPTION_MB19758:
	riscv_opts.b19758 = 1;
	riscv_opts.b19758_effect = 1;
      break;
    case OPTION_MNO_B19758:
	riscv_opts.b19758 = 0;
	riscv_opts.b19758_effect = riscv_opts.b25057;
      break;
    case OPTION_MB25057:
	riscv_opts.b25057 = 1;
	riscv_opts.b19758_effect = 1;
      break;
    case OPTION_MNO_B25057:
	riscv_opts.b25057 = 0;
	riscv_opts.b19758_effect = riscv_opts.b19758;
      break;

    case OPTION_MB20282:
	riscv_opts.b20282 = 1;
      break;

    case OPTION_MB22827:
	riscv_opts.b22827 = 1;
      break;
    case OPTION_MB22827_1:
	riscv_opts.b22827_1 = 1;
      break;

    case OPTION_FULL_ARCH:
	riscv_opts.full_arch = 1;
      break;

    default:
      return 0;
    }

  return 1;
}

void
riscv_after_parse_args (void)
{
#ifdef TARGET_OS
  riscv_opts.is_linux = (0 == strcmp (TARGET_OS, "elf")) ? 0 : 1;
#else
  #error "TARGET_OS not defined!"
#endif

  /* The --with-arch is optional for now, so we still need to set the xlen
     according to the default_arch, which is set by the --target.  */
  if (xlen == 0)
    {
      if (strcmp (default_arch, "riscv32") == 0)
	xlen = 32;
      else if (strcmp (default_arch, "riscv64") == 0)
	xlen = 64;
      else
	as_bad ("unknown default architecture `%s'", default_arch);
    }

  /* Set default specs.  */
  if (default_isa_spec == ISA_SPEC_CLASS_NONE)
    riscv_set_default_isa_spec (DEFAULT_RISCV_ISA_SPEC);
  if (default_priv_spec == PRIV_SPEC_CLASS_NONE)
    riscv_set_default_priv_spec (DEFAULT_RISCV_PRIV_SPEC);

  riscv_set_arch (default_arch_with_ext);

  /* If the CIE to be produced has not been overridden on the command line,
     then produce version 3 by default.  This allows us to use the full
     range of registers in a .cfi_return_column directive.  */
  if (flag_dwarf_cie_version == -1)
    flag_dwarf_cie_version = 3;

  /* { Andes */
  memset (&nsta, 0, sizeof (nsta)); /* init once.  */

  /* disable --cmodel=large if RV32  */
  if (riscv_opts.cmodel == CMODEL_LARGE && xlen <= 32)
	riscv_opts.cmodel = CMODEL_DEFAULT;

  if (riscv_opts.atomic)
    riscv_parse_add_subset (&riscv_rps_as, "a", RISCV_UNKNOWN_VERSION,
			    RISCV_UNKNOWN_VERSION, false);

  if (riscv_opts.dsp)
    riscv_parse_add_subset (&riscv_rps_as, "p", RISCV_UNKNOWN_VERSION,
			    RISCV_UNKNOWN_VERSION, false);

#if 0 /* defer to md_assemble. */
  if (riscv_opts.nexecit_op)
    riscv_parse_add_subset (&riscv_rps_as, "xnexecit", RISCV_UNKNOWN_VERSION,
			    RISCV_UNKNOWN_VERSION, false);
#endif

  if (riscv_opts.vector)
    riscv_parse_add_subset (&riscv_rps_as, "v", RISCV_UNKNOWN_VERSION,
			    RISCV_UNKNOWN_VERSION, false);

  if (riscv_opts.efhw)
    riscv_parse_add_subset (&riscv_rps_as, "xefhw", RISCV_UNKNOWN_VERSION,
			    RISCV_UNKNOWN_VERSION, false);



  if (riscv_opts.atomic || riscv_opts.dsp || riscv_opts.vector
      || riscv_opts.efhw)
    {
      riscv_parse_add_implicit_subsets (&riscv_rps_as);
      riscv_parse_check_conflicts (&riscv_rps_as);
    }
  /* } Andes */
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
  bool relaxable = false;
  offsetT loc;
  segT sub_segment;

  /* Remember value for tc_gen_reloc.  */
  fixP->fx_addnumber = *valP;

  /* Convert the correct ICT relocs according to the ict
     flag in the fixup.  */
  riscv_convert_ict_relocs (&fixP);

  switch (fixP->fx_r_type)
    {
    case BFD_RELOC_RISCV_HI20:
    case BFD_RELOC_RISCV_LO12_I:
    case BFD_RELOC_RISCV_LO12_S:
    case BFD_RELOC_RISCV_ICT_HI20:
    case BFD_RELOC_RISCV_ICT_LO12_I:
      bfd_putl32 (riscv_apply_const_reloc (fixP->fx_r_type, *valP)
		  | bfd_getl32 (buf), buf);
      if (fixP->fx_addsy == NULL)
	fixP->fx_done = true;
      relaxable = true;
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
      relaxable = true;
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
	 in .eh_frame.  Othrewise, the value may be adjusted twice.  */
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
		    as_fatal (_("internal: bad CFA value #%d"), subtype);
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
	  /* Fill in a tentative value to improve objdump readability.  */
	  bfd_vma target = S_GET_VALUE (fixP->fx_addsy) + *valP;
	  bfd_vma delta = target - md_pcrel_from (fixP);
	  bfd_putl32 (bfd_getl32 (buf) | ENCODE_JTYPE_IMM (delta), buf);
	}
      break;

    case BFD_RELOC_12_PCREL:
      if (fixP->fx_addsy)
	{
	  /* Fill in a tentative value to improve objdump readability.  */
	  bfd_vma target = S_GET_VALUE (fixP->fx_addsy) + *valP;
	  bfd_vma delta = target - md_pcrel_from (fixP);
	  bfd_putl32 (bfd_getl32 (buf) | ENCODE_BTYPE_IMM (delta), buf);
	}
      break;

    case BFD_RELOC_RISCV_RVC_BRANCH:
      if (fixP->fx_addsy)
	{
	  /* Fill in a tentative value to improve objdump readability.  */
	  bfd_vma target = S_GET_VALUE (fixP->fx_addsy) + *valP;
	  bfd_vma delta = target - md_pcrel_from (fixP);
	  bfd_putl16 (bfd_getl16 (buf) | ENCODE_CBTYPE_IMM (delta), buf);
	}
      break;

    case BFD_RELOC_RISCV_RVC_JUMP:
      if (fixP->fx_addsy)
	{
	  /* Fill in a tentative value to improve objdump readability.  */
	  bfd_vma target = S_GET_VALUE (fixP->fx_addsy) + *valP;
	  bfd_vma delta = target - md_pcrel_from (fixP);
	  bfd_putl16 (bfd_getl16 (buf) | ENCODE_CJTYPE_IMM (delta), buf);
	}
      break;

    case BFD_RELOC_RISCV_CALL:
    case BFD_RELOC_RISCV_CALL_PLT:
    case BFD_RELOC_RISCV_CALL_ICT:
      relaxable = true;
      break;

    case BFD_RELOC_RISCV_PCREL_HI20:
    case BFD_RELOC_RISCV_PCREL_LO12_S:
    case BFD_RELOC_RISCV_PCREL_LO12_I:
    case BFD_RELOC_RISCV_PCREL_ICT_HI20:
      relaxable = riscv_opts.relax;
      break;

    case BFD_RELOC_RISCV_ALIGN:
      break;

    /* { Andes */
    case BFD_RELOC_RISCV_10_PCREL:
      if (fixP->fx_addsy)
	{
	  /* Fill in a tentative value to improve objdump readability.  */
	  bfd_vma target = S_GET_VALUE (fixP->fx_addsy) + *valP;
	  bfd_vma delta = target - md_pcrel_from (fixP);
	  bfd_putl32 (bfd_getl32 (buf) | ENCODE_STYPE_IMM10 (delta), buf);
	}
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
    /* } Andes */

    default:
      /* We ignore generic BFD relocations we don't know about.  */
      if (bfd_reloc_type_lookup (stdoutput, fixP->fx_r_type) != NULL)
	as_fatal (_("internal: bad relocation #%d"), fixP->fx_r_type);
    }

  if (fixP->fx_subsy != NULL)
    as_bad_subtract (fixP);

  /* Add an R_RISCV_RELAX reloc if the reloc is relaxable.  */
  if (relaxable && fixP->fx_tcbit && fixP->fx_addsy != NULL)
    {
      fixP->fx_next = xmemdup (fixP, sizeof (*fixP), sizeof (*fixP));
      fixP->fx_next->fx_addsy = fixP->fx_next->fx_subsy = NULL;
      fixP->fx_next->fx_r_type = BFD_RELOC_RISCV_RELAX;
      fixP->fx_next->fx_size = 0;
      /* Clean up the ict flag for R_RISCV_RELAX.  */
      fixP->fx_next->tc_fix_data.ict = 0;
    }
}

/* Because the value of .cfi_remember_state may changed after relaxation,
   we insert a fix to relocate it again in link-time.  */

void
riscv_pre_output_hook (void)
{
  const frchainS *frch;
  segT s;

  /* Save the current segment info.  */
  segT seg = now_seg;
  subsegT subseg = now_subseg;

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

		/* We must set the segment before creating a frag after all
		   frag chains have been chained together.  */
		subseg_set (s, frch->frch_subseg);

		fix_new_exp (frag, (int) frag->fr_offset, 1, &exp, 0,
			     BFD_RELOC_RISCV_CFA);
	      }
	  }
      }

  /* Restore the original segment info.  */
  subseg_set (seg, subseg);
}

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
      riscv_update_subset (&riscv_rps_as, "+c");
      riscv_set_rvc (true);
      riscv_rvc_reloc_setting (1);
    }
  else if (strcmp (name, "norvc") == 0)
    {
      /* Force to set the 4-byte aligned when converting
	 rvc to norvc.  The repeated alignment setting is
	 fine since linker will remove the redundant nops.  */
      if (riscv_opts.rvc && !riscv_opts.no_16_bit && start_assemble
	  && !riscv_opts.is_linux)
	riscv_frag_align_code (2);
      riscv_update_subset (&riscv_rps_as, "-c");
      riscv_set_rvc (false);
      riscv_rvc_reloc_setting (0);
    }
  else if (strcmp (name, "pic") == 0)
    riscv_opts.pic = true;
  else if (strcmp (name, "nopic") == 0)
    riscv_opts.pic = false;
  else if (strcmp (name, "relax") == 0)
    riscv_opts.relax = true;
  else if (strcmp (name, "norelax") == 0)
    riscv_opts.relax = false;
  else if (strcmp (name, "csr-check") == 0)
    riscv_opts.csr_check = true;
  else if (strcmp (name, "no-csr-check") == 0)
    riscv_opts.csr_check = false;
  else if (strncmp (name, "arch,", 5) == 0)
    {
      name += 5;
      if (ISSPACE (*name) && *name != '\0')
	name++;
      riscv_update_subset (&riscv_rps_as, name);

      riscv_set_rvc (false);
      if (riscv_subset_supports (&riscv_rps_as, "c")
	  || riscv_subset_supports (&riscv_rps_as, "zca"))
	riscv_set_rvc (true);
    }
  else if (strcmp (name, "push") == 0)
    {
      struct riscv_option_stack *s;

      s = XNEW (struct riscv_option_stack);
      s->next = riscv_opts_stack;
      s->options = riscv_opts;
      s->subset_list = riscv_subsets;
      riscv_opts_stack = s;
      riscv_subsets = riscv_copy_subset_list (s->subset_list);
      riscv_rps_as.subset_list = riscv_subsets;
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
	  riscv_subset_list_t *release_subsets = riscv_subsets;
	  riscv_opts_stack = s->next;
	  riscv_opts = s->options;
	  riscv_subsets = s->subset_list;
	  riscv_rps_as.subset_list = riscv_subsets;
	  riscv_release_subset_list (release_subsets);
	  free (s);
	}

      /* Deal with the rvc setting.  */
      if (riscv_opts.rvc && !pre_rvc)
	/* norvc to rvc.  */
	riscv_rvc_reloc_setting (1);
      else if (!riscv_opts.rvc && pre_rvc)
	{
	  /* rvc to norvc.  */
	  if (!riscv_opts.no_16_bit)
	    {
	      riscv_opts.rvc = 1;
	      if (!riscv_opts.is_linux)
		riscv_frag_align_code (2);
	    }
	  riscv_opts.rvc = 0;
	  riscv_rvc_reloc_setting (0);
	}
    }
  /* { Andes  */
  else if (strcmp (name, "execit") == 0
	   || strcmp (name, "ex9") == 0)
    riscv_opts.execit = TRUE;
  else if (strcmp (name, "verbatim") == 0)
    riscv_opts.verbatim = TRUE;
  else if (strcmp (name, "no_branch_relax") == 0)
    riscv_opts.no_branch_relax = true;
  else if (strcmp (name, "no_rvc_convert") == 0)
    riscv_opts.no_rvc_convert = true;
  else if (strncmp (name, "cmodel_", 7) == 0)
    {
      if (strcmp (name+7, "large") == 0 && xlen > 32)
	riscv_opts.cmodel = CMODEL_LARGE;
      else if (strcmp (name+7, "medany") == 0)
	riscv_opts.cmodel = CMODEL_DEFAULT;
      else if (strcmp (name+7, "medlow") == 0)
	riscv_opts.cmodel = CMODEL_DEFAULT;
    }
  /* } Andes  */
  else
    {
      as_warn (_("unrecognized .option directive: %s\n"), name);
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
      as_bad (_("unsupported use of %s"), (bytes == 8
					   ? ".dtpreldword"
					   : ".dtprelword"));
      ignore_rest_of_line ();
    }

  p = frag_more (bytes);
  md_number_to_chars (p, 0, bytes);
  fix_new_exp (frag_now, p - frag_now->fr_literal, bytes, &ex, false,
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

static void
riscv_make_nops (char *buf, bfd_vma bytes)
{
  bfd_vma i = 0;

  /* RISC-V instructions cannot begin or end on odd addresses, so this case
     means we are not within a valid instruction sequence.  It is thus safe
     to use a zero byte, even though that is not a valid instruction.  */
  if (bytes % 2 == 1)
    buf[i++] = 0;

  /* Use at most one 2-byte NOP.  */
  if ((bytes - i) % 4 == 2)
    {
      number_to_chars_littleendian (buf + i, RVC_NOP, 2);
      i += 2;
    }

  /* Fill the remainder with 4-byte NOPs.  */
  for ( ; i < bytes; i += 4)
    number_to_chars_littleendian (buf + i, RISCV_NOP, 4);
}

/* Called from md_do_align.  Used to create an alignment frag in a
   code section by emitting a worst-case NOP sequence that the linker
   will later relax to the correct number of NOPs.  We can't compute
   the correct alignment now because of other linker relaxations.  */

bool
riscv_frag_align_code (int n)
{
  bfd_vma bytes = (bfd_vma) 1 << n;
  bfd_vma insn_alignment = riscv_opts.rvc ? 2 : 4;
  bfd_vma worst_case_bytes = bytes - insn_alignment;
  char *nops;
  expressionS ex;

  /* If we are moving to a smaller alignment than the instruction size, then no
     alignment is required. */
  if (bytes <= insn_alignment)
    return true;

  /* When not relaxing, riscv_handle_align handles code alignment.  */
  if (!riscv_opts.relax)
    return false;

  nops = frag_more (worst_case_bytes);

  ex.X_op = O_constant;
  ex.X_add_number = worst_case_bytes;

  riscv_make_nops (nops, worst_case_bytes);

  fix_new_exp (frag_now, nops - frag_now->fr_literal, 0,
	       &ex, false, BFD_RELOC_RISCV_ALIGN);

  riscv_mapping_state (MAP_INSN, worst_case_bytes);

  /* We need to start a new frag after the alignment which may be removed by
     the linker, to prevent the assembler from computing static offsets.
     This is necessary to get correct EH info.  */
  frag_wane (frag_now);
  frag_new (0);

  return true;
}

/* Implement HANDLE_ALIGN.  */

void
riscv_handle_align (fragS *fragP)
{
  switch (fragP->fr_type)
    {
    case rs_align_code:
      /* When relaxing, riscv_frag_align_code handles code alignment.  */
      if (!riscv_opts.relax)
	{
	  bfd_signed_vma bytes = (fragP->fr_next->fr_address
				  - fragP->fr_address - fragP->fr_fix);
	  /* We have 4 byte uncompressed nops.  */
	  bfd_signed_vma size = 4;
	  bfd_signed_vma excess = bytes % size;
	  bfd_boolean odd_padding = (excess % 2 == 1);
	  char *p = fragP->fr_literal + fragP->fr_fix;

	  if (bytes <= 0)
	    break;

	  /* Insert zeros or compressed nops to get 4 byte alignment.  */
	  if (excess)
	    {
	      if (odd_padding)
		riscv_add_odd_padding_symbol (fragP);
	      riscv_make_nops (p, excess);
	      fragP->fr_fix += excess;
	      p += excess;
	    }

	  /* The frag will be changed to `rs_fill` later.  The function
	     `write_contents` will try to fill the remaining spaces
	     according to the patterns we give.  In this case, we give
	     a 4 byte uncompressed nop as the pattern, and set the size
	     of the pattern into `fr_var`.  The nop will be output to the
	     file `fr_offset` times.  However, `fr_offset` could be zero
	     if we don't need to pad the boundary finally.  */
	  riscv_make_nops (p, size);
	  fragP->fr_var = size;
	}
      break;

    default:
      break;
    }
}

/* This usually called from frag_var.  */

void
riscv_init_frag (fragS * fragP, int max_chars)
{
  /* Do not add mapping symbol to debug sections.  */
  if (bfd_section_flags (now_seg) & SEC_DEBUGGING)
    return;

  switch (fragP->fr_type)
    {
    case rs_fill:
    case rs_align:
    case rs_align_test:
      riscv_mapping_state (MAP_DATA, max_chars);
      break;
    case rs_align_code:
      riscv_mapping_state (MAP_INSN, max_chars);
      break;
    case rs_machine_dependent:
      {
	int type = RELAX_CMODEL_TYPE (fragP->fr_subtype);
	int length = RELAX_CMODEL_LENGTH (fragP->fr_subtype);
	if (type == TYPE_IS)
	  riscv_mapping_state (MAP_DATA, length);
	else if (type == TYPE_ALIGN)
	  riscv_mapping_state (MAP_INSN, length);
      }
    default:
      break;
    }
}

int
md_estimate_size_before_relax (fragS *fragp, asection *segtype)
{
  if (RELAX_BRANCH_P (fragp->fr_subtype))
    fragp->fr_var = relaxed_branch_length (fragp, segtype, false);
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
    case BFD_RELOC_RISCV_DATA:
      /* Prevent linker from optimizing data in text sections.
	 For example, jump table.  */
      reloc->addend = fixp->fx_size;
      break;

    default:
      /* In general, addend of a relocation is the offset to the
	 associated symbol.  */
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
      fragp->fr_var = relaxed_branch_length (fragp, sec, true);
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

  /* Andes: the relocation for the branch over jump has to be kept.
     since the linker optimizations, inlcuding target aligned and EXECIT,
     may change the immediate field of the branch.  */

  if (RELAX_BRANCH_RVC (fragp->fr_subtype))
    {
      switch (RELAX_BRANCH_LENGTH (fragp->fr_subtype))
	{
	  case 8:
	  case 4:
	    /* Expand the RVC branch into a RISC-V one.  */
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
	    /* Invert the branch condition.  Branch over the jump.  */
	    insn = bfd_getl16 (buf);
	    insn ^= MATCH_C_BEQZ ^ MATCH_C_BNEZ;
	    insn |= ENCODE_CBTYPE_IMM (6);
	    bfd_putl16 (insn, buf);
	    /* Keep the relocation for the RVC branch.  */
	    exp.X_add_symbol = symbol_temp_new (sec, fragp->fr_next, 0);
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
				2, &exp, false, reloc);
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
	  insn |= ENCODE_BTYPE_IMM (8);
	  reloc = BFD_RELOC_12_PCREL;
	}
      bfd_putl32 (insn, buf);
      /* Keep the relocation for the branch.  */
      exp.X_add_symbol = symbol_temp_new (sec, fragp->fr_next, 0);
      exp.X_add_number = 0;
      fixp = fix_new_exp (fragp, buf - (bfd_byte *)fragp->fr_literal,
			  4, &exp, FALSE, reloc);
      buf += 4;

    jump:
      /* Jump to the target.  */
      exp.X_add_symbol = fragp->fr_symbol;
      exp.X_add_number = fragp->fr_offset;
      fixp = fix_new_exp (fragp, buf - (bfd_byte *)fragp->fr_literal,
			  4, &exp, false, BFD_RELOC_RISCV_JMP);
      bfd_putl32 (MATCH_JAL, buf);
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
			  4, &exp, false, reloc);
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
  int relax = RELAX_CMODEL_RELAX (fragp->fr_subtype);
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
    case TYPE_ALIGN:
      if (is_same_sec)
	gas_assert (length == 0);
      else
	{ /* add relocation here now!  */
	  gas_assert (length == 6);
	  expressionS ex;
	  ex.X_op = O_constant;
	  ex.X_add_number = ALIGN_LEN;
	  fix_new_exp (fragp, buf - (bfd_byte *)fragp->fr_literal,
		       0, &ex, FALSE, BFD_RELOC_RISCV_ALIGN);
	}
      break;
    case TYPE_IS:
      if (is_same_sec)
	gas_assert (length == 0);
      else
	{  /* add relocation here now!  */
	  gas_assert (length == CMODEL_SECTION_ENTRY_SIZE);
	  /* SYM rela */
	  reloc = BFD_RELOC_64;
	  fix_new_exp (fragp, buf - (bfd_byte *)fragp->fr_literal,
		       CMODEL_SECTION_ENTRY_SIZE, &exp, FALSE, reloc);
	  /* _DATA */
	  expressionS ex;
	  ex.X_op = O_constant;
	  ex.X_add_number = 0;
	  fix_new_exp (fragp, buf - (bfd_byte *)fragp->fr_literal, 8,
		       &ex, 0, BFD_RELOC_RISCV_DATA);
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
	  fixS *fix;
	  reloc = BFD_RELOC_RISCV_PCREL_HI20;
	  fix = fix_new_exp (fragp, buf - (bfd_byte *)fragp->fr_literal,
			     4, &exp_ind, FALSE, reloc);
	  fix->fx_tcbit = relax;

	  reloc = BFD_RELOC_RISCV_PCREL_LO12_I;
	  fix = fix_new_exp (fragp, buf - (bfd_byte *)fragp->fr_literal + 4,
			     4, &exp_ref, FALSE, reloc);
	  fix->fx_tcbit = relax;

	  /* TODO: relax jalr to c.jalr  */
	}
      break;
    case TYPE_LA:
      gas_assert (length == 8);
      if (is_same_sec)
	{
	  fixS *fix;
	  int32_t *bin = (int32_t *) buf;
	  bin[1] = bin[2];

	  reloc = BFD_RELOC_RISCV_PCREL_HI20;
	  fix = fix_new_exp (fragp, buf - (bfd_byte *)fragp->fr_literal,
			     4, &exp, FALSE, reloc);
	  fix->fx_tcbit = relax;

	  reloc = BFD_RELOC_RISCV_PCREL_LO12_I;
	  fix = fix_new_exp (fragp, buf - (bfd_byte *)fragp->fr_literal + 4,
			     4, &exp_ref, FALSE, reloc);
	  fix->fx_tcbit = relax;
	}
      else
	{
	  fixS *fix;
	  reloc = BFD_RELOC_RISCV_PCREL_HI20;
	  fix = fix_new_exp (fragp, buf - (bfd_byte *)fragp->fr_literal,
			     4, &exp_ind, FALSE, reloc);
	  fix->fx_tcbit = relax;

	  reloc = BFD_RELOC_RISCV_PCREL_LO12_I;
	  fix = fix_new_exp (fragp, buf - (bfd_byte *)fragp->fr_literal + 4,
			     4, &exp_ref, FALSE, reloc);
	  fix->fx_tcbit = relax;
	}
      break;
    case TYPE_LD:
      if (is_same_sec)
	{
	  fixS *fix;
	  gas_assert (length == 8);
	  int32_t *bin = (int32_t *) buf;
	  bin[1] = bin[2];

	  reloc = BFD_RELOC_RISCV_PCREL_HI20;
	  fix = fix_new_exp (fragp, buf - (bfd_byte *)fragp->fr_literal,
			     4, &exp, FALSE, reloc);
	  fix->fx_tcbit = relax;

	  reloc = BFD_RELOC_RISCV_PCREL_LO12_I;
	  fix = fix_new_exp (fragp, buf - (bfd_byte *)fragp->fr_literal + 4,
			     4, &exp_ref, FALSE, reloc);
	  fix->fx_tcbit = relax;
	}
      else
	{
	  fixS *fix;
	  gas_assert (length == 12);
	  reloc = BFD_RELOC_RISCV_PCREL_HI20;
	  fix = fix_new_exp (fragp, buf - (bfd_byte *)fragp->fr_literal,
			     4, &exp_ind, FALSE, reloc);
	  fix->fx_tcbit = relax;

	  reloc = BFD_RELOC_RISCV_PCREL_LO12_I;
	  fix = fix_new_exp (fragp, buf - (bfd_byte *)fragp->fr_literal + 4,
			     4, &exp_ref, FALSE, reloc);
	  fix->fx_tcbit = relax;
	}
      break;
    case TYPE_ST:
      if (is_same_sec)
	{
	  fixS *fix;
	  gas_assert (length == 8);
	  int32_t *bin = (int32_t *) buf;
	  bin[1] = bin[2];

	  reloc = BFD_RELOC_RISCV_PCREL_HI20;
	  fix = fix_new_exp (fragp, buf - (bfd_byte *)fragp->fr_literal,
			     4, &exp, FALSE, reloc);
	  fix->fx_tcbit = relax;

	  reloc = BFD_RELOC_RISCV_PCREL_LO12_S;
	  fix = fix_new_exp (fragp, buf - (bfd_byte *)fragp->fr_literal + 4,
			     4, &exp_ref, FALSE, reloc);
	  fix->fx_tcbit = relax;
	}
      else
	{
	  fixS *fix;
	  gas_assert (length == 12);
	  reloc = BFD_RELOC_RISCV_PCREL_HI20;
	  fix = fix_new_exp (fragp, buf - (bfd_byte *)fragp->fr_literal,
			     4, &exp_ind, FALSE, reloc);
	  fix->fx_tcbit = relax;

	  reloc = BFD_RELOC_RISCV_PCREL_LO12_I;
	  fix = fix_new_exp (fragp, buf - (bfd_byte *)fragp->fr_literal + 4,
			     4, &exp_ref, FALSE, reloc);
	  fix->fx_tcbit = relax;
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
	  fixS *fix;
	  reloc = BFD_RELOC_RISCV_CALL;
	  fix = fix_new_exp (fragp, buf - (bfd_byte *)fragp->fr_literal,
			     4, &exp, FALSE, reloc);
	  fix->fx_tcbit = relax;
	}
      break;
    default:
      as_fatal (_("internal error: invalid CModel type!"));
    }
    break;
  case CSI_B22827:
  case CSI_B22827_1: /* TODO: relax nop to c.nop if has RVC  */
    /* blank  */
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
md_convert_frag (bfd *abfd ATTRIBUTE_UNUSED, segT asec,
		 fragS *fragp)
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
  -fpic or -fPIC              generate position-independent code\n\
  -fno-pic                    don't generate position-independent code (default)\n\
  -march=ISA                  set the RISC-V architecture\n\
  -misa-spec=ISAspec          set the RISC-V ISA spec (2.2, 20190608, 20191213)\n\
  -mpriv-spec=PRIVspec        set the RISC-V privilege spec (1.9.1, 1.10, 1.11, 1.12)\n\
  -mabi=ABI                   set the RISC-V ABI\n\
  -mrelax                     enable relax (default)\n\
  -mno-relax                  disable relax\n\
  -march-attr                 generate RISC-V arch attribute\n\
  -mno-arch-attr              don't generate RISC-V arch attribute\n\
  -mcsr-check                 enable the csr ISA and privilege spec version checks\n\
  -mno-csr-check              disable the csr ISA and privilege spec version checks (default)\n\
  -mbig-endian                assemble for big-endian\n\
  -mlittle-endian             assemble for little-endian\n\
"));

  /* Andes explicit options */
  fprintf (stream, _("\n\
NDS specific command line options:\n\
  -mno-16-bit                 don't generate rvc instructions\n\
  -matomic                    enable atomic extension\n\
  -mace                       support user defined instruction extension\n\
  -O1                         optimize for performance\n\
  -Os                         optimize for space\n\
  -mext-dsp                   enable dsp extension\n\
"));

  /* Andes hidden options */
  char *var = getenv("ANDES_HELP");
  if (var)
    {
      fprintf (stream, _("\
  -mext-efhw                  enable efhw extension\n\
  -mext-vector                enable vector extension\n\
  -mcmodel=TYPE               set cmodel type\n\
  -mict-model=TYPE            set ICT model type\n\
  -mno-workaround             disable all workarounds\n\
  -mb19758                    enable workaround b19758\n\
  -mb25057                    enable workaround b25057\n\
  -mb20282                    enable workaround b20282\n\
  -mb22827                    enable workaround b22827\n\
  -mb22827.1                  enable workaround b22827.1\n\
  -mfull-arch                 disable arch attribute suppression\n\
"));
    }
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

  /* CSRs are numbered 4096 -> 8191.  */
  if ((reg = reg_lookup_internal (regname, RCLASS_CSR)) >= 0)
    return reg + 4096;

  as_bad (_("unknown register `%s'"), regname);
  return -1;
}

void
riscv_elf_final_processing (void)
{
  riscv_set_abi_by_arch ();
  elf_elfheader (stdoutput)->e_flags |= elf_flags;
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

/* Parse the .insn directive.  There are three formats,
   Format 1: .insn <type> <operand1>, <operand2>, ...
   Format 2: .insn <length>, <value>
   Format 3: .insn <value>.  */

static void
s_riscv_insn (int x ATTRIBUTE_UNUSED)
{
  char *str = input_line_pointer;
  struct riscv_cl_insn insn;
  expressionS imm_expr;
  bfd_reloc_code_real_type imm_reloc = BFD_RELOC_UNUSED;
  char save_c;
  insn.cmodel.method = METHOD_DEFAULT;

  while (!is_end_of_line[(unsigned char) *input_line_pointer])
    ++input_line_pointer;

  save_c = *input_line_pointer;
  *input_line_pointer = '\0';

  riscv_mapping_state (MAP_INSN, 0);

  const char *error = riscv_ip (str, &insn, &imm_expr,
				&imm_reloc, insn_type_hash);
  if (error)
    {
      char *save_in = input_line_pointer;
      error = riscv_ip_hardcode (str, &insn, &imm_expr, error);
      input_line_pointer = save_in;
    }

  if (error)
    as_bad ("%s `%s'", error, str);
  else
    {
      gas_assert (insn.insn_mo->pinfo != INSN_MACRO);
      append_insn (&insn, &imm_expr, imm_reloc);
    }

  *input_line_pointer = save_c;
  demand_empty_rest_of_line ();
}

/* Update architecture and privileged elf attributes.  If we don't set
   them, then try to output the default ones.  */

static void
riscv_write_out_attrs (void)
{
  const char *arch_str, *priv_str, *p;
  /* versions[0]: major version.
     versions[1]: minor version.
     versions[2]: revision version.  */
  unsigned versions[3] = {0}, number = 0;
  unsigned int i;

  /* Re-write architecture elf attribute.  */
  arch_str = riscv_arch_str_ext (xlen, riscv_subsets,
				 riscv_opts.full_arch, default_isa_spec);
  bfd_elf_add_proc_attr_string (stdoutput, Tag_RISCV_arch, arch_str);
  xfree ((void *) arch_str);

  /* For the file without any instruction, we don't set the default_priv_spec
     according to the privileged elf attributes since the md_assemble isn't
     called.  */
  if (!start_assemble
      && !riscv_set_default_priv_spec (NULL))
    return;

  /* If we already have set privileged elf attributes, then no need to do
     anything.  Otherwise, don't generate or update them when no CSR and
     privileged instructions are used.  */
  if (!explicit_priv_attr)
    return;

  RISCV_GET_PRIV_SPEC_NAME (priv_str, default_priv_spec);
  p = priv_str;
  for (i = 0; *p; ++p)
    {
      if (*p == '.' && i < 3)
       {
         versions[i++] = number;
         number = 0;
       }
      else if (ISDIGIT (*p))
       number = (number * 10) + (*p - '0');
      else
       {
         as_bad (_("internal: bad RISC-V privileged spec (%s)"), priv_str);
         return;
       }
    }
  versions[i] = number;

  /* Re-write privileged elf attributes.  */
  bfd_elf_add_proc_attr_int (stdoutput, Tag_RISCV_priv_spec, versions[0]);
  bfd_elf_add_proc_attr_int (stdoutput, Tag_RISCV_priv_spec_minor, versions[1]);
  bfd_elf_add_proc_attr_int (stdoutput, Tag_RISCV_priv_spec_revision, versions[2]);

  /* { Andes */
  if (m_ict_model)
    {
      bfd_elf_add_proc_attr_int (stdoutput, Tag_RISCV_ict_version,
				 DEFAULT_ICT_VERSION);
      bfd_elf_add_proc_attr_string (stdoutput, Tag_RISCV_ict_model,
				    m_ict_model);
    }
  /* } Andes */
}

/* Add the default contents for the .riscv.attributes section.  */

static void
riscv_set_public_attributes (void)
{
  if (riscv_opts.arch_attr || explicit_attr)
    riscv_write_out_attrs ();
}

/* Implement TC_START_LABEL and md_cleanup. Release cache instruction
   when assemble finished parsing input file or defining a label  */

bfd_boolean
riscv_md_cleanup (void)
{
  if (has_cached_insn ())
    release_cached_insn ();

  return TRUE;
}

/* Called after all assembly has been done.  */

void
riscv_md_end (void)
{
  if (use_insn_combiner ()
	&& insn_combiner)
    {
      free (insn_combiner);
    }
  riscv_set_public_attributes ();
}

/* { Andes */
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

/* The Addend of BFD_RELOC_RISCV_NO_RVC_REGION_BEGIN means,
   0: norvc, unchecked
   1: rvc, unchecked
   2: Already checked.  */

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

  /* Assume the offset of the NO_RVC_REGION are in order.  */
  for (; fixp; fixp = fixp->fx_next)
    {
      /* Find the next effective NO_RVC_REGION relocations.  */
      riscv_find_next_effective_rvc_region (&fixp);
      if (!fixp)
	break;

      /* Remove the redundant NO_RVC_REGION relocations.  */
      if (fixp->fx_offset == 0)
	{
	  /* norvc to norvc.  */
	  if (current_rvc == -1)
	    fixp->fx_done = 1;
	  else
	    {
	      /* rvc to norvc.  */
	      current_rvc = -1;
	      pre_fixp_begin = fixp;
	    }
	}
      else if (fixp->fx_offset == 1)
	{
	  /* Cannot find the corresponding NO_RVC_REGION_BEGIN
	     or rvc to rvc.  */
	  if (!pre_fixp_begin
	      || current_rvc == 1)
	    fixp->fx_done = 1;
	  else
	    {
	      /* norvc to rvc.  */
	      current_rvc = 1;
	      pre_fixp_begin = NULL;
	      fixp->fx_r_type = BFD_RELOC_RISCV_NO_RVC_REGION_END;
	    }
	}
      fixp->fx_offset = 2;
    }
}

/* final both .no_execit_[begin|end]
 *        and .innermost_loop_[begin|end]
 */
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

  /* First, we also need to insert noexecit directives according to
     the NO_RVC_REGION directives set at riscv_final_no_rvc_region.  */
  fixp = seginfo->fix_root;
  for (; fixp; fixp = fixp->fx_next)
    {
      /* skip redundant fixes  */
      if (fixp->fx_done)
	continue;

      if (fixp->fx_r_type == BFD_RELOC_RISCV_NO_RVC_REGION_BEGIN)
	fix_new (fixp->fx_frag, fixp->fx_where, 0, abs_section_sym,
		 R_RISCV_RELAX_REGION_NO_EXECIT_FLAG, 0,
		 BFD_RELOC_RISCV_RELAX_REGION_BEGIN);
      else if (fixp->fx_r_type == BFD_RELOC_RISCV_NO_RVC_REGION_END)
	fix_new (fixp->fx_frag, fixp->fx_where, 0, abs_section_sym,
		 R_RISCV_RELAX_REGION_NO_EXECIT_FLAG, 0,
		 BFD_RELOC_RISCV_RELAX_REGION_END);
    }

  /* Assume the offset of the BFD_RELOC_RISCV_RELAX_REGION_BEGIN/END
     are in order.  */
  no_execit_count = 0;
  innermost_loop_count = 0;
  fixp = seginfo->fix_root;
  for (; fixp; fixp = fixp->fx_next)
    {
      if (fixp->fx_r_type == BFD_RELOC_RISCV_RELAX_REGION_BEGIN)
	{
	  if (fixp->fx_offset == R_RISCV_RELAX_REGION_NO_EXECIT_FLAG)
	    {
	      /* We must find the corresponding REGION_END later.  */
	      if (no_execit_count > 0)
		fixp->fx_done = 1;
	      no_execit_count++;
	    }
	  else if (fixp->fx_offset == R_RISCV_RELAX_REGION_IMLOOP_FLAG)
	    {
	      /* eliminate nested ".innermost_loop_begin".  */
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
		  /* Find the unmatched REGION_END, ignore it.  */
		  no_execit_count++;
		  fixp->fx_done = 1;
		}
	    }
	  else if (fixp->fx_offset == R_RISCV_RELAX_REGION_IMLOOP_FLAG)
	    {
	      innermost_loop_count--;
	      /* eliminate nested ".innermost_loop_end".  */
	      if (innermost_loop_count > 0)
		fixp->fx_done = 1;
	      else if (innermost_loop_count < 0)
		{
		  /* unmatched ".innermost_loop_end", ignore it.  */
		  innermost_loop_count++;
		  fixp->fx_done = 1;
		}
	    }
	}
    }

  /* We have handle the negative no_execit_count cases above.  */
  if (no_execit_count > 0)
    {
      /* Find the unmatched REGION_BEGIN, we should print
	 warning/error msg here.  */
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

  /* The original code says that it is not necessary to insert the
     R_RISCV_RELAX_ENTRY when there is no relocation and the execit
     is disabled. It is weird for me now, I think always insert the
     R_RISCV_RELAX_ENTRY is fine and do no harm.  */

  /* Set RELAX_ENTRY flags for linker.  */
  frch = seginfo->frchainP;
  X_add_number = 0;

  if (!riscv_opts.relax)
    X_add_number |= R_RISCV_RELAX_ENTRY_DISABLE_RELAX_FLAG;
  if (riscv_opts.execit)
    X_add_number |= R_RISCV_RELAX_ENTRY_EXECIT_FLAG;

  fixp = fix_at_start (frch->frch_root, 0, abs_section_sym, X_add_number,
		       0, BFD_RELOC_RISCV_RELAX_ENTRY);
  fixp->fx_no_overflow = 1;
}

static void
andes_trim_seg_end_padding (bfd *abfd ATTRIBUTE_UNUSED, asection *sec,
			    void *xxx ATTRIBUTE_UNUSED)
{
  segment_info_type *seginfo;
  frchainS *frch;
  struct frag *fragP;
  bfd_signed_vma size;

  seginfo = seg_info (sec);
  if (!seginfo || !symbol_rootP || !subseg_text_p (sec) || sec->size == 0)
    return;

  subseg_change (sec, 0);

  /* tag segment pading zeros.  */
  frch = seginfo->frchainP;
  for (fragP = frch->frch_root; fragP; fragP = fragP->fr_next)
    {
      struct frag *next = fragP->fr_next;
      if (!next || next->fr_next)
	continue;

      gas_assert (fragP->fr_type == rs_fill
		  && next->fr_type == rs_fill && next->fr_fix == 0);

      size = fragP->fr_var * fragP->fr_offset;
      sec->size -= size;
      fragP->fr_offset = 0;
      /* mapping symbol check needs next frag there.  */
      fragP->fr_next->fr_address -= size;
      fragP->fr_next->last_fr_address -= size;
      break;
    }
}

void
riscv_post_relax_hook (void)
{
  /* TODO: Maybe we can sort the relocations here to reduce the burden
     of linker.  */
  bfd_map_over_sections (stdoutput, riscv_final_no_rvc_region, NULL);
  bfd_map_over_sections (stdoutput, riscv_final_no_execit_region, NULL);
  bfd_map_over_sections (stdoutput, riscv_insert_relax_entry, NULL);
  bfd_map_over_sections (stdoutput, andes_trim_seg_end_padding, NULL);
}

/* Insert relocations to mark the region that can not do EXECIT relaxation.  */

static void
riscv_no_execit (int mode)
{
  expressionS exp;

  exp.X_op = O_symbol;
  exp.X_add_symbol = abs_section_sym;
  if (mode == 1)
    {
      /* The begin of the region without EXECIT.  */
      exp.X_add_number = R_RISCV_RELAX_REGION_NO_EXECIT_FLAG;
      fix_new_exp (frag_now, frag_now_fix (), 0, &exp, 0,
		   BFD_RELOC_RISCV_RELAX_REGION_BEGIN);
    }
  else
    {
      /* The end of the region without EXECIT.  */
      exp.X_add_number = R_RISCV_RELAX_REGION_NO_EXECIT_FLAG;
      fix_new_exp (frag_now, frag_now_fix (), 0, &exp, 0,
		   BFD_RELOC_RISCV_RELAX_REGION_END);
    }
}

/* Insert relocations to mark the innermost loop region.  */

static void
riscv_innermost_loop (int mode)
{
  /* Insert loop region relocation here.  */
  expressionS exp;

  exp.X_op = O_symbol;
  exp.X_add_symbol = abs_section_sym;
  if (mode == 1)
    {
      exp.X_add_number = R_RISCV_RELAX_REGION_IMLOOP_FLAG;
      fix_new_exp (frag_now, frag_now_fix (), 0, &exp, 0,
		   BFD_RELOC_RISCV_RELAX_REGION_BEGIN);
    }
  else
    {
      exp.X_add_number = R_RISCV_RELAX_REGION_IMLOOP_FLAG;
      fix_new_exp (frag_now, frag_now_fix (), 0, &exp, 0,
		   BFD_RELOC_RISCV_RELAX_REGION_END);
    }
}

/* } Andes */

/* Adjust the symbol table.  */

void
riscv_adjust_symtab (void)
{
  bfd_map_over_sections (stdoutput, riscv_check_mapping_symbols, (char *) 0);
  elf_adjust_symtab ();
}

/* Given a symbolic attribute NAME, return the proper integer value.
   Returns -1 if the attribute is not known.  */

int
riscv_convert_symbolic_attribute (const char *name)
{
  static const struct
  {
    const char *name;
    const int tag;
  }
  attribute_table[] =
  {
    /* When you modify this table you should
       also modify the list in doc/c-riscv.texi.  */
#define T(tag) {#tag, Tag_RISCV_##tag}, {"Tag_RISCV_" #tag, Tag_RISCV_##tag}
    T(arch),
    T(priv_spec),
    T(priv_spec_minor),
    T(priv_spec_revision),
    T(unaligned_access),
    T(stack_align),
    T(ict_version),
    T(ict_model),
#undef T
  };

  if (name == NULL)
    return -1;

  unsigned int i;
  for (i = 0; i < ARRAY_SIZE (attribute_table); i++)
    if (strcmp (name, attribute_table[i].name) == 0)
      return attribute_table[i].tag;

  return -1;
}

/* Parse a .attribute directive.  */

static void
s_riscv_attribute (int ignored ATTRIBUTE_UNUSED)
{
  int tag = obj_elf_vendor_attribute (OBJ_ATTR_PROC);
  unsigned old_xlen;
  obj_attribute *attr;

  explicit_attr = true;
  switch (tag)
    {
    case Tag_RISCV_arch:
      old_xlen = xlen;
      attr = elf_known_obj_attributes_proc (stdoutput);
      if (!start_assemble)
	riscv_set_arch (attr[Tag_RISCV_arch].s);
      else
	as_fatal (_("architecture elf attributes must set before "
		    "any instructions"));

      if (old_xlen != xlen)
	{
	  /* We must re-init bfd again if xlen is changed.  */
	  unsigned long mach = xlen == 64 ? bfd_mach_riscv64 : bfd_mach_riscv32;
	  bfd_find_target (riscv_target_format (), stdoutput);

	  if (! bfd_set_arch_mach (stdoutput, bfd_arch_riscv, mach))
	    as_warn (_("could not set architecture and machine"));
	}
      break;

    case Tag_RISCV_priv_spec:
    case Tag_RISCV_priv_spec_minor:
    case Tag_RISCV_priv_spec_revision:
      if (start_assemble)
       as_fatal (_("privileged elf attributes must set before "
		   "any instructions"));
      break;

    default:
      break;
    }
}

/* Mark symbol that it follows a variant CC convention.  */

static void
s_variant_cc (int ignored ATTRIBUTE_UNUSED)
{
  char *name;
  char c;
  symbolS *sym;
  asymbol *bfdsym;
  elf_symbol_type *elfsym;

  c = get_symbol_name (&name);
  if (!*name)
    as_bad (_("missing symbol name for .variant_cc directive"));
  sym = symbol_find_or_make (name);
  restore_line_pointer (c);
  demand_empty_rest_of_line ();

  bfdsym = symbol_get_bfdsym (sym);
  elfsym = elf_symbol_from (bfdsym);
  gas_assert (elfsym);
  elfsym->internal_elf_sym.st_other |= STO_RISCV_VARIANT_CC;
}

/* Same as elf_copy_symbol_attributes, but without copying st_other.
   This is needed so RISC-V specific st_other values can be independently
   specified for an IFUNC resolver (that is called by the dynamic linker)
   and the symbol it resolves (aliased to the resolver).  In particular,
   if a function symbol has special st_other value set via directives,
   then attaching an IFUNC resolver to that symbol should not override
   the st_other setting.  Requiring the directive on the IFUNC resolver
   symbol would be unexpected and problematic in C code, where the two
   symbols appear as two independent function declarations.  */

void
riscv_elf_copy_symbol_attributes (symbolS *dest, symbolS *src)
{
  struct elf_obj_sy *srcelf = symbol_get_obj (src);
  struct elf_obj_sy *destelf = symbol_get_obj (dest);
  if (srcelf->size)
    {
      if (destelf->size == NULL)
	destelf->size = XNEW (expressionS);
      *destelf->size = *srcelf->size;
    }
  else
    {
      if (destelf->size != NULL)
	free (destelf->size);
      destelf->size = NULL;
    }
  S_SET_SIZE (dest, S_GET_SIZE (src));
}

/* RISC-V pseudo-ops table.  */
static const pseudo_typeS riscv_pseudo_table[] =
{
  {"option", s_riscv_option, 0},
#if 0
  {"half", cons, 2},
  {"word", cons, 4},
  {"dword", cons, 8},
#endif
  {"dtprelword", s_dtprel, 4},
  {"dtpreldword", s_dtprel, 8},
  {"bss", s_bss, 0},
  {"sleb128", s_riscv_leb128, 1},
  {"insn", s_riscv_insn, 0},
  {"attribute", s_riscv_attribute, 0},
  {"variant_cc", s_variant_cc, 0},
  {"float16", float_cons, 'h'},

  /* { Andes */
  {"byte", riscv_aligned_cons, 0},
  {"2byte", riscv_aligned_cons, 1},
  {"half", riscv_aligned_cons, 1},
  {"short", riscv_aligned_cons, 1},
  {"4byte", riscv_aligned_cons, 2},
  {"word", riscv_aligned_cons, 2},
  {"long", riscv_aligned_cons, 2},
  {"8byte", riscv_aligned_cons, 3},
  {"dword", riscv_aligned_cons, 3},
  {"quad", riscv_aligned_cons, 3},
  {"no_ex9_begin", riscv_no_execit, 1},
  {"no_ex9_end", riscv_no_execit, 0},
  {"no_execit_begin", riscv_no_execit, 1},
  {"no_execit_end", riscv_no_execit, 0},
  {"innermost_loop_begin", riscv_innermost_loop, 1},
  {"innermost_loop_end", riscv_innermost_loop, 0},
  /* } Andes */

  { NULL, NULL, 0 },
};

void
riscv_pop_insert (void)
{
  extern void pop_insert (const pseudo_typeS *);

  pop_insert (riscv_pseudo_table);
}

/* Implement md_parse_name for parsing SYNBOL@ICT.  */

int
riscv_parse_name (char const *name, expressionS *exprP,
                  enum expr_mode mode ATTRIBUTE_UNUSED,
                  char *nextcharP)
{
  segT segment;
  char *next;

  /* We only deal with the case that includes `@ICT'.  */
  if (*nextcharP != '@'
      || (strncasecmp (input_line_pointer + 1, "ICT", 3) != 0
	  && strncasecmp (input_line_pointer + 1, "ict", 3) != 0))
    return 0;

  gas_assert (nsta.ict_exp == NULL);
  exprP->X_op_symbol = NULL;
  exprP->X_md = BFD_RELOC_UNUSED;
  exprP->X_add_symbol = symbol_find_or_make (name);
  exprP->X_op = O_symbol;
  exprP->X_add_number = 0;

  /* Check the specail name if a symbol.  */
  segment = S_GET_SEGMENT (exprP->X_add_symbol);
  if ((segment != undefined_section) && (*nextcharP != '@'))
    return 0;

  next = input_line_pointer + 1 + 3;	/* strlen (ict/ICT) is 3.  */

  if (!is_part_of_name (*next))
    {
      exprP->X_md = BFD_RELOC_RISCV_ICT_HI20;
      nsta.ict_exp = exprP;
      *input_line_pointer = *nextcharP;
      input_line_pointer = next;
      *nextcharP = *input_line_pointer;
      *input_line_pointer = '\0';
    }

  return 1;
}

/* { Andes */

/* This fix_new is called by cons via TC_CONS_FIX_NEW_POST.  */

void
tc_cons_fix_new_post_riscv (void *ptr, expressionS *exp)
{
  fixS *fix = ptr;
  if (exp == nsta.ict_exp)
    {
      nsta.ict_exp = NULL;
      fix->tc_fix_data.ict = exp->X_md;
    }
}

void
tc_cons_count_check (int count)
{ /* how many items of the current pseudo instruction.  */
  nsta.cons_count = count;
}

static void
riscv_rvc_reloc_setting (int mode)
{
  /* We skip the rvc/norvc options which are set before the first
     instruction.  It is no necessary to insert the NO_RVC_REGION relocs
     according to these options since the first rvc information is
     stored in the fragment's tc_frag_data.rvc.  */
  /* RVC is disable entirely when -mno-16-bit is enabled  */
  if (!start_assemble  || riscv_opts.no_16_bit)
    return;

  if (mode)
    /* RVC.  */
    fix_new (frag_now, frag_now_fix (), 0, abs_section_sym,
	     0x1, 0, BFD_RELOC_RISCV_NO_RVC_REGION_BEGIN);
  else
    /* No RVC.  */
    fix_new (frag_now, frag_now_fix (), 0, abs_section_sym,
	     0x0, 0, BFD_RELOC_RISCV_NO_RVC_REGION_BEGIN);
}


#ifndef MASK_AQRL
  #define MASK_AQRL (0x3u << 25)
#endif

static bool
is_b19758_associated_insn (struct riscv_opcode *insn)
{
  static insn_t lr_insns[] =
    {
      MATCH_LR_W,
      #if 0
      MATCH_LR_D,
      #endif
      0
    };
  static insn_t amo_insns[] =
    {
      MATCH_AMOSWAP_W,
      MATCH_AMOADD_W,
      MATCH_AMOAND_W,
      MATCH_AMOOR_W,
      MATCH_AMOXOR_W,
      MATCH_AMOMAX_W,
      MATCH_AMOMAXU_W,
      MATCH_AMOMIN_W,
      MATCH_AMOMINU_W,
      #if 0
      MATCH_AMOSWAP_D,
      MATCH_AMOADD_D,
      MATCH_AMOAND_D,
      MATCH_AMOOR_D,
      MATCH_AMOXOR_D,
      MATCH_AMOMAX_D,
      MATCH_AMOMAXU_D,
      MATCH_AMOMIN_D,
      MATCH_AMOMINU_D,
      #endif
      0
    };
  const insn_t lr_mask = MASK_LR_W | MASK_AQRL;
  const insn_t amo_mask = MASK_AMOSWAP_W | MASK_AQRL;
  bool rz = false;
  int i = 0;

  if (insn->mask == lr_mask)
    {
      insn_t match = insn->match & ~(MASK_AQRL|0x1000);
      while (lr_insns[i])
	{
	  if (match == lr_insns[i++])
	    {
	      rz = true;
	      break;
	    }
	}
    }
  else if (insn->mask == amo_mask)
    {
      insn_t match = insn->match & ~(MASK_AQRL|0x1000);
      while (amo_insns[i])
	{
	  if (match == amo_insns[i++])
	    {
	      rz = true;
	      break;
	    }
	}
    }
  return rz;
}

static bool
is_indirect_jump (struct riscv_opcode *insn)
{
  static insn_t insns[] =
    {
      MATCH_JALR, MATCH_C_JALR, MATCH_C_JR,
      0
    };
  bool rz = false;
  int i = 0;
  insn_t x;
  while ((x = insns[i++]))
    {
      if (x == insn->match)
	{
	  rz = true;
	  break;
	}
    }
  return rz;
}

static bool
is_conditional_branch (struct riscv_opcode *insn)
{
  static insn_t insns[] =
    {
      MATCH_BEQ, MATCH_BEQC, MATCH_C_BEQZ,
      MATCH_BNE, MATCH_BNEC, MATCH_C_BNEZ,
      MATCH_BLT, MATCH_BLTU,
      MATCH_BGE, MATCH_BGEU,
      MATCH_BBC, MATCH_BBS,
      0
    };
  bool rz = false;
  int i = 0;
  insn_t x;
  while ((x = insns[i++]))
    {
      if (x == insn->match)
	{
	  rz = true;
	  break;
	}
    }
  return rz;
}

#define MASK_RM (0x7u << 12)

static bool
is_insn_fdiv_or_fsqrt (const struct riscv_opcode *insn)
{
  static insn_t insns[] =
    {
      MATCH_FDIV_D, MATCH_FSQRT_D,
      MATCH_FDIV_S, MATCH_FSQRT_S,
      0
    };
  bool rz = false;
  if (insn)
    {
      insn_t x;
      insn_t match = insn->match & ~MASK_RM; /* all rounding mode  */
      int i = 0;
      while ((x = insns[i++]))
	{
	  if (x == match)
	    {
	      rz = true;
	      break;
	    }
	}
    }
  return rz;
}

static inline int
insn_fp_rd (insn_t insn)
{
  int rd = 0x1fu & (insn >> 7);
  return rd;
}

static bool
is_insn_in_b22827_list (const struct riscv_opcode *insn,
			insn_t prev, insn_t curr)
{
  static insn_t insns[] =
    {
      /* unconditional  */
      MATCH_FSUB_S, MATCH_FADD_S, MATCH_FMUL_S, MATCH_FMADD_S,
      MATCH_FSQRT_S, MATCH_FDIV_S,
      MATCH_FSUB_D, MATCH_FADD_D, MATCH_FMUL_D, MATCH_FMADD_D,
      MATCH_FSQRT_D, MATCH_FDIV_D,
      MATCH_FSUB_Q, MATCH_FADD_Q, MATCH_FMUL_Q, MATCH_FMADD_Q,
      MATCH_FSQRT_Q, MATCH_FDIV_Q,
      0
    };

  bool rz = false;
  insn_t x;
  insn_t match = insn->match & ~MASK_RM; /* all rounding mode  */
  int i = 0;
  while ((x = insns[i++]))
    {
      if (x == match)
	{
	  rz = true;
	  return !rz;
	}
    }

  /* RD(FDIV/FSQRT) has to be in fa0-7 to exclude jal/ret  */
  if ((((insn->match & MASK_JAL) == MATCH_JAL)
       && (curr & (0x1fu << 7))) // JAL RD != 0 (not J)
      || (insn->match == (MATCH_JAL|(0x1u << 7)))   // JAL RA
      || ((insn->match & MASK_JALR) == MATCH_JALR)  // JALR|JR
      || (insn->match == MATCH_C_JAL)               // C.JAL
      || ((insn->match & MASK_C_JR) == MATCH_C_JR)  // C.JR
      || (insn->match == MATCH_C_JALR))             // C.JALR
    {
      int rd = insn_fp_rd (prev);
      rz = (10 <= rd) && (rd <= 17); /* rd in fa0 .. fa7  */
    }

  return !rz;
}

static inline bool
is_insn_fmt_s (insn_t insn)
{
  int fmt = 0x3u & (insn >> 25);
  return fmt == 0; /* 0:s, 1:d, 2:h, 3:q  */
}

static inline bool
is_insn_fshw (const struct riscv_opcode *insn)
{
  return insn && (insn->match == MATCH_FSHW);
}

static bool
is_insn_of_std_type (const struct riscv_opcode *insn, const char *type)
{
  bool rz = false;
  const char *p = type;
  enum riscv_insn_class klass = insn->insn_class;
  while (p && !rz)
    {
      switch (*p)
	{
	case 'D':
	  if (klass == INSN_CLASS_D
	      || klass == INSN_CLASS_D_AND_C
	      || klass == INSN_CLASS_D_OR_ZDINX
	      || klass == INSN_CLASS_D_AND_ZFH)
	    rz = true;
	  break;
	case 'F':
	  if (klass == INSN_CLASS_F
	      || klass == INSN_CLASS_F_AND_C
	      || klass == INSN_CLASS_F_OR_ZFINX
	      || klass == INSN_CLASS_F_AND_ZFH)
	    rz = true;
	  break;
	case 'Q':
	  if (klass == INSN_CLASS_Q
	      || klass == INSN_CLASS_Q_OR_ZQINX
	      || klass == INSN_CLASS_Q_AND_ZFH)
	    rz = true;
	  break;
	default:
	  gas_assert (0);
	}
    }
  return rz;
}

static bool
is_insn_of_fp_types (const struct riscv_opcode *insn)
{
  bool rz = false;
  if (insn)
    {
      if (insn->match == MATCH_FSHW
	  || insn->match == MATCH_FLHW)
	rz = true;
      else
	rz = is_insn_of_std_type (insn, "FDQ");
    }
  return rz;
}

static void
riscv_aligned_cons (int idx)
{
  unsigned long size = 1 << idx;
  /* Call default handler.  */
  cons (size);
  if (now_seg->flags & SEC_CODE
      && now_seg->flags & SEC_ALLOC && now_seg->flags & SEC_RELOC)
    {
      /* Use BFD_RELOC_RISCV_DATA to avoid EXECIT optimization replacing data.  */
      expressionS exp;

      exp.X_add_number = 0;
      exp.X_op = O_constant;
      size *= nsta.cons_count;
      fix_new_exp (frag_now, frag_now_fix () - size, size,
		   &exp, 0, BFD_RELOC_RISCV_DATA);
    }
}

/* Andes BTB alignmemt implementation:
* insert a 4-byte NOP tagged with ALIGN_BTB for liner relaxation.
* Do this only when RVC is enabled and NOT (Os and .option norelax.)
* sample:
*   call test / jr a0
*   => jalr  ra / jalr a0
*   << nop @ R_RISCV_ALIGN_BTB >> insertion
*/

static void
andes_insert_btb_reloc (struct riscv_cl_insn *ip)
{
  insn_t opc = ip->insn_opcode;
  if (optimize && riscv_opts.verbatim
      && (((opc & MASK_JALR) == MATCH_JALR && RV_X (opc, 7, 5))
          || ((opc & MASK_JAL) == MATCH_JAL && RV_X (opc, 7, 5)))
      && riscv_opts.relax && riscv_opts.rvc)
    { /* append NOP @ ALIGN_BTB  */
      char *nops = frag_more (4);
      expressionS ex;
      ex.X_op = O_constant;
      ex.X_add_number = 4;
      riscv_make_nops (nops, 4);
      fix_new_exp (frag_now, nops - frag_now->fr_literal, 4,
		   &ex, false, BFD_RELOC_RISCV_ALIGN_BTB);
    }
}
/* } Andes */

/* { Andes ACE */
static void
ace_encode_insn (unsigned int v, ace_op_t * ace_op, struct riscv_cl_insn *ip)
{
  unsigned int bit_value = v;

  /* Perform mask to truncate oversize value */
  bit_value <<= 32 - ace_op->bitsize;
  bit_value >>= 32 - ace_op->bitsize;

  /* Shift value to specified position */
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
	/* Extract msb from string */
	psep = strchr (pval, '_');
	*psep = '\0';
	msb = strtoul (pval, (char **) NULL, 10);
	/* Extract width from string */
	pval = psep + 1;
	psep = strchr (pval, '|');
	if (psep)
	  *psep = '\0';
	else
	  found_or_token = FALSE;
	width = strtoul (pval, (char **) NULL, 10);

	/* Perform mask to truncate oversize value */
	bit_value = v >> width_acc;
	bit_value <<= 32 - width;
	bit_value >>= 32 - width;

	/* Shift value to specified position */
	bit_value <<= msb - width + 1;

	ip->insn_opcode = (unsigned int) ip->insn_opcode | bit_value;
	width_acc += width;

	/* Prepare condition for next iteration */
	pval = psep + 1;
  }

}

/* Assemble ACE instruction string to binary */

static void
ace_ip (char **args, char **str, struct riscv_cl_insn *ip)
{
  /* Extract field attribute name from opcode description (ace_ops) and
     store the extracted result to var of op_name for finding the
     field attribute information from ace_op_hash */
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
  /* Cat null character to the end of op_name to avoid gash */
  memcpy (op_name + op_name_size, "\0", 1);

  /* Check whether encounter the end of line in assembly code */
  bfd_boolean found_asm_end = FALSE;
  if (strchr (*str, ',') == NULL && strchr (*str, '\0') != NULL)
    found_asm_end = TRUE;

  /* With rGPR encoding format, operand bit-field may be discrete.
     There is an "|" token in discrete format */
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

  /*  Find the field attribute from ace_op_hash and encode instruction */
  ace_op_t *ace_op = (ace_op_t *) str_hash_find (ace_op_hash, op_name);
  switch (ace_op->hw_res)
    {
    case HW_GPR:
	{
	  unsigned int regno;
	  /* Extract the GPR index string from assembly code (*str) */
	  if (reg_lookup (str, RCLASS_GPR, &regno))
	    /* Encode instruction */
	    ace_encode_insn (regno, ace_op, ip);

	  /* Update the address of pointer of assembly code (*str) */
	  if (!found_asm_end)
	    *str += 1;
	}
      break;

    case HW_FPR:
	{
	  unsigned int regno;
	  /* Extract the FPR index string from assembly code (*str) */
	  if (reg_lookup (str, RCLASS_FPR, &regno))
	    /* Encode instruction */
	    ace_encode_insn (regno, ace_op, ip);

	  /* Update the address of pointer of assembly code (*str) */
	  if (!found_asm_end)
	    *str += 1;
	}
      break;

    case HW_VR:
	{
	  unsigned int regno;
	  /* Extract the VR index string from assembly code (*str) */
	  if (reg_lookup (str, RCLASS_VECR, &regno))
	    /* Encode instruction */
	    ace_encode_insn (regno, ace_op, ip);

	  /* Update the address of pointer of assembly code (*str) */
	  if (!found_asm_end)
	    *str += 1;
	}
      break;

    case HW_UINT:
	{
	  /* Extract the IMM value string from assembly code (*str) */
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

	  /* Encode instruction */
	  if (is_discrete)
	    ace_encode_insn_discrete (imm_value, op_name_discrete, "imm",  ip);
	  else
	    ace_encode_insn (imm_value, ace_op, ip);

	  /* Update the address of pointer of assembly code (*str) */
	  if (found_asm_end)
	    *str += imm_size;
	  else
	    *str += imm_size + 1;
	}
      break;

    case HW_ACR:
	{
	  /* Extract the ACR register index string from assembly code (*str) */
	  char *p = strchr (*str, ',');
	  if (p == NULL)
	    p = strchr (*str, '\0');
	  if (p == NULL)
	    as_fatal (_("No ACR register index is given."));
	  unsigned int reg_idx_size = p - *str;
	  char *reg_idx = malloc (reg_idx_size + 1);
	  memcpy (reg_idx, *str, reg_idx_size);
	  // always append EOL at ACR index string
	  memcpy (reg_idx + reg_idx_size, "\0", 1);

	  /* Find the digit number of ACR register index string */
	  ace_keyword_t *ace_reg =
	    (ace_keyword_t *) str_hash_find (ace_keyword_hash, reg_idx);
	  if (ace_reg != NULL)
	    /* Encode instruction */
	    if (is_discrete)
	      ace_encode_insn_discrete (ace_reg->value, op_name_discrete, ace_op->hw_name,  ip);
	    else
	      ace_encode_insn (ace_reg->value, ace_op, ip);
	  else
	    as_fatal (_("Wrong ACR register index (%s)) is given."), reg_idx);

	  /* Update the address of pointer of assembly code (*str) */
	  if (found_asm_end)
	    *str += reg_idx_size;
	  else
	    *str += reg_idx_size + 1;
	}
      break;

    default:
      as_fatal (_("Broken assembler.  Cannot find field attribute."));
    }

  /* Update the address of pointer of the field attribute (*args) */
  if (found_op_str_end == TRUE)
    *args = pch - 1;
  else
    *args = pch;
}
/* } Andes ACE */
