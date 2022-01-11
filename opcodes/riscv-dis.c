/* RISC-V disassembler
   Copyright (C) 2011-2022 Free Software Foundation, Inc.

   Contributed by Andrew Waterman (andrew@sifive.com).
   Based on MIPS target.

   This file is part of the GNU opcodes library.

   This library is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   It is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
   or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
   License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; see the file COPYING3. If not,
   see <http://www.gnu.org/licenses/>.  */

#include "sysdep.h"
#include "disassemble.h"
#include "libiberty.h"
#include "opcode/riscv.h"
#include "opintl.h"
#include "elf-bfd.h"
#include "elf/riscv.h"
#include "elfxx-riscv.h"

#include <stdint.h>
#include <ctype.h>

#ifndef __MINGW32__
#include <dlfcn.h>
#endif

static enum riscv_spec_class default_isa_spec = ISA_SPEC_CLASS_DRAFT - 1;
static enum riscv_spec_class default_priv_spec = PRIV_SPEC_CLASS_NONE;

unsigned xlen = 0;

static riscv_subset_list_t riscv_subsets;
static riscv_parse_subset_t riscv_rps_dis =
{
  &riscv_subsets,	/* subset_list.  */
  opcodes_error_handler,/* error_handler.  */
  opcodes_error_handler,/* TODO: warning_handler.  */
  &xlen,		/* xlen.  */
  &default_isa_spec,	/* isa_spec.  */
  false,		/* check_unknown_prefixed_ext.  */
  STATE_DEFAULT,	/* state  */
  false,		/* exec.it enabled?  */
};

struct riscv_private_data
{
  bfd_vma gp;
  bfd_vma print_addr;
  bfd_vma jvt_base;
  bfd_vma jvt_end;
  bfd_vma hi_addr[OP_MASK_RD + 1];
  /* { Andes */
#define FLAG_EXECIT      (1u << 0)
#define FLAG_EXECIT_TAB  (1u << 1)
  bfd_vma flags;
  /* } Andes */
};

typedef struct riscv_private_data private_data_t;

/* Used for mapping symbols.  */
static int last_map_symbol = -1;
static bfd_vma last_stop_offset = 0;
enum riscv_seg_mstate last_map_state;

static const char * const *riscv_gpr_names;
static const char * const *riscv_fpr_names;

/* If set, disassemble as most general instruction.  */
static int no_aliases;
/* If set, disassemble numeric register names instead of ABI names.  */
static int numeric;

/* { Andes  */
/* If set, disassemble as prefer ISA instruction.  */
static int no_prefer;
/* } Andes  */

/* { Andes  */
typedef bool (*has_subset_fun_t) (enum riscv_insn_class);

#if 0
static bool has_rvc(enum riscv_insn_class k)
{
  return ((k == INSN_CLASS_C)
	  || (k == INSN_CLASS_F_AND_C)
	  || (k == INSN_CLASS_D_AND_C));
}
#endif

static bool has_rvp(enum riscv_insn_class k)
{
  return (k == INSN_CLASS_P);
}

static int
riscv_disassemble_insn (bfd_vma memaddr, insn_t word, disassemble_info *info);
static bool
andes_find_op_of_subset (has_subset_fun_t has_subset,
			 int no_aliases_p,
			 const struct riscv_opcode **hash,
			 insn_t word,
			 const struct riscv_opcode **pop);
static bool
andes_find_op_name_match (const char *mne,
			  insn_t match,
			  const riscv_opcode_t **hash,
			  const riscv_opcode_t **pop);

/* Test if the op is favorite one.  */

typedef struct
  {
    bool has_c;
    bool has_p;
    bool has_zcm;
    bool has_xnexecit;
  } args_t;

static bool
is_preferred_subset (const struct riscv_opcode *op, args_t *args)
{
  if (args->has_zcm && op->insn_class == INSN_CLASS_F_AND_C)
    {
      return false;
    }

  return true;
}

static void
riscv_execit_info (bfd_vma pc ATTRIBUTE_UNUSED,
		   disassemble_info *info, uint32_t execit_index)
{
  uint32_t insn;
  static asection *section = NULL;
  static bfd_vma bias = 0;
  bfd_byte buffer[4];
  int insnlen;
  private_data_t *pd = info->private_data;
  bfd_vma keep;

  /* If no section info can be related to this exec.it insn, this may be just
     a uninitiated memory content, so not to decode it.  */
  if (info->section == NULL)
    return;

  /* Lookup section in which itb is located.  */
  if (!section)
    {
      section = bfd_get_section_by_name (info->section->owner, EXECIT_SECTION);
      /* if not found, try symbol "_ITB_BASE_".  */
      if (section == NULL)
	{ /* TODO: find the existed API to do this.  */
	  int i;
	  for (i=0; i<info->symtab_size; i++)
	    {
	      if (0 == strcmp ("_ITB_BASE_", info->symtab[i]->name))
		{
		  section = info->symtab[i]->section;
		  bias = info->symtab[i]->value;
		  break;
		}
	    }
	}

      /* Lookup it only once, in case .exec.itable doesn't exist at all.  */
      if (section == NULL)
	section = (void *) -1;
    }

  if (section == (void *) -1)
    return;

  if (!section->owner)
    return;

  bfd_get_section_contents (section->owner, section, buffer,
			    execit_index * 4 + bias, 4);
  insn = bfd_get_32 (section->owner, buffer);
  insnlen = riscv_insn_length (insn);

  keep = pd->flags;
  pd->flags |= FLAG_EXECIT;
  /* 16-bit instructions in .exec.itable.  */
  if (insnlen == 2)
    riscv_disassemble_insn (pc, (insn & 0x0000FFFF), info);
  /* 32-bit instructions in .exec.itable.  */
  else
    riscv_disassemble_insn (pc, insn, info);
  pd->flags = keep;

  /* bytes_per_chunk is referred to dump insn binary after v2.32
     fix it here for exec.it.  */
  info->bytes_per_chunk = 2;
}
/* } Andes  */

/* { Andes ACE */
/* Pointers for storing symbols from ACE shared library */
struct riscv_opcode *ace_opcs;
ace_op_t *ace_ops;
ace_keyword_t *ace_keys;
/* Represent whether ACE shared library is loaded successfully */
bool ace_lib_load_success = false;
/* Debugging mode:
 * Show the ACE insn even if the ACE library is loaded fail.  */
static int debugging;

static void
print_ace_args (const char **args, insn_t l, disassemble_info * info);
/* } Andes ACE */

static void
set_default_riscv_dis_options (void)
{
  riscv_gpr_names = riscv_gpr_names_abi;
  riscv_fpr_names = riscv_fpr_names_abi;
  no_aliases = 0;
  no_prefer = 0;
  numeric = 0;
}

static bool
parse_riscv_dis_option_without_args (const char *option)
{
  if (strcmp (option, "no-aliases") == 0)
    no_aliases = 1;
  else if (strcmp (option, "numeric") == 0)
    {
      riscv_gpr_names = riscv_gpr_names_numeric;
      riscv_fpr_names = riscv_fpr_names_numeric;
      numeric = 1;
    }
  /* { Andes */
  else if (strcmp (option, "_no-prefer") == 0)
    no_prefer = 1;
  /* } Andes */
  /* { Andes ACE */
  else if (strcmp (option, "debugging") == 0)
    debugging = 1;
  /* } Andes ACE */
  else
    return false;
  return true;
}

/* Note: sub andes_ace_load_hooks is shared between gas and gdb
	  without a common header file. */

char *andes_ace_load_hooks (const char *arg)
{
  void *dlc = dlopen (arg, RTLD_NOW | RTLD_LOCAL);
  char *err = NULL;

  if (dlc == NULL)
    err = (char *) dlerror ();
  else
    {
      ace_ops = (ace_op_t *) dlsym (dlc, "ace_operands");
      err = (char *) dlerror ();
      if (err == NULL)
	{
	  ace_opcs = (struct riscv_opcode *) dlsym (dlc, "ace_opcodes_3");
	  err = (char *) dlerror ();
	  if (err == NULL)
	    {
	      ace_keys = (ace_keyword_t *) dlsym (dlc, "ace_keywords");
	      err = (char *) dlerror ();
	    }
	}
    }

  if (err == NULL)
    ace_lib_load_success = true;

  return err;
}

static void
parse_riscv_dis_option (const char *option)
{
  char *equal, *value;

  if (parse_riscv_dis_option_without_args (option))
    return;

  equal = strchr (option, '=');
  if (equal == NULL)
    {
      /* The option without '=' should be defined above.  */
      opcodes_error_handler (_("unrecognized disassembler option: %s"), option);
      return;
    }
  if (equal == option
      || *(equal + 1) == '\0')
    {
      /* Invalid options with '=', no option name before '=',
       and no value after '='.  */
      opcodes_error_handler (_("unrecognized disassembler option with '=': %s"),
                            option);
      return;
    }

  *equal = '\0';
  value = equal + 1;
  if (strcmp (option, "priv-spec") == 0)
    {
      enum riscv_spec_class priv_spec = PRIV_SPEC_CLASS_NONE;
      const char *name = NULL;

      RISCV_GET_PRIV_SPEC_CLASS (value, priv_spec);
      if (priv_spec == PRIV_SPEC_CLASS_NONE)
	opcodes_error_handler (_("unknown privileged spec set by %s=%s"),
			       option, value);
      else if (default_priv_spec == PRIV_SPEC_CLASS_NONE)
	default_priv_spec = priv_spec;
      else if (default_priv_spec != priv_spec)
	{
	  RISCV_GET_PRIV_SPEC_NAME (name, default_priv_spec);
	  opcodes_error_handler (_("mis-matched privilege spec set by %s=%s, "
				   "the elf privilege attribute is %s"),
				 option, value, name);
	}
    }
  /* { Andes ACE */
  /* Load ACE shared library if ACE option is enable */
  else if (strcmp (option, "ace") == 0)
    {
#ifndef __MINGW32__
      char *ace_lib_path = malloc (strlen (value));
      strcpy (ace_lib_path, value);
      char *err = andes_ace_load_hooks(ace_lib_path);
      if (err)
        opcodes_error_handler (_("Fault to load ACE shared library: %s\n"), err);
#endif
    }
  /* } Andes ACE */
  /* { Andes */
  else if (strcmp (option, "_patch-arch") == 0)
    {
      while (value)
	{
	  char *p = strstr (value, "_");
	  if (p)
	    *p = 0;
	  riscv_parse_add_subset (&riscv_rps_dis, value,
		RISCV_UNKNOWN_VERSION, RISCV_UNKNOWN_VERSION, false);
	  value = p ? p + 1 : p;
	}
    }
  /* } Andes */
  else
    {
      /* xgettext:c-format */
      opcodes_error_handler (_("unrecognized disassembler option: %s"), option);
    }
}

static void
parse_riscv_dis_options (const char *opts_in)
{
  char *opts = xstrdup (opts_in), *opt = opts, *opt_end = opts;

  set_default_riscv_dis_options ();

  for ( ; opt_end != NULL; opt = opt_end + 1)
    {
      if ((opt_end = strchr (opt, ',')) != NULL)
	*opt_end = 0;
      parse_riscv_dis_option (opt);
    }

  free (opts);
}

/* Print one argument from an array.  */

static void
arg_print (struct disassemble_info *info, unsigned long val,
	   const char* const* array, size_t size)
{
  const char *s = val >= size || array[val] == NULL ? "unknown" : array[val];
  (*info->fprintf_func) (info->stream, "%s", s);
}

static void
maybe_print_address (struct riscv_private_data *pd, int base_reg, int offset,
		     int wide)
{
  if (pd->hi_addr[base_reg] != (bfd_vma)-1)
    {
      pd->print_addr = (base_reg != 0 ? pd->hi_addr[base_reg] : 0) + offset;
      pd->hi_addr[base_reg] = -1;
    }
  else if (base_reg == X_GP && pd->gp != (bfd_vma)-1)
    pd->print_addr = pd->gp + offset;
  else if (base_reg == X_TP || base_reg == 0)
    pd->print_addr = offset;

  /* Sign-extend a 32-bit value to a 64-bit value.  */
  if (wide)
    pd->print_addr = (bfd_vma)(int32_t) pd->print_addr;
}

/* Print table jump index.  */

static bool
print_jvt_index (disassemble_info *info, unsigned int index)
{
  bfd_vma entry_value;
  bfd_vma memaddr;
  int status;

  bfd_byte packet[8] = {0};
  struct riscv_private_data *pd = info->private_data;

  memaddr = pd->jvt_base + index * (xlen/8);
  status = (*info->read_memory_func) (memaddr, packet, xlen / 8, info);
  if (status != 0)
    return false;

  entry_value = xlen == 32 ? bfd_getl32 (packet)
			    : bfd_getl64 (packet);

  maybe_print_address (pd, 0, entry_value, 0);
  return true;
}

/* Print table jump entry value.  */

static bool
print_jvt_entry_value (disassemble_info *info, bfd_vma memaddr)
{
  bfd_vma entry_value;
  int status;
  struct riscv_private_data *pd = info->private_data;
  bfd_byte packet[8] = {0};
  unsigned index = (memaddr - pd->jvt_base) / (xlen / 8);

  status = (*info->read_memory_func) (memaddr, packet, xlen / 8, info);
  if (status != 0)
    return false;

  entry_value = xlen == 32 ? bfd_getl32 (packet)
			    : bfd_getl64 (packet);

  info->target = entry_value;
  (*info->fprintf_func) (info->stream, "index %u # ", index);
  (*info->print_address_func) (info->target, info);
  return true;
}

/* Get ZCMP rlist field. */

static void
print_rlist (disassemble_info *info, insn_t l)
{
  unsigned rlist = (int)EXTRACT_OPERAND (RLIST, l);
  unsigned r_start = numeric ? X_S2 : X_S0;
  info->fprintf_func (info->stream, "%s", riscv_gpr_names[X_RA]);

  if (rlist == 5)
    info->fprintf_func (info->stream, ",%s", riscv_gpr_names[X_S0]);
  else if (rlist == 6 || (numeric && rlist > 6))
    info->fprintf_func (info->stream, ",%s-%s",
	  riscv_gpr_names[X_S0],
	  riscv_gpr_names[X_S1]);

  if (rlist == 15)
    info->fprintf_func (info->stream, ",%s-%s",
	  riscv_gpr_names[r_start],
	  riscv_gpr_names[X_S11]);
  else if (rlist == 7 && numeric)
    info->fprintf_func (info->stream, ",%s",
	  riscv_gpr_names[X_S2]);
  else if (rlist > 6)
    info->fprintf_func (info->stream, ",%s-%s",
	  riscv_gpr_names[r_start],
	  riscv_gpr_names[rlist + 11]);
}

/* Get ZCMP sp adjustment immediate. */

static int
riscv_get_spimm (insn_t l)
{
  int spimm = riscv_get_base_spimm(l, &riscv_rps_dis);

  spimm += EXTRACT_ZCMP_SPIMM (l);

  if (((l ^ MATCH_CM_PUSH) & MASK_CM_PUSH) == 0)
    spimm *= -1;

  return spimm;
}

/* Get s-register regno by using sreg number.
  e.g. the regno of s0 is 8, so
  riscv_get_sregno (0) equals 8. */

static unsigned
riscv_get_sregno (unsigned sreg_idx)
{
  return sreg_idx > 1 ?
      sreg_idx + 16 : sreg_idx + 8;
}

/* Print insn arguments for 32/64-bit code.  */

static void
print_insn_args (const char *oparg, insn_t l, bfd_vma pc, disassemble_info *info)
{
  struct riscv_private_data *pd = info->private_data;
  int rs1 = (l >> OP_SH_RS1) & OP_MASK_RS1;
  int rd = (l >> OP_SH_RD) & OP_MASK_RD;
  fprintf_ftype print = info->fprintf_func;
  const char *opargStart;

  if (*oparg != '\0')
    print (info->stream, "\t");

  for (; *oparg != '\0'; oparg++)
    {
      opargStart = oparg;
      switch (*oparg)
	{
	case 'C': /* RVC */
	  switch (*++oparg)
	    {
	    case 's': /* RS1 x8-x15.  */
	    case 'w': /* RS1 x8-x15.  */
	      print (info->stream, "%s",
		     riscv_gpr_names[EXTRACT_OPERAND (CRS1S, l) + 8]);
	      break;
	    case 't': /* RS2 x8-x15.  */
	    case 'x': /* RS2 x8-x15.  */
	      print (info->stream, "%s",
		     riscv_gpr_names[EXTRACT_OPERAND (CRS2S, l) + 8]);
	      break;
	    case 'U': /* RS1, constrained to equal RD.  */
	      print (info->stream, "%s", riscv_gpr_names[rd]);
	      break;
	    case 'c': /* RS1, constrained to equal sp.  */
	      print (info->stream, "%s", riscv_gpr_names[X_SP]);
	      break;
	    case 'V': /* RS2 */
	      print (info->stream, "%s",
		     riscv_gpr_names[EXTRACT_OPERAND (CRS2, l)]);
	      break;
	    case 'o':
	    case 'j':
	      if (((l & MASK_C_ADDI) == MATCH_C_ADDI) && rd != 0)
		maybe_print_address (pd, rd, EXTRACT_CITYPE_IMM (l), 0);
	      if (info->mach == bfd_mach_riscv64
		  && ((l & MASK_C_ADDIW) == MATCH_C_ADDIW) && rd != 0)
		maybe_print_address (pd, rd, EXTRACT_CITYPE_IMM (l), 1);
	      print (info->stream, "%d", (int)EXTRACT_CITYPE_IMM (l));
	      break;
	    case 'k':
	      print (info->stream, "%d", (int)EXTRACT_CLTYPE_LW_IMM (l));
	      break;
	    case 'l':
	      print (info->stream, "%d", (int)EXTRACT_CLTYPE_LD_IMM (l));
	      break;
	    case 'm':
	      print (info->stream, "%d", (int)EXTRACT_CITYPE_LWSP_IMM (l));
	      break;
	    case 'n':
	      print (info->stream, "%d", (int)EXTRACT_CITYPE_LDSP_IMM (l));
	      break;
	    case 'K':
	      print (info->stream, "%d", (int)EXTRACT_CIWTYPE_ADDI4SPN_IMM (l));
	      break;
	    case 'L':
	      print (info->stream, "%d", (int)EXTRACT_CITYPE_ADDI16SP_IMM (l));
	      break;
	    case 'M':
	      print (info->stream, "%d", (int)EXTRACT_CSSTYPE_SWSP_IMM (l));
	      break;
	    case 'N':
	      print (info->stream, "%d", (int)EXTRACT_CSSTYPE_SDSP_IMM (l));
	      break;
	    case 'p':
	      info->target = EXTRACT_CBTYPE_IMM (l) + pc;
	      (*info->print_address_func) (info->target, info);
	      break;
	    case 'a':
	      info->target = EXTRACT_CJTYPE_IMM (l) + pc;
	      (*info->print_address_func) (info->target, info);
	      break;
	    case 'u':
	      print (info->stream, "0x%x",
		     (int)(EXTRACT_CITYPE_IMM (l) & (RISCV_BIGIMM_REACH-1)));
	      break;
	    case '>':
	      print (info->stream, "0x%x", (int)EXTRACT_CITYPE_IMM (l) & 0x3f);
	      break;
	    case '<':
	      print (info->stream, "0x%x", (int)EXTRACT_CITYPE_IMM (l) & 0x1f);
	      break;
	    case 'T': /* Floating-point RS2.  */
	      print (info->stream, "%s",
		     riscv_fpr_names[EXTRACT_OPERAND (CRS2, l)]);
	      break;
	    case 'D': /* Floating-point RS2 x8-x15.  */
	      print (info->stream, "%s",
		     riscv_fpr_names[EXTRACT_OPERAND (CRS2S, l) + 8]);
	      break;
	    /* { Andes  */
	    case 'e':
	      switch (*++oparg)
		{
		case 'i':
		  print (info->stream, "#%d	!", (int)EXTRACT_RVC_EX9IT_IMM (l) >> 2);
		  riscv_execit_info (pc, info, (int)EXTRACT_RVC_EX9IT_IMM (l) >> 2);
		  break;
		case 't':
		  print (info->stream, "#%d     !", (int)EXTRACT_RVC_EXECIT_IMM (l) >> 2);
		  riscv_execit_info (pc, info, (int)EXTRACT_RVC_EXECIT_IMM (l) >> 2);
		  break;
		case 'T':
		  print (info->stream, "#%d     !", (int)EXTRACT_RVC_NEXECIT_IMM (l) >> 2);
		  riscv_execit_info (pc, info, (int)EXTRACT_RVC_NEXECIT_IMM (l) >> 2);
		  break;
		}
	      break;
	    /* } Andes  */
	    case 'Z': /* ZC 16 bits length instruction fields. */
	      switch (*++oparg)
		{
		case '1':
		  print (info->stream, "%s", riscv_gpr_names[
		      riscv_get_sregno (EXTRACT_OPERAND (SREG1, l))]);
		  break;
		case '2':
		  print (info->stream, "%s", riscv_gpr_names[
		      riscv_get_sregno (EXTRACT_OPERAND (SREG2, l))]);
		  break;
		case 'b':
		  print (info->stream, "%d", (int)EXTRACT_ZCB_BYTE_UIMM (l));
		  break;
		case 'h':
		  print (info->stream, "%d", (int)EXTRACT_ZCB_HALFWORD_UIMM (l));
		  break;
		case 'B':
		  print (info->stream, "%d", (int)EXTRACT_ZCMB_BYTE_UIMM (l));
		  break;
		case 'H':
		  print (info->stream, "%d", (int)EXTRACT_ZCMB_HALFWORD_UIMM (l));
		  break;
		case 'r':
		  print_rlist (info, l);
		  break;
		case 'p':
		  print (info->stream, "%d", riscv_get_spimm (l));
		  break;
		case 'i':
		case 'I':
		  print (info->stream, "%lu", EXTRACT_ZCMP_TABLE_JUMP_INDEX (l));
		  print_jvt_index (info, EXTRACT_ZCMP_TABLE_JUMP_INDEX (l));
		  break;
		default: break;
		}
	      break;
	    }
	  break;

	case 'V': /* RVV */
	  switch (*++oparg)
	    {
	    case 'd':
	    case 'f':
	      print (info->stream, "%s",
		     riscv_vecr_names_numeric[EXTRACT_OPERAND (VD, l)]);
	      break;
	    case 'e':
	      if (!EXTRACT_OPERAND (VWD, l))
		print (info->stream, "%s", riscv_gpr_names[0]);
	      else
		print (info->stream, "%s",
		       riscv_vecr_names_numeric[EXTRACT_OPERAND (VD, l)]);
	      break;
	    case 's':
	      print (info->stream, "%s",
		     riscv_vecr_names_numeric[EXTRACT_OPERAND (VS1, l)]);
	      break;
	    case 't':
	    case 'u': /* VS1 == VS2 already verified at this point.  */
	    case 'v': /* VD == VS1 == VS2 already verified at this point.  */
	      print (info->stream, "%s",
		     riscv_vecr_names_numeric[EXTRACT_OPERAND (VS2, l)]);
	      break;
	    case '0':
	      print (info->stream, "%s", riscv_vecr_names_numeric[0]);
	      break;
	    case 'b':
	    case 'c':
	      {
		int imm = (*oparg == 'b') ? EXTRACT_RVV_VB_IMM (l)
					  : EXTRACT_RVV_VC_IMM (l);
		unsigned int imm_vlmul = EXTRACT_OPERAND (VLMUL, imm);
		unsigned int imm_vsew = EXTRACT_OPERAND (VSEW, imm);
		unsigned int imm_vta = EXTRACT_OPERAND (VTA, imm);
		unsigned int imm_vma = EXTRACT_OPERAND (VMA, imm);
		unsigned int imm_vtype_res = (imm >> 8);

		if (imm_vsew < ARRAY_SIZE (riscv_vsew)
		    && imm_vlmul < ARRAY_SIZE (riscv_vlmul)
		    && imm_vta < ARRAY_SIZE (riscv_vta)
		    && imm_vma < ARRAY_SIZE (riscv_vma)
		    && !imm_vtype_res
		    && riscv_vsew[imm_vsew] != NULL
		    && riscv_vlmul[imm_vlmul] != NULL)
		  print (info->stream, "%s,%s,%s,%s", riscv_vsew[imm_vsew],
			 riscv_vlmul[imm_vlmul], riscv_vta[imm_vta],
			 riscv_vma[imm_vma]);
		else
		  print (info->stream, "%d", imm);
	      }
	      break;
	    case 'i':
	      print (info->stream, "%d", (int)EXTRACT_RVV_VI_IMM (l));
	      break;
	    case 'j':
	      print (info->stream, "%d", (int)EXTRACT_RVV_VI_UIMM (l));
	      break;
	    case 'k':
	      print (info->stream, "%d", (int)EXTRACT_RVV_OFFSET (l));
	      break;
	    case 'm':
	      if (! EXTRACT_OPERAND (VMASK, l))
		print (info->stream, ",%s", riscv_vecm_names_numeric[0]);
	      break;
	    }
	  break;

	case 'f':
	  print (info->stream, "%d", (int)EXTRACT_STYPE_IMM (l));
	  break;

	/* { Andes  */
	case 'g':
	  info->target = EXTRACT_STYPE_IMM10 (l) + pc;
	  (*info->print_address_func) (info->target, info);
	  break;

	case 'h':
	  print (info->stream, "%d", (int)EXTRACT_ITYPE_IMM6H (l));
	  break;

	case 'i':
	  print (info->stream, "%d", (int)EXTRACT_STYPE_IMM7 (l));
	  break;

	case 'k':
	  print (info->stream, "%d", (int)EXTRACT_TYPE_CIMM6 (l));
	  break;

	case 'l':
	  print (info->stream, "%d", (int)EXTRACT_ITYPE_IMM6L (l));
	  break;

	case 'G':
	  switch (*++oparg)
	    {
	    case 'b':
	      maybe_print_address (pd, X_GP, EXTRACT_GPTYPE_LB_IMM (l), 0);
	      print (info->stream, "%d", (int)EXTRACT_GPTYPE_LB_IMM (l));
	      break;
	    case 'h':
	      maybe_print_address (pd, X_GP, EXTRACT_GPTYPE_LH_IMM (l), 0);
	      print (info->stream, "%d", (int)EXTRACT_GPTYPE_LH_IMM (l));
	      break;
	    case 'w':
	      maybe_print_address (pd, X_GP, EXTRACT_GPTYPE_LW_IMM (l), 0);
	      print (info->stream, "%d", (int)EXTRACT_GPTYPE_LW_IMM (l));
	      break;
	    case 'd':
	      maybe_print_address (pd, X_GP, EXTRACT_GPTYPE_LD_IMM (l), 0);
	      print (info->stream, "%d", (int)EXTRACT_GPTYPE_LD_IMM (l));
	      break;
	    }
	  break;

	case 'H':
	  switch (*++oparg)
	    {
	    case 'b':
	      maybe_print_address (pd, X_GP, EXTRACT_GPTYPE_SB_IMM (l), 0);
	      print (info->stream, "%d", (int)EXTRACT_GPTYPE_SB_IMM (l));
	      break;
	    case 'h':
	      maybe_print_address (pd, X_GP, EXTRACT_GPTYPE_SH_IMM (l), 0);
	      print (info->stream, "%d", (int)EXTRACT_GPTYPE_SH_IMM (l));
	      break;
	    case 'w':
	      maybe_print_address (pd, X_GP, EXTRACT_GPTYPE_SW_IMM (l), 0);
	      print (info->stream, "%d", (int)EXTRACT_GPTYPE_SW_IMM (l));
	      break;
	    case 'd':
	      maybe_print_address (pd, X_GP, EXTRACT_GPTYPE_SD_IMM (l), 0);
	      print (info->stream, "%d", (int)EXTRACT_GPTYPE_SD_IMM (l));
	      break;
	    }
	  break;

	case 'N':
	  switch (*++oparg)
	    {
	    case 'c': /* rc */
	      print (info->stream, "%s",
		     riscv_gpr_names[EXTRACT_OPERAND (RC, l)]);
	      break;
	    case 'd': /* rdp */
	      print (info->stream, "%s", riscv_gpr_names[rd]);
	      break;
	    case 's': /* rsp */
	      print (info->stream, "%s", riscv_gpr_names[rs1]);
	      break;
	    case 't': /* rtp */
	      print (info->stream, "%s",
		     riscv_gpr_names[EXTRACT_OPERAND (RS2, l)]);
	      break;
	    case '3': /* i3u */
	      print (info->stream, "%d", (int)EXTRACT_PTYPE_IMM3U (l));
	      break;
	    case '4': /* i4u */
	      print (info->stream, "%d", (int)EXTRACT_PTYPE_IMM4U (l));
	      break;
	    case '5': /* i5u */
	      print (info->stream, "%d", (int)EXTRACT_PTYPE_IMM5U (l));
	      break;
	    case '6': /* i6u */
	      print (info->stream, "%d", (int)EXTRACT_PTYPE_IMM6U (l));
	      break;
	    case 'f': /* i15s */
	      print (info->stream, "%d", (int)EXTRACT_PTYPE_IMM15S (l));
	      break;
	    }
	  break;
	/* } Andes  */

	case ',':
	case '(':
	case ')':
	case '[':
	case ']':
	case '{':
	case '}':
	  print (info->stream, "%c", *oparg);
	  break;

	case '0':
	  /* Only print constant 0 if it is the last argument.  */
	  if (!oparg[1])
	    print (info->stream, "0");
	  break;

	case 'b':
	case 's':
	  if ((l & MASK_JALR) == MATCH_JALR)
	    maybe_print_address (pd, rs1, 0, 0);
	  print (info->stream, "%s", riscv_gpr_names[rs1]);
	  break;

	case 't':
	  print (info->stream, "%s",
		 riscv_gpr_names[EXTRACT_OPERAND (RS2, l)]);
	  break;

	case 'u':
	  print (info->stream, "0x%x",
		 (unsigned)EXTRACT_UTYPE_IMM (l) >> RISCV_IMM_BITS);
	  break;

	case 'm':
	  arg_print (info, EXTRACT_OPERAND (RM, l),
		     riscv_rm, ARRAY_SIZE (riscv_rm));
	  break;

	case 'P':
	  arg_print (info, EXTRACT_OPERAND (PRED, l),
		     riscv_pred_succ, ARRAY_SIZE (riscv_pred_succ));
	  break;

	case 'Q':
	  arg_print (info, EXTRACT_OPERAND (SUCC, l),
		     riscv_pred_succ, ARRAY_SIZE (riscv_pred_succ));
	  break;

	case 'o':
	  maybe_print_address (pd, rs1, EXTRACT_ITYPE_IMM (l), 0);
	  /* Fall through.  */
	case 'j':
	  if (((l & MASK_ADDI) == MATCH_ADDI && rs1 != 0)
	      || (l & MASK_JALR) == MATCH_JALR)
	    maybe_print_address (pd, rs1, EXTRACT_ITYPE_IMM (l), 0);
	  if (info->mach == bfd_mach_riscv64
	      && ((l & MASK_ADDIW) == MATCH_ADDIW) && rs1 != 0)
	    maybe_print_address (pd, rs1, EXTRACT_ITYPE_IMM (l), 1);
	  print (info->stream, "%d", (int)EXTRACT_ITYPE_IMM (l));
	  break;

	case 'q':
	  maybe_print_address (pd, rs1, EXTRACT_STYPE_IMM (l), 0);
	  print (info->stream, "%d", (int)EXTRACT_STYPE_IMM (l));
	  break;

	case 'a':
	  if (pd->flags & FLAG_EXECIT)
	    { /* Check instruction in .exec.itable.  */
	      info->target = EXTRACT_UJTYPE_IMM_EXECIT_TAB (l);
	      info->target |= (pc & 0xffe00000);
	      (*info->print_address_func) (info->target, info);
	    }
	  else if (pd->flags & FLAG_EXECIT_TAB)
	    { /* Check if decode .exec.itable.  */
	      info->target = EXTRACT_UJTYPE_IMM_EXECIT_TAB (l);
	      print (info->stream, "PC(31,21)|#0x%lx", (long) info->target);
	    }
	  else
	    {
	      info->target = EXTRACT_JTYPE_IMM (l) + pc;
	      (*info->print_address_func) (info->target, info);
	    }
	  break;

	case 'p':
	  info->target = EXTRACT_BTYPE_IMM (l) + pc;
	  (*info->print_address_func) (info->target, info);
	  break;

	case 'd':
	  if ((l & MASK_AUIPC) == MATCH_AUIPC)
	    pd->hi_addr[rd] = pc + EXTRACT_UTYPE_IMM (l);
	  else if ((l & MASK_LUI) == MATCH_LUI)
	    pd->hi_addr[rd] = EXTRACT_UTYPE_IMM (l);
	  else if ((l & MASK_C_LUI) == MATCH_C_LUI)
	    pd->hi_addr[rd] = EXTRACT_CITYPE_LUI_IMM (l);
	  print (info->stream, "%s", riscv_gpr_names[rd]);
	  break;

	case 'y':
	  print (info->stream, "0x%x", (int)EXTRACT_OPERAND (BS, l));
	  break;

	case 'z':
	  print (info->stream, "%s", riscv_gpr_names[0]);
	  break;

	case '>':
	  print (info->stream, "0x%x", (int)EXTRACT_OPERAND (SHAMT, l));
	  break;

	case '<':
	  print (info->stream, "0x%x", (int)EXTRACT_OPERAND (SHAMTW, l));
	  break;

	case 'S':
	case 'U':
	  print (info->stream, "%s", riscv_fpr_names[rs1]);
	  break;

	case 'T':
	  print (info->stream, "%s", riscv_fpr_names[EXTRACT_OPERAND (RS2, l)]);
	  break;

	case 'D':
	  print (info->stream, "%s", riscv_fpr_names[rd]);
	  break;

	case 'R':
	  print (info->stream, "%s", riscv_fpr_names[EXTRACT_OPERAND (RS3, l)]);
	  break;

	case 'E':
	  {
	    static const char *riscv_csr_hash[4096]; /* Total 2^12 CSRs.  */
	    static bool init_csr = false;
	    unsigned int csr = EXTRACT_OPERAND (CSR, l);

	    if (!init_csr)
	      {
		unsigned int i;
		for (i = 0; i < 4096; i++)
		  riscv_csr_hash[i] = NULL;

		/* Set to the newest privileged version.  */
		if (default_priv_spec == PRIV_SPEC_CLASS_NONE)
		  default_priv_spec = PRIV_SPEC_CLASS_DRAFT - 1;

#define DECLARE_CSR(name, num, class, define_version, abort_version)	\
		if (riscv_csr_hash[num] == NULL 			\
		    && ((define_version == PRIV_SPEC_CLASS_NONE 	\
			 && abort_version == PRIV_SPEC_CLASS_NONE)	\
			|| (default_priv_spec >= define_version 	\
			    && default_priv_spec < abort_version)))	\
		  riscv_csr_hash[num] = #name;
#define DECLARE_CSR_ALIAS(name, num, class, define_version, abort_version) \
		DECLARE_CSR (name, num, class, define_version, abort_version)
#include "opcode/riscv-opc.h"
#undef DECLARE_CSR
	      }

	    if (riscv_csr_hash[csr] != NULL)
	      print (info->stream, "%s", riscv_csr_hash[csr]);
	    else
	      print (info->stream, "0x%x", csr);
	    break;
	  }

	/* { Andes ACE */
	/* Handle ACE operand field */
	case 'X':
	  if (ace_lib_load_success)
	    {
	      print_ace_args (&oparg, l, info);
	      break;
	    }
	  else
	    {
	      print (info->stream,
		     _("# ACE shared library is not loaded successfully"));
	      return;
	    }
	/* } Andes ACE */

	case 'Y':
	  print (info->stream, "0x%x", (int)EXTRACT_OPERAND (RNUM, l));
	  break;

	case 'Z':
	  print (info->stream, "%d", rs1);
	  break;

	default:
	  /* xgettext:c-format */
	  print (info->stream, _("# internal error, undefined modifier (%c)"),
		 *opargStart);
	  return;
	}
    }
}

/* Print the RISC-V instruction at address MEMADDR in debugged memory,
   on using INFO.  Returns length of the instruction, in bytes.
   BIGENDIAN must be 1 if this is big-endian code, 0 if
   this is little-endian code.  */

static int
riscv_disassemble_insn (bfd_vma memaddr, insn_t word, disassemble_info *info)
{
  const struct riscv_opcode *op;
  static bool init = 0;
  static const struct riscv_opcode *riscv_hash[OP_MASK_OP + 1];
  struct riscv_private_data *pd;
  int insnlen;
  static args_t args; /* Andes */

#define OP_HASH_IDX(i) ((i) & (riscv_insn_length (i) == 2 ? 0x3 : OP_MASK_OP))

  /* Build a hash table to shorten the search time.  */
  if (! init)
    {
      for (op = riscv_opcodes; op->name; op++)
	if (!riscv_hash[OP_HASH_IDX (op->match)])
	  riscv_hash[OP_HASH_IDX (op->match)] = op;

      /* { Andes ACE */
      /* Insert ACE opcode attributes into hash table if exist */
      if (ace_lib_load_success && ace_opcs != NULL && ace_ops != NULL)
	{
	  for (op = ace_opcs; op->name; op++)
	    if (!riscv_hash[OP_HASH_IDX (op->match)])
	      riscv_hash[OP_HASH_IDX (op->match)] = op;
	}
      /* } Andes ACE */

      /* { Andes */
      args.has_c = riscv_multi_subset_supports (&riscv_rps_dis, INSN_CLASS_C);
      args.has_p = riscv_subset_supports (&riscv_rps_dis, "p");
      args.has_zcm = riscv_subset_supports_fuzzy (&riscv_rps_dis, "zcm");
      args.has_xnexecit = riscv_subset_supports (&riscv_rps_dis, "xnexecit");
      /* } Andes */

      init = 1;
    }

  if (info->private_data == NULL)
    {
      int i;
      bfd_vma sym_val;

      pd = info->private_data = xcalloc (1, sizeof (struct riscv_private_data));
      pd->gp = -1;
      pd->print_addr = -1;
      pd->jvt_base = -1;
      pd->jvt_end = -1;

      for (i = 0; i < (int)ARRAY_SIZE (pd->hi_addr); i++)
	pd->hi_addr[i] = -1;

      for (i = 0; i < info->symtab_size; i++)
        {
	  if (strcmp (bfd_asymbol_name (info->symtab[i]), RISCV_GP_SYMBOL) == 0)
	    pd->gp = bfd_asymbol_value (info->symtab[i]);
	  /* Read the address of table jump entries.  */
	  else if (strcmp (bfd_asymbol_name (info->symtab[i]),
				  RISCV_TABLE_JUMP_BASE_SYMBOL) == 0)
	    pd->jvt_base = bfd_asymbol_value (info->symtab[i]);
	}

      /* Calculate the closest symbol from jvt base to determine the size of table jump
          entry section.  */
      if (pd->jvt_base != 0)
	{
	  for (i = 0; i < info->symtab_size; i++)
	    {
	      sym_val = bfd_asymbol_value (info->symtab[i]);
	      if (sym_val > pd->jvt_base && sym_val < pd->jvt_end)
	        pd->jvt_end = sym_val;
	    }
	}
    }
  else
    pd = info->private_data;

  /* { Andes */
  if (info->section
      && strstr (info->section->name, EXECIT_SECTION) != NULL)
    pd->flags |= FLAG_EXECIT_TAB;
  else
    pd->flags &= ~FLAG_EXECIT_TAB;
  /* } Andes */

  insnlen = riscv_insn_length (word);

  /* RISC-V instructions are always little-endian.  */
  info->endian_code = BFD_ENDIAN_LITTLE;

  info->bytes_per_chunk = insnlen % 4 == 0 ? 4 : 2;
  info->bytes_per_line = 8;
  /* We don't support constant pools, so this must be code.  */
  info->display_endian = info->endian_code;
  info->insn_info_valid = 1;
  info->branch_delay_insns = 0;
  info->data_size = 0;
  info->insn_type = dis_nonbranch;
  info->target = 0;
  info->target2 = 0;

  op = riscv_hash[OP_HASH_IDX (word)];
  if (op != NULL)
    {
      /* If XLEN is not known, get its value from the ELF class.  */
      if (info->mach == bfd_mach_riscv64)
	xlen = 64;
      else if (info->mach == bfd_mach_riscv32)
	xlen = 32;
      else if (info->section != NULL)
	{
	  Elf_Internal_Ehdr *ehdr = elf_elfheader (info->section->owner);
	  xlen = ehdr->e_ident[EI_CLASS] == ELFCLASS64 ? 64 : 32;
	}

      if (pd->jvt_base
	  && (pd->jvt_end > pd->jvt_base + 255 * (xlen / 8)))
        pd->jvt_end = pd->jvt_base + 255 * (xlen / 8);

      /* Dump jump table entries.  */
      if (riscv_subset_supports (&riscv_rps_dis, "zcmt")
	  && pd->jvt_base != 0
	  && pd->jvt_base != (bfd_vma)-1
	  && memaddr >= pd->jvt_base
	  && memaddr < pd->jvt_end
	  && print_jvt_entry_value (info, memaddr))
	{
	  info->bytes_per_chunk = xlen / 8;
	  return xlen / 8;
	}

      /* If arch has ZFINX flags, use gpr for disassemble.  */
      if(riscv_subset_supports (&riscv_rps_dis, "zfinx"))
	riscv_fpr_names = riscv_gpr_names_abi;

      /* { Andes */
      /* prefer RVC/RVP when supported.  */
      const struct riscv_opcode *op2 = NULL;
      while (!no_prefer)
	{
	  /* RVC has non-canonical aliases within riscv_opcodes[].  */
	  if (insnlen == 2 && args.has_c
	      && andes_find_op_name_match ("c.unimp", 0, riscv_hash, &op2))
	    break;
	#if 0
	  if (insnlen == 2 && has_c
	      && andes_find_op_of_subset (has_rvc, 1, riscv_hash,
					  word, &op2)) break;
	#endif
	  if (insnlen == 4 && args.has_p
	      && andes_find_op_of_subset (has_rvp, no_aliases, riscv_hash,
					  word, &op2)) break;
	  break; /* once */
	}
      op = op2 ? op2 : op;
      /* } Andes */

      for (; op->name; op++)
	{
	  /* Does the opcode match?  */
	  if (! (op->match_func) (op, word))
	    continue;
	  /* Is this a pseudo-instruction and may we print it as such?  */
	  if (no_aliases && (op->pinfo & INSN_ALIAS))
	    continue;
	  /* Is this instruction restricted to a certain value of XLEN?  */
	  if ((op->xlen_requirement != 0) && (op->xlen_requirement != xlen))
	    continue;

	  if (!riscv_multi_subset_supports (&riscv_rps_dis, op->insn_class))
	    continue;

	  if (!riscv_disassemble_subset_tweak (&riscv_rps_dis, op, word))
	    continue;

	  if (!is_preferred_subset (op, &args))
	    continue;

	  /* pick nexec.it if support xnexecit.  */
	  if (args.has_xnexecit && 0 == strcmp (op->name, "exec.it"))
	    continue;

	  /* prefer cm.* if support zcm*.  */
	  if (args.has_zcm && 0 == strncmp (op->name, "c.f", 3))
	    continue;

	  /* It's a match.  */
	  (*info->fprintf_func) (info->stream, "%s", op->name);
	  print_insn_args (op->args, word, memaddr, info);

	  /* Try to disassemble multi-instruction addressing sequences.  */
	  if (pd->print_addr != (bfd_vma)-1)
	    {
	      info->target = pd->print_addr;
	      (*info->fprintf_func) (info->stream, " # ");
	      (*info->print_address_func) (info->target, info);
	      pd->print_addr = -1;
	    }

	  /* Finish filling out insn_info fields.  */
	  switch (op->pinfo & INSN_TYPE)
	    {
	    case INSN_BRANCH:
	      info->insn_type = dis_branch;
	      break;
	    case INSN_CONDBRANCH:
	      info->insn_type = dis_condbranch;
	      break;
	    case INSN_JSR:
	      info->insn_type = dis_jsr;
	      break;
	    case INSN_DREF:
	      info->insn_type = dis_dref;
	      break;
	    default:
	      break;
	    }

	  if (op->pinfo & INSN_DATA_SIZE)
	    {
	      int size = ((op->pinfo & INSN_DATA_SIZE)
			  >> INSN_DATA_SIZE_SHIFT);
	      info->data_size = 1 << (size - 1);
	    }

	  return insnlen;
	}
    }

  /* { Andes ACE */
  /* It may be an ACE insn but the ACE shared library is not loaded.  */
  if (debugging && !ace_lib_load_success && (word & 0x7f) == 0x7b)
    {
      info->insn_type = dis_noninsn;
      (*info->fprintf_func) (info->stream, "ACE insn (0x%llx)",
			     (unsigned long long) word);
    }
  /* } Andes ACE */

  /* We did not find a match, so just print the instruction bits.  */
  info->insn_type = dis_noninsn;
  switch (insnlen)
    {
    case 2:
    case 4:
    case 8:
      (*info->fprintf_func) (info->stream, ".%dbyte\t0x%llx",
                             insnlen, (unsigned long long) word);
      break;
    default:
      {
        int i;
        (*info->fprintf_func) (info->stream, ".byte\t");
        for (i = 0; i < insnlen; ++i)
          {
            if (i > 0)
              (*info->fprintf_func) (info->stream, ", ");
            (*info->fprintf_func) (info->stream, "0x%02x",
                                   (unsigned int) (word & 0xff));
            word >>= 8;
          }
      }
      break;
    }
  return insnlen;
}

/* Return true if we find the suitable mapping symbol,
   and also update the STATE.  Otherwise, return false.  */

static bool
riscv_get_map_state (int n,
		     enum riscv_seg_mstate *state,
		     struct disassemble_info *info)
{
  const char *name;

  /* If the symbol is in a different section, ignore it.  */
  if (info->section != NULL
      && info->section != info->symtab[n]->section)
    return false;

  name = bfd_asymbol_name(info->symtab[n]);
  if (strcmp (name, "$x") == 0)
    *state = MAP_INSN;
  else if (strcmp (name, "$d") == 0)
    *state = MAP_DATA;
  else
    return false;

  return true;
}

/* Check the sorted symbol table (sorted by the symbol value), find the
   suitable mapping symbols.  */

static enum riscv_seg_mstate
riscv_search_mapping_symbol (bfd_vma memaddr,
			     struct disassemble_info *info)
{
  enum riscv_seg_mstate mstate;
  bool from_last_map_symbol;
  bool found = false;
  int symbol = -1;
  int n;

  /* Decide whether to print the data or instruction by default, in case
     we can not find the corresponding mapping symbols.  */
  mstate = MAP_DATA;
  if ((info->section
       && info->section->flags & SEC_CODE)
      || !info->section)
    mstate = MAP_INSN;

  if (info->symtab_size == 0
      || bfd_asymbol_flavour (*info->symtab) != bfd_target_elf_flavour)
    return mstate;

  /* Reset the last_map_symbol if we start to dump a new section.  */
  if (memaddr <= 0)
    last_map_symbol = -1;

  /* If the last stop offset is different from the current one, then
     don't use the last_map_symbol to search.  We usually reset the
     info->stop_offset when handling a new section.  */
  from_last_map_symbol = (last_map_symbol >= 0
			  && info->stop_offset == last_stop_offset);

  /* Start scanning at the start of the function, or wherever
     we finished last time.  */
  n = info->symtab_pos + 1;
  if (from_last_map_symbol && n >= last_map_symbol)
    n = last_map_symbol;

  /* Find the suitable mapping symbol to dump.  */
  for (; n < info->symtab_size; n++)
    {
      bfd_vma addr = bfd_asymbol_value (info->symtab[n]);
      /* We have searched all possible symbols in the range.  */
      if (addr > memaddr)
	break;
      if (riscv_get_map_state (n, &mstate, info))
	{
	  symbol = n;
	  found = true;
	  /* Do not stop searching, in case there are some mapping
	     symbols have the same value, but have different names.
	     Use the last one.  */
	}
    }

  /* We can not find the suitable mapping symbol above.  Therefore, we
     look forwards and try to find it again, but don't go pass the start
     of the section.  Otherwise a data section without mapping symbols
     can pick up a text mapping symbol of a preceeding section.  */
  if (!found)
    {
      n = info->symtab_pos;
      if (from_last_map_symbol && n >= last_map_symbol)
	n = last_map_symbol;

      for (; n >= 0; n--)
	{
	  bfd_vma addr = bfd_asymbol_value (info->symtab[n]);
	  /* We have searched all possible symbols in the range.  */
	  if (addr < (info->section ? info->section->vma : 0))
	    break;
	  /* Stop searching once we find the closed mapping symbol.  */
	  if (riscv_get_map_state (n, &mstate, info))
	    {
	      symbol = n;
	      found = true;
	      break;
	    }
	}
    }

  /* Save the information for next use.  */
  last_map_symbol = symbol;
  last_stop_offset = info->stop_offset;

  return mstate;
}

/* Decide which data size we should print.  */

static bfd_vma
riscv_data_length (bfd_vma memaddr,
		   disassemble_info *info)
{
  bfd_vma length;
  bool found = false;

  length = 4;
  if (info->symtab_size != 0
      && bfd_asymbol_flavour (*info->symtab) == bfd_target_elf_flavour
      && last_map_symbol >= 0)
    {
      int n;
      enum riscv_seg_mstate m = MAP_NONE;
      for (n = last_map_symbol + 1; n < info->symtab_size; n++)
	{
	  bfd_vma addr = bfd_asymbol_value (info->symtab[n]);
	  if (addr > memaddr
	      && riscv_get_map_state (n, &m, info))
	    {
	      if (addr - memaddr < length)
		length = addr - memaddr;
	      found = true;
	      break;
	    }
	}
    }
  if (!found)
    {
      /* Do not set the length which exceeds the section size.  */
      bfd_vma offset = info->section->vma + info->section->size;
      offset -= memaddr;
      length = (offset < length) ? offset : length;
    }
  length = length == 3 ? 2 : length;
  return length;
}

/* Dump the data contents.  */

static int
riscv_disassemble_data (bfd_vma memaddr ATTRIBUTE_UNUSED,
			insn_t data,
			disassemble_info *info)
{
  info->display_endian = info->endian;

  switch (info->bytes_per_chunk)
    {
    case 1:
      info->bytes_per_line = 6;
      (*info->fprintf_func) (info->stream, ".byte\t0x%02llx",
			     (unsigned long long) data);
      break;
    case 2:
      info->bytes_per_line = 8;
      (*info->fprintf_func) (info->stream, ".short\t0x%04llx",
			     (unsigned long long) data);
      break;
    case 4:
      info->bytes_per_line = 8;
      (*info->fprintf_func) (info->stream, ".word\t0x%08llx",
			     (unsigned long long) data);
      break;
    case 8:
      info->bytes_per_line = 8;
      (*info->fprintf_func) (info->stream, ".dword\t0x%016llx",
			     (unsigned long long) data);
      break;
    default:
      abort ();
    }
  return info->bytes_per_chunk;
}

int
print_insn_riscv (bfd_vma memaddr, struct disassemble_info *info)
{
  bfd_byte packet[8];
  insn_t insn = 0;
  bfd_vma dump_size;
  int status;
  enum riscv_seg_mstate mstate;
  int (*riscv_disassembler) (bfd_vma, insn_t, struct disassemble_info *);

  if (info->disassembler_options != NULL)
    {
      parse_riscv_dis_options (info->disassembler_options);
      /* Avoid repeatedly parsing the options.  */
      info->disassembler_options = NULL;
    }
  else if (riscv_gpr_names == NULL)
    set_default_riscv_dis_options ();

  mstate = riscv_search_mapping_symbol (memaddr, info);
  /* Save the last mapping state.  */
  last_map_state = mstate;

  /* Set the size to dump.  */
  if ((mstate == MAP_DATA
       && (info->flags & DISASSEMBLE_DATA) == 0)
       /* odd byte as data.
        * info->stop_offset=0 if invoked by gdb x/i
	*/
      || (info->stop_offset > memaddr
	  && (info->stop_offset - memaddr) == 1))
    {
      dump_size = riscv_data_length (memaddr, info);
      info->bytes_per_chunk = dump_size;
      riscv_disassembler = riscv_disassemble_data;
    }
  else
    {
      /* Get the first 2-bytes to check the lenghth of instruction.  */
      status = (*info->read_memory_func) (memaddr, packet, 2, info);
      if (status != 0)
	{
	  (*info->memory_error_func) (status, memaddr, info);
	  return status;
	}
      insn = (insn_t) bfd_getl16 (packet);
      dump_size = riscv_insn_length (insn);
      riscv_disassembler = riscv_disassemble_insn;
    }

  /* Fetch the instruction to dump.  */
  status = (*info->read_memory_func) (memaddr, packet, dump_size, info);
  if (status != 0)
    {
      (*info->memory_error_func) (status, memaddr, info);
      return status;
    }
  insn = (insn_t) bfd_get_bits (packet, dump_size * 8, false);

  return (*riscv_disassembler) (memaddr, insn, info);
}

disassembler_ftype
riscv_get_disassembler (bfd *abfd)
{
  const char *default_arch = "rv64gc";

  if (abfd)
    {
      const struct elf_backend_data *ebd = get_elf_backend_data (abfd);
      if (ebd)
	{
	  const char *sec_name = ebd->obj_attrs_section;
	  if (bfd_get_section_by_name (abfd, sec_name) != NULL)
	    {
	      obj_attribute *attr = elf_known_obj_attributes_proc (abfd);
	      unsigned int Tag_a = Tag_RISCV_priv_spec;
	      unsigned int Tag_b = Tag_RISCV_priv_spec_minor;
	      unsigned int Tag_c = Tag_RISCV_priv_spec_revision;
	      riscv_get_priv_spec_class_from_numbers (attr[Tag_a].i,
						      attr[Tag_b].i,
						      attr[Tag_c].i,
						      &default_priv_spec);
	      default_arch = attr[Tag_RISCV_arch].s;
	    }
	}
    }

  riscv_release_subset_list (&riscv_subsets);
  riscv_parse_subset (&riscv_rps_dis, default_arch);
  return print_insn_riscv;
}

/* Prevent use of the fake labels that are generated as part of the DWARF
   and for relaxable relocations in the assembler.  */

bool
riscv_symbol_is_valid (asymbol * sym,
                       struct disassemble_info * info ATTRIBUTE_UNUSED)
{
  const char * name;

  if (sym == NULL)
    return false;

  name = bfd_asymbol_name (sym);

  return (strcmp (name, RISCV_FAKE_LABEL_NAME) != 0
	  && !riscv_elf_is_mapping_symbols (name));
}


/* Indices into option argument vector for options accepting an argument.
   Use RISCV_OPTION_ARG_NONE for options accepting no argument.  */

typedef enum
{
  RISCV_OPTION_ARG_NONE = -1,
  RISCV_OPTION_ARG_PRIV_SPEC,

  RISCV_OPTION_ARG_COUNT
} riscv_option_arg_t;

/* Valid RISCV disassembler options.  */

static struct
{
  const char *name;
  const char *description;
  riscv_option_arg_t arg;
} riscv_options[] =
{
  { "numeric",
    N_("Print numeric register names, rather than ABI names."),
    RISCV_OPTION_ARG_NONE },
  { "no-aliases",
    N_("Disassemble only into canonical instructions."),
    RISCV_OPTION_ARG_NONE },
  { "priv-spec=",
    N_("Print the CSR according to the chosen privilege spec."),
    RISCV_OPTION_ARG_PRIV_SPEC }
  /* { Andes */
  ,
  { "_no-prefer",
    N_("Disassemble no prefer instructions."),
    RISCV_OPTION_ARG_NONE },
  { "_arch-patch",
    N_("Patch arch attributes."),
    RISCV_OPTION_ARG_NONE },
  /* } Andes */
};

/* Build the structure representing valid RISCV disassembler options.
   This is done dynamically for maintenance ease purpose; a static
   initializer would be unreadable.  */

const disasm_options_and_args_t *
disassembler_options_riscv (void)
{
  static disasm_options_and_args_t *opts_and_args;

  if (opts_and_args == NULL)
    {
      size_t num_options = ARRAY_SIZE (riscv_options);
      size_t num_args = RISCV_OPTION_ARG_COUNT;
      disasm_option_arg_t *args;
      disasm_options_t *opts;
      size_t i, priv_spec_count;

      /* { Andes */
      /* hide andes options if env not set.  */
      if (getenv ("ANDES_HELP") == NULL)
	{
	  int underscore = 0;
	  for (i = 0; i < num_options; i++)
	    {
	      if (riscv_options[i].name[0] == '_')
		underscore++;
	    }
	  num_options -= underscore;
	}
      /* } Andes */

      args = XNEWVEC (disasm_option_arg_t, num_args + 1);

      args[RISCV_OPTION_ARG_PRIV_SPEC].name = "SPEC";
      priv_spec_count = PRIV_SPEC_CLASS_DRAFT - PRIV_SPEC_CLASS_NONE - 1;
      args[RISCV_OPTION_ARG_PRIV_SPEC].values
        = XNEWVEC (const char *, priv_spec_count + 1);
      for (i = 0; i < priv_spec_count; i++)
	args[RISCV_OPTION_ARG_PRIV_SPEC].values[i]
          = riscv_priv_specs[i].name;
      /* The array we return must be NULL terminated.  */
      args[RISCV_OPTION_ARG_PRIV_SPEC].values[i] = NULL;

      /* The array we return must be NULL terminated.  */
      args[num_args].name = NULL;
      args[num_args].values = NULL;

      opts_and_args = XNEW (disasm_options_and_args_t);
      opts_and_args->args = args;

      opts = &opts_and_args->options;
      opts->name = XNEWVEC (const char *, num_options + 1);
      opts->description = XNEWVEC (const char *, num_options + 1);
      opts->arg = XNEWVEC (const disasm_option_arg_t *, num_options + 1);
      for (i = 0; i < num_options; i++)
	{
	  opts->name[i] = riscv_options[i].name;
	  opts->description[i] = _(riscv_options[i].description);
	  if (riscv_options[i].arg != RISCV_OPTION_ARG_NONE)
	    opts->arg[i] = &args[riscv_options[i].arg];
	  else
	    opts->arg[i] = NULL;
	}
      /* The array we return must be NULL terminated.  */
      opts->name[i] = NULL;
      opts->description[i] = NULL;
      opts->arg[i] = NULL;
    }

  return opts_and_args;
}

void
print_riscv_disassembler_options (FILE *stream)
{
  const disasm_options_and_args_t *opts_and_args;
  const disasm_option_arg_t *args;
  const disasm_options_t *opts;
  size_t max_len = 0;
  size_t i;
  size_t j;

  opts_and_args = disassembler_options_riscv ();
  opts = &opts_and_args->options;
  args = opts_and_args->args;

  fprintf (stream, _("\n\
The following RISC-V specific disassembler options are supported for use\n\
with the -M switch (multiple options should be separated by commas):\n"));
  fprintf (stream, "\n");

  /* Compute the length of the longest option name.  */
  for (i = 0; opts->name[i] != NULL; i++)
    {
      size_t len = strlen (opts->name[i]);

      if (opts->arg[i] != NULL)
	len += strlen (opts->arg[i]->name);
      if (max_len < len)
	max_len = len;
    }

  for (i = 0, max_len++; opts->name[i] != NULL; i++)
    {
      fprintf (stream, "  %s", opts->name[i]);
      if (opts->arg[i] != NULL)
	fprintf (stream, "%s", opts->arg[i]->name);
      if (opts->description[i] != NULL)
	{
	  size_t len = strlen (opts->name[i]);

	  if (opts->arg != NULL && opts->arg[i] != NULL)
	    len += strlen (opts->arg[i]->name);
	  fprintf (stream, "%*c %s", (int) (max_len - len), ' ',
                   opts->description[i]);
	}
      fprintf (stream, "\n");
    }

  for (i = 0; args[i].name != NULL; i++)
    {
      fprintf (stream, _("\n\
  For the options above, the following values are supported for \"%s\":\n   "),
	       args[i].name);
      for (j = 0; args[i].values[j] != NULL; j++)
	fprintf (stream, " %s", args[i].values[j]);
      fprintf (stream, _("\n"));
    }

  fprintf (stream, _("\n"));
}

/* { Andes ACE */
static unsigned int
ace_get_discrete_bit_value(unsigned int bit_value, char *op_name_discrete, const char *op)
{
  bool found_or_token = true;
  unsigned val, ret = 0;
  char *psep, *pval = op_name_discrete + strlen(op);
  unsigned msb = 0, width = 0, width_acc = 0;

  while (found_or_token)
    {
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
	found_or_token = false;
      width = strtoul (pval, (char **) NULL, 10);

      /* Perform mask to truncate oversize value */
      val = bit_value << (32 - msb - 1);
      val >>= 32 - width;
      val <<= width_acc;
      ret |= val;
      width_acc += width;

      /* Prepare condition for next iteration */
      pval = psep + 1;
    }
  return ret;
}

/* Print out ACE instruction assembly code */

static void
print_ace_args (const char **args, insn_t l, disassemble_info * info)
{
  fprintf_ftype print = info->fprintf_func;

  /* Extract field attribute name from opcode description (ace_ops) and
     store the extracted result to var of op_name for finding the
     field attribute information from ace_field_hash */
  bool found_op_str_end = false;
  char *pch = strchr (*args, ',');
  if (pch == NULL)
    {
      pch = strchr (*args, '\0');
      found_op_str_end = true;
    }
  if (pch == NULL)
    return;

  unsigned int op_name_size = pch - (*args + 1);
  char *op_name = malloc (op_name_size + 1);
  memcpy (op_name, *args + 1, op_name_size);
  /* Cat null character to the end of op_name to avoid gash */
  memcpy (op_name + op_name_size, "\0", 1);

  /* With rGPR encoding format, operand bit-field may be discrete.
     There is an "|" token in discrete format */
  bool is_discrete = false;
  char *por = strchr(op_name, '|');
  char *op_name_discrete;
  if (por != NULL)
    {
      is_discrete = true;
      op_name_discrete = malloc(op_name_size + 1);
      strcpy(op_name_discrete, op_name);
      *por = '\0';
    }

  /*  Find the field attribute from ace_field_hash and encode instruction */
  ace_op_t *ace_op = NULL;
  unsigned int i = 0;
  while (ace_ops[i].name)
    {
      if (strcmp (ace_ops[i].name, op_name) == 0)
	{
	  ace_op = &ace_ops[i];
	  break;
	}
      i++;
    }

  if (ace_op != NULL)
    {
      /* Extract the value from defined location */
      unsigned int bit_value = l;
      bit_value <<= 32 - (ace_op->bitpos + 1);
      bit_value >>= 32 - ace_op->bitsize;

      switch (ace_op->hw_res)
	{
	case HW_GPR:
	  print (info->stream, "%s", riscv_gpr_names[bit_value]);
	  break;

	case HW_FPR:
	  print (info->stream, "%s", riscv_fpr_names[bit_value]);
	  break;

	case HW_VR:
	  print (info->stream, "%s", riscv_vecr_names_numeric[bit_value]);
	  break;

	case HW_UINT:
	  if (is_discrete)
	    bit_value = ace_get_discrete_bit_value(l, op_name_discrete, "imm");
	  print (info->stream, "%d", bit_value);
	  break;

	case HW_ACR:
	  if (is_discrete)
	    bit_value = ace_get_discrete_bit_value(l, op_name_discrete, ace_op->hw_name);
	  print (info->stream, "%s_%d", ace_op->hw_name, bit_value);
	  break;
	}
    }
  else
    {
      fprintf (stderr, _("ace_op is NULL\n"));
      return;
    }

  /* Update the address of pointer of the field attribute (*args) */
  if (found_op_str_end == true)
    *args = pch - 1;
  else
    {
      *args = pch;
      print (info->stream, ",");
    }
}
/* } Andes ACE */

/* { Andes */
static bool
andes_find_op_of_subset (has_subset_fun_t has_subset,
			 int no_aliases_p,
			 const struct riscv_opcode **hash,
			 insn_t word,
			 const struct riscv_opcode **pop)
{
  bool is_found = false;
  const struct riscv_opcode *op;

  op = hash[OP_HASH_IDX (word)];
  for (; op->name; op++)
    {
      if (! has_subset (op->insn_class))
	continue;
      if (! (op->match_func) (op, word))
	continue;
      if (no_aliases_p && (op->pinfo & INSN_ALIAS))
	continue;
      if ((op->xlen_requirement != 0) && (op->xlen_requirement != xlen))
	continue;
      is_found = true;
      *pop = op;
      break;
    }

  return is_found;
}

static bool
andes_find_op_name_match (const char *mne,
			  insn_t match,
			  const riscv_opcode_t **hash,
			  const riscv_opcode_t **pop)
{
  bool is_found = false;
  const riscv_opcode_t *op;

  op = hash[OP_HASH_IDX (match)];
  for (; op->name; op++)
    {
      if ((op->xlen_requirement != 0) && (op->xlen_requirement != xlen))
	continue;
      if (op->match != match)
	continue;
      if (strcmp (op->name, mne) != 0)
	continue;

      is_found = true;
      *pop = op;
      break;
    }

  return is_found;
}
/* } Andes */
