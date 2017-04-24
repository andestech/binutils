#include "as.h"
#include "safe-ctype.h"
#include "subsegs.h"
#include "symcat.h"
#include "dwarf2dbg.h"
#include "dw2gencfi.h"
#include "opcodes/nds32-asm.h"
#include "elf/nds32.h"
#include "bfd/elf32-nds32.h"
#include "hash.h"
#include "sb.h"
#include "macro.h"
#include "struc-symbol.h"
#include "opcode/nds32.h"
#include <stdio.h>
#include <errno.h>
#include <limits.h>
const char comment_chars[] = "!";
const char line_comment_chars[] = "#!";
const char line_separator_chars[] = ";";
const char EXP_CHARS[] = "eE";
const char FLT_CHARS[] = "dDfF";
static int enable_16bit = 1;
static bfd_boolean pseudo_opcode = FALSE;
static struct nds32_relocs_pattern *relocs_list = NULL;
struct nds32_relocs_pattern
{
  segT seg;
  fragS *frag;
  frchainS *frchain;
  symbolS *sym;
  fixS* fixP;
  struct nds32_opcode *opcode;
  char *where;
  struct nds32_relocs_pattern *next;
  uint32_t insn;
};
struct suffix_name
{
  char *suffix;
  short unsigned int reloc;
};
static int vec_size = 0;
static int verbatim = 0;
static struct hash_control *nds32_gprs_hash;
static struct hash_control *nds32_hint_hash;
#define TLS_REG "$r27"
#define GOT_NAME "_GLOBAL_OFFSET_TABLE_"
static int enable_relax_relocs = 1;
static int optimize = 0;
static int optimize_for_space = 0;
static int label_exist = 0;
static int in_omit_fp = 0;
extern keyword_t keyword_gpr[];
static bfd_boolean relaxing = FALSE;
static bfd_boolean crcing = FALSE;
static bfd_boolean inline_asm = FALSE;
static bfd_boolean compatible_abi = FALSE;
enum ict_option {
  ICT_NONE = 0,
  ICT_SMALL,
  ICT_LARGE
};
static enum ict_option ict_flag = ICT_NONE;
static bfd_boolean ict_exist = FALSE;
static struct hash_control *nds32_relax_info_hash;
static relax_info_t relax_table[] =
{
    {
      .opcode = "jal",
      .br_range = BR_RANGE_S16M,
      .cond_field = {
     {0, 0, 0, FALSE}
      },
      .relax_code_seq[BR_RANGE_S256] = {
   INSN_JAL},
      .relax_code_size[BR_RANGE_S256] = 4,
      .relax_branch_isize[BR_RANGE_S256] = 4,
      .relax_fixup[BR_RANGE_S256] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_25_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S16K] = {
   INSN_JAL},
      .relax_code_size[BR_RANGE_S16K] = 4,
      .relax_branch_isize[BR_RANGE_S16K] = 4,
      .relax_fixup[BR_RANGE_S16K] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_25_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S64K] = {
   INSN_JAL},
      .relax_code_size[BR_RANGE_S64K] = 4,
      .relax_branch_isize[BR_RANGE_S64K] = 4,
      .relax_fixup[BR_RANGE_S64K] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_25_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S16M] = {
   INSN_JAL},
      .relax_code_size[BR_RANGE_S16M] = 4,
      .relax_branch_isize[BR_RANGE_S16M] = 4,
      .relax_fixup[BR_RANGE_S16M] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_25_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_U4G] = {
   INSN_SETHI_TA,
   INSN_ORI_TA,
   INSN_JRAL_TA},
      .relax_code_size[BR_RANGE_U4G] = 12,
      .relax_branch_isize[BR_RANGE_U4G] = 4,
      .relax_fixup[BR_RANGE_U4G] = {
     {0, 4, 0, BFD_RELOC_NDS32_HI20},
     {0, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_LONGCALL4},
     {4, 4, NDS32_HINT | NDS32_FIX, BFD_RELOC_NDS32_LO12S0_ORI},
     {4, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_PTR},
     {8, 4, NDS32_ABS | NDS32_HINT, BFD_RELOC_NDS32_PTR_RESOLVED},
     {8, 4, NDS32_SYM | NDS32_HINT, BFD_RELOC_NDS32_EMPTY},
     {8, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 0, 0, 0}
      },
    },
    {
      .opcode = "bgezal",
      .br_range = BR_RANGE_S64K,
      .cond_field = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_seq[BR_RANGE_S256] = {
   INSN_BGEZAL},
      .relax_code_condition[BR_RANGE_S256] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE},
      },
      .relax_code_size[BR_RANGE_S256] = 4,
      .relax_branch_isize[BR_RANGE_S256] = 4,
      .relax_fixup[BR_RANGE_S256] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_17_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S16K] = {
   INSN_BGEZAL},
      .relax_code_condition[BR_RANGE_S16K] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE},
      },
      .relax_code_size[BR_RANGE_S16K] = 4,
      .relax_branch_isize[BR_RANGE_S16K] = 4,
      .relax_fixup[BR_RANGE_S16K] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_17_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S64K] = {
   INSN_BGEZAL},
      .relax_code_condition[BR_RANGE_S64K] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE},
      },
      .relax_code_size[BR_RANGE_S64K] = 4,
      .relax_branch_isize[BR_RANGE_S64K] = 4,
      .relax_fixup[BR_RANGE_S64K] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_17_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S16M] = {
   INSN_BLTZ,
   INSN_JAL},
      .relax_code_condition[BR_RANGE_S16M] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE},
      },
      .relax_code_size[BR_RANGE_S16M] = 8,
      .relax_branch_isize[BR_RANGE_S16M] = 4,
      .relax_fixup[BR_RANGE_S16M] = {
     {0, 4, NDS32_CREATE_LABEL | NDS32_PCREL, BFD_RELOC_NDS32_17_PCREL},
     {0, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_LONGCALL5},
     {4, 4, NDS32_PCREL, BFD_RELOC_NDS32_25_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_U4G] = {
   INSN_BLTZ,
   INSN_SETHI_TA,
   INSN_ORI_TA,
   INSN_JRAL_TA},
      .relax_code_condition[BR_RANGE_U4G] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE},
      },
      .relax_code_size[BR_RANGE_U4G] = 16,
      .relax_branch_isize[BR_RANGE_U4G] = 4,
      .relax_fixup[BR_RANGE_U4G] = {
     {0, 4, NDS32_CREATE_LABEL | NDS32_PCREL, BFD_RELOC_NDS32_17_PCREL},
     {0, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_LONGCALL6},
     {4, 4, 0, BFD_RELOC_NDS32_HI20},
     {4, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_PTR},
     {8, 4, NDS32_FIX | NDS32_HINT, BFD_RELOC_NDS32_LO12S0_ORI},
     {8, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_PTR},
     {12, 4, NDS32_ABS | NDS32_HINT, BFD_RELOC_NDS32_PTR_RESOLVED},
     {12, 4, NDS32_SYM | NDS32_HINT, BFD_RELOC_NDS32_EMPTY},
     {12, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 0, 0, 0}
      },
    },
    {
      .opcode = "bltzal",
      .br_range = BR_RANGE_S64K,
      .cond_field = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_seq[BR_RANGE_S256] = {
   INSN_BLTZAL},
      .relax_code_condition[BR_RANGE_S256] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE},
      },
      .relax_code_size[BR_RANGE_S256] = 4,
      .relax_branch_isize[BR_RANGE_S256] = 4,
      .relax_fixup[BR_RANGE_S256] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_17_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S16K] = {
   INSN_BLTZAL},
      .relax_code_condition[BR_RANGE_S16K] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE},
      },
      .relax_code_size[BR_RANGE_S16K] = 4,
      .relax_branch_isize[BR_RANGE_S16K] = 4,
      .relax_fixup[BR_RANGE_S16K] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_17_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S64K] = {
   INSN_BLTZAL},
      .relax_code_condition[BR_RANGE_S64K] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE},
      },
      .relax_code_size[BR_RANGE_S64K] = 4,
      .relax_branch_isize[BR_RANGE_S64K] = 4,
      .relax_fixup[BR_RANGE_S64K] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_17_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S16M] = {
   INSN_BGEZ,
   INSN_JAL},
      .relax_code_condition[BR_RANGE_S16M] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE},
      },
      .relax_code_size[BR_RANGE_S16M] = 8,
      .relax_branch_isize[BR_RANGE_S16M] = 4,
      .relax_fixup[BR_RANGE_S16M] = {
     {0, 4, NDS32_CREATE_LABEL | NDS32_PCREL, BFD_RELOC_NDS32_17_PCREL},
     {0, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_LONGCALL5},
     {4, 4, NDS32_PCREL, BFD_RELOC_NDS32_25_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_U4G] = {
   INSN_BGEZ,
   INSN_SETHI_TA,
   INSN_ORI_TA,
   INSN_JRAL_TA},
      .relax_code_condition[BR_RANGE_U4G] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE},
      },
      .relax_code_size[BR_RANGE_U4G] = 16,
      .relax_branch_isize[BR_RANGE_U4G] = 4,
      .relax_fixup[BR_RANGE_U4G] = {
     {0, 4, NDS32_CREATE_LABEL | NDS32_PCREL, BFD_RELOC_NDS32_17_PCREL},
     {0, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_LONGCALL6},
     {4, 4, 0, BFD_RELOC_NDS32_HI20},
     {4, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_PTR},
     {8, 4, NDS32_FIX | NDS32_HINT, BFD_RELOC_NDS32_LO12S0_ORI},
     {8, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_PTR},
     {12, 4, NDS32_ABS | NDS32_HINT, BFD_RELOC_NDS32_PTR_RESOLVED},
     {12, 4, NDS32_SYM | NDS32_HINT, BFD_RELOC_NDS32_EMPTY},
     {12, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 0, 0, 0}
      },
    },
    {
      .opcode = "j",
      .br_range = BR_RANGE_S16M,
      .cond_field = {
     {0, 0, 0, FALSE}
      },
      .relax_code_seq[BR_RANGE_S256] = {
   (INSN_J8 << 16)},
      .relax_code_size[BR_RANGE_S256] = 2,
      .relax_branch_isize[BR_RANGE_S256] = 2,
      .relax_fixup[BR_RANGE_S256] = {
     {0, 2, NDS32_PCREL, BFD_RELOC_NDS32_9_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S16K] = {
   INSN_J},
      .relax_code_size[BR_RANGE_S16K] = 4,
      .relax_branch_isize[BR_RANGE_S16K] = 4,
      .relax_fixup[BR_RANGE_S16K] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_25_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S64K] = {
   INSN_J},
      .relax_code_size[BR_RANGE_S64K] = 4,
      .relax_branch_isize[BR_RANGE_S64K] = 4,
      .relax_fixup[BR_RANGE_S64K] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_25_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S16M] = {
   INSN_J},
      .relax_code_size[BR_RANGE_S16M] = 4,
      .relax_branch_isize[BR_RANGE_S16M] = 4,
      .relax_fixup[BR_RANGE_S16M] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_25_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_U4G] = {
   INSN_SETHI_TA,
   INSN_ORI_TA,
   INSN_JR_TA},
      .relax_code_size[BR_RANGE_U4G] = 12,
      .relax_branch_isize[BR_RANGE_U4G] = 4,
      .relax_fixup[BR_RANGE_U4G] = {
     {0, 4, 0, BFD_RELOC_NDS32_HI20},
     {0, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_LONGJUMP4},
     {4, 4, NDS32_HINT | NDS32_FIX, BFD_RELOC_NDS32_LO12S0_ORI},
     {4, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_PTR},
     {8, 4, NDS32_ABS | NDS32_HINT, BFD_RELOC_NDS32_PTR_RESOLVED},
     {8, 4, NDS32_SYM | NDS32_HINT, BFD_RELOC_NDS32_EMPTY},
     {8, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 0, 0, 0}
      },
    },
    {
      .opcode = "j8",
      .br_range = BR_RANGE_S256,
      .cond_field = {
     {0, 0, 0, FALSE}
      },
      .relax_code_seq[BR_RANGE_S256] = {
   (INSN_J8 << 16)},
      .relax_code_size[BR_RANGE_S256] = 2,
      .relax_branch_isize[BR_RANGE_S256] = 2,
      .relax_fixup[BR_RANGE_S256] = {
     {0, 2, NDS32_PCREL, BFD_RELOC_NDS32_9_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S16K] = {
   INSN_J},
      .relax_code_size[BR_RANGE_S16K] = 4,
      .relax_branch_isize[BR_RANGE_S16K] = 4,
      .relax_fixup[BR_RANGE_S16K] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_25_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S64K] = {
   INSN_J},
      .relax_code_size[BR_RANGE_S64K] = 4,
      .relax_branch_isize[BR_RANGE_S64K] = 4,
      .relax_fixup[BR_RANGE_S64K] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_25_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S16M] = {
   INSN_J},
      .relax_code_size[BR_RANGE_S16M] = 4,
      .relax_branch_isize[BR_RANGE_S16M] = 4,
      .relax_fixup[BR_RANGE_S16M] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_25_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_U4G] = {
   INSN_SETHI_TA,
   INSN_ORI_TA,
   INSN_JR_TA},
      .relax_code_size[BR_RANGE_U4G] = 12,
      .relax_branch_isize[BR_RANGE_U4G] = 4,
      .relax_fixup[BR_RANGE_U4G] = {
     {0, 4, 0, BFD_RELOC_NDS32_HI20},
     {0, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_LONGJUMP4},
     {4, 4, NDS32_HINT | NDS32_FIX, BFD_RELOC_NDS32_LO12S0_ORI},
     {4, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_PTR},
     {8, 4, NDS32_ABS | NDS32_HINT, BFD_RELOC_NDS32_PTR_RESOLVED},
     {8, 4, NDS32_SYM | NDS32_HINT, BFD_RELOC_NDS32_EMPTY},
     {8, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 0, 0, 0}
      },
    },
    {
      .opcode = "beqz",
      .br_range = BR_RANGE_S64K,
      .cond_field = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_seq[BR_RANGE_S256] = {
   INSN_BEQZ},
      .relax_code_condition[BR_RANGE_S256] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE},
      },
      .relax_code_size[BR_RANGE_S256] = 4,
      .relax_branch_isize[BR_RANGE_S256] = 4,
      .relax_fixup[BR_RANGE_S256] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_17_PCREL},
     {0, 4, NDS32_INSN16 , BFD_RELOC_NDS32_INSN16},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S16K] = {
   INSN_BEQZ},
      .relax_code_condition[BR_RANGE_S16K] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE},
      },
      .relax_code_size[BR_RANGE_S16K] = 4,
      .relax_branch_isize[BR_RANGE_S16K] = 4,
      .relax_fixup[BR_RANGE_S16K] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_17_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S64K] = {
   INSN_BEQZ},
      .relax_code_condition[BR_RANGE_S64K] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE},
      },
      .relax_code_size[BR_RANGE_S64K] = 4,
      .relax_branch_isize[BR_RANGE_S64K] = 4,
      .relax_fixup[BR_RANGE_S64K] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_17_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S16M] = {
   INSN_BNEZ,
   INSN_J},
      .relax_code_condition[BR_RANGE_S16M] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE},
      },
      .relax_code_size[BR_RANGE_S16M] = 8,
      .relax_branch_isize[BR_RANGE_S16M] = 4,
      .relax_fixup[BR_RANGE_S16M] = {
     {0, 4, NDS32_CREATE_LABEL | NDS32_PCREL, BFD_RELOC_NDS32_15_PCREL},
     {0, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_LONGJUMP5},
     {4, 4, NDS32_PCREL, BFD_RELOC_NDS32_25_PCREL},
     {4, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_U4G] = {
   INSN_BNEZ,
   INSN_SETHI_TA,
   INSN_ORI_TA,
   INSN_JR_TA},
      .relax_code_condition[BR_RANGE_U4G] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE},
      },
      .relax_code_size[BR_RANGE_U4G] = 16,
      .relax_branch_isize[BR_RANGE_U4G] = 4,
      .relax_fixup[BR_RANGE_U4G] = {
     {0, 4, NDS32_CREATE_LABEL | NDS32_PCREL, BFD_RELOC_NDS32_15_PCREL},
     {0, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_LONGJUMP6},
     {4, 4, 0, BFD_RELOC_NDS32_HI20},
     {4, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_PTR},
     {8, 4, NDS32_FIX | NDS32_HINT, BFD_RELOC_NDS32_LO12S0_ORI},
     {8, 4, NDS32_PTR |NDS32_HINT, BFD_RELOC_NDS32_PTR},
     {12, 4, NDS32_ABS | NDS32_HINT, BFD_RELOC_NDS32_PTR_RESOLVED},
     {12, 4, NDS32_SYM | NDS32_HINT, BFD_RELOC_NDS32_EMPTY},
     {12, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 0, 0, 0}
      },
    },
    {
      .opcode = "bgez",
      .br_range = BR_RANGE_S64K,
      .cond_field = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_seq[BR_RANGE_S256] = {
   INSN_BGEZ},
      .relax_code_condition[BR_RANGE_S256] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE},
      },
      .relax_code_size[BR_RANGE_S256] = 4,
      .relax_branch_isize[BR_RANGE_S256] = 4,
      .relax_fixup[BR_RANGE_S256] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_17_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S16K] = {
   INSN_BGEZ},
      .relax_code_condition[BR_RANGE_S16K] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE},
      },
      .relax_code_size[BR_RANGE_S16K] = 4,
      .relax_branch_isize[BR_RANGE_S16K] = 4,
      .relax_fixup[BR_RANGE_S16K] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_17_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S64K] = {
   INSN_BGEZ},
      .relax_code_condition[BR_RANGE_S64K] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE},
      },
      .relax_code_size[BR_RANGE_S64K] = 4,
      .relax_branch_isize[BR_RANGE_S64K] = 4,
      .relax_fixup[BR_RANGE_S64K] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_17_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S16M] = {
   INSN_BLTZ,
   INSN_J},
      .relax_code_condition[BR_RANGE_S16M] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE},
      },
      .relax_code_size[BR_RANGE_S16M] = 8,
      .relax_branch_isize[BR_RANGE_S16M] = 4,
      .relax_fixup[BR_RANGE_S16M] = {
     {0, 4, NDS32_CREATE_LABEL | NDS32_PCREL, BFD_RELOC_NDS32_15_PCREL},
     {0, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_LONGJUMP5},
     {4, 4, NDS32_PCREL, BFD_RELOC_NDS32_25_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_U4G] = {
   INSN_BLTZ,
   INSN_SETHI_TA,
   INSN_ORI_TA,
   INSN_JR_TA},
      .relax_code_condition[BR_RANGE_U4G] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE},
      },
      .relax_code_size[BR_RANGE_U4G] = 16,
      .relax_branch_isize[BR_RANGE_U4G] = 4,
      .relax_fixup[BR_RANGE_U4G] = {
     {0, 4, NDS32_CREATE_LABEL | NDS32_PCREL, BFD_RELOC_NDS32_15_PCREL},
     {0, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_LONGJUMP6},
     {4, 4, 0, BFD_RELOC_NDS32_HI20},
     {4, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_PTR},
     {8, 4, NDS32_FIX | NDS32_HINT, BFD_RELOC_NDS32_LO12S0_ORI},
     {8, 4, NDS32_PTR |NDS32_HINT, BFD_RELOC_NDS32_PTR},
     {12, 4, NDS32_ABS | NDS32_HINT, BFD_RELOC_NDS32_PTR_RESOLVED},
     {12, 4, NDS32_SYM | NDS32_HINT, BFD_RELOC_NDS32_EMPTY},
     {12, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 0, 0, 0}
      },
    },
    {
      .opcode = "bnez",
      .br_range = BR_RANGE_S64K,
      .cond_field = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_seq[BR_RANGE_S256] = {
   INSN_BNEZ},
      .relax_code_condition[BR_RANGE_S256] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE},
      },
      .relax_code_size[BR_RANGE_S256] = 4,
      .relax_branch_isize[BR_RANGE_S256] = 4,
      .relax_fixup[BR_RANGE_S256] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_17_PCREL},
     {0, 4, NDS32_INSN16, BFD_RELOC_NDS32_INSN16},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S16K] = {
   INSN_BNEZ},
      .relax_code_condition[BR_RANGE_S16K] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE},
      },
      .relax_code_size[BR_RANGE_S16K] = 4,
      .relax_branch_isize[BR_RANGE_S16K] = 4,
      .relax_fixup[BR_RANGE_S16K] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_17_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S64K] = {
   INSN_BNEZ},
      .relax_code_condition[BR_RANGE_S64K] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE},
      },
      .relax_code_size[BR_RANGE_S64K] = 4,
      .relax_branch_isize[BR_RANGE_S64K] = 4,
      .relax_fixup[BR_RANGE_S64K] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_17_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S16M] = {
   INSN_BEQZ,
   INSN_J},
      .relax_code_condition[BR_RANGE_S16M] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE},
      },
      .relax_code_size[BR_RANGE_S16M] = 8,
      .relax_branch_isize[BR_RANGE_S16M] = 4,
      .relax_fixup[BR_RANGE_S16M] = {
     {0, 4, NDS32_CREATE_LABEL | NDS32_PCREL, BFD_RELOC_NDS32_15_PCREL},
     {0, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_LONGJUMP5},
     {4, 4, NDS32_PCREL, BFD_RELOC_NDS32_25_PCREL},
     {4, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_U4G] = {
   INSN_BEQZ,
   INSN_SETHI_TA,
   INSN_ORI_TA,
   INSN_JR_TA},
      .relax_code_condition[BR_RANGE_U4G] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE},
      },
      .relax_code_size[BR_RANGE_U4G] = 16,
      .relax_branch_isize[BR_RANGE_U4G] = 4,
      .relax_fixup[BR_RANGE_U4G] = {
     {0, 4, NDS32_CREATE_LABEL | NDS32_PCREL, BFD_RELOC_NDS32_15_PCREL},
     {0, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_LONGJUMP6},
     {4, 4, 0, BFD_RELOC_NDS32_HI20},
     {4, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_PTR},
     {8, 4, NDS32_FIX | NDS32_HINT, BFD_RELOC_NDS32_LO12S0_ORI},
     {8, 4, NDS32_PTR |NDS32_HINT, BFD_RELOC_NDS32_PTR},
     {12, 4, NDS32_ABS | NDS32_HINT, BFD_RELOC_NDS32_PTR_RESOLVED},
     {12, 4, NDS32_SYM | NDS32_HINT, BFD_RELOC_NDS32_EMPTY},
     {12, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 0, 0, 0}
      },
    },
    {
      .opcode = "bgtz",
      .br_range = BR_RANGE_S64K,
      .cond_field = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_seq[BR_RANGE_S256] = {
   INSN_BGTZ},
      .relax_code_condition[BR_RANGE_S256] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE},
      },
      .relax_code_size[BR_RANGE_S256] = 4,
      .relax_branch_isize[BR_RANGE_S256] = 4,
      .relax_fixup[BR_RANGE_S256] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_17_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S16K] = {
   INSN_BGTZ},
      .relax_code_condition[BR_RANGE_S16K] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE},
      },
      .relax_code_size[BR_RANGE_S16K] = 4,
      .relax_branch_isize[BR_RANGE_S16K] = 4,
      .relax_fixup[BR_RANGE_S16K] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_17_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S64K] = {
   INSN_BGTZ},
      .relax_code_condition[BR_RANGE_S64K] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE},
      },
      .relax_code_size[BR_RANGE_S64K] = 4,
      .relax_branch_isize[BR_RANGE_S64K] = 4,
      .relax_fixup[BR_RANGE_S64K] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_17_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S16M] = {
   INSN_BLEZ,
   INSN_J},
      .relax_code_condition[BR_RANGE_S16M] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE},
      },
      .relax_code_size[BR_RANGE_S16M] = 8,
      .relax_branch_isize[BR_RANGE_S16M] = 4,
      .relax_fixup[BR_RANGE_S16M] = {
     {0, 4, NDS32_CREATE_LABEL | NDS32_PCREL, BFD_RELOC_NDS32_15_PCREL},
     {0, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_LONGJUMP5},
     {4, 4, NDS32_PCREL, BFD_RELOC_NDS32_25_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_U4G] = {
   INSN_BLEZ,
   INSN_SETHI_TA,
   INSN_ORI_TA,
   INSN_JR_TA},
      .relax_code_condition[BR_RANGE_U4G] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE},
      },
      .relax_code_size[BR_RANGE_U4G] = 16,
      .relax_branch_isize[BR_RANGE_U4G] = 4,
      .relax_fixup[BR_RANGE_U4G] = {
     {0, 4, NDS32_CREATE_LABEL | NDS32_PCREL, BFD_RELOC_NDS32_15_PCREL},
     {0, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_LONGJUMP6},
     {4, 4, 0, BFD_RELOC_NDS32_HI20},
     {4, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_PTR},
     {8, 4, NDS32_FIX | NDS32_HINT, BFD_RELOC_NDS32_LO12S0_ORI},
     {8, 4, NDS32_PTR |NDS32_HINT, BFD_RELOC_NDS32_PTR},
     {12, 4, NDS32_ABS | NDS32_HINT, BFD_RELOC_NDS32_PTR_RESOLVED},
     {12, 4, NDS32_SYM | NDS32_HINT, BFD_RELOC_NDS32_EMPTY},
     {12, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 0, 0, 0}
      },
    },
    {
      .opcode = "blez",
      .br_range = BR_RANGE_S64K,
      .cond_field = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_seq[BR_RANGE_S256] = {
   INSN_BLEZ},
      .relax_code_condition[BR_RANGE_S256] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE},
      },
      .relax_code_size[BR_RANGE_S256] = 4,
      .relax_branch_isize[BR_RANGE_S256] = 4,
      .relax_fixup[BR_RANGE_S256] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_17_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S16K] = {
   INSN_BLEZ},
      .relax_code_condition[BR_RANGE_S16K] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE},
      },
      .relax_code_size[BR_RANGE_S16K] = 4,
      .relax_branch_isize[BR_RANGE_S16K] = 4,
      .relax_fixup[BR_RANGE_S16K] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_17_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S64K] = {
   INSN_BLEZ},
      .relax_code_condition[BR_RANGE_S64K] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE},
      },
      .relax_code_size[BR_RANGE_S64K] = 4,
      .relax_branch_isize[BR_RANGE_S64K] = 4,
      .relax_fixup[BR_RANGE_S64K] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_17_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S16M] = {
   INSN_BGTZ,
   INSN_J},
      .relax_code_condition[BR_RANGE_S16M] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE},
      },
      .relax_code_size[BR_RANGE_S16M] = 8,
      .relax_branch_isize[BR_RANGE_S16M] = 4,
      .relax_fixup[BR_RANGE_S16M] = {
     {0, 4, NDS32_CREATE_LABEL | NDS32_PCREL, BFD_RELOC_NDS32_15_PCREL},
     {0, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_LONGJUMP5},
     {4, 4, NDS32_PCREL, BFD_RELOC_NDS32_25_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_U4G] = {
   INSN_BGTZ,
   INSN_SETHI_TA,
   INSN_ORI_TA,
   INSN_JR_TA},
      .relax_code_condition[BR_RANGE_U4G] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE},
      },
      .relax_code_size[BR_RANGE_U4G] = 16,
      .relax_branch_isize[BR_RANGE_U4G] = 4,
      .relax_fixup[BR_RANGE_U4G] = {
     {0, 4, NDS32_CREATE_LABEL | NDS32_PCREL, BFD_RELOC_NDS32_15_PCREL},
     {0, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_LONGJUMP6},
     {4, 4, 0, BFD_RELOC_NDS32_HI20},
     {4, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_PTR},
     {8, 4, NDS32_FIX | NDS32_HINT, BFD_RELOC_NDS32_LO12S0_ORI},
     {8, 4, NDS32_PTR |NDS32_HINT, BFD_RELOC_NDS32_PTR},
     {12, 4, NDS32_ABS | NDS32_HINT, BFD_RELOC_NDS32_PTR_RESOLVED},
     {12, 4, NDS32_SYM | NDS32_HINT, BFD_RELOC_NDS32_EMPTY},
     {12, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 0, 0, 0}
      },
    },
    {
      .opcode = "bltz",
      .br_range = BR_RANGE_S64K,
      .cond_field = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_seq[BR_RANGE_S256] = {
   INSN_BLTZ},
      .relax_code_condition[BR_RANGE_S256] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE},
      },
      .relax_code_size[BR_RANGE_S256] = 4,
      .relax_branch_isize[BR_RANGE_S256] = 4,
      .relax_fixup[BR_RANGE_S256] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_17_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S16K] = {
   INSN_BLTZ},
      .relax_code_condition[BR_RANGE_S16K] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE},
      },
      .relax_code_size[BR_RANGE_S16K] = 4,
      .relax_branch_isize[BR_RANGE_S16K] = 4,
      .relax_fixup[BR_RANGE_S16K] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_17_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S64K] = {
   INSN_BLTZ},
      .relax_code_condition[BR_RANGE_S64K] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE},
      },
      .relax_code_size[BR_RANGE_S64K] = 4,
      .relax_branch_isize[BR_RANGE_S64K] = 4,
      .relax_fixup[BR_RANGE_S64K] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_17_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S16M] = {
   INSN_BGEZ,
   INSN_J},
      .relax_code_condition[BR_RANGE_S16M] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE},
      },
      .relax_code_size[BR_RANGE_S16M] = 8,
      .relax_branch_isize[BR_RANGE_S16M] = 4,
      .relax_fixup[BR_RANGE_S16M] = {
     {0, 4, NDS32_CREATE_LABEL | NDS32_PCREL, BFD_RELOC_NDS32_15_PCREL},
     {0, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_LONGJUMP5},
     {4, 4, NDS32_PCREL, BFD_RELOC_NDS32_25_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_U4G] = {
   INSN_BGEZ,
   INSN_SETHI_TA,
   INSN_ORI_TA,
   INSN_JR_TA},
      .relax_code_condition[BR_RANGE_U4G] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE},
      },
      .relax_code_size[BR_RANGE_U4G] = 16,
      .relax_branch_isize[BR_RANGE_U4G] = 4,
      .relax_fixup[BR_RANGE_U4G] = {
     {0, 4, NDS32_CREATE_LABEL | NDS32_PCREL, BFD_RELOC_NDS32_15_PCREL},
     {0, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_LONGJUMP6},
     {4, 4, 0, BFD_RELOC_NDS32_HI20},
     {4, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_PTR},
     {8, 4, NDS32_FIX | NDS32_HINT, BFD_RELOC_NDS32_LO12S0_ORI},
     {8, 4, NDS32_PTR |NDS32_HINT, BFD_RELOC_NDS32_PTR},
     {12, 4, NDS32_ABS | NDS32_HINT, BFD_RELOC_NDS32_PTR_RESOLVED},
     {12, 4, NDS32_SYM | NDS32_HINT, BFD_RELOC_NDS32_EMPTY},
     {12, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 0, 0, 0}
      },
    },
    {
      .opcode = "beq",
      .br_range = BR_RANGE_S16K,
      .cond_field = {
     {0, 20, 0x1F, FALSE},
     {0, 15, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_seq[BR_RANGE_S256] = {
   INSN_BEQ},
      .relax_code_condition[BR_RANGE_S256] = {
     {0, 20, 0x1F, FALSE},
     {0, 15, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_size[BR_RANGE_S256] = 4,
      .relax_branch_isize[BR_RANGE_S256] = 4,
      .relax_fixup[BR_RANGE_S256] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_15_PCREL},
     {0, 4, NDS32_INSN16, BFD_RELOC_NDS32_INSN16},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S16K] = {
   INSN_BEQ},
      .relax_code_condition[BR_RANGE_S16K] = {
     {0, 20, 0x1F, FALSE},
     {0, 15, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_size[BR_RANGE_S16K] = 4,
      .relax_branch_isize[BR_RANGE_S16K] = 4,
      .relax_fixup[BR_RANGE_S16K] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_15_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S64K] = {
   INSN_BNE,
   INSN_J},
      .relax_code_condition[BR_RANGE_S64K] = {
     {0, 20, 0x1F, FALSE},
     {0, 15, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_size[BR_RANGE_S64K] = 8,
      .relax_branch_isize[BR_RANGE_S64K] = 4,
      .relax_fixup[BR_RANGE_S64K] = {
     {0, 4, NDS32_CREATE_LABEL | NDS32_PCREL, BFD_RELOC_NDS32_15_PCREL},
     {0, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_LONGJUMP5},
     {4, 4, NDS32_PCREL, BFD_RELOC_NDS32_25_PCREL},
     {4, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S16M] = {
   INSN_BNE,
   INSN_J},
      .relax_code_condition[BR_RANGE_S16M] = {
     {0, 20, 0x1F, FALSE},
     {0, 15, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_size[BR_RANGE_S16M] = 8,
      .relax_branch_isize[BR_RANGE_S16M] = 4,
      .relax_fixup[BR_RANGE_S16M] = {
     {0, 4, NDS32_CREATE_LABEL | NDS32_PCREL, BFD_RELOC_NDS32_15_PCREL},
     {0, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_LONGJUMP5},
     {4, 4, NDS32_PCREL, BFD_RELOC_NDS32_25_PCREL},
     {4, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_U4G] = {
   INSN_BNE,
   INSN_SETHI_TA,
   INSN_ORI_TA,
   INSN_JR_TA},
      .relax_code_condition[BR_RANGE_U4G] = {
     {0, 20, 0x1F, FALSE},
     {0, 15, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_size[BR_RANGE_U4G] = 16,
      .relax_branch_isize[BR_RANGE_U4G] = 4,
      .relax_fixup[BR_RANGE_U4G] = {
     {0, 4, NDS32_CREATE_LABEL | NDS32_PCREL, BFD_RELOC_NDS32_15_PCREL},
     {0, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_LONGJUMP6},
     {4, 4, 0, BFD_RELOC_NDS32_HI20},
     {4, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_PTR},
     {8, 4, NDS32_FIX | NDS32_HINT, BFD_RELOC_NDS32_LO12S0_ORI},
     {8, 4, NDS32_PTR |NDS32_HINT, BFD_RELOC_NDS32_PTR},
     {12, 4, NDS32_ABS | NDS32_HINT, BFD_RELOC_NDS32_PTR_RESOLVED},
     {12, 4, NDS32_SYM | NDS32_HINT, BFD_RELOC_NDS32_EMPTY},
     {12, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 0, 0, 0}
      },
    },
    {
      .opcode = "bne",
      .br_range = BR_RANGE_S16K,
      .cond_field = {
     {0, 20, 0x1F, FALSE},
     {0, 15, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_seq[BR_RANGE_S256] = {
   INSN_BNE},
      .relax_code_condition[BR_RANGE_S256] = {
     {0, 20, 0x1F, FALSE},
     {0, 15, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_size[BR_RANGE_S256] = 4,
      .relax_branch_isize[BR_RANGE_S256] = 4,
      .relax_fixup[BR_RANGE_S256] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_15_PCREL},
     {0, 4, NDS32_INSN16, BFD_RELOC_NDS32_INSN16},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S16K] = {
   INSN_BNE},
      .relax_code_condition[BR_RANGE_S16K] = {
     {0, 20, 0x1F, FALSE},
     {0, 15, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_size[BR_RANGE_S16K] = 4,
      .relax_branch_isize[BR_RANGE_S16K] = 4,
      .relax_fixup[BR_RANGE_S16K] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_15_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S64K] = {
   INSN_BEQ,
   INSN_J},
      .relax_code_condition[BR_RANGE_S64K] = {
     {0, 20, 0x1F, FALSE},
     {0, 15, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_size[BR_RANGE_S64K] = 8,
      .relax_branch_isize[BR_RANGE_S64K] = 4,
      .relax_fixup[BR_RANGE_S64K] = {
     {0, 4, NDS32_CREATE_LABEL | NDS32_PCREL, BFD_RELOC_NDS32_15_PCREL},
     {0, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_LONGJUMP5},
     {4, 4, NDS32_PCREL, BFD_RELOC_NDS32_25_PCREL},
     {4, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S16M] = {
   INSN_BEQ,
   INSN_J},
      .relax_code_condition[BR_RANGE_S16M] = {
     {0, 20, 0x1F, FALSE},
     {0, 15, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_size[BR_RANGE_S16M] = 8,
      .relax_branch_isize[BR_RANGE_S16M] = 4,
      .relax_fixup[BR_RANGE_S16M] = {
     {0, 4, NDS32_CREATE_LABEL | NDS32_PCREL, BFD_RELOC_NDS32_15_PCREL},
     {0, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_LONGJUMP5},
     {4, 4, NDS32_PCREL, BFD_RELOC_NDS32_25_PCREL},
     {4, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_U4G] = {
   INSN_BEQ,
   INSN_SETHI_TA,
   INSN_ORI_TA,
   INSN_JR_TA},
      .relax_code_condition[BR_RANGE_U4G] = {
     {0, 20, 0x1F, FALSE},
     {0, 15, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_size[BR_RANGE_U4G] = 16,
      .relax_branch_isize[BR_RANGE_U4G] = 4,
      .relax_fixup[BR_RANGE_U4G] = {
     {0, 4, NDS32_CREATE_LABEL | NDS32_PCREL, BFD_RELOC_NDS32_15_PCREL},
     {0, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_LONGJUMP6},
     {4, 4, 0, BFD_RELOC_NDS32_HI20},
     {4, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_PTR},
     {8, 4, NDS32_FIX | NDS32_HINT, BFD_RELOC_NDS32_LO12S0_ORI},
     {8, 4, NDS32_PTR |NDS32_HINT, BFD_RELOC_NDS32_PTR},
     {12, 4, NDS32_ABS | NDS32_HINT, BFD_RELOC_NDS32_PTR_RESOLVED},
     {12, 4, NDS32_SYM | NDS32_HINT, BFD_RELOC_NDS32_EMPTY},
     {12, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 0, 0, 0}
      },
    },
    {
      .opcode = "beqz38",
      .br_range = BR_RANGE_S256,
      .cond_field = {
     {0, 8, 0x7, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_seq[BR_RANGE_S256] = {
   INSN_BEQZ38 << 16},
      .relax_code_condition[BR_RANGE_S256] = {
     {0, 8, 0x7, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_size[BR_RANGE_S256] = 2,
      .relax_branch_isize[BR_RANGE_S256] = 2,
      .relax_fixup[BR_RANGE_S256] = {
     {0, 2, NDS32_PCREL, BFD_RELOC_NDS32_9_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S16K] = {
   INSN_BEQZ},
      .relax_code_condition[BR_RANGE_S16K] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_size[BR_RANGE_S16K] = 4,
      .relax_branch_isize[BR_RANGE_S16K] = 4,
      .relax_fixup[BR_RANGE_S16K] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_17_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S64K] = {
   INSN_BEQZ},
      .relax_code_condition[BR_RANGE_S64K] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_size[BR_RANGE_S64K] = 4,
      .relax_branch_isize[BR_RANGE_S64K] = 4,
      .relax_fixup[BR_RANGE_S64K] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_17_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S16M] = {
   INSN_BNEZ,
   INSN_J},
      .relax_code_condition[BR_RANGE_S16M] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_size[BR_RANGE_S16M] = 8,
      .relax_branch_isize[BR_RANGE_S16M] = 4,
      .relax_fixup[BR_RANGE_S16M] = {
     {0, 4, NDS32_CREATE_LABEL | NDS32_PCREL, BFD_RELOC_NDS32_15_PCREL},
     {0, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_LONGJUMP5},
     {4, 4, NDS32_PCREL, BFD_RELOC_NDS32_25_PCREL},
     {4, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_U4G] = {
   INSN_BNEZ,
   INSN_SETHI_TA,
   INSN_ORI_TA,
   INSN_JR_TA},
      .relax_code_condition[BR_RANGE_U4G] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_size[BR_RANGE_U4G] = 16,
      .relax_branch_isize[BR_RANGE_U4G] = 4,
      .relax_fixup[BR_RANGE_U4G] = {
     {0, 4, NDS32_CREATE_LABEL | NDS32_PCREL, BFD_RELOC_NDS32_15_PCREL},
     {0, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_LONGJUMP6},
     {4, 4, 0, BFD_RELOC_NDS32_HI20},
     {4, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_PTR},
     {8, 4, NDS32_FIX | NDS32_HINT, BFD_RELOC_NDS32_LO12S0_ORI},
     {8, 4, NDS32_PTR |NDS32_HINT, BFD_RELOC_NDS32_PTR},
     {12, 4, NDS32_ABS | NDS32_HINT, BFD_RELOC_NDS32_PTR_RESOLVED},
     {12, 4, NDS32_SYM | NDS32_HINT, BFD_RELOC_NDS32_EMPTY},
     {12, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 0, 0, 0}
      },
    },
    {
      .opcode = "bnez38",
      .br_range = BR_RANGE_S256,
      .cond_field = {
     {0, 8, 0x7, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_seq[BR_RANGE_S256] = {
   INSN_BNEZ38 << 16},
      .relax_code_condition[BR_RANGE_S256] = {
     {0, 8, 0x7, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_size[BR_RANGE_S256] = 2,
      .relax_branch_isize[BR_RANGE_S256] = 2,
      .relax_fixup[BR_RANGE_S256] = {
     {0, 2, NDS32_PCREL, BFD_RELOC_NDS32_9_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S16K] = {
   INSN_BNEZ},
      .relax_code_condition[BR_RANGE_S16K] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_size[BR_RANGE_S16K] = 4,
      .relax_branch_isize[BR_RANGE_S16K] = 4,
      .relax_fixup[BR_RANGE_S16K] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_17_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S64K] = {
   INSN_BNEZ},
      .relax_code_condition[BR_RANGE_S64K] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_size[BR_RANGE_S64K] = 4,
      .relax_branch_isize[BR_RANGE_S64K] = 4,
      .relax_fixup[BR_RANGE_S64K] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_17_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S16M] = {
   INSN_BEQZ,
   INSN_J},
      .relax_code_condition[BR_RANGE_S16M] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_size[BR_RANGE_S16M] = 8,
      .relax_branch_isize[BR_RANGE_S16M] = 4,
      .relax_fixup[BR_RANGE_S16M] = {
     {0, 4, NDS32_CREATE_LABEL | NDS32_PCREL, BFD_RELOC_NDS32_15_PCREL},
     {0, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_LONGJUMP5},
     {4, 4, NDS32_PCREL, BFD_RELOC_NDS32_25_PCREL},
     {4, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_U4G] = {
   INSN_BEQZ,
   INSN_SETHI_TA,
   INSN_ORI_TA,
   INSN_JR_TA},
      .relax_code_condition[BR_RANGE_U4G] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_size[BR_RANGE_U4G] = 16,
      .relax_branch_isize[BR_RANGE_U4G] = 4,
      .relax_fixup[BR_RANGE_U4G] = {
     {0, 4, NDS32_CREATE_LABEL | NDS32_PCREL, BFD_RELOC_NDS32_15_PCREL},
     {0, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_LONGJUMP6},
     {4, 4, 0, BFD_RELOC_NDS32_HI20},
     {4, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_PTR},
     {8, 4, NDS32_FIX | NDS32_HINT, BFD_RELOC_NDS32_LO12S0_ORI},
     {8, 4, NDS32_PTR |NDS32_HINT, BFD_RELOC_NDS32_PTR},
     {12, 4, NDS32_ABS | NDS32_HINT, BFD_RELOC_NDS32_PTR_RESOLVED},
     {12, 4, NDS32_SYM | NDS32_HINT, BFD_RELOC_NDS32_EMPTY},
     {12, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 0, 0, 0}
      },
    },
    {
      .opcode = "beqzs8",
      .br_range = BR_RANGE_S256,
      .cond_field = {
     {0, 0, 0, FALSE}
      },
      .relax_code_seq[BR_RANGE_S256] = {
   INSN_BEQZS8 << 16},
      .relax_code_size[BR_RANGE_S256] = 2,
      .relax_branch_isize[BR_RANGE_S256] = 2,
      .relax_fixup[BR_RANGE_S256] = {
     {0, 2, NDS32_PCREL, BFD_RELOC_NDS32_9_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S16K] = {
   INSN_BEQZ_TA},
      .relax_code_size[BR_RANGE_S16K] = 4,
      .relax_branch_isize[BR_RANGE_S16K] = 4,
      .relax_fixup[BR_RANGE_S16K] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_17_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S64K] = {
   INSN_BEQZ_TA},
      .relax_code_size[BR_RANGE_S64K] = 4,
      .relax_branch_isize[BR_RANGE_S64K] = 4,
      .relax_fixup[BR_RANGE_S64K] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_17_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S16M] = {
   INSN_BNEZ_TA,
   INSN_J},
      .relax_code_size[BR_RANGE_S16M] = 8,
      .relax_branch_isize[BR_RANGE_S16M] = 4,
      .relax_fixup[BR_RANGE_S16M] = {
     {0, 4, NDS32_CREATE_LABEL | NDS32_PCREL, BFD_RELOC_NDS32_15_PCREL},
     {0, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_LONGJUMP5},
     {4, 4, NDS32_PCREL, BFD_RELOC_NDS32_25_PCREL},
     {4, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_U4G] = {
   INSN_BNEZ_TA,
   INSN_SETHI_TA,
   INSN_ORI_TA,
   INSN_JR_TA},
      .relax_code_size[BR_RANGE_U4G] = 16,
      .relax_branch_isize[BR_RANGE_U4G] = 4,
      .relax_fixup[BR_RANGE_U4G] = {
     {0, 4, NDS32_CREATE_LABEL | NDS32_PCREL, BFD_RELOC_NDS32_15_PCREL},
     {0, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_LONGJUMP6},
     {4, 4, 0, BFD_RELOC_NDS32_HI20},
     {4, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_PTR},
     {8, 4, NDS32_FIX | NDS32_HINT, BFD_RELOC_NDS32_LO12S0_ORI},
     {8, 4, NDS32_PTR |NDS32_HINT, BFD_RELOC_NDS32_PTR},
     {12, 4, NDS32_ABS | NDS32_HINT, BFD_RELOC_NDS32_PTR_RESOLVED},
     {12, 4, NDS32_SYM | NDS32_HINT, BFD_RELOC_NDS32_EMPTY},
     {12, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 0, 0, 0}
      },
    },
    {
      .opcode = "bnezs8",
      .br_range = BR_RANGE_S256,
      .cond_field = {
     {0, 0, 0, FALSE}
      },
      .relax_code_seq[BR_RANGE_S256] = {
   INSN_BNEZS8 << 16},
      .relax_code_size[BR_RANGE_S256] = 2,
      .relax_branch_isize[BR_RANGE_S256] = 2,
      .relax_fixup[BR_RANGE_S256] = {
     {0, 2, NDS32_PCREL, BFD_RELOC_NDS32_9_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S16K] = {
   INSN_BNEZ_TA},
      .relax_code_size[BR_RANGE_S16K] = 4,
      .relax_branch_isize[BR_RANGE_S16K] = 4,
      .relax_fixup[BR_RANGE_S16K] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_17_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S64K] = {
   INSN_BNEZ_TA},
      .relax_code_size[BR_RANGE_S64K] = 4,
      .relax_branch_isize[BR_RANGE_S64K] = 4,
      .relax_fixup[BR_RANGE_S64K] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_17_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S16M] = {
   INSN_BEQZ_TA,
   INSN_J},
      .relax_code_size[BR_RANGE_S16M] = 8,
      .relax_branch_isize[BR_RANGE_S16M] = 4,
      .relax_fixup[BR_RANGE_S16M] = {
     {0, 4, NDS32_CREATE_LABEL | NDS32_PCREL, BFD_RELOC_NDS32_15_PCREL},
     {0, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_LONGJUMP5},
     {4, 4, NDS32_PCREL, BFD_RELOC_NDS32_25_PCREL},
     {4, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_U4G] = {
   INSN_BEQZ_TA,
   INSN_SETHI_TA,
   INSN_ORI_TA,
   INSN_JR_TA},
      .relax_code_size[BR_RANGE_U4G] = 16,
      .relax_branch_isize[BR_RANGE_U4G] = 4,
      .relax_fixup[BR_RANGE_U4G] = {
     {0, 4, NDS32_CREATE_LABEL | NDS32_PCREL, BFD_RELOC_NDS32_15_PCREL},
     {0, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_LONGJUMP6},
     {4, 4, 0, BFD_RELOC_NDS32_HI20},
     {4, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_PTR},
     {8, 4, NDS32_FIX | NDS32_HINT, BFD_RELOC_NDS32_LO12S0_ORI},
     {8, 4, NDS32_PTR |NDS32_HINT, BFD_RELOC_NDS32_PTR},
     {12, 4, NDS32_ABS | NDS32_HINT, BFD_RELOC_NDS32_PTR_RESOLVED},
     {12, 4, NDS32_SYM | NDS32_HINT, BFD_RELOC_NDS32_EMPTY},
     {12, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 0, 0, 0}
      },
    },
    {
      .opcode = "bnes38",
      .br_range = BR_RANGE_S256,
      .cond_field = {
     {0, 8, 0x7, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_seq[BR_RANGE_S256] = {
   INSN_BNES38 << 16},
      .relax_code_condition[BR_RANGE_S256] = {
     {0, 8, 0x7, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_size[BR_RANGE_S256] = 2,
      .relax_branch_isize[BR_RANGE_S256] = 2,
      .relax_fixup[BR_RANGE_S256] = {
     {0, 2, NDS32_PCREL, BFD_RELOC_NDS32_9_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S16K] = {
   INSN_BNE_R5},
      .relax_code_condition[BR_RANGE_S16K] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_size[BR_RANGE_S16K] = 4,
      .relax_branch_isize[BR_RANGE_S16K] = 4,
      .relax_fixup[BR_RANGE_S16K] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_15_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S64K] = {
   INSN_BEQ_R5,
   INSN_J},
      .relax_code_condition[BR_RANGE_S64K] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_size[BR_RANGE_S64K] = 8,
      .relax_branch_isize[BR_RANGE_S64K] = 4,
      .relax_fixup[BR_RANGE_S64K] = {
     {0, 4, NDS32_CREATE_LABEL | NDS32_PCREL, BFD_RELOC_NDS32_15_PCREL},
     {0, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_LONGJUMP5},
     {4, 4, NDS32_PCREL, BFD_RELOC_NDS32_25_PCREL},
     {4, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S16M] = {
   INSN_BEQ_R5,
   INSN_J},
      .relax_code_condition[BR_RANGE_S16M] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_size[BR_RANGE_S16M] = 8,
      .relax_branch_isize[BR_RANGE_S16M] = 4,
      .relax_fixup[BR_RANGE_S16M] = {
     {0, 4, NDS32_CREATE_LABEL | NDS32_PCREL, BFD_RELOC_NDS32_15_PCREL},
     {0, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_LONGJUMP5},
     {4, 4, NDS32_PCREL, BFD_RELOC_NDS32_25_PCREL},
     {4, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_U4G] = {
   INSN_BEQ_R5,
   INSN_SETHI_TA,
   INSN_ORI_TA,
   INSN_JR_TA},
      .relax_code_condition[BR_RANGE_U4G] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_size[BR_RANGE_U4G] = 16,
      .relax_branch_isize[BR_RANGE_U4G] = 4,
      .relax_fixup[BR_RANGE_U4G] = {
     {0, 4, NDS32_CREATE_LABEL | NDS32_PCREL, BFD_RELOC_NDS32_15_PCREL},
     {0, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_LONGJUMP6},
     {4, 4, 0, BFD_RELOC_NDS32_HI20},
     {4, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_PTR},
     {8, 4, NDS32_FIX | NDS32_HINT, BFD_RELOC_NDS32_LO12S0_ORI},
     {8, 4, NDS32_PTR |NDS32_HINT, BFD_RELOC_NDS32_PTR},
     {12, 4, NDS32_ABS | NDS32_HINT, BFD_RELOC_NDS32_PTR_RESOLVED},
     {12, 4, NDS32_SYM | NDS32_HINT, BFD_RELOC_NDS32_EMPTY},
     {12, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 0, 0, 0}
      },
    },
    {
      .opcode = "beqs38",
      .br_range = BR_RANGE_S256,
      .cond_field = {
     {0, 8, 0x7, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_seq[BR_RANGE_S256] = {
   INSN_BEQS38 << 16},
      .relax_code_condition[BR_RANGE_S256] = {
     {0, 8, 0x7, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_size[BR_RANGE_S256] = 2,
      .relax_branch_isize[BR_RANGE_S256] = 2,
      .relax_fixup[BR_RANGE_S256] = {
     {0, 2, NDS32_PCREL, BFD_RELOC_NDS32_9_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S16K] = {
   INSN_BEQ_R5},
      .relax_code_condition[BR_RANGE_S16K] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_size[BR_RANGE_S16K] = 4,
      .relax_branch_isize[BR_RANGE_S16K] = 4,
      .relax_fixup[BR_RANGE_S16K] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_15_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S64K] = {
   INSN_BNE_R5,
   INSN_J},
      .relax_code_condition[BR_RANGE_S64K] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_size[BR_RANGE_S64K] = 8,
      .relax_branch_isize[BR_RANGE_S64K] = 4,
      .relax_fixup[BR_RANGE_S64K] = {
     {0, 4, NDS32_CREATE_LABEL | NDS32_PCREL, BFD_RELOC_NDS32_15_PCREL},
     {0, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_LONGJUMP5},
     {4, 4, NDS32_PCREL, BFD_RELOC_NDS32_25_PCREL},
     {4, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S16M] = {
   INSN_BNE_R5,
   INSN_J},
      .relax_code_condition[BR_RANGE_S16M] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_size[BR_RANGE_S16M] = 8,
      .relax_branch_isize[BR_RANGE_S16M] = 4,
      .relax_fixup[BR_RANGE_S16M] = {
     {0, 4, NDS32_CREATE_LABEL | NDS32_PCREL, BFD_RELOC_NDS32_15_PCREL},
     {0, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_LONGJUMP5},
     {4, 4, NDS32_PCREL, BFD_RELOC_NDS32_25_PCREL},
     {4, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_U4G] = {
   INSN_BNE_R5,
   INSN_SETHI_TA,
   INSN_ORI_TA,
   INSN_JR_TA},
      .relax_code_condition[BR_RANGE_U4G] = {
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_size[BR_RANGE_U4G] = 16,
      .relax_branch_isize[BR_RANGE_U4G] = 4,
      .relax_fixup[BR_RANGE_U4G] = {
     {0, 4, NDS32_CREATE_LABEL | NDS32_PCREL, BFD_RELOC_NDS32_15_PCREL},
     {0, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_LONGJUMP6},
     {4, 4, 0, BFD_RELOC_NDS32_HI20},
     {4, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_PTR},
     {8, 4, NDS32_FIX | NDS32_HINT, BFD_RELOC_NDS32_LO12S0_ORI},
     {8, 4, NDS32_PTR |NDS32_HINT, BFD_RELOC_NDS32_PTR},
     {12, 4, NDS32_ABS | NDS32_HINT, BFD_RELOC_NDS32_PTR_RESOLVED},
     {12, 4, NDS32_SYM | NDS32_HINT, BFD_RELOC_NDS32_EMPTY},
     {12, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 0, 0, 0}
      },
    },
    {
      .opcode = "beqc",
      .br_range = BR_RANGE_S256,
      .cond_field = {
     {0, 8, 0x7FF, TRUE},
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_seq[BR_RANGE_S256] = {
   INSN_BEQC},
      .relax_code_condition[BR_RANGE_S256] = {
     {0, 8, 0x7FF, FALSE},
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_size[BR_RANGE_S256] = 4,
      .relax_branch_isize[BR_RANGE_S256] = 4,
      .relax_fixup[BR_RANGE_S256] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_WORD_9_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S16K] = {
   INSN_MOVI_TA,
   INSN_BEQ_TA},
      .relax_code_condition[BR_RANGE_S16K] = {
     {0, 0, 0xFFFFF, FALSE},
     {4, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_size[BR_RANGE_S16K] = 8,
      .relax_branch_isize[BR_RANGE_S16K] = 4,
      .relax_fixup[BR_RANGE_S16K] = {
     {0, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_LONGJUMP7},
     {4, 4, NDS32_PCREL, BFD_RELOC_NDS32_15_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S64K] = {
   INSN_BNEC,
   INSN_J},
      .relax_code_condition[BR_RANGE_S64K] = {
     {0, 8, 0x7FF, FALSE},
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_size[BR_RANGE_S64K] = 8,
      .relax_branch_isize[BR_RANGE_S64K] = 4,
      .relax_fixup[BR_RANGE_S64K] = {
     {0, 4, NDS32_CREATE_LABEL | NDS32_PCREL, BFD_RELOC_NDS32_WORD_9_PCREL},
     {4, 4, NDS32_PCREL, BFD_RELOC_NDS32_25_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S16M] = {
   INSN_BNEC,
   INSN_J},
      .relax_code_condition[BR_RANGE_S16M] = {
     {0, 8, 0x7FF, FALSE},
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_size[BR_RANGE_S16M] = 8,
      .relax_branch_isize[BR_RANGE_S16M] = 4,
      .relax_fixup[BR_RANGE_S16M] = {
     {0, 4, NDS32_CREATE_LABEL | NDS32_PCREL, BFD_RELOC_NDS32_WORD_9_PCREL},
     {4, 4, NDS32_PCREL, BFD_RELOC_NDS32_25_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_U4G] = {
   INSN_BNEC,
   INSN_SETHI_TA,
   INSN_ORI_TA,
   INSN_JR_TA},
      .relax_code_condition[BR_RANGE_U4G] = {
     {0, 8, 0x7FF, FALSE},
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_size[BR_RANGE_U4G] = 16,
      .relax_branch_isize[BR_RANGE_U4G] = 4,
      .relax_fixup[BR_RANGE_U4G] = {
     {0, 4, NDS32_CREATE_LABEL | NDS32_PCREL, BFD_RELOC_NDS32_WORD_9_PCREL},
     {4, 4, 0, BFD_RELOC_NDS32_HI20},
     {8, 4, 0, BFD_RELOC_NDS32_LO12S0_ORI},
     {12, 4, NDS32_INSN16, BFD_RELOC_NDS32_INSN16},
     {0, 0, 0, 0}
      },
    },
    {
      .opcode = "bnec",
      .br_range = BR_RANGE_S256,
      .cond_field = {
     {0, 8, 0x7FF, TRUE},
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_seq[BR_RANGE_S256] = {
   INSN_BNEC},
      .relax_code_condition[BR_RANGE_S256] = {
     {0, 8, 0x7FF, FALSE},
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_size[BR_RANGE_S256] = 4,
      .relax_branch_isize[BR_RANGE_S256] = 4,
      .relax_fixup[BR_RANGE_S256] = {
     {0, 4, NDS32_PCREL, BFD_RELOC_NDS32_WORD_9_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S16K] = {
   INSN_MOVI_TA,
   INSN_BNE_TA},
      .relax_code_condition[BR_RANGE_S16K] = {
     {0, 0, 0xFFFFF, FALSE},
     {4, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_size[BR_RANGE_S16K] = 8,
      .relax_branch_isize[BR_RANGE_S16K] = 4,
      .relax_fixup[BR_RANGE_S16K] = {
     {0, 4, NDS32_INSN16 | NDS32_HINT, BFD_RELOC_NDS32_INSN16},
     {0, 4, NDS32_PTR | NDS32_HINT, BFD_RELOC_NDS32_LONGJUMP7},
     {4, 4, NDS32_PCREL, BFD_RELOC_NDS32_15_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S64K] = {
   INSN_BEQC,
   INSN_J},
      .relax_code_condition[BR_RANGE_S64K] = {
     {0, 8, 0x7FF, FALSE},
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_size[BR_RANGE_S64K] = 8,
      .relax_branch_isize[BR_RANGE_S64K] = 4,
      .relax_fixup[BR_RANGE_S64K] = {
     {0, 4, NDS32_CREATE_LABEL | NDS32_PCREL, BFD_RELOC_NDS32_WORD_9_PCREL},
     {4, 4, NDS32_PCREL, BFD_RELOC_NDS32_25_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_S16M] = {
   INSN_BEQC,
   INSN_J},
      .relax_code_condition[BR_RANGE_S16M] = {
     {0, 8, 0x7FF, FALSE},
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_size[BR_RANGE_S16M] = 8,
      .relax_branch_isize[BR_RANGE_S16M] = 4,
      .relax_fixup[BR_RANGE_S16M] = {
     {0, 4, NDS32_CREATE_LABEL | NDS32_PCREL, BFD_RELOC_NDS32_WORD_9_PCREL},
     {4, 4, NDS32_PCREL, BFD_RELOC_NDS32_25_PCREL},
     {0, 0, 0, 0}
      },
      .relax_code_seq[BR_RANGE_U4G] = {
   INSN_BEQC,
   INSN_SETHI_TA,
   INSN_ORI_TA,
   INSN_JR_TA},
      .relax_code_condition[BR_RANGE_U4G] = {
     {0, 8, 0x7FF, FALSE},
     {0, 20, 0x1F, FALSE},
     {0, 0, 0, FALSE}
      },
      .relax_code_size[BR_RANGE_U4G] = 16,
      .relax_branch_isize[BR_RANGE_U4G] = 4,
      .relax_fixup[BR_RANGE_U4G] = {
     {0, 4, NDS32_CREATE_LABEL | NDS32_PCREL, BFD_RELOC_NDS32_WORD_9_PCREL},
     {4, 4, 0, BFD_RELOC_NDS32_HI20},
     {8, 4, 0, BFD_RELOC_NDS32_LO12S0_ORI},
     {12, 4, NDS32_INSN16, BFD_RELOC_NDS32_INSN16},
     {0, 0, 0, 0}
      },
    },
    {
      .opcode = NULL,
    },
};
enum options
{
  OPTION_BIG = OPTION_MD_BASE,
  OPTION_LITTLE,
  OPTION_TURBO,
  OPTION_PIC,
  OPTION_RELAX_FP_AS_GP_OFF,
  OPTION_RELAX_B2BB_ON,
  OPTION_RELAX_ALL_OFF,
  OPTION_OPTIMIZE,
  OPTION_OPTIMIZE_SPACE
};
const char *md_shortopts = "m:O:";
struct option md_longopts[] = {
  {"O1", no_argument, NULL, OPTION_OPTIMIZE},
  {"Os", no_argument, NULL, OPTION_OPTIMIZE_SPACE},
  {"big", no_argument, NULL, OPTION_BIG},
  {"little", no_argument, NULL, OPTION_LITTLE},
  {"EB", no_argument, NULL, OPTION_BIG},
  {"EL", no_argument, NULL, OPTION_LITTLE},
  {"meb", no_argument, NULL, OPTION_BIG},
  {"mel", no_argument, NULL, OPTION_LITTLE},
  {"mall-ext", no_argument, NULL, OPTION_TURBO},
  {"mext-all", no_argument, NULL, OPTION_TURBO},
  {"mpic", no_argument, NULL, OPTION_PIC},
  {"mno-fp-as-gp-relax", no_argument, NULL, OPTION_RELAX_FP_AS_GP_OFF},
  {"mb2bb", no_argument, NULL, OPTION_RELAX_B2BB_ON},
  {"mno-all-relax", no_argument, NULL, OPTION_RELAX_ALL_OFF},
  {NULL, no_argument, NULL, 0}
};
size_t md_longopts_size = sizeof (md_longopts);
struct nds32_parse_option_table
{
  const char *name;
  char *help;
  int (*func) (char *arg);
};
#ifdef NDS32_DEFAULT_ARCH_NAME
static char* nds32_arch_name = NDS32_DEFAULT_ARCH_NAME;
#else
static char* nds32_arch_name = "v3";
#endif
static int nds32_baseline = -1;
static int nds32_gpr16 = -1;
static int nds32_fpu_sp_ext = -1;
static int nds32_fpu_dp_ext = -1;
static int nds32_freg = -1;
static int nds32_abi = -1;
static int nds32_elf_flags = 0;
static int nds32_fpu_com = 0;
static int nds32_parse_arch (char *str);
static int nds32_parse_baseline (char *str);
static int nds32_parse_freg (char *str);
static int nds32_parse_abi (char *str);
static void add_mapping_symbol (enum mstate state,
    unsigned int padding_byte, unsigned int align);
static struct nds32_parse_option_table parse_opts [] =
{
  {"ace=", N_("<shrlibfile>\t  Support user defined instruction extension"),
    nds32_parse_udi},
  {"cop0=", N_("<shrlibfile>\t  Support coprocessor 0 extension"),
     nds32_parse_cop0},
  {"cop1=", N_("<shrlibfile>\t  Support coprocessor 1 extension"),
     nds32_parse_cop1},
  {"cop2=", N_("<shrlibfile>\t  Support coprocessor 2 extension"),
     nds32_parse_cop2},
  {"cop3=", N_("<shrlibfile>\t  Support coprocessor 3 extension"),
     nds32_parse_cop3},
  {"arch=", N_("<arch name>\t  Assemble for architecture <arch name>\n\
     <arch name> could be\n\
     v3, v3j, v3m, v3m+ v3f, v3s, "\
     "v2, v2j, v2f, v2s"), nds32_parse_arch},
  {"baseline=", N_("<baseline>\t  Assemble for baseline <baseline>\n\
     <baseline> could be v2, v3, v3m"),
    nds32_parse_baseline},
  {"fpu-freg=", N_("<freg>\t  Specify a FPU configuration\n\
     <freg>\n\
     0/4: 8 SP / 4 DP registers\n\
     1/5: 16 SP / 8 DP registers\n\
     2/6: 32 SP / 16 DP registers\n\
     3/7: 32 SP / 32 DP registers"), nds32_parse_freg},
  {"abi=", N_("<abi>\t          Specify a abi version\n\
     <abi> could be v1, v2, v2fp, v2fp+"), nds32_parse_abi},
  {NULL, NULL, NULL}
};
static int nds32_mac = 1;
static int nds32_div = 1;
static int nds32_16bit_ext = 1;
static int nds32_dx_regs = NDS32_DEFAULT_DX_REGS;
static int nds32_perf_ext = NDS32_DEFAULT_PERF_EXT;
static int nds32_perf_ext2 = NDS32_DEFAULT_PERF_EXT2;
static int nds32_string_ext = NDS32_DEFAULT_STRING_EXT;
static int nds32_audio_ext = NDS32_DEFAULT_AUDIO_EXT;
static int nds32_dsp_ext = NDS32_DEFAULT_DSP_EXT;
static int nds32_zol_ext = NDS32_DEFAULT_ZOL_EXT;
static int nds32_fpu_fma = 0;
static int nds32_pic = 0;
static int nds32_relax_fp_as_gp = 1;
static int nds32_relax_b2bb = 0;
static int nds32_relax_all = 1;
struct nds32_set_option_table
{
  const char *name;
  char *help;
  int *var;
  int value;
};
static struct nds32_set_option_table toggle_opts [] =
{
  {"mac", N_("Multiply instructions support"), &nds32_mac, 1},
  {"div", N_("Divide instructions support"), &nds32_div, 1},
  {"16bit-ext", N_("16-bit extension"), &nds32_16bit_ext, 1},
  {"dx-regs", N_("d0/d1 registers"), &nds32_dx_regs, 1},
  {"perf-ext", N_("Performance extension"), &nds32_perf_ext, 1},
  {"perf2-ext", N_("Performance extension 2"), &nds32_perf_ext2, 1},
  {"string-ext", N_("String extension"), &nds32_string_ext, 1},
  {"reduced-regs", N_("Reduced Register configuration (GPR16) option"), &nds32_gpr16, 1},
  {"audio-isa-ext", N_("AUDIO ISA extension"), &nds32_audio_ext, 1},
  {"fpu-sp-ext", N_("FPU SP extension"), &nds32_fpu_sp_ext, 1},
  {"fpu-dp-ext", N_("FPU DP extension"), &nds32_fpu_dp_ext, 1},
  {"fpu-fma", N_("FPU fused-multiply-add instructions"), &nds32_fpu_fma, 1},
  {"dsp-ext", N_("DSP extension"), &nds32_dsp_ext, 1},
  {"zol-ext", N_("hardware loop extension"), &nds32_zol_ext, 1},
  {NULL, NULL, NULL, 0}
};
int
nds32_asm_parse_operand (struct nds32_asm_desc *pdesc,
    struct nds32_asm_insn *pinsn,
    char **pstr, int64_t *value);
static struct nds32_asm_desc asm_desc;
void
nds32_after_parse_args (void)
{
  nds32_parse_arch (nds32_arch_name);
}
void
md_show_usage (FILE *stream)
{
  struct nds32_parse_option_table *coarse_tune;
  struct nds32_set_option_table *fine_tune;
  fprintf (stream, _("\n NDS32-specific assembler options:\n"));
  fprintf (stream, _("\
  -O1, Optimize for performance\n\
  -Os Optimize for space\n"));
  fprintf (stream, _("\
  -EL, -mel or -little Produce little endian output\n\
  -EB, -meb or -big Produce big endian output\n\
  -mpic Generate PIC\n\
  -mno-fp-as-gp-relax Suppress fp-as-gp relaxation for this file\n\
  -mb2bb-relax Back-to-back branch optimization\n\
  -mno-all-relax Suppress all relaxation for this file\n"));
  for (coarse_tune = parse_opts; coarse_tune->name != NULL; coarse_tune++)
    {
      if (coarse_tune->help != NULL)
 fprintf (stream, _("  -m%s%s\n"),
   coarse_tune->name, _(coarse_tune->help));
    }
  for (fine_tune = toggle_opts; fine_tune->name != NULL; fine_tune++)
    {
      if (fine_tune->help != NULL)
 fprintf (stream, _("  -m[no-]%-17sEnable/Disable %s\n"),
   fine_tune->name, _(fine_tune->help));
    }
  fprintf (stream, _("\
  -mall-ext Turn on all extensions and instructions support\n"));
}
void
nds32_frag_init (fragS *fragp)
{
  fragp->tc_frag_data.flag = 0;
  fragp->tc_frag_data.opcode = NULL;
  fragp->tc_frag_data.fixup = NULL;
}
static char *
parse_expression (char *str, expressionS *exp)
{
  char *s;
  char *tmp;
  tmp = input_line_pointer;
  input_line_pointer = str;
  expression (exp);
  s = input_line_pointer;
  input_line_pointer = tmp;
  return s;
}
void
nds32_start_line_hook (void)
{
}
typedef void (*nds32_pseudo_opcode_func) (int argc, char *argv[], int pv);
struct nds32_pseudo_opcode
{
  const char *opcode;
  int argc;
  nds32_pseudo_opcode_func proc;
  int pseudo_val;
  int physical_op;
};
#define PV_DONT_CARE 0
static struct hash_control *nds32_pseudo_opcode_hash = NULL;
static int
builtin_isreg (const char *s, const char *x ATTRIBUTE_UNUSED)
{
  if (s [0] == '$' && hash_find (nds32_gprs_hash, (s + 1)))
    return 1;
  return 0;
}
static int
builtin_regnum (const char *s, const char *x ATTRIBUTE_UNUSED)
{
  struct nds32_keyword *k;
  if (*s != '$')
    return -1;
  s++;
  k = hash_find (nds32_gprs_hash, s);
  if (k == NULL)
    return -1;
  return k->value;
}
static int
builtin_addend (const char *s, char *x ATTRIBUTE_UNUSED)
{
  const char *ptr = s;
  while (*ptr != '+' && *ptr != '-' && *ptr)
    ++ptr;
  if (*ptr == 0)
    return 0;
  else
    return strtol (ptr, NULL, 0);
}
static void
md_assemblef (char *format, ...)
{
  char line[1024];
  va_list ap;
  unsigned int r;
  va_start (ap, format);
  r = vsnprintf (line, sizeof (line), format, ap);
  md_assemble (line);
  gas_assert (r < sizeof (line));
}
static void do_pseudo_li_internal (char *rt, int imm32s);
static void do_pseudo_move_reg_internal (char *dst, char *src);
static void
do_pseudo_b (int argc ATTRIBUTE_UNUSED, char *argv[], int pv ATTRIBUTE_UNUSED)
{
  char *arg_label = argv[0];
  relaxing = TRUE;
  if (nds32_pic)
    {
      md_assemblef ("sethi $ta,hi20(%s)", arg_label);
      md_assemblef ("ori $ta,$ta,lo12(%s)", arg_label);
      md_assemble ("add $ta,$ta,$gp");
      md_assemble ("jr $ta");
    }
  else
    {
      md_assemblef ("j %s", arg_label);
    }
  relaxing = FALSE;
}
static void
do_pseudo_bal (int argc ATTRIBUTE_UNUSED, char *argv[], int pv ATTRIBUTE_UNUSED)
{
  char *arg_label = argv[0];
  relaxing = TRUE;
  if (nds32_pic)
    {
      md_assemblef ("sethi $ta,hi20(%s)", arg_label);
      md_assemblef ("ori $ta,$ta,lo12(%s)", arg_label);
      md_assemble ("add $ta,$ta,$gp");
      md_assemble ("jral $ta");
    }
  else
    {
      md_assemblef ("jal %s", arg_label);
    }
  relaxing = FALSE;
}
static void
do_pseudo_bge (int argc ATTRIBUTE_UNUSED, char *argv[], int pv ATTRIBUTE_UNUSED)
{
  md_assemblef ("slt $ta,%s,%s", argv[0], argv[1]);
  md_assemblef ("beqz $ta,%s", argv[2]);
}
static void
do_pseudo_bges (int argc ATTRIBUTE_UNUSED, char *argv[], int pv ATTRIBUTE_UNUSED)
{
  md_assemblef ("slts $ta,%s,%s", argv[0], argv[1]);
  md_assemblef ("beqz $ta,%s", argv[2]);
}
static void
do_pseudo_bgt (int argc ATTRIBUTE_UNUSED, char *argv[], int pv ATTRIBUTE_UNUSED)
{
  md_assemblef ("slt $ta,%s,%s", argv[1], argv[0]);
  md_assemblef ("bnez $ta,%s", argv[2]);
}
static void
do_pseudo_bgts (int argc ATTRIBUTE_UNUSED, char *argv[], int pv ATTRIBUTE_UNUSED)
{
  md_assemblef ("slts $ta,%s,%s", argv[1], argv[0]);
  md_assemblef ("bnez $ta,%s", argv[2]);
}
static void
do_pseudo_ble (int argc ATTRIBUTE_UNUSED, char *argv[], int pv ATTRIBUTE_UNUSED)
{
  md_assemblef ("slt $ta,%s,%s", argv[1], argv[0]);
  md_assemblef ("beqz $ta,%s", argv[2]);
}
static void
do_pseudo_bles (int argc ATTRIBUTE_UNUSED, char *argv[], int pv ATTRIBUTE_UNUSED)
{
  md_assemblef ("slts $ta,%s,%s", argv[1], argv[0]);
  md_assemblef ("beqz $ta,%s", argv[2]);
}
static void
do_pseudo_blt (int argc ATTRIBUTE_UNUSED, char *argv[], int pv ATTRIBUTE_UNUSED)
{
  md_assemblef ("slt $ta,%s,%s", argv[0], argv[1]);
  md_assemblef ("bnez $ta,%s", argv[2]);
}
static void
do_pseudo_blts (int argc ATTRIBUTE_UNUSED, char *argv[], int pv ATTRIBUTE_UNUSED)
{
  md_assemblef ("slts $ta,%s,%s", argv[0], argv[1]);
  md_assemblef ("bnez $ta,%s", argv[2]);
}
static void
do_pseudo_br (int argc ATTRIBUTE_UNUSED, char *argv[], int pv ATTRIBUTE_UNUSED)
{
  md_assemblef ("jr %s", argv[0]);
}
static void
do_pseudo_bral (int argc, char *argv[], int pv ATTRIBUTE_UNUSED)
{
  if (argc == 1)
    md_assemblef ("jral $lp,%s", argv[0]);
  else
    md_assemblef ("jral %s,%s", argv[0], argv[1]);
}
static void
do_pseudo_la_internal (const char *arg_reg, char *arg_label,
         const char *line)
{
  expressionS exp;
  parse_expression (arg_label, &exp);
  if (exp.X_op != O_symbol)
    {
      as_bad (_("la must use with symbol. '%s'"), line);
      return;
    }
  relaxing = TRUE;
  if (!nds32_pic && !strstr (arg_label, "@"))
    {
      md_assemblef ("sethi %s,hi20(%s)", arg_reg, arg_label);
      md_assemblef ("ori %s,%s,lo12(%s)", arg_reg, arg_reg, arg_label);
    }
  else if (strstr (arg_label, "@ICT"))
    {
      md_assemblef ("sethi %s,hi20(%s)", arg_reg, arg_label);
      md_assemblef ("ori %s,%s,lo12(%s)", arg_reg, arg_reg, arg_label);
    }
  else if (strstr (arg_label, "@TPOFF"))
    {
      md_assemblef ("sethi $ta,hi20(%s)", arg_label);
      md_assemblef ("ori $ta,$ta,lo12(%s)", arg_label);
      md_assemblef ("add %s,$ta,%s", arg_reg, TLS_REG);
    }
  else if (strstr (arg_label, "@GOTTPOFF"))
    {
      md_assemblef ("sethi $ta,hi20(%s)", arg_label);
      md_assemblef ("lwi $ta,[$ta+lo12(%s)]", arg_label);
      md_assemblef ("add %s,$ta,%s", arg_reg, TLS_REG);
    }
  else if (nds32_pic && ((strstr (arg_label, "@PLT")
     || strstr (arg_label, "@GOTOFF"))))
    {
      md_assemblef ("sethi $ta,hi20(%s)", arg_label);
      md_assemblef ("ori $ta,$ta,lo12(%s)", arg_label);
      md_assemblef ("add %s,$ta,$gp", arg_reg);
    }
  else if (nds32_pic && strstr (arg_label, "@GOT"))
    {
      long addend = builtin_addend (arg_label, NULL);
      md_assemblef ("sethi $ta,hi20(%s)", arg_label);
      md_assemblef ("ori $ta,$ta,lo12(%s)", arg_label);
      md_assemblef ("lw %s,[$gp+$ta]", arg_reg);
      if (addend != 0)
 {
   if (addend < 0x4000 && addend >= -0x4000)
     {
       md_assemblef ("addi %s,%s,%d", arg_reg, arg_reg, addend);
     }
   else
     {
       do_pseudo_li_internal ("$ta", addend);
       md_assemblef ("add %s,$ta,%s", arg_reg, arg_reg);
     }
 }
    }
   else
      as_bad (_("need PIC qualifier with symbol. '%s'"), line);
  relaxing = FALSE;
}
static void
do_pseudo_la (int argc ATTRIBUTE_UNUSED, char *argv[], int pv ATTRIBUTE_UNUSED)
{
  do_pseudo_la_internal (argv[0], argv[1], argv[argc]);
}
static void
do_pseudo_li_internal (char *rt, int imm32s)
{
  if (enable_16bit && imm32s <= 0xf && imm32s >= -0x10)
    md_assemblef ("movi55 %s,%d", rt, imm32s);
  else if (imm32s <= 0x7ffff && imm32s >= -0x80000)
    md_assemblef ("movi %s,%d", rt, imm32s);
  else if ((imm32s & 0xfff) == 0)
    md_assemblef ("sethi %s,hi20(%d)", rt, imm32s);
  else
    {
      md_assemblef ("sethi %s,hi20(%d)", rt, imm32s);
      md_assemblef ("ori %s,%s,lo12(%d)", rt, rt, imm32s);
    }
}
static void
do_pseudo_li (int argc ATTRIBUTE_UNUSED, char *argv[], int pv ATTRIBUTE_UNUSED)
{
  expressionS exp;
  parse_expression (argv[1], &exp);
  if (exp.X_op != O_constant)
    {
      as_bad (_("Operand is not a constant. `%s'"), argv[argc]);
      return;
    }
  do_pseudo_li_internal (argv[0], exp.X_add_number);
}
static void
do_pseudo_ls_bhw (int argc ATTRIBUTE_UNUSED, char *argv[], int pv)
{
  char ls = 'r';
  char size = 'x';
  const char *sign = "";
  sign = (pv & 0x10) ? "s" : "";
  ls = (pv & 0x80000000) ? 's' : 'l';
  switch (pv & 0x3)
    {
    case 0: size = 'b'; break;
    case 1: size = 'h'; break;
    case 2: size = 'w'; break;
    }
  if (ls == 's' || size == 'w')
    sign = "";
  if (builtin_isreg (argv[1], NULL))
    {
      md_assemblef ("%c%ci %s,[%s]", ls, size, argv[0], argv[1]);
    }
  else if (!nds32_pic)
    {
      relaxing = TRUE;
      if (strstr (argv[1], "@TPOFF"))
 {
   md_assemblef ("sethi $ta,hi20(%s)", argv[1]);
   md_assemblef ("ori $ta,$ta,lo12(%s)", argv[1]);
   md_assemblef ("%c%c%s %s,[$ta+%s]", ls, size, sign, argv[0], TLS_REG);
 }
      else if (strstr (argv[1], "@GOTTPOFF"))
 {
   md_assemblef ("sethi $ta,hi20(%s)", argv[1]);
   md_assemblef ("lwi $ta,[$ta+lo12(%s)]", argv[1]);
   md_assemblef ("%c%c%s %s,[$ta+%s]", ls, size, sign, argv[0], TLS_REG);
 }
      else
 {
   md_assemblef ("sethi $ta,hi20(%s)", argv[1]);
   md_assemblef ("%c%c%si %s,[$ta+lo12(%s)]", ls, size, sign, argv[0], argv[1]);
 }
      relaxing = FALSE;
    }
  else
    {
      relaxing = TRUE;
      if (strstr (argv[1], "@GOTOFF"))
 {
   md_assemblef ("sethi $ta,hi20(%s)", argv[1]);
   md_assemblef ("ori $ta,$ta,lo12(%s)", argv[1]);
   md_assemblef ("%c%c%s %s,[$ta+$gp]", ls, size, sign, argv[0]);
 }
      else if (strstr (argv[1], "@GOT"))
 {
   long addend = builtin_addend (argv[1], NULL);
   md_assemblef ("sethi $ta,hi20(%s)", argv[1]);
   md_assemblef ("ori $ta,$ta,lo12(%s)", argv[1]);
   md_assemble ("lw $ta,[$gp+$ta]");
   if (addend < 0x10000 && addend >= -0x10000)
     {
       md_assemblef ("%c%c%si %s,[$ta+(%d)]", ls, size, sign, argv[0], addend);
     }
   else
     {
       do_pseudo_li_internal (argv[0], addend);
       md_assemblef ("%c%c%s %s,[$ta+%s]", ls, size, sign, argv[0], argv[0]);
     }
 }
      else
 {
   as_bad (_("needs @GOT or @GOTOFF. %s"), argv[argc]);
 }
      relaxing = FALSE;
    }
}
static void
do_pseudo_ls_bhwp (int argc ATTRIBUTE_UNUSED, char *argv[], int pv)
{
  char *arg_rt = argv[0];
  char *arg_label = argv[1];
  char *arg_inc = argv[2];
  char ls = 'r';
  char size = 'x';
  const char *sign = "";
  sign = (pv & 0x10) ? "s" : "";
  ls = (pv & 0x80000000) ? 's' : 'l';
  switch (pv & 0x3)
    {
    case 0: size = 'b'; break;
    case 1: size = 'h'; break;
    case 2: size = 'w'; break;
    }
  if (ls == 's' || size == 'w')
    sign = "";
  do_pseudo_la_internal ("$ta", arg_label, argv[argc]);
  md_assemblef ("%c%c%si.bi %s,[$ta],%s", ls, size, sign, arg_rt, arg_inc);
}
static void
do_pseudo_ls_bhwpc (int argc ATTRIBUTE_UNUSED, char *argv[], int pv)
{
  char *arg_rt = argv[0];
  char *arg_inc = argv[1];
  char ls = 'r';
  char size = 'x';
  const char *sign = "";
  sign = (pv & 0x10) ? "s" : "";
  ls = (pv & 0x80000000) ? 's' : 'l';
  switch (pv & 0x3)
    {
    case 0: size = 'b'; break;
    case 1: size = 'h'; break;
    case 2: size = 'w'; break;
    }
  if (ls == 's' || size == 'w')
    sign = "";
  md_assemblef ("%c%c%si.bi %s,[$ta],%s", ls, size, sign, arg_rt, arg_inc);
}
static void
do_pseudo_ls_bhwi (int argc ATTRIBUTE_UNUSED, char *argv[], int pv)
{
  char ls = 'r';
  char size = 'x';
  const char *sign = "";
  sign = (pv & 0x10) ? "s" : "";
  ls = (pv & 0x80000000) ? 's' : 'l';
  switch (pv & 0x3)
    {
    case 0: size = 'b'; break;
    case 1: size = 'h'; break;
    case 2: size = 'w'; break;
    }
  if (ls == 's' || size == 'w')
    sign = "";
  md_assemblef ("%c%c%si.bi %s,%s,%s",
  ls, size, sign, argv[0], argv[1], argv[2]);
}
static void
do_pseudo_move_reg_internal (char *dst, char *src)
{
  if (enable_16bit)
    md_assemblef ("mov55 %s,%s", dst, src);
  else
    md_assemblef ("ori %s,%s,0", dst, src);
}
static void
do_pseudo_move (int argc ATTRIBUTE_UNUSED, char *argv[], int pv ATTRIBUTE_UNUSED)
{
  expressionS exp;
  if (builtin_isreg (argv[1], NULL))
    do_pseudo_move_reg_internal (argv[0], argv[1]);
  else
    {
      parse_expression (argv[1], &exp);
      if (exp.X_op == O_constant)
 do_pseudo_li_internal (argv[0], exp.X_add_number);
      else
 do_pseudo_ls_bhw (argc, argv, 2);
    }
}
static void
do_pseudo_neg (int argc ATTRIBUTE_UNUSED, char *argv[], int pv ATTRIBUTE_UNUSED)
{
  md_assemblef ("subri %s,%s,0", argv[0], argv[1]);
}
static void
do_pseudo_not (int argc ATTRIBUTE_UNUSED, char *argv[], int pv ATTRIBUTE_UNUSED)
{
  md_assemblef ("nor %s,%s,%s", argv[0], argv[1], argv[1]);
}
static void
do_pseudo_pushpopm (int argc, char *argv[], int pv ATTRIBUTE_UNUSED)
{
  int rb, re, ra, en4;
  int i;
  char *opc = "pushpopm";
  if (argc == 3)
    as_bad ("'pushm/popm $ra5, $rb5, $label' is deprecated.  "
     "Only 'pushm/popm $ra5' is supported now. %s", argv[argc]);
  else if (argc == 1)
    as_bad ("'pushm/popm $ra5, $rb5'. %s\n", argv[argc]);
  if (strstr (argv[argc], "pop") == argv[argc])
    opc = "lmw.bim";
  else if (strstr (argv[argc], "push") == argv[argc])
    opc = "smw.adm";
  else
    as_fatal ("nds32-as internal error. %s", argv[argc]);
  rb = builtin_regnum (argv[0], NULL);
  re = builtin_regnum (argv[1], NULL);
  if (re < rb)
    {
      as_warn ("$rb should not be smaller than $ra. %s", argv[argc]);
      ra = re;
      re = rb;
      rb = ra;
    }
  en4 = 0;
  if (re >= 28 || rb >= 28)
    {
      for (i = (rb >= 28? rb: 28); i <= re; i++)
 en4 |= 1 << (3 - (i - 28));
    }
  if (rb >= 28)
    rb = re = 31;
  else if (nds32_gpr16 != 1 && re >= 28)
    re = 27;
  if (nds32_gpr16 && re > 10 && !(rb == 31 && re == 31))
    {
      if (re >= 15 && strstr (opc, "smw") != NULL)
 md_assemblef ("%s $r15,[$sp],$r15,%d", opc, en4);
      if (rb <= 10)
 md_assemblef ("%s $r%d,[$sp],$r10, 0x0", opc, rb);
      if (re >= 15 && strstr (opc, "lmw") != NULL)
 md_assemblef ("%s $r15,[$sp],$r15,%d", opc, en4);
    }
  else
    md_assemblef ("%s $r%d,[$sp],$r%d,%d", opc, rb, re, en4);
}
static void
do_pseudo_pushpop (int argc, char *argv[], int pv ATTRIBUTE_UNUSED)
{
  char *argvm[3];
  if (argc == 2)
    as_bad ("'push/pop $ra5, rb5' is deprecated.  "
     "Only 'push/pop $ra5' is supported now. %s", argv[argc]);
  argvm[0] = argv[0];
  argvm[1] = argv[0];
  argvm[2] = argv[argc];
  do_pseudo_pushpopm (2, argvm, PV_DONT_CARE);
}
static void
do_pseudo_v3push (int argc ATTRIBUTE_UNUSED, char *argv[], int pv ATTRIBUTE_UNUSED)
{
  md_assemblef ("push25 %s,%s", argv[0], argv[1]);
}
static void
do_pseudo_v3pop (int argc ATTRIBUTE_UNUSED, char *argv[], int pv ATTRIBUTE_UNUSED)
{
  md_assemblef ("pop25 %s,%s", argv[0], argv[1]);
}
static void
do_pseudo_pushpop_stack (int argc, char *argv[], int pv)
{
  int rb, re;
  int en4;
  int last_arg_index;
  const char *opc = (pv == 0) ? "smw.adm" : "lmw.bim";
  rb = re = 0;
  if (argc == 1)
    {
      rb = re = 31;
    }
  else if (argc == 2 || argc == 3)
    {
      rb = builtin_regnum (argv[0], NULL);
      re = builtin_regnum (argv[1], NULL);
      if (rb > re)
 as_bad ("The first operand (%s) should be equal to or smaller than "
  "second operand (%s).", argv[0], argv[1]);
      if (rb >= 28)
 as_bad ("Cannot use $fp, $gp, $lp, or $sp at first operand !!");
      if (re >= 28)
 as_bad ("Cannot use $fp, $gp, $lp, or $sp at second operand !!");
    }
  else
    {
      as_bad ("Invalid operands pattern !!");
    }
  en4 = 0;
  last_arg_index = argc - 1;
  if (strstr (argv[last_arg_index], "$fp"))
    en4 |= 8;
  if (strstr (argv[last_arg_index], "$gp"))
    en4 |= 4;
  if (strstr (argv[last_arg_index], "$lp"))
    en4 |= 2;
  if (strstr (argv[last_arg_index], "$sp"))
    en4 |= 1;
  md_assemblef ("%s $r%d,[$sp],$r%d,%d", opc, rb, re, en4);
}
static void
do_pseudo_push_bhwd (int argc ATTRIBUTE_UNUSED, char *argv[], int pv ATTRIBUTE_UNUSED)
{
  char size = 'x';
  char location[8] = "$sp";
  switch (pv & 0x3)
    {
    case 0: size = 'b'; break;
    case 1: size = 'h'; break;
    case 2: size = 'w'; break;
    case 3: size = 'w'; break;
    }
  if (argc == 2)
    {
      strncpy (location, argv[1], 8);
      location[7] = '\0';
    }
  md_assemblef ("l.%c $ta,%s", size, argv[0]);
  md_assemblef ("smw.adm $ta,[%s],$ta", location);
  if ((pv & 0x3) == 0x3)
    {
      md_assemblef ("l.w $ta,%s+4", argv[0]);
      md_assemblef ("smw.adm $ta,[%s],$ta", location);
    }
}
static void
do_pseudo_pop_bhwd (int argc ATTRIBUTE_UNUSED, char *argv[], int pv ATTRIBUTE_UNUSED)
{
  char size = 'x';
  char location[8] = "$sp";
  switch (pv & 0x3)
    {
    case 0: size = 'b'; break;
    case 1: size = 'h'; break;
    case 2: size = 'w'; break;
    case 3: size = 'w'; break;
    }
  if (argc == 3)
    {
      strncpy (location, argv[2], 8);
      location[7] = '\0';
    }
  if ((pv & 0x3) == 0x3)
    {
      md_assemblef ("lmw.bim %s,[%s],%s", argv[1], location, argv[1]);
      md_assemblef ("s.w %s,%s+4", argv[1], argv[0]);
    }
  md_assemblef ("lmw.bim %s,[%s],%s", argv[1], location, argv[1]);
  md_assemblef ("s.%c %s,%s", size, argv[1], argv[0]);
}
static void
do_pseudo_pusha (int argc ATTRIBUTE_UNUSED, char *argv[], int pv ATTRIBUTE_UNUSED)
{
  char location[8] = "$sp";
  if (argc == 2)
    {
      strncpy (location, argv[1], 8);
      location[7] = '\0';
    }
  md_assemblef ("la $ta,%s", argv[0]);
  md_assemblef ("smw.adm $ta,[%s],$ta", location);
}
static void
do_pseudo_pushi (int argc ATTRIBUTE_UNUSED, char *argv[], int pv ATTRIBUTE_UNUSED)
{
  char location[8] = "$sp";
  if (argc == 2)
    {
      strncpy (location, argv[1], 8);
      location[7] = '\0';
    }
  md_assemblef ("li $ta,%s", argv[0]);
  md_assemblef ("smw.adm $ta,[%s],$ta", location);
}
static struct nds32_pseudo_opcode nds32_pseudo_opcode_table[] = {
  {"b", 1, do_pseudo_b, 0, 0},
  {"bal", 1, do_pseudo_bal, 0, 0},
  {"bge", 3, do_pseudo_bge, 0, 0},
  {"bges", 3, do_pseudo_bges, 0, 0},
  {"bgt", 3, do_pseudo_bgt, 0, 0},
  {"bgts", 3, do_pseudo_bgts, 0, 0},
  {"ble", 3, do_pseudo_ble, 0, 0},
  {"bles", 3, do_pseudo_bles, 0, 0},
  {"blt", 3, do_pseudo_blt, 0, 0},
  {"blts", 3, do_pseudo_blts, 0, 0},
  {"br", 1, do_pseudo_br, 0, 0},
  {"bral", 1, do_pseudo_bral, 0, 0},
  {"call", 1, do_pseudo_bal, 0, 0},
  {"la", 2, do_pseudo_la, 0, 0},
  {"li", 2, do_pseudo_li, 0, 0},
  {"l.b", 2, do_pseudo_ls_bhw, 0, 0},
  {"l.h", 2, do_pseudo_ls_bhw, 1, 0},
  {"l.w", 2, do_pseudo_ls_bhw, 2, 0},
  {"l.bs", 2, do_pseudo_ls_bhw, 0 | 0x10, 0},
  {"l.hs", 2, do_pseudo_ls_bhw, 1 | 0x10, 0},
  {"s.b", 2, do_pseudo_ls_bhw, 0 | 0x80000000, 0},
  {"s.h", 2, do_pseudo_ls_bhw, 1 | 0x80000000, 0},
  {"s.w", 2, do_pseudo_ls_bhw, 2 | 0x80000000, 0},
  {"l.bp", 3, do_pseudo_ls_bhwp, 0, 0},
  {"l.bpc", 3, do_pseudo_ls_bhwpc, 0, 0},
  {"l.hp", 3, do_pseudo_ls_bhwp, 1, 0},
  {"l.hpc", 3, do_pseudo_ls_bhwpc, 1, 0},
  {"l.wp", 3, do_pseudo_ls_bhwp, 2, 0},
  {"l.wpc", 3, do_pseudo_ls_bhwpc, 2, 0},
  {"l.bsp", 3, do_pseudo_ls_bhwp, 0 | 0x10, 0},
  {"l.bspc", 3, do_pseudo_ls_bhwpc, 0 | 0x10, 0},
  {"l.hsp", 3, do_pseudo_ls_bhwp, 1 | 0x10, 0},
  {"l.hspc", 3, do_pseudo_ls_bhwpc, 1 | 0x10, 0},
  {"s.bp", 3, do_pseudo_ls_bhwp, 0 | 0x80000000, 0},
  {"s.bpc", 3, do_pseudo_ls_bhwpc, 0 | 0x80000000, 0},
  {"s.hp", 3, do_pseudo_ls_bhwp, 1 | 0x80000000, 0},
  {"s.hpc", 3, do_pseudo_ls_bhwpc, 1 | 0x80000000, 0},
  {"s.wp", 3, do_pseudo_ls_bhwp, 2 | 0x80000000, 0},
  {"s.wpc", 3, do_pseudo_ls_bhwpc, 2 | 0x80000000, 0},
  {"s.bsp", 3, do_pseudo_ls_bhwp, 0 | 0x80000000 | 0x10, 0},
  {"s.hsp", 3, do_pseudo_ls_bhwp, 1 | 0x80000000 | 0x10, 0},
  {"lbi.p", 3, do_pseudo_ls_bhwi, 0, 0},
  {"lhi.p", 3, do_pseudo_ls_bhwi, 1, 0},
  {"lwi.p", 3, do_pseudo_ls_bhwi, 2, 0},
  {"sbi.p", 3, do_pseudo_ls_bhwi, 0 | 0x80000000, 0},
  {"shi.p", 3, do_pseudo_ls_bhwi, 1 | 0x80000000, 0},
  {"swi.p", 3, do_pseudo_ls_bhwi, 2 | 0x80000000, 0},
  {"lbsi.p", 3, do_pseudo_ls_bhwi, 0 | 0x10, 0},
  {"lhsi.p", 3, do_pseudo_ls_bhwi, 1 | 0x10, 0},
  {"lwsi.p", 3, do_pseudo_ls_bhwi, 2 | 0x10, 0},
  {"move", 2, do_pseudo_move, 0, 0},
  {"neg", 2, do_pseudo_neg, 0, 0},
  {"not", 2, do_pseudo_not, 0, 0},
  {"pop", 2, do_pseudo_pushpop, 0, 0},
  {"push", 2, do_pseudo_pushpop, 0, 0},
  {"popm", 2, do_pseudo_pushpopm, 0, 0},
  {"pushm", 3, do_pseudo_pushpopm, 0, 0},
  {"v3push", 2, do_pseudo_v3push, 0, 0},
  {"v3pop", 2, do_pseudo_v3pop, 0, 0},
  { "push.s", 3, do_pseudo_pushpop_stack, 0, 0 },
  { "pop.s", 3, do_pseudo_pushpop_stack, 1, 0 },
  { "push.b", 2, do_pseudo_push_bhwd, 0, 0 },
  { "push.h", 2, do_pseudo_push_bhwd, 1, 0 },
  { "push.w", 2, do_pseudo_push_bhwd, 2, 0 },
  { "push.d", 2, do_pseudo_push_bhwd, 3, 0 },
  { "pop.b", 3, do_pseudo_pop_bhwd, 0, 0 },
  { "pop.h", 3, do_pseudo_pop_bhwd, 1, 0 },
  { "pop.w", 3, do_pseudo_pop_bhwd, 2, 0 },
  { "pop.d", 3, do_pseudo_pop_bhwd, 3, 0 },
  { "pusha", 2, do_pseudo_pusha, 0, 0 },
  { "pushi", 2, do_pseudo_pushi, 0, 0 },
  {NULL, 0, NULL, 0, 0}
};
static void
nds32_init_nds32_pseudo_opcodes (void)
{
  struct nds32_pseudo_opcode *opcode = nds32_pseudo_opcode_table;
  nds32_pseudo_opcode_hash = hash_new ();
  for ( ; opcode->opcode; opcode++)
    {
      void *op;
      op = hash_find (nds32_pseudo_opcode_hash, opcode->opcode);
      if (op != NULL)
 {
   as_warn (_("Duplicated pseudo-opcode %s."), opcode->opcode);
   continue;
 }
      hash_insert (nds32_pseudo_opcode_hash, opcode->opcode, opcode);
    }
}
static struct nds32_pseudo_opcode *
nds32_lookup_pseudo_opcode (char *str)
{
  int i = 0;
  int maxlen = strlen (str);
  char *op = alloca (maxlen + 1);
  for (i = 0; i < maxlen; i++)
    {
      if (ISSPACE (op[i] = str[i]))
 break;
    }
  op[i] = '\0';
  return hash_find (nds32_pseudo_opcode_hash, op);
}
static void
nds32_pseudo_opcode_wrapper (char *line, struct nds32_pseudo_opcode *opcode)
{
  int argc = 0;
  char *argv[8] = {NULL};
  char *s;
  char *str = xstrdup (line);
  s = str + strlen (opcode->opcode);
  if (!s[0])
    goto end;
  s[0] = ',';
  do
    {
      if (s[0] == ',')
 {
   if (argc >= opcode->argc
       || (argc >= (int)ARRAY_SIZE (argv) - 1))
     as_bad (_("Too many argument. `%s'"), line);
   argv[argc] = s + 1;
   argc ++;
   s[0] = '\0';
 }
      ++s;
    } while (s[0] != '\0');
end:
  argv[argc] = line;
  opcode->proc (argc, argv, opcode->pseudo_val);
  free (str);
}
static int
nds32_parse_arch (char *str)
{
  static const struct nds32_arch
  {
    const char *name;
    int baseline;
    int reduced_reg;
    int fpu_sp_ext;
    int fpu_dp_ext;
    int fpu_freg;
    int abi;
  } archs[] =
  {
    {"v3m", ISA_V3M, 1, 0, 0, E_NDS32_FPU_REG_32SP_16DP, E_NDS_ABI_AABI},
    {"v3m+",ISA_V3M, 1, 0, 0, E_NDS32_FPU_REG_32SP_16DP, E_NDS_ABI_AABI},
    {"v3j", ISA_V3, 1, 0, 0, E_NDS32_FPU_REG_32SP_16DP, E_NDS_ABI_AABI},
    {"v3s", ISA_V3, 0, 1, 0, E_NDS32_FPU_REG_32SP_16DP, E_NDS_ABI_V2FP_PLUS},
    {"v3f", ISA_V3, 0, 1, 1, E_NDS32_FPU_REG_32SP_16DP, E_NDS_ABI_V2FP_PLUS},
    {"v3", ISA_V3, 0, 0, 0, E_NDS32_FPU_REG_32SP_16DP, E_NDS_ABI_AABI},
    {"v2j", ISA_V2, 1, 0, 0, E_NDS32_FPU_REG_32SP_16DP, E_NDS_ABI_AABI},
    {"v2s", ISA_V2, 0, 1, 0, E_NDS32_FPU_REG_32SP_16DP, E_NDS_ABI_V2FP_PLUS},
    {"v2f", ISA_V2, 0, 1, 1, E_NDS32_FPU_REG_32SP_16DP, E_NDS_ABI_V2FP_PLUS},
    {"v2", ISA_V2, 0, 0, 0, E_NDS32_FPU_REG_32SP_16DP, E_NDS_ABI_AABI},
  };
  size_t i;
  for (i = 0; i < ARRAY_SIZE (archs); i++)
    {
      if (strcmp (str, archs[i].name) != 0)
 continue;
      nds32_baseline = (-1 != nds32_baseline) ? nds32_baseline : archs[i].baseline;
      nds32_gpr16 = (-1 != nds32_gpr16) ? nds32_gpr16 : archs[i].reduced_reg;
      nds32_fpu_sp_ext = (-1 != nds32_fpu_sp_ext) ? nds32_fpu_sp_ext : archs[i].fpu_sp_ext;
      nds32_fpu_dp_ext = (-1 != nds32_fpu_dp_ext) ? nds32_fpu_dp_ext : archs[i].fpu_dp_ext;
      nds32_freg = (-1 != nds32_freg) ? nds32_freg : archs[i].fpu_freg;
      nds32_abi = (-1 != nds32_abi) ? nds32_abi : archs[i].abi;
      return 1;
    }
  as_bad (_("unknown arch name `%s'\n"), str);
  return 1;
}
static int
nds32_parse_baseline (char *str)
{
  if (strcasecmp (str, "v3") == 0)
    nds32_baseline = ISA_V3;
  else if (strcasecmp (str, "v3m") == 0)
    nds32_baseline = ISA_V3M;
  else if (strcasecmp (str, "v2") == 0)
    nds32_baseline = ISA_V2;
  else
    {
      as_bad (_("unknown baseline `%s'\n"), str);
      return 0;
    }
  return 1;
}
static int
nds32_parse_freg (char *str)
{
  if (strcmp (str, "2") == 0 || strcmp (str, "6") == 0)
    nds32_freg = E_NDS32_FPU_REG_32SP_16DP;
  else if (strcmp (str, "3") == 0 || strcmp (str, "7") == 0)
    nds32_freg = E_NDS32_FPU_REG_32SP_32DP;
  else if (strcmp (str, "1") == 0 || strcmp (str, "5") == 0)
    nds32_freg = E_NDS32_FPU_REG_16SP_8DP;
  else if (strcmp (str, "0") == 0 || strcmp (str, "4") == 0)
    nds32_freg = E_NDS32_FPU_REG_8SP_4DP;
  else
    {
      as_bad (_("unknown FPU configuration `%s'\n"), str);
      return 0;
    }
  return 1;
}
static int
nds32_parse_abi (char *str)
{
  if (strcmp (str, "v2") == 0)
    nds32_abi = E_NDS_ABI_AABI;
  else if (strcmp (str, "v2fp") == 0)
    nds32_abi = E_NDS_ABI_V2FP;
  else if (strcmp (str, "v1") == 0)
    nds32_abi = E_NDS_ABI_V1;
  else if (strcmp (str,"v2fpp") == 0 || strcmp (str,"v2fp+") == 0)
    nds32_abi = E_NDS_ABI_V2FP_PLUS;
  else
    {
      if (TRUE)
 return 1;
      else
 {
   as_bad (_("unknown ABI version`%s'\n"), str);
   return 0;
 }
    }
  return 1;
}
static int
nds32_all_ext (void)
{
  nds32_mac = 1;
  nds32_div = 1;
  nds32_dx_regs = 1;
  nds32_16bit_ext = 1;
  nds32_perf_ext = 1;
  nds32_perf_ext2 = 1;
  nds32_string_ext = 1;
  nds32_audio_ext = 1;
  nds32_fpu_fma = 1;
  nds32_fpu_sp_ext = 1;
  nds32_fpu_dp_ext = 1;
  nds32_dsp_ext = 1;
  nds32_zol_ext = 1;
  nds32_gpr16 = 0;
  return 1;
}
int
nds32_parse_option (int c, char *arg)
{
  struct nds32_parse_option_table *coarse_tune;
  struct nds32_set_option_table *fine_tune;
  char *ptr_arg = NULL;
  switch (c)
    {
    case OPTION_OPTIMIZE:
      optimize = 1;
      optimize_for_space = 0;
      break;
    case OPTION_OPTIMIZE_SPACE:
      optimize = 0;
      optimize_for_space = 1;
      break;
    case OPTION_BIG:
      target_big_endian = 1;
      break;
    case OPTION_LITTLE:
      target_big_endian = 0;
      break;
    case OPTION_TURBO:
      nds32_all_ext ();
      break;
    case OPTION_PIC:
      nds32_pic = 1;
      break;
    case OPTION_RELAX_FP_AS_GP_OFF:
      nds32_relax_fp_as_gp = 0;
      break;
    case OPTION_RELAX_B2BB_ON:
      nds32_relax_b2bb = 1;
      break;
    case OPTION_RELAX_ALL_OFF:
      nds32_relax_all = 0;
      break;
    default:
      if (!arg)
 return 0;
      ptr_arg = strchr (arg, '=');
      if (ptr_arg)
 {
   if (ptr_arg != NULL)
     ptr_arg++;
   for (coarse_tune = parse_opts; coarse_tune->name != NULL; coarse_tune++)
     {
       if (strncmp (arg, coarse_tune->name, (ptr_arg - arg)) == 0)
  {
    coarse_tune->func (ptr_arg);
    return 1;
  }
     }
 }
      else
 {
   int disable = 0;
   if (strncmp (arg, "no-", 3) == 0)
     {
       disable = 1;
       arg += 3;
     }
   for (fine_tune = toggle_opts; fine_tune->name != NULL; fine_tune++)
     {
       if (strcmp (arg, fine_tune->name) == 0)
  {
    if (fine_tune->var != NULL)
      *fine_tune->var = (disable) ? 0 : 1;
    return 1;
  }
     }
 }
      return 0;
    }
  return 1;
}
void
nds32_check_label (symbolS *label ATTRIBUTE_UNUSED)
{
}
static void
set_endian_little (int on)
{
  target_big_endian = !on;
}
static void
trigger_16bit (int trigger)
{
  enable_16bit = trigger;
}
static int backup_16bit_mode;
static void
restore_16bit (int no_use ATTRIBUTE_UNUSED)
{
  enable_16bit = backup_16bit_mode;
}
static void
off_16bit (int no_use ATTRIBUTE_UNUSED)
{
  backup_16bit_mode = enable_16bit;
  enable_16bit = 0;
}
typedef struct nds32_seg_entryT
{
  segT s;
  const char *name;
  flagword flags;
} nds32_seg_entry;
static nds32_seg_entry nds32_seg_table[] = {
  {NULL, ".sdata_f", SEC_ALLOC | SEC_LOAD | SEC_RELOC | SEC_DATA
       | SEC_HAS_CONTENTS | SEC_SMALL_DATA},
  {NULL, ".sdata_b", SEC_ALLOC | SEC_LOAD | SEC_RELOC | SEC_DATA
       | SEC_HAS_CONTENTS | SEC_SMALL_DATA},
  {NULL, ".sdata_h", SEC_ALLOC | SEC_LOAD | SEC_RELOC | SEC_DATA
       | SEC_HAS_CONTENTS | SEC_SMALL_DATA},
  {NULL, ".sdata_w", SEC_ALLOC | SEC_LOAD | SEC_RELOC | SEC_DATA
       | SEC_HAS_CONTENTS | SEC_SMALL_DATA},
  {NULL, ".sdata_d", SEC_ALLOC | SEC_LOAD | SEC_RELOC | SEC_DATA
       | SEC_HAS_CONTENTS | SEC_SMALL_DATA},
  {NULL, ".sbss_f", SEC_ALLOC | SEC_SMALL_DATA},
  {NULL, ".sbss_b", SEC_ALLOC | SEC_SMALL_DATA},
  {NULL, ".sbss_h", SEC_ALLOC | SEC_SMALL_DATA},
  {NULL, ".sbss_w", SEC_ALLOC | SEC_SMALL_DATA},
  {NULL, ".sbss_d", SEC_ALLOC | SEC_SMALL_DATA}
};
enum NDS32_SECTIONS_ENUM
{
  SDATA_F_SECTION = 0,
  SDATA_B_SECTION = 1,
  SDATA_H_SECTION = 2,
  SDATA_W_SECTION = 3,
  SDATA_D_SECTION = 4,
  SBSS_F_SECTION = 5,
  SBSS_B_SECTION = 6,
  SBSS_H_SECTION = 7,
  SBSS_W_SECTION = 8,
  SBSS_D_SECTION = 9
};
static void
do_nds32_seg (int i, subsegT sub)
{
  nds32_seg_entry *seg = nds32_seg_table + i;
  obj_elf_section_change_hook ();
  if (seg->s != NULL)
    subseg_set (seg->s, sub);
  else
    {
      seg->s = subseg_new (seg->name, sub);
      if (OUTPUT_FLAVOR == bfd_target_elf_flavour)
 {
   bfd_set_section_flags (stdoutput, seg->s, seg->flags);
   if ((seg->flags & SEC_LOAD) == 0)
     seg_info (seg->s)->bss = 1;
 }
    }
}
static void
nds32_seg (int i)
{
  subsegT sub = get_absolute_expression ();
  do_nds32_seg (i, sub);
  demand_empty_rest_of_line ();
}
static symbolS *nds32_last_label;
static void
add_mapping_symbol_for_align (int shift, valueT addr, int is_data_align)
{
  if ((shift > 1) && (addr & 1))
    {
      int n = (1 << shift) - 1;
      if (!is_data_align)
 add_mapping_symbol (MAP_CODE, 1, 0);
      else if ((int) (addr & n) != n)
 add_mapping_symbol (MAP_CODE, 1, 0);
    }
  else if ((shift > 1) && ((int) (addr & 1) == 0))
    add_mapping_symbol (MAP_CODE, 0, 0);
}
static void
nds32_adjust_label (int n)
{
  symbolS *label = nds32_last_label;
  nds32_last_label = NULL;
  if (((now_seg->flags & SEC_ALLOC) == 0 && (now_seg->flags & SEC_CODE) == 0)
      || strcmp (now_seg->name, ".eh_frame") == 0
      || strcmp (now_seg->name, ".gcc_except_table") == 0)
    return;
  if (frag_now_fix () & ((1 << n) -1 ))
    {
      if (subseg_text_p (now_seg))
 {
   add_mapping_symbol_for_align (n, frag_now_fix (), 1);
   frag_align_code (n, 0);
 }
      else
 frag_align (n, 0, 0);
      record_alignment (now_seg, n - OCTETS_PER_BYTE_POWER);
    }
  if (label != NULL)
    {
      symbolS *sym;
      int label_seen = FALSE;
      struct frag *old_frag;
      valueT old_value, new_value;
      gas_assert (S_GET_SEGMENT (label) == now_seg);
      old_frag = symbol_get_frag (label);
      old_value = S_GET_VALUE (label);
      new_value = (valueT) frag_now_fix ();
      for (sym = symbol_lastP; sym != NULL; sym = symbol_previous (sym))
 {
   if (symbol_get_frag (sym) == old_frag
       && S_GET_VALUE (sym) == old_value)
     {
       label_seen = TRUE;
       symbol_set_frag (sym, frag_now);
       S_SET_VALUE (sym, new_value);
     }
   else if (label_seen && symbol_get_frag (sym) != old_frag)
     break;
 }
    }
}
void
nds32_cons_align (int size ATTRIBUTE_UNUSED)
{
}
static void
make_mapping_symbol (enum mstate state, valueT value, fragS * frag, unsigned int align)
{
  symbolS *symbol_p = NULL;
  const char *symbol_name = NULL;
  switch (state)
    {
    case MAP_DATA:
      if (align == 0) {
              symbol_name = "$d0";
      }
      else if (align == 1) {
              symbol_name = "$d1";
      }
      else if (align == 2)
              symbol_name = "$d2";
      else if (align == 3)
              symbol_name = "$d3";
      else if (align == 4)
              symbol_name = "$d4";
      break;
    case MAP_CODE:
      symbol_name = "$c";
      break;
    default:
      abort ();
    }
  symbol_p = symbol_new (symbol_name, now_seg, value, frag);
  symbol_get_bfdsym (symbol_p)->flags |= BSF_NO_FLAGS | BSF_LOCAL;
}
static void
add_mapping_symbol (enum mstate state, unsigned int padding_byte, unsigned int align)
{
  enum mstate current_mapping_state =
    seg_info (now_seg)->tc_segment_info_data.mapstate;
  if (state == MAP_CODE && current_mapping_state == state)
    return;
  if (!SEG_NORMAL (now_seg) || !subseg_text_p (now_seg))
    return;
  seg_info (now_seg)->tc_segment_info_data.mapstate = state;
  make_mapping_symbol (state, (valueT) frag_now_fix () + padding_byte,
         frag_now, align);
}
static void
nds32_aligned_cons (int idx)
{
  nds32_adjust_label (idx);
  add_mapping_symbol (MAP_DATA, 0, idx);
  cons (1 << idx);
  if (now_seg->flags & SEC_CODE
      && now_seg->flags & SEC_ALLOC && now_seg->flags & SEC_RELOC)
    {
      expressionS exp;
      exp.X_add_number = 0;
      exp.X_op = O_constant;
      fix_new_exp (frag_now, frag_now_fix () - (1 << idx), 1 << idx,
     &exp, 0, BFD_RELOC_NDS32_DATA);
    }
}
static void
nds32_aligned_float_cons (int type)
{
  switch (type)
    {
    case 'f':
    case 'F':
    case 's':
    case 'S':
      nds32_adjust_label (2);
      break;
    case 'd':
    case 'D':
    case 'r':
    case 'R':
      nds32_adjust_label (4);
      break;
    default:
      as_bad ("Unrecognized float type, %c\n", (char)type);
    }
  float_cons (type);
}
static void
nds32_enable_pic (int ignore ATTRIBUTE_UNUSED)
{
  nds32_pic = 1;
}
static void
nds32_set_abi (int ver)
{
  nds32_abi = ver;
}
static void
nds32_relax_relocs (int relax)
{
  char saved_char;
  char *name;
  int i;
  const char *subtype_relax[] =
    {"", ""};
  name = input_line_pointer;
  while (*input_line_pointer && !ISSPACE (*input_line_pointer))
    input_line_pointer++;
  saved_char = *input_line_pointer;
  *input_line_pointer = 0;
  for (i = 0; i < (int) ARRAY_SIZE (subtype_relax); i++)
    {
      if (strcmp (name, subtype_relax[i]) == 0)
 {
   switch (i)
     {
     case 0:
     case 1:
       enable_relax_relocs = relax & enable_relax_relocs;
       break;
     default:
       break;
     }
   break;
 }
    }
  *input_line_pointer = saved_char;
  ignore_rest_of_line ();
}
static void
nds32_set_hint_func_args (int ignore ATTRIBUTE_UNUSED)
{
  ignore_rest_of_line ();
}
static void
nds32_omit_fp_begin (int mode)
{
  expressionS exp;
  if (nds32_relax_fp_as_gp == 0)
    return;
  exp.X_op = O_symbol;
  exp.X_add_symbol = abs_section_sym;
  if (mode == 1)
    {
      in_omit_fp = 1;
      exp.X_add_number = R_NDS32_RELAX_REGION_OMIT_FP_FLAG;
      fix_new_exp (frag_now, frag_now_fix (), 0, &exp, 0,
     BFD_RELOC_NDS32_RELAX_REGION_BEGIN);
    }
  else
    {
      in_omit_fp = 0;
      exp.X_add_number = R_NDS32_RELAX_REGION_OMIT_FP_FLAG;
      fix_new_exp (frag_now, frag_now_fix (), 0, &exp, 0,
     BFD_RELOC_NDS32_RELAX_REGION_END);
    }
}
static void
nds32_loop_begin (int mode)
{
  expressionS exp;
  exp.X_op = O_symbol;
  exp.X_add_symbol = abs_section_sym;
  if (mode == 1)
    {
      exp.X_add_number = R_NDS32_RELAX_REGION_INNERMOST_LOOP_FLAG;
      fix_new_exp (frag_now, frag_now_fix (), 0, &exp, 0,
     BFD_RELOC_NDS32_RELAX_REGION_BEGIN);
    }
  else
    {
      exp.X_add_number = R_NDS32_RELAX_REGION_INNERMOST_LOOP_FLAG;
      fix_new_exp (frag_now, frag_now_fix (), 0, &exp, 0,
     BFD_RELOC_NDS32_RELAX_REGION_END);
    }
}
static void
nds32_inline_asm (int mode)
{
  if (mode)
    inline_asm = TRUE;
  else
    inline_asm = FALSE;
}
struct nds32_relocs_group
{
  struct nds32_relocs_pattern *pattern;
  struct nds32_relocs_group *next;
};
static struct nds32_relocs_group *nds32_relax_hint_current = NULL;
static int relax_hint_bias = 0;
static int relax_hint_id_current = -1;
int reset_bias = 0;
int relax_hint_begin = 0;
struct relax_hint_id
{
  int old_id;
  int new_id;
  struct relax_hint_id *next;
};
struct relax_hint_id *record_id_head = NULL;
#define MAX_BUFFER 12
static char *nds_itoa (int n);
static char *
nds_itoa (int n)
{
  char *buf = xmalloc (MAX_BUFFER * sizeof (char));
  snprintf (buf, MAX_BUFFER, "%d", n);
  return buf;
}
static void
nds32_relax_hint (int mode ATTRIBUTE_UNUSED)
{
  char *name = NULL;
  char saved_char;
  struct nds32_relocs_pattern *relocs = NULL;
  struct nds32_relocs_group *group, *new;
  struct relax_hint_id *record_id;
  name = input_line_pointer;
  while (*input_line_pointer && !ISSPACE (*input_line_pointer))
    input_line_pointer++;
  saved_char = *input_line_pointer;
  *input_line_pointer = 0;
  name = strdup (name);
  if (name && strcmp (name, "begin") == 0)
    {
      if (relax_hint_id_current == -1)
        reset_bias = 1;
      relax_hint_bias++;
      relax_hint_id_current++;
      relax_hint_begin = 1;
    }
  if (!relax_hint_begin)
    {
      int tmp = strtol (name, NULL, 10);
      record_id = record_id_head;
      while (record_id)
 {
   if (record_id->old_id == tmp)
     {
       name = nds_itoa (record_id->new_id);
       goto reordered_id;
     }
   record_id = record_id->next;
 }
      if (reset_bias)
 {
   relax_hint_bias = relax_hint_id_current - atoi (name) + 1;
   reset_bias = 0;
        }
      relax_hint_id_current = tmp + relax_hint_bias;
      struct relax_hint_id *tmp_id = malloc (sizeof (struct relax_hint_id));
      tmp_id->old_id = tmp;
      tmp_id->new_id = relax_hint_id_current;
      tmp_id->next = record_id_head;
      record_id_head = tmp_id;
    }
    if (name && strcmp (name, "end") == 0)
      relax_hint_begin = 0;
    name = nds_itoa (relax_hint_id_current);
reordered_id:
  relocs = hash_find (nds32_hint_hash, name);
  if (relocs == NULL)
    {
      relocs = malloc (sizeof (struct nds32_relocs_pattern));
      memset (relocs, 0, sizeof (struct nds32_relocs_pattern));
      hash_insert (nds32_hint_hash, name, relocs);
    }
  else
    {
      while (relocs->next)
 relocs=relocs->next;
      relocs->next = malloc (sizeof (struct nds32_relocs_pattern));
      relocs = relocs->next;
      memset (relocs, 0, sizeof (struct nds32_relocs_pattern));
    }
  relocs->next = NULL;
  *input_line_pointer = saved_char;
  ignore_rest_of_line ();
  new = malloc (sizeof (struct nds32_relocs_group));
  memset (new, 0, sizeof (struct nds32_relocs_group));
  new->pattern = relocs;
  new->next = NULL;
  group = nds32_relax_hint_current;
  if (!group)
    nds32_relax_hint_current = new;
  else
    {
      while (group->next != NULL)
 group = group->next;
      group->next = new;
    }
  relaxing = TRUE;
}
static void
nds32_maybe_align (int mode ATTRIBUTE_UNUSED)
{
  ignore_rest_of_line ();
}
static void
nds32_security_end (int mode ATTRIBUTE_UNUSED)
{
  if (crcing == FALSE)
    as_bad (_("Found unexpected branches inside the "
       "signature protected region."));
}
static void
nds32_vec_size (int ignore ATTRIBUTE_UNUSED)
{
  expressionS exp;
  expression (&exp);
  if (exp.X_op == O_constant)
    {
      if (exp.X_add_number == 4 || exp.X_add_number == 16)
 {
   if (vec_size == 0)
     vec_size = exp.X_add_number;
   else if (vec_size != exp.X_add_number)
     as_warn (_("Different arguments of .vec_size are found, "
         "previous %d, current %d"),
       (int) vec_size, (int) exp.X_add_number);
 }
      else
 as_warn (_("Argument of .vec_size is expected 4 or 16, actual: %d."),
   (int) exp.X_add_number);
    }
  else
    as_warn (_("Argument of .vec_size is not a constant."));
}
static void
nds32_flag (int ignore ATTRIBUTE_UNUSED)
{
  char *name;
  char saved_char;
  int i;
  const char *possible_flags[] = { "verbatim" };
  name = input_line_pointer;
  while (*input_line_pointer && !ISSPACE (*input_line_pointer))
    input_line_pointer++;
  saved_char = *input_line_pointer;
  *input_line_pointer = 0;
  for (i = 0; i < (int) ARRAY_SIZE (possible_flags); i++)
    {
      if (strcmp (name, possible_flags[i]) == 0)
 {
   switch (i)
     {
     case 0:
       verbatim = 1;
       break;
     default:
       break;
     }
   break;
 }
    }
  *input_line_pointer = saved_char;
  ignore_rest_of_line ();
}
static void
ict_model (int ignore ATTRIBUTE_UNUSED)
{
  char *name;
  char saved_char;
  int i;
  const char *possible_flags[] = { "small", "large" };
  name = input_line_pointer;
  while (*input_line_pointer && !ISSPACE (*input_line_pointer))
    input_line_pointer++;
  saved_char = *input_line_pointer;
  *input_line_pointer = 0;
  for (i = 0; i < (int) ARRAY_SIZE (possible_flags); i++)
    {
      if (strcmp (name, possible_flags[i]) == 0)
 {
   switch (i)
     {
     case 0:
       ict_flag = ICT_SMALL;
       break;
     case 1:
       ict_flag = ICT_LARGE;
       break;
     default:
       break;
     }
   break;
 }
    }
  *input_line_pointer = saved_char;
  ignore_rest_of_line ();
}
static void
nds32_compatible_abi (int mode ATTRIBUTE_UNUSED)
{
  compatible_abi = TRUE;
}
static void
nds32_n12hc (int ignore ATTRIBUTE_UNUSED)
{
}
const pseudo_typeS md_pseudo_table[] = {
  {"ascii", stringer, 8 + 0},
  {"asciz", stringer, 8 + 1},
  {"double", nds32_aligned_float_cons, 'd'},
  {"dword", nds32_aligned_cons, 3},
  {"float", nds32_aligned_float_cons, 'f'},
  {"half", nds32_aligned_cons, 1},
  {"hword", nds32_aligned_cons, 1},
  {"int", nds32_aligned_cons, 2},
  {"long", nds32_aligned_cons, 2},
  {"octa", nds32_aligned_cons, 4},
  {"quad", nds32_aligned_cons, 3},
  {"qword", nds32_aligned_cons, 4},
  {"short", nds32_aligned_cons, 1},
  {"byte", nds32_aligned_cons, 0},
  {"single", nds32_aligned_float_cons, 'f'},
  {"string", stringer, 8 + 1},
  {"word", nds32_aligned_cons, 2},
  {"little", set_endian_little, 1},
  {"big", set_endian_little, 0},
  {"16bit_on", trigger_16bit, 1},
  {"16bit_off", trigger_16bit, 0},
  {"restore_16bit", restore_16bit, 0},
  {"off_16bit", off_16bit, 0},
  {"sdata_d", nds32_seg, SDATA_D_SECTION},
  {"sdata_w", nds32_seg, SDATA_W_SECTION},
  {"sdata_h", nds32_seg, SDATA_H_SECTION},
  {"sdata_b", nds32_seg, SDATA_B_SECTION},
  {"sdata_f", nds32_seg, SDATA_F_SECTION},
  {"sbss_d", nds32_seg, SBSS_D_SECTION},
  {"sbss_w", nds32_seg, SBSS_W_SECTION},
  {"sbss_h", nds32_seg, SBSS_H_SECTION},
  {"sbss_b", nds32_seg, SBSS_B_SECTION},
  {"sbss_f", nds32_seg, SBSS_F_SECTION},
  {"pic", nds32_enable_pic, 0},
  {"n12_hc", nds32_n12hc, 0},
  {"abi_1", nds32_set_abi, E_NDS_ABI_V1},
  {"abi_2", nds32_set_abi, E_NDS_ABI_AABI},
  {"abi_2fp", nds32_set_abi, E_NDS_ABI_V2FP},
  {"abi_2fp_plus", nds32_set_abi, E_NDS_ABI_V2FP_PLUS},
  {"relax", nds32_relax_relocs, 1},
  {"no_relax", nds32_relax_relocs, 0},
  {"hint_func_args", nds32_set_hint_func_args, 0},
  {"omit_fp_begin", nds32_omit_fp_begin, 1},
  {"omit_fp_end", nds32_omit_fp_begin, 0},
  {"vec_size", nds32_vec_size, 0},
  {"flag", nds32_flag, 0},
  {"innermost_loop_begin", nds32_loop_begin, 1},
  {"innermost_loop_end", nds32_loop_begin, 0},
  {"relax_hint", nds32_relax_hint, 0},
  {"maybe_align", nds32_maybe_align, 0},
  {"signature_end", nds32_security_end, 0},
  {"inline_asm_begin", nds32_inline_asm, 1},
  {"inline_asm_end", nds32_inline_asm, 0},
  {"ict_model", ict_model, 0},
  {"v2abi_compatible", nds32_compatible_abi, 0},
  {NULL, NULL, 0}
};
void
nds32_pre_do_align (int n, char *fill, int len, int max)
{
  fragS *fragP;
  if (n != 0 && !need_pass_2)
    {
      if (fill == NULL)
 {
   if (subseg_text_p (now_seg))
     {
       dwarf2_emit_insn (0);
       fragP = frag_now;
       add_mapping_symbol_for_align (n, frag_now_fix (), 0);
       frag_align_code (n, max);
       if (label_exist)
  {
    fragP->tc_frag_data.flag = NDS32_FRAG_LABEL;
    label_exist = 0;
  }
     }
   else
     frag_align (n, 0, max);
 }
      else if (len <= 1)
 frag_align (n, *fill, max);
      else
 frag_align_pattern (n, fill, len, max);
    }
}
void
nds32_do_align (int n)
{
  expressionS exp;
  if (!enable_relax_relocs || !subseg_text_p (now_seg))
    return;
  exp.X_op = O_symbol;
  exp.X_add_symbol = section_symbol (now_seg);
  exp.X_add_number = n;
  fix_new_exp (frag_now,
        frag_now_fix (), 0, &exp, 0, BFD_RELOC_NDS32_LABEL);
}
struct nds32_machs
{
  enum bfd_architecture bfd_mach;
  int mach_flags;
};
int
nds32_asm_parse_operand (struct nds32_asm_desc *pdesc ATTRIBUTE_UNUSED,
    struct nds32_asm_insn *pinsn,
    char **pstr, int64_t *value)
{
  char *hold;
  expressionS *pexp = pinsn->info;
  hold = input_line_pointer;
  input_line_pointer = *pstr;
  expression (pexp);
  *pstr = input_line_pointer;
  input_line_pointer = hold;
  switch (pexp->X_op)
    {
    case O_symbol:
      *value = 0;
      return NASM_R_SYMBOL;
    case O_constant:
      *value = pexp->X_add_number;
      return NASM_R_CONST;
    case O_illegal:
    case O_absent:
    case O_register:
    default:
      return NASM_R_ILLEGAL;
    }
}
void
md_begin (void)
{
  struct nds32_keyword *k;
  relax_info_t *relax_info;
  int flags = 0;
  bfd_set_arch_mach (stdoutput, TARGET_ARCH, nds32_baseline);
  nds32_init_nds32_pseudo_opcodes ();
  asm_desc.parse_operand = nds32_asm_parse_operand;
  if (nds32_gpr16)
    flags |= NASM_OPEN_REDUCED_REG;
  nds32_asm_init (&asm_desc, flags);
  nds32_gprs_hash = hash_new ();
  for (k = keyword_gpr; k->name; k++)
    hash_insert (nds32_gprs_hash, k->name, k);
  nds32_relax_info_hash = hash_new ();
  for (relax_info = relax_table; relax_info->opcode; relax_info++)
    hash_insert (nds32_relax_info_hash, relax_info->opcode, relax_info);
  nds32_hint_hash = hash_new ();
  enable_16bit = nds32_16bit_ext;
}
void
nds32_handle_align (fragS *fragp)
{
  static const unsigned char nop16[] = { 0x92, 0x00 };
  static const unsigned char nop32[] = { 0x40, 0x00, 0x00, 0x09 };
  int bytes;
  char *p;
  if (fragp->fr_type != rs_align_code)
    return;
  bytes = fragp->fr_next->fr_address - fragp->fr_address - fragp->fr_fix;
  p = fragp->fr_literal + fragp->fr_fix;
  if (bytes & 1)
    {
      *p++ = 0;
      bytes--;
    }
  if (bytes & 2)
    {
      expressionS exp_t;
      exp_t.X_op = O_symbol;
      exp_t.X_add_symbol = abs_section_sym;
      exp_t.X_add_number = R_NDS32_INSN16_CONVERT_FLAG;
      fix_new_exp (fragp, fragp->fr_fix, 2, &exp_t, 0,
     BFD_RELOC_NDS32_INSN16);
      memcpy (p, nop16, 2);
      p += 2;
      bytes -= 2;
    }
  while (bytes >= 4)
    {
      memcpy (p, nop32, 4);
      p += 4;
      bytes -= 4;
    }
  bytes = fragp->fr_next->fr_address - fragp->fr_address - fragp->fr_fix;
  fragp->fr_fix += bytes;
}
void
nds32_flush_pending_output (void)
{
  nds32_last_label = NULL;
}
void
nds32_frob_label (symbolS *label)
{
  dwarf2_emit_label (label);
}
int
nds32_start_label (int asmdone ATTRIBUTE_UNUSED, int secdone ATTRIBUTE_UNUSED)
{
  if (optimize && subseg_text_p (now_seg))
    label_exist = 1;
  return 1;
}
const char *
nds32_target_format (void)
{
#ifdef TE_LINUX
  if (target_big_endian)
    return "elf32-nds32be-linux";
  else
    return "elf32-nds32le-linux";
#else
  if (target_big_endian)
    return "elf32-nds32be";
  else
    return "elf32-nds32le";
#endif
}
static enum nds32_br_range
get_range_type (const struct nds32_field *field)
{
  gas_assert (field != NULL);
  if (field->bitpos != 0)
    return BR_RANGE_U4G;
  if (field->bitsize == 24 && field->shift == 1)
    return BR_RANGE_S16M;
  else if (field->bitsize == 16 && field->shift == 1)
    return BR_RANGE_S64K;
  else if (field->bitsize == 14 && field->shift == 1)
    return BR_RANGE_S16K;
  else if (field->bitsize == 8 && field->shift == 1)
    return BR_RANGE_S256;
  else
    return BR_RANGE_U4G;
}
static struct nds32_relocs_pattern*
nds32_elf_save_pseudo_pattern (fixS* fixP, struct nds32_asm_insn *insn,
          char *out, symbolS *sym,
          struct nds32_relocs_pattern *reloc_ptr,
          fragS *fragP)
{
  struct nds32_opcode *opcode = insn->opcode;
  if (!reloc_ptr)
    reloc_ptr = malloc (sizeof (struct nds32_relocs_pattern));
  reloc_ptr->seg = now_seg;
  reloc_ptr->sym = sym;
  reloc_ptr->frag = fragP;
  reloc_ptr->frchain = frchain_now;
  reloc_ptr->fixP = fixP;
  reloc_ptr->opcode = opcode;
  reloc_ptr->where = out;
  reloc_ptr->insn = insn->insn;
  reloc_ptr->next = NULL;
  return reloc_ptr;
}
static fixS*
nds32_elf_record_fixup_exp (fragS *fragP, char *str,
       const struct nds32_field *fld,
       expressionS *pexp, char* out,
       struct nds32_asm_insn *insn)
{
  int reloc = -1;
  expressionS exp;
  fixS *fixP = NULL;
  if (fld && fld->bitpos == 0 && (insn->attr & NASM_ATTR_HI20))
    {
      switch (pexp->X_md)
 {
 case BFD_RELOC_NDS32_GOTOFF:
   reloc = BFD_RELOC_NDS32_GOTOFF_HI20;
   break;
 case BFD_RELOC_NDS32_GOT20:
   reloc = BFD_RELOC_NDS32_GOT_HI20;
   break;
 case BFD_RELOC_NDS32_25_PLTREL:
   if (!nds32_pic)
     as_bad (_("Invalid PIC expression."));
   else
     reloc = BFD_RELOC_NDS32_PLT_GOTREL_HI20;
   break;
 case BFD_RELOC_NDS32_GOTPC20:
   reloc = BFD_RELOC_NDS32_GOTPC_HI20;
   break;
 case BFD_RELOC_NDS32_TPOFF:
   reloc = BFD_RELOC_NDS32_TLS_LE_HI20;
   break;
 case BFD_RELOC_NDS32_GOTTPOFF:
   reloc = nds32_pic ? BFD_RELOC_NDS32_TLS_IEGP_HI20 : BFD_RELOC_NDS32_TLS_IE_HI20;
   break;
 case BFD_RELOC_NDS32_TLS_DESC:
   reloc = BFD_RELOC_NDS32_TLS_DESC_HI20;
   break;
 case BFD_RELOC_NDS32_ICT:
   reloc = BFD_RELOC_NDS32_ICT_HI20;
   break;
 default:
   if (nds32_pic)
     reloc = BFD_RELOC_NDS32_PLT_GOTREL_HI20;
   else
     reloc = BFD_RELOC_NDS32_HI20;
   break;
 }
      fixP = fix_new_exp (fragP, out - fragP->fr_literal, insn->opcode->isize,
     insn->info, 0 , reloc);
    }
  else if (fld && fld->bitpos == 0 && (insn->attr & NASM_ATTR_LO12))
    {
      if (fld->bitsize == 15 && fld->shift == 0)
 {
   switch (pexp->X_md)
     {
     case BFD_RELOC_NDS32_GOTOFF:
       reloc = BFD_RELOC_NDS32_GOTOFF_LO12;
       break;
     case BFD_RELOC_NDS32_GOT20:
       reloc = BFD_RELOC_NDS32_GOT_LO12;
       break;
     case BFD_RELOC_NDS32_25_PLTREL:
       if (!nds32_pic)
  as_bad (_("Invalid PIC expression."));
       else
  reloc = BFD_RELOC_NDS32_PLT_GOTREL_LO12;
       break;
     case BFD_RELOC_NDS32_GOTPC20:
       reloc = BFD_RELOC_NDS32_GOTPC_LO12;
       break;
     case BFD_RELOC_NDS32_TPOFF:
       reloc = BFD_RELOC_NDS32_TLS_LE_LO12;
       break;
     case BFD_RELOC_NDS32_GOTTPOFF:
       reloc = nds32_pic ? BFD_RELOC_NDS32_TLS_IEGP_LO12 : BFD_RELOC_NDS32_TLS_IE_LO12;
       break;
     case BFD_RELOC_NDS32_TLS_DESC:
       reloc = BFD_RELOC_NDS32_TLS_DESC_LO12;
       break;
     case BFD_RELOC_NDS32_ICT:
       reloc = BFD_RELOC_NDS32_ICT_LO12;
       break;
     default:
       if (nds32_pic)
  reloc = BFD_RELOC_NDS32_PLT_GOTREL_LO12;
       else
  reloc = BFD_RELOC_NDS32_LO12S0;
       break;
     }
 }
      else if (fld->bitsize == 15 && fld->shift == 1)
 reloc = BFD_RELOC_NDS32_LO12S1;
      else if (fld->bitsize == 15 && fld->shift == 2)
 {
   switch (pexp->X_md)
     {
     case BFD_RELOC_NDS32_GOTTPOFF:
       reloc = nds32_pic ? BFD_RELOC_NDS32_TLS_IEGP_LO12S2 : BFD_RELOC_NDS32_TLS_IE_LO12S2;
       break;
     case BFD_RELOC_NDS32_ICT:
       reloc = BFD_RELOC_NDS32_ICT_LO12S2;
       break;
     default:
       reloc = BFD_RELOC_NDS32_LO12S2;
       break;
     }
 }
      else if (fld->bitsize == 15 && fld->shift == 3)
 reloc = BFD_RELOC_NDS32_LO12S3;
      else if (fld->bitsize == 12 && fld->shift == 2)
 reloc = BFD_RELOC_NDS32_LO12S2_SP;
      fixP = fix_new_exp (fragP, out - fragP->fr_literal, insn->opcode->isize,
     insn->info, 0 , reloc);
    }
  else if (fld && fld->bitpos == 0 && insn->opcode->isize == 4
    && (insn->attr & NASM_ATTR_PCREL))
    {
      if (fld->bitsize == 24 && fld->shift == 1)
 {
   if (pexp->X_md == BFD_RELOC_NDS32_ICT)
     reloc = BFD_RELOC_NDS32_ICT_25PC;
   else
     reloc = BFD_RELOC_NDS32_25_PCREL;
 }
      else if (fld->bitsize == 16 && fld->shift == 1)
 reloc = BFD_RELOC_NDS32_17_PCREL;
      else if (fld->bitsize == 14 && fld->shift == 1)
 reloc = BFD_RELOC_NDS32_15_PCREL;
      else if (fld->bitsize == 8 && fld->shift == 1)
 reloc = BFD_RELOC_NDS32_WORD_9_PCREL;
      else
 abort ();
      fixP = fix_new_exp (fragP, out - fragP->fr_literal, insn->opcode->isize,
     insn->info, 1 , reloc);
    }
  else if (fld && fld->bitpos == 0 && insn->opcode->isize == 4
    && (insn->attr & NASM_ATTR_GPREL))
    {
      if (fld->bitsize == 19 && fld->shift == 0)
 reloc = BFD_RELOC_NDS32_SDA19S0;
      else if (fld->bitsize == 18 && fld->shift == 1)
 reloc = BFD_RELOC_NDS32_SDA18S1;
      else if (fld->bitsize == 17 && fld->shift == 2)
 reloc = BFD_RELOC_NDS32_SDA17S2;
      else
 abort ();
      fixP = fix_new_exp (fragP, out - fragP->fr_literal, insn->opcode->isize,
     insn->info, 0 , reloc);
      exp.X_op = O_symbol;
      exp.X_add_symbol = abs_section_sym;
      exp.X_add_number = 0;
      if (in_omit_fp && reloc == BFD_RELOC_NDS32_SDA17S2)
 fix_new_exp (fragP, out - fragP->fr_literal,
       insn->opcode->isize, &exp, 0 ,
       BFD_RELOC_NDS32_INSN16);
    }
  else if (fld && fld->bitpos == 0 && insn->opcode->isize == 2
    && (insn->attr & NASM_ATTR_PCREL))
    {
      if (fld->bitsize == 8 && fld->shift == 1)
 reloc = BFD_RELOC_NDS32_9_PCREL;
      else
 abort ();
      fixP = fix_new_exp (fragP, out - fragP->fr_literal, insn->opcode->isize,
     insn->info, 1 , reloc);
    }
  else if (fld)
    as_bad (_("Don't know how to handle this field. %s"), str);
  return fixP;
}
static void
nds32_elf_build_relax_relation (fixS *fixP, expressionS *pexp, char* out,
    struct nds32_asm_insn *insn, fragS *fragP,
    const struct nds32_field *fld,
    bfd_boolean pseudo_hint)
{
  struct nds32_relocs_pattern *reloc_ptr;
  struct nds32_relocs_group *group;
  symbolS *sym = NULL;
  if (fld)
    sym = pexp->X_add_symbol;
  if (pseudo_hint)
    {
      group = nds32_relax_hint_current;
      while (group)
 {
   if (group->pattern->opcode == NULL)
     nds32_elf_save_pseudo_pattern (fixP, insn, out, sym,
        group->pattern, fragP);
   else
     {
       group->pattern->next =
  nds32_elf_save_pseudo_pattern (fixP, insn, out, sym,
            NULL, fragP);
       group->pattern = group->pattern->next;
     }
   group = group->next;
 }
    }
  else if (pseudo_opcode)
    {
      reloc_ptr = nds32_elf_save_pseudo_pattern (fixP, insn, out, sym,
       NULL, fragP);
      if (!relocs_list)
 relocs_list = reloc_ptr;
      else
 {
   struct nds32_relocs_pattern *temp = relocs_list;
   while (temp->next)
     temp = temp->next;
   temp->next = reloc_ptr;
 }
    }
  else if (nds32_relax_hint_current)
    {
      group = nds32_relax_hint_current;
      while (group)
 {
   nds32_elf_save_pseudo_pattern (fixP, insn, out, sym,
      group->pattern, fragP);
   group = group->next;
   free (nds32_relax_hint_current);
   nds32_relax_hint_current = group;
 }
    }
  if (!pseudo_opcode)
    relaxing = FALSE;
}
#define N32_MEM_EXT(insn) ((N32_OP6_MEM << 25) | insn)
static struct nds32_relax_hint_table relax_ls_table[] =
{
  {
    .main_type = NDS32_RELAX_HINT_LA_FLSI,
    .relax_code_size = 12,
    .relax_code_seq =
      {
 OP6 (SETHI),
 OP6 (ORI),
 OP6 (LBI),
      },
    .relax_fixup =
      {
 {0, 4, NDS32_HINT | NDS32_ADDEND, BFD_RELOC_NDS32_LOADSTORE},
 {4, 4, NDS32_HINT | NDS32_PTR, BFD_RELOC_NDS32_PTR},
 {4, 4, NDS32_HINT | NDS32_INSN16, BFD_RELOC_NDS32_INSN16},
 {8, 4, NDS32_HINT | NDS32_SYM, BFD_RELOC_NDS32_LSI},
 {8, 4, NDS32_HINT | NDS32_ABS, BFD_RELOC_NDS32_PTR_RESOLVED},
 {8, 4, NDS32_HINT | NDS32_INSN16, BFD_RELOC_NDS32_INSN16},
 {0, 0, 0, 0}
      }
  },
  {
    .main_type = NDS32_RELAX_HINT_LALS,
    .relax_code_size = 12,
    .relax_code_seq =
      {
 OP6 (SETHI),
 OP6 (ORI),
 OP6 (LBI),
      },
    .relax_fixup =
      {
 {0, 4, NDS32_HINT | NDS32_ADDEND, BFD_RELOC_NDS32_LOADSTORE},
 {4, 4, NDS32_HINT | NDS32_INSN16, BFD_RELOC_NDS32_INSN16},
 {8, 4, NDS32_HINT | NDS32_INSN16, BFD_RELOC_NDS32_INSN16},
 {0, 0, 0, 0}
      }
  },
  {
    .main_type = NDS32_RELAX_HINT_LA_PLT,
    .relax_code_size = 16,
    .relax_code_seq =
      {
 OP6 (SETHI),
 OP6 (ORI),
 OP6 (ALU1),
 OP6 (JREG),
      },
    .relax_fixup =
      {
 {0, 4, NDS32_HINT | NDS32_ADDEND, BFD_RELOC_NDS32_LOADSTORE},
 {4, 4, NDS32_HINT | NDS32_PTR, BFD_RELOC_NDS32_PTR},
 {8, 4, NDS32_HINT | NDS32_PTR, BFD_RELOC_NDS32_PTR},
 {12, 4, NDS32_HINT | NDS32_ABS, BFD_RELOC_NDS32_PLT_GOT_SUFF},
 {12, 4, NDS32_HINT | NDS32_ABS, BFD_RELOC_NDS32_PTR_RESOLVED},
 {12, 4, NDS32_HINT | NDS32_INSN16, BFD_RELOC_NDS32_INSN16},
 {0, 0, 0, 0}
      }
  },
  {
    .main_type = NDS32_RELAX_HINT_LA_GOT,
    .relax_code_size = 12,
    .relax_code_seq =
      {
 OP6 (SETHI),
 OP6 (ORI),
 OP6 (MEM),
      },
    .relax_fixup =
      {
 {0, 4, NDS32_HINT | NDS32_ADDEND, BFD_RELOC_NDS32_LOADSTORE},
 {4, 4, NDS32_HINT | NDS32_PTR, BFD_RELOC_NDS32_PTR},
 {8, 4, NDS32_HINT | NDS32_ABS, BFD_RELOC_NDS32_PTR_RESOLVED},
 {8, 4, NDS32_HINT | NDS32_ABS, BFD_RELOC_NDS32_GOT_SUFF},
 {0, 0, 0, 0}
      }
  },
  {
    .main_type = NDS32_RELAX_HINT_LA_GOTOFF,
    .relax_code_size = 16,
    .relax_code_seq =
      {
 OP6 (SETHI),
 OP6 (ORI),
 OP6 (ALU1),
 OP6 (MEM),
      },
    .relax_fixup =
      {
 {0, 4, NDS32_HINT | NDS32_ADDEND, BFD_RELOC_NDS32_LOADSTORE},
 {4, 4, NDS32_HINT | NDS32_PTR, BFD_RELOC_NDS32_PTR},
 {8, 4, NDS32_HINT | NDS32_ABS, BFD_RELOC_NDS32_PTR_RESOLVED},
 {8, 4, NDS32_HINT | NDS32_ABS, BFD_RELOC_NDS32_GOTOFF_SUFF},
 {12, 4, NDS32_HINT | NDS32_ABS, BFD_RELOC_NDS32_PTR_RESOLVED},
 {12, 4, NDS32_HINT | NDS32_ABS, BFD_RELOC_NDS32_GOTOFF_SUFF},
 {0, 0, 0, 0}
      }
  },
  {
    .main_type = NDS32_RELAX_HINT_TLS_LE_LS,
    .relax_code_size = 16,
    .relax_code_seq =
      {
 OP6(SETHI),
 OP6(ORI),
 OP6(MEM),
 OP6(ALU1),
      },
    .relax_fixup =
      {
 {0, 4, NDS32_HINT | NDS32_ADDEND, BFD_RELOC_NDS32_LOADSTORE},
 {4, 4, NDS32_HINT | NDS32_PTR_MULTIPLE, BFD_RELOC_NDS32_PTR},
 {8, 4, NDS32_HINT | NDS32_ABS, BFD_RELOC_NDS32_PTR_RESOLVED},
 {8, 4, NDS32_HINT | NDS32_SYM, BFD_RELOC_NDS32_TLS_LE_LS},
 {12, 4, NDS32_HINT | NDS32_ABS, BFD_RELOC_NDS32_PTR_RESOLVED},
 {12, 4, NDS32_HINT | NDS32_SYM, BFD_RELOC_NDS32_TLS_LE_ADD},
 {0, 0, 0, 0}
      }
  },
  {
    .main_type = NDS32_RELAX_HINT_TLS_IE_LA,
    .relax_code_size = 8,
    .relax_code_seq =
      {
 OP6(SETHI),
 OP6(LBI),
      },
    .relax_fixup =
      {
 {0, 4, NDS32_HINT | NDS32_ADDEND, BFD_RELOC_NDS32_LOADSTORE},
 {4, 4, NDS32_HINT | NDS32_INSN16, BFD_RELOC_NDS32_INSN16},
 {0, 0, 0, 0}
      }
  },
  {
    .main_type = NDS32_RELAX_HINT_TLS_IEGP_LA,
    .relax_code_size = 12,
    .relax_code_seq =
      {
 OP6 (SETHI),
 OP6 (ORI),
 OP6 (MEM),
      },
    .relax_fixup =
      {
 {0, 4, NDS32_HINT | NDS32_ADDEND, BFD_RELOC_NDS32_LOADSTORE},
 {4, 4, NDS32_HINT | NDS32_PTR_PATTERN, BFD_RELOC_NDS32_PTR},
 {8, 4, NDS32_HINT | NDS32_ABS, BFD_RELOC_NDS32_PTR_RESOLVED},
 {8, 4, NDS32_HINT | NDS32_SYM, BFD_RELOC_NDS32_TLS_IEGP_LW},
 {0, 0, 0, 0}
      }
  },
  {
    .main_type = NDS32_RELAX_HINT_TLS_DESC_LS,
    .relax_code_size = 24,
    .relax_code_seq =
      {
 OP6 (SETHI),
 OP6 (ORI),
 OP6 (ALU1),
 OP6 (LBI),
 OP6 (JREG),
 OP6 (MEM),
      },
    .relax_fixup =
      {
 {0, 4, NDS32_HINT | NDS32_ADDEND, BFD_RELOC_NDS32_LOADSTORE},
 {4, 4, NDS32_HINT | NDS32_PTR_PATTERN, BFD_RELOC_NDS32_PTR},
 {8, 4, NDS32_HINT | NDS32_ABS, BFD_RELOC_NDS32_PTR_RESOLVED},
 {8, 4, NDS32_HINT | NDS32_SYM, BFD_RELOC_NDS32_TLS_DESC_ADD},
 {12, 4, NDS32_HINT | NDS32_SYM, BFD_RELOC_NDS32_TLS_DESC_FUNC},
 {16, 4, NDS32_HINT | NDS32_SYM, BFD_RELOC_NDS32_TLS_DESC_CALL},
 {20, 4, NDS32_HINT | NDS32_SYM_DESC_MEM, BFD_RELOC_NDS32_TLS_DESC_MEM},
 {0, 0, 0, 0}
      }
  },
  {
    .main_type = NDS32_RELAX_HINT_ICT_LA,
    .relax_code_size = 8,
    .relax_code_seq =
      {
 OP6 (SETHI),
 OP6 (ORI),
      },
    .relax_fixup =
      {
 {0, 0, 0, 0}
      }
  },
  {
    .main_type = 0,
    .relax_code_seq = {0},
    .relax_fixup = {{0, 0 , 0, 0}}
  }
};
static int
nds32_elf_sethi_range (struct nds32_relocs_pattern *pattern)
{
  int range = 0;
  while (pattern)
    {
      switch (pattern->opcode->value)
 {
 case INSN_LBI:
 case INSN_SBI:
 case INSN_LBSI:
 case N32_MEM_EXT (N32_MEM_LB):
 case N32_MEM_EXT (N32_MEM_LBS):
 case N32_MEM_EXT (N32_MEM_SB):
   range = NDS32_LOADSTORE_BYTE;
   break;
 case INSN_LHI:
 case INSN_SHI:
 case INSN_LHSI:
 case N32_MEM_EXT (N32_MEM_LH):
 case N32_MEM_EXT (N32_MEM_LHS):
 case N32_MEM_EXT (N32_MEM_SH):
   range = NDS32_LOADSTORE_HALF;
   break;
 case INSN_LWI:
 case INSN_SWI:
 case N32_MEM_EXT (N32_MEM_LW):
 case N32_MEM_EXT (N32_MEM_SW):
   range = NDS32_LOADSTORE_WORD;
   break;
 case INSN_FLSI:
 case INSN_FSSI:
   range = NDS32_LOADSTORE_FLOAT_S;
   break;
 case INSN_FLDI:
 case INSN_FSDI:
   range = NDS32_LOADSTORE_FLOAT_D;
   break;
 case INSN_ORI:
   range = NDS32_LOADSTORE_IMM;
   break;
 default:
   range = NDS32_LOADSTORE_NONE;
   break;
 }
      if (range != NDS32_LOADSTORE_NONE)
 break;
      pattern = pattern->next;
    }
  return range;
}
#define SET_ADDEND(size,convertible,optimize,insn16_on) \
  (((size) & 0xff) | ((convertible) ? 1 << 31 : 0) \
   | ((optimize) ? 1<< 30 : 0) | (insn16_on ? 1 << 29 : 0))
#define MAC_COMBO (E_NDS32_HAS_FPU_MAC_INST|E_NDS32_HAS_MAC_DX_INST)
static void
nds32_set_elf_flags_by_insn (struct nds32_asm_insn * insn)
{
  static int skip_flags = NASM_ATTR_FPU_FMA | NASM_ATTR_BRANCH
      | NASM_ATTR_SATURATION_EXT | NASM_ATTR_GPREL | NASM_ATTR_DXREG
      | NASM_ATTR_ISA_V1 | NASM_ATTR_ISA_V2 | NASM_ATTR_ISA_V3
      | NASM_ATTR_ISA_V3M | NASM_ATTR_PCREL;
  int new_flags = insn->opcode->attr & ~skip_flags;
  while (new_flags)
    {
      int next = 1 << (ffs (new_flags) - 1);
      new_flags &= ~next;
      switch (next)
 {
 case NASM_ATTR_PERF_EXT:
   {
     if (nds32_perf_ext)
       {
  nds32_elf_flags |= E_NDS32_HAS_EXT_INST;
  skip_flags |= NASM_ATTR_PERF_EXT;
       }
     else
       as_bad (_("instruction %s requires enabling performance "
   "extension"), insn->opcode->opcode);
   }
   break;
 case NASM_ATTR_PERF2_EXT:
   {
     if (nds32_perf_ext2)
       {
  nds32_elf_flags |= E_NDS32_HAS_EXT2_INST;
  skip_flags |= NASM_ATTR_PERF2_EXT;
       }
     else
       as_bad (_("instruction %s requires enabling performance "
   "extension II"), insn->opcode->opcode);
   }
   break;
 case NASM_ATTR_AUDIO_ISAEXT:
   {
     if (nds32_audio_ext)
       {
  nds32_elf_flags |= E_NDS32_HAS_AUDIO_INST;
  skip_flags |= NASM_ATTR_AUDIO_ISAEXT;
       }
     else
       as_bad (_("instruction %s requires enabling AUDIO extension"),
        insn->opcode->opcode);
   }
   break;
 case NASM_ATTR_STR_EXT:
   {
     if (nds32_string_ext)
       {
  nds32_elf_flags |= E_NDS32_HAS_STRING_INST;
  skip_flags |= NASM_ATTR_STR_EXT;
       }
     else
       as_bad (_("instruction %s requires enabling STRING extension"),
        insn->opcode->opcode);
   }
   break;
 case NASM_ATTR_DIV:
   {
     if (insn->opcode->attr & NASM_ATTR_DXREG)
       {
  if (nds32_div && nds32_dx_regs)
    {
      nds32_elf_flags |= E_NDS32_HAS_DIV_DX_INST;
      skip_flags |= NASM_ATTR_DIV;
    }
  else
    as_bad (_("instruction %s requires enabling DIV & DX_REGS "
       "extension"), insn->opcode->opcode);
       }
   }
   break;
 case NASM_ATTR_FPU:
   {
     if (nds32_fpu_sp_ext || nds32_fpu_dp_ext)
       {
  if (!(nds32_elf_flags
        & (E_NDS32_HAS_FPU_INST | E_NDS32_HAS_FPU_DP_INST)))
    nds32_fpu_com = 1;
  skip_flags |= NASM_ATTR_FPU;
       }
     else
       as_bad (_("instruction %s requires enabling FPU extension"),
        insn->opcode->opcode);
   }
   break;
 case NASM_ATTR_FPU_SP_EXT:
   {
     if (nds32_fpu_sp_ext)
       {
  nds32_elf_flags |= E_NDS32_HAS_FPU_INST;
  skip_flags |= NASM_ATTR_FPU_SP_EXT;
       }
     else
       as_bad (_("instruction %s requires enabling FPU_SP extension"),
        insn->opcode->opcode);
   }
   break;
 case NASM_ATTR_FPU_DP_EXT:
   {
     if (nds32_fpu_dp_ext)
       {
  nds32_elf_flags |= E_NDS32_HAS_FPU_DP_INST;
  skip_flags |= NASM_ATTR_FPU_DP_EXT;
       }
     else
       as_bad (_("instruction %s requires enabling FPU_DP extension"),
        insn->opcode->opcode);
   }
   break;
 case NASM_ATTR_MAC:
   {
     if (insn->opcode->attr & NASM_ATTR_FPU_SP_EXT)
       {
  if (nds32_fpu_sp_ext && nds32_mac)
    nds32_elf_flags |= E_NDS32_HAS_FPU_MAC_INST;
  else
    as_bad (_("instruction %s requires enabling FPU_MAC "
       "extension"), insn->opcode->opcode);
       }
     else if (insn->opcode->attr & NASM_ATTR_FPU_DP_EXT)
       {
  if (nds32_fpu_dp_ext && nds32_mac)
    nds32_elf_flags |= E_NDS32_HAS_FPU_MAC_INST;
  else
    as_bad (_("instruction %s requires enabling FPU_MAC "
       "extension"), insn->opcode->opcode);
       }
     else if (insn->opcode->attr & NASM_ATTR_DXREG)
       {
  if (nds32_dx_regs && nds32_mac)
    nds32_elf_flags |= E_NDS32_HAS_MAC_DX_INST;
  else
    as_bad (_("instruction %s requires enabling DX_REGS "
       "extension"), insn->opcode->opcode);
       }
     if (MAC_COMBO == (MAC_COMBO & nds32_elf_flags))
       skip_flags |= NASM_ATTR_MAC;
   }
   break;
 case NASM_ATTR_DSP_ISAEXT:
   {
     if (nds32_dsp_ext)
       {
  nds32_elf_flags |= E_NDS32_HAS_DSP_INST;
  skip_flags |= NASM_ATTR_DSP_ISAEXT;
       }
     else
       as_bad (_("instruction %s requires enabling dsp extension"),
        insn->opcode->opcode);
   }
   break;
 case NASM_ATTR_ZOL:
   {
     if (nds32_zol_ext)
       {
  nds32_elf_flags |= E_NDS32_HAS_ZOL;
  skip_flags |= NASM_ATTR_ZOL;
       }
     else
       as_bad (_("instruction %s requires enabling zol extension"),
        insn->opcode->opcode);
   }
   break;
 default:
   as_bad (_("internal error: unknown instruction attribute: 0x%08x"),
    next);
 }
    }
}
enum nds32_insn_type
{
  N32_RELAX_SETHI = 1,
  N32_RELAX_BR = (1 << 1),
  N32_RELAX_LSI = (1 << 2),
  N32_RELAX_JUMP = (1 << 3),
  N32_RELAX_CALL = (1 << 4),
  N32_RELAX_ORI = (1 << 5),
  N32_RELAX_MEM = (1 << 6),
  N32_RELAX_MOVI = (1 << 7),
  N32_RELAX_ALU1 = (1 << 8),
  N32_RELAX_16BIT = (1 << 9),
};
struct nds32_hint_map
{
  bfd_reloc_code_real_type hi_type;
  const char *opc;
  enum nds32_relax_hint_type hint_type;
  enum nds32_br_range range;
  enum nds32_insn_type insn_list;
  enum nds32_insn_type option_list;
};
static struct nds32_hint_map hint_map [] =
{
  {
    BFD_RELOC_NDS32_HI20,
    "jal",
    NDS32_RELAX_HINT_NONE,
    BR_RANGE_U4G,
    N32_RELAX_SETHI | N32_RELAX_ORI | N32_RELAX_CALL,
    0,
  },
  {
    _dummy_first_bfd_reloc_code_real,
    "bgezal",
    NDS32_RELAX_HINT_NONE,
    BR_RANGE_S16M,
    N32_RELAX_BR | N32_RELAX_CALL,
    0,
  },
  {
    BFD_RELOC_NDS32_HI20,
    "bgezal",
    NDS32_RELAX_HINT_NONE,
    BR_RANGE_U4G,
    N32_RELAX_BR | N32_RELAX_SETHI | N32_RELAX_ORI | N32_RELAX_CALL,
    0,
  },
  {
    BFD_RELOC_NDS32_HI20,
    "j",
    NDS32_RELAX_HINT_NONE,
    BR_RANGE_U4G,
    N32_RELAX_SETHI | N32_RELAX_ORI | N32_RELAX_JUMP,
    0,
  },
  {
    _dummy_first_bfd_reloc_code_real,
    "beq",
    NDS32_RELAX_HINT_NONE,
    BR_RANGE_S16M,
    N32_RELAX_BR | N32_RELAX_JUMP,
    0,
  },
  {
    BFD_RELOC_NDS32_HI20,
    "beq",
    NDS32_RELAX_HINT_NONE,
    BR_RANGE_U4G,
    N32_RELAX_SETHI | N32_RELAX_ORI | N32_RELAX_BR | N32_RELAX_JUMP,
    0,
  },
  {
    _dummy_first_bfd_reloc_code_real,
    "beqc",
    NDS32_RELAX_HINT_NONE,
    BR_RANGE_S16K,
    N32_RELAX_MOVI | N32_RELAX_BR,
    0,
  },
  {
    BFD_RELOC_NDS32_PLT_GOTREL_HI20,
    NULL,
    NDS32_RELAX_HINT_LA_PLT,
    BR_RANGE_U4G,
    N32_RELAX_SETHI | N32_RELAX_ORI,
    N32_RELAX_ALU1 | N32_RELAX_CALL | N32_RELAX_JUMP,
  },
  {
    BFD_RELOC_NDS32_HI20,
    NULL,
    NDS32_RELAX_HINT_LA_FLSI,
    BR_RANGE_U4G,
    N32_RELAX_SETHI | N32_RELAX_ORI | N32_RELAX_LSI,
    0,
  },
  {
    BFD_RELOC_NDS32_HI20,
    NULL,
    NDS32_RELAX_HINT_LALS,
    BR_RANGE_U4G,
    N32_RELAX_SETHI,
    N32_RELAX_ORI | N32_RELAX_LSI,
  },
  {
    BFD_RELOC_NDS32_GOTPC_HI20,
    NULL,
    NDS32_RELAX_HINT_LALS,
    BR_RANGE_U4G,
    N32_RELAX_SETHI | N32_RELAX_ORI,
    0,
  },
  {
    BFD_RELOC_NDS32_GOT_HI20,
    NULL,
    NDS32_RELAX_HINT_LA_GOT,
    BR_RANGE_U4G,
    N32_RELAX_SETHI | N32_RELAX_ORI,
    N32_RELAX_MEM,
  },
  {
    BFD_RELOC_NDS32_GOTOFF_HI20,
    NULL,
    NDS32_RELAX_HINT_LA_GOTOFF,
    BR_RANGE_U4G,
    N32_RELAX_SETHI | N32_RELAX_ORI,
    N32_RELAX_ALU1 | N32_RELAX_MEM,
  },
  {
    BFD_RELOC_NDS32_TLS_LE_HI20,
    NULL,
    NDS32_RELAX_HINT_TLS_LE_LS,
    BR_RANGE_U4G,
    N32_RELAX_SETHI | N32_RELAX_ORI,
    N32_RELAX_ALU1 | N32_RELAX_MEM,
  },
  {
    BFD_RELOC_NDS32_TLS_IE_HI20,
    NULL,
    NDS32_RELAX_HINT_TLS_IE_LA,
    BR_RANGE_U4G,
    N32_RELAX_SETHI | N32_RELAX_LSI,
    0,
  },
  {
    BFD_RELOC_NDS32_TLS_IE_HI20,
    NULL,
    NDS32_RELAX_HINT_TLS_IE_LS,
    BR_RANGE_U4G,
    N32_RELAX_SETHI | N32_RELAX_LSI | N32_RELAX_MEM,
    0,
  },
  {
    BFD_RELOC_NDS32_TLS_IEGP_HI20,
    NULL,
    NDS32_RELAX_HINT_TLS_IEGP_LA,
    BR_RANGE_U4G,
    N32_RELAX_SETHI | N32_RELAX_ORI | N32_RELAX_MEM,
    0,
  },
  {
    BFD_RELOC_NDS32_TLS_DESC_HI20,
    NULL,
    NDS32_RELAX_HINT_TLS_DESC_LS,
    BR_RANGE_U4G,
    N32_RELAX_SETHI | N32_RELAX_ORI | N32_RELAX_ALU1 | N32_RELAX_CALL,
    N32_RELAX_LSI | N32_RELAX_MEM,
  },
  {
    BFD_RELOC_NDS32_ICT_HI20,
    NULL,
    NDS32_RELAX_HINT_ICT_LA,
    BR_RANGE_U4G,
    N32_RELAX_SETHI | N32_RELAX_ORI,
    0,
  },
  {0, NULL, 0, 0 ,0, 0}
};
static bfd_boolean
nds32_find_reloc_table (struct nds32_relocs_pattern *relocs_pattern,
   struct nds32_relax_hint_table *hint_info)
{
  unsigned int opcode, seq_size;
  enum nds32_br_range range;
  struct nds32_relocs_pattern *pattern, *hi_pattern = NULL;
  const char *opc = NULL;
  relax_info_t *relax_info = NULL;
  nds32_relax_fixup_info_t *fixup_info, *hint_fixup;
  enum nds32_relax_hint_type hint_type = NDS32_RELAX_HINT_NONE;
  struct nds32_relax_hint_table *table_ptr;
  uint32_t *code_seq, *hint_code;
  enum nds32_insn_type relax_type = 0;
  struct nds32_hint_map *map_ptr = hint_map;
  unsigned int i;
  const char *check_insn[] =
    { "bnes38", "beqs38", "bnez38", "bnezs8", "beqz38", "beqzs8" };
  pattern = relocs_pattern;
  while (pattern)
    {
      if (pattern->opcode->isize == 4)
 {
   opcode = N32_OP6 (pattern->opcode->value);
   switch (opcode)
     {
     case N32_OP6_SETHI:
       hi_pattern = pattern;
       relax_type |= N32_RELAX_SETHI;
       break;
     case N32_OP6_MEM:
       relax_type |= N32_RELAX_MEM;
       break;
     case N32_OP6_ALU1:
       relax_type |= N32_RELAX_ALU1;
       break;
     case N32_OP6_ORI:
       relax_type |= N32_RELAX_ORI;
       break;
     case N32_OP6_BR1:
     case N32_OP6_BR2:
     case N32_OP6_BR3:
       relax_type |= N32_RELAX_BR;
       break;
     case N32_OP6_MOVI:
       relax_type |= N32_RELAX_MOVI;
       break;
     case N32_OP6_LBI:
     case N32_OP6_SBI:
     case N32_OP6_LBSI:
     case N32_OP6_LHI:
     case N32_OP6_SHI:
     case N32_OP6_LHSI:
     case N32_OP6_LWI:
     case N32_OP6_SWI:
     case N32_OP6_LWC:
     case N32_OP6_SWC:
     case N32_OP6_LDC:
     case N32_OP6_SDC:
       relax_type |= N32_RELAX_LSI;
       break;
     case N32_OP6_JREG:
       if (__GF (pattern->opcode->value, 0, 1) == 1)
  relax_type |= N32_RELAX_CALL;
       else
  relax_type |= N32_RELAX_JUMP;
       break;
     case N32_OP6_JI:
       if (__GF (pattern->opcode->value, 24, 1) == 1)
  relax_type |= N32_RELAX_CALL;
       else
  relax_type |= N32_RELAX_JUMP;
       break;
     default:
       as_warn (_("relax hint unrecognized instruction: line %d."),
         pattern->frag->fr_line);
       return FALSE;
     }
 }
      else
 {
   int is_matched = 0;
   for (i = 0; i < ARRAY_SIZE (check_insn); i++)
     {
       if (strcmp (pattern->opcode->opcode, check_insn[i]) == 0)
  {
    relax_type |= N32_RELAX_BR;
    is_matched += 1;
    break;
  }
     }
   if (!is_matched)
     {
       relax_type |= N32_RELAX_16BIT;
     }
 }
      pattern = pattern->next;
    }
  while (map_ptr->insn_list != 0)
    {
      struct nds32_hint_map *hint = map_ptr++;
      enum nds32_insn_type must = hint->insn_list;
      enum nds32_insn_type optional = hint->option_list;
      enum nds32_insn_type extra;
      if (must != (must & relax_type))
 continue;
      extra = relax_type ^ must;
      if (extra != (extra & optional))
 continue;
      if (!hi_pattern
   || (hi_pattern->fixP
       && hi_pattern->fixP->fx_r_type == hint->hi_type))
 {
   opc = hint->opc;
   hint_type = hint->hint_type;
   range = hint->range;
   map_ptr = hint;
   break;
 }
    }
  if (map_ptr->insn_list == 0)
    {
      if (!nds32_pic)
        as_warn (_("Can not find match relax hint. line : %d"),
          relocs_pattern->fixP->fx_line);
      return FALSE;
    }
  if (opc)
    {
      relax_info = hash_find (nds32_relax_info_hash, opc);
      if (!relax_info)
 return FALSE;
      fixup_info = relax_info->relax_fixup[range];
      code_seq = relax_info->relax_code_seq[range];
      seq_size = relax_info->relax_code_size[range];
    }
  else if (hint_type)
    {
      table_ptr = relax_ls_table;
      while (table_ptr->main_type != 0)
 {
   if (table_ptr->main_type == hint_type)
     {
       fixup_info = table_ptr->relax_fixup;
       code_seq = table_ptr->relax_code_seq;
       seq_size = table_ptr->relax_code_size;
       break;
     }
   table_ptr++;
 }
      if (table_ptr->main_type == 0)
 return FALSE;
    }
  else
    return FALSE;
  hint_fixup = hint_info->relax_fixup;
  hint_code = hint_info->relax_code_seq;
  hint_info->relax_code_size = seq_size;
  while (fixup_info->size != 0)
    {
      if (fixup_info->ramp & NDS32_HINT)
 {
   memcpy (hint_fixup, fixup_info, sizeof (nds32_relax_fixup_info_t));
   hint_fixup++;
 }
      fixup_info++;
    }
  memset (hint_fixup, 0, sizeof (nds32_relax_fixup_info_t));
  memcpy (hint_code, code_seq, seq_size);
  return TRUE;
}
#define CLEAN_REG(insn) ((insn) & 0xfe0003ff)
#define GET_OPCODE(insn) ((insn) & 0xfe000000)
static bfd_boolean
nds32_match_hint_insn (struct nds32_opcode *opcode, uint32_t seq)
{
  const char *check_insn[] =
    { "bnes38", "beqs38", "bnez38", "bnezs8", "beqz38", "beqzs8", "jral5" };
  uint32_t insn = opcode->value;
  unsigned int i;
  insn = CLEAN_REG (opcode->value);
  if (insn == seq)
    return TRUE;
  switch (seq)
    {
    case OP6 (LBI):
      if (insn == OP6 (LBI) || insn == OP6 (SBI) || insn == OP6 (LBSI)
   || insn == OP6 (LHI) || insn == OP6 (SHI) || insn == OP6 (LHSI)
   || insn == OP6 (LWI) || insn == OP6 (SWI)
   || insn == OP6 (LWC) || insn == OP6 (SWC)
   || insn == OP6 (LDC) || insn == OP6 (SDC))
 return TRUE;
      break;
    case OP6 (BR2):
      if (insn == OP6 (BR2))
 return TRUE;
      break;
    case OP6 (BR1):
      if (opcode->isize == 4
   && (insn == OP6 (BR1) || insn == OP6 (BR2) || insn == OP6 (BR3)))
 return TRUE;
      else if (opcode->isize == 2)
 {
   for (i = 0; i < ARRAY_SIZE (check_insn); i++)
     if (strcmp (opcode->opcode, check_insn[i]) == 0)
       return TRUE;
 }
      break;
    case OP6 (MOVI):
      if (opcode->isize == 2 && strcmp (opcode->opcode, "movi55") == 0)
 return TRUE;
      break;
    case OP6 (MEM):
      if (OP6 (MEM) == GET_OPCODE (insn))
 return TRUE;
      break;
    case OP6 (JREG):
      if ((insn & ~(__BIT (24))) == JREG (JRAL))
 return TRUE;
      break;
    default:
      if (opcode->isize == 2)
 {
   for (i = 0; i < ARRAY_SIZE (check_insn); i++)
     if (strcmp (opcode->opcode, check_insn[i]) == 0)
       return TRUE;
   if ((strcmp (opcode->opcode, "add5.pc") == 0) ||
       (strcmp (opcode->opcode, "add45") == 0))
     return TRUE;
 }
    }
  return FALSE;
}
static void
nds32_elf_append_relax_relocs (const char *key, void *value)
{
  struct nds32_relocs_pattern *relocs_pattern =
    (struct nds32_relocs_pattern *) value;
  struct nds32_relocs_pattern *pattern_temp, *pattern_now;
  symbolS *sym, *hi_sym = NULL;
  expressionS exp;
  fragS *fragP;
  segT seg_bak = now_seg;
  frchainS *frchain_bak = frchain_now;
  struct nds32_relax_hint_table hint_info;
  nds32_relax_fixup_info_t *hint_fixup, *fixup_now;
  size_t fixup_size;
  offsetT branch_offset, hi_branch_offset = 0;
  fixS *fixP;
  int range, offset;
  unsigned int ptr_offset, hint_count, relax_code_size, count = 0;
  uint32_t *code_seq, code_insn;
  char *where;
  int pcrel;
  if (!relocs_pattern)
    return;
  if (!nds32_find_reloc_table (relocs_pattern, &hint_info))
    return;
  pattern_now = relocs_pattern;
  while (pattern_now)
    {
      if (pattern_now->opcode->value == OP6 (SETHI))
 {
   hi_sym = pattern_now->sym;
   hi_branch_offset = pattern_now->fixP->fx_offset;
   break;
 }
      pattern_now = pattern_now->next;
    }
  now_seg = relocs_pattern->seg;
  frchain_now = relocs_pattern->frchain;
  fragP = relocs_pattern->frag;
  branch_offset = fragP->fr_offset;
  hint_fixup = hint_info.relax_fixup;
  code_seq = hint_info.relax_code_seq;
  relax_code_size = hint_info.relax_code_size;
  pattern_now = relocs_pattern;
#ifdef NDS32_LINUX_TOOLCHAIN
  long group_id = 0;
  if (key)
    {
      errno = 0;
      group_id = strtol (key, NULL, 10);
      if ((errno == ERANGE && (group_id == LONG_MAX || group_id == LONG_MIN))
   || (errno != 0 && group_id == 0))
 {
   as_bad (_("Internal error: .relax_hint KEY is not a number!"));
   goto restore;
 }
    }
#endif
  exp.X_op = O_symbol;
  while (pattern_now)
    {
      if (count >= relax_code_size / 4)
 count = 0;
      code_insn = CLEAN_REG (*(code_seq + count));
      if (!nds32_match_hint_insn (pattern_now->opcode, code_insn))
 {
   count = 0;
   code_insn = CLEAN_REG (*(code_seq + count));
   while (!nds32_match_hint_insn (pattern_now->opcode, code_insn))
     {
       count++;
       if (count >= relax_code_size / 4)
  {
    as_bad (_("Internal error: Relax hint (%s) error. %s: %s (%x)"),
     key,
     now_seg->name,
     pattern_now->opcode->opcode,
     pattern_now->opcode->value);
    goto restore;
  }
       code_insn = CLEAN_REG (*(code_seq + count));
     }
 }
      fragP = pattern_now->frag;
      sym = pattern_now->sym;
      branch_offset = fragP->fr_offset;
      offset = count * 4;
      where = pattern_now->where;
      fixup_now = hint_fixup;
      while (fixup_now->offset != offset)
 {
   fixup_now++;
   if (fixup_now->size == 0)
     break;
 }
      if (fixup_now->size == 0)
 {
   pattern_now = pattern_now->next;
   continue;
 }
      fixup_size = fixup_now->size;
      while (fixup_size != 0 && fixup_now->offset == offset)
 {
   fixup_size = pattern_now->opcode->isize;
   pcrel = ((fixup_now->ramp & NDS32_PCREL) != 0) ? 1 : 0;
   if (fixup_now->ramp & NDS32_FIX)
     {
       pattern_now->fixP->fx_r_type = fixup_now->r_type ;
       fixup_size = 0;
     }
   else if ((fixup_now->ramp & NDS32_PTR) != 0)
     {
       pattern_temp = relocs_pattern;
       hint_count = hint_info.relax_code_size / 4;
       code_insn = CLEAN_REG (*(code_seq + hint_count - 1));
       while (pattern_temp)
  {
    if (nds32_match_hint_insn (pattern_temp->opcode, code_insn))
      {
        ptr_offset =
   pattern_temp->where - pattern_temp->frag->fr_literal;
        exp.X_add_symbol = symbol_temp_new (now_seg, ptr_offset,
         pattern_temp->frag);
        exp.X_add_number = 0;
        fixP =
   fix_new_exp (fragP, where - fragP->fr_literal,
         fixup_size, &exp, 0, fixup_now->r_type);
        fixP->fx_addnumber = fixP->fx_offset;
      }
    pattern_temp = pattern_temp->next;
  }
       fixup_size = 0;
     }
   else if (fixup_now->ramp & NDS32_ADDEND)
     {
       range = nds32_elf_sethi_range (relocs_pattern);
       if (range == NDS32_LOADSTORE_NONE)
  {
    as_bad (_("Internal error: Range error. %s"), now_seg->name);
    return;
  }
       exp.X_add_symbol = abs_section_sym;
       exp.X_add_number = SET_ADDEND (4, 0, optimize, enable_16bit);
       exp.X_add_number |= ((range & 0x3f) << 8);
     }
   else if ((fixup_now->ramp & NDS32_ABS) != 0)
     {
       exp.X_add_symbol = abs_section_sym;
       exp.X_add_number = 0;
     }
   else if ((fixup_now->ramp & NDS32_INSN16) != 0)
     {
       if (!enable_16bit)
  fixup_size = 0;
       exp.X_add_symbol = abs_section_sym;
       exp.X_add_number = 0;
     }
   else if ((fixup_now->ramp & NDS32_SYM) != 0)
     {
       exp.X_add_symbol = hi_sym;
       exp.X_add_number = hi_branch_offset;
     }
   else if (NDS32_SYM_DESC_MEM & fixup_now->ramp)
     {
       exp.X_add_symbol = hi_sym;
       exp.X_add_number = hi_branch_offset;
       if ((REG_GP == N32_RA5 (pattern_now->insn))
    || (REG_GP == N32_RB5 (pattern_now->insn)))
  {
    fixP = fix_new_exp (fragP, where - fragP->fr_literal,
          fixup_size, &exp, pcrel,
          BFD_RELOC_NDS32_TLS_DESC_FUNC);
    fixP->fx_addnumber = fixP->fx_offset;
    fixup_size = 0;
  }
     }
   else if (fixup_now->ramp & NDS32_PTR_PATTERN)
     {
       nds32_relax_fixup_info_t *next_fixup = fixup_now + 1;
       uint32_t resolved_pattern = 0;
       while (next_fixup->offset)
  {
    if (next_fixup->r_type == BFD_RELOC_NDS32_PTR_RESOLVED)
      {
        uint32_t new_pattern = code_seq[next_fixup->offset >> 2];
        if (!resolved_pattern)
   resolved_pattern = new_pattern;
        else if (new_pattern != resolved_pattern)
   {
     as_warn (_("Multiple BFD_RELOC_NDS32_PTR_RESOLVED patterns are not supported yet!"));
     break;
   }
      }
    ++next_fixup;
  }
       struct nds32_relocs_pattern *next_pattern = pattern_now->next;
       while (next_pattern)
  {
    uint32_t cur_pattern = GET_OPCODE (next_pattern->opcode->value);
    if (cur_pattern == resolved_pattern)
      {
        ptr_offset = next_pattern->where
     - next_pattern->frag->fr_literal;
        exp.X_add_symbol = symbol_temp_new (now_seg, ptr_offset,
         next_pattern->frag);
        exp.X_add_number = 0;
        fixP = fix_new_exp (fragP, where - fragP->fr_literal,
       fixup_size, &exp, 0,
       fixup_now->r_type);
        fixP->fx_addnumber = fixP->fx_offset;
      }
    next_pattern = next_pattern->next;
  }
       fixup_size = 0;
     }
   else if (fixup_now->ramp & NDS32_PTR_MULTIPLE)
     {
       nds32_relax_fixup_info_t *next_fixup = fixup_now + 1;
       while (next_fixup->offset)
  {
    if (next_fixup->r_type == BFD_RELOC_NDS32_PTR_RESOLVED)
      {
        uint32_t pattern = code_seq[next_fixup->offset >> 2];
        struct nds32_relocs_pattern *next_insn = pattern_now->next;
        while (next_insn)
   {
     uint32_t insn_pattern = GET_OPCODE(
         next_insn->opcode->value);
     if (insn_pattern == pattern)
       {
         ptr_offset = next_insn->where
      - next_insn->frag->fr_literal;
         exp.X_add_symbol = symbol_temp_new (
      now_seg, ptr_offset, next_insn->frag);
         exp.X_add_number = 0;
         fixP = fix_new_exp (fragP,
        where - fragP->fr_literal,
        fixup_size, &exp, 0,
        fixup_now->r_type);
         fixP->fx_addnumber = fixP->fx_offset;
       }
     next_insn = next_insn->next;
   }
      }
    ++next_fixup;
  }
       fixup_size = 0;
     }
   else
     {
       exp.X_add_symbol = sym;
       exp.X_add_number = branch_offset;
     }
   if (fixup_size != 0)
     {
       fixP = fix_new_exp (fragP, where - fragP->fr_literal, fixup_size,
      &exp, pcrel, fixup_now->r_type);
       fixP->fx_addnumber = fixP->fx_offset;
     }
   fixup_now++;
   fixup_size = fixup_now->size;
 }
#ifdef NDS32_LINUX_TOOLCHAIN
      if (key)
 {
   exp.X_add_symbol = hi_sym;
   exp.X_add_number = group_id;
   fixP = fix_new_exp (fragP, where - fragP->fr_literal, fixup_size,
         &exp, pcrel, BFD_RELOC_NDS32_GROUP);
   fixP->fx_addnumber = fixP->fx_offset;
 }
#endif
      if (count < relax_code_size / 4)
 count++;
      pattern_now = pattern_now->next;
    }
restore:
  now_seg = seg_bak;
  frchain_now = frchain_bak;
}
static void
nds32_str_tolower (char *src, char *dest)
{
  unsigned int i, len;
  len = strlen (src);
  for (i = 0; i < len; i++)
    *(dest + i) = TOLOWER (*(src + i));
  *(dest + i) = '\0';
}
static bfd_boolean
nds32_check_insn_available (struct nds32_asm_insn insn, char *str)
{
  int attr = insn.attr & ATTR_ALL;
  static int baseline_isa = 0;
  char *s;
  s = alloca (strlen (str) + 1);
  nds32_str_tolower (str, s);
  if (verbatim && inline_asm
      && (((insn.opcode->value == ALU2 (MTUSR)
     || insn.opcode->value == ALU2 (MFUSR))
    && (strstr (s, "lc")
        || strstr (s, "le")
        || strstr (s, "lb")))
   || (insn.attr & NASM_ATTR_ZOL)))
    {
      as_bad (_("Not support instruction %s in verbatim."), str);
      return FALSE;
    }
  if (!enable_16bit && insn.opcode->isize == 2)
    {
      as_bad (_("16-bit instruction is disabled: %s."), str);
      return FALSE;
    }
  if (attr == 0 || attr == ATTR_ALL)
    return TRUE;
  if (baseline_isa == 0)
    {
      switch (nds32_baseline)
 {
 case ISA_V2:
   baseline_isa = ATTR (ISA_V2);
   break;
 case ISA_V3:
   baseline_isa = ATTR (ISA_V3);
   break;
 case ISA_V3M:
   baseline_isa = ATTR (ISA_V3M);
   break;
 }
    }
  if ((baseline_isa & attr) == 0)
    {
      as_bad (_("Not support instruction %s in the baseline."), str);
      return FALSE;
    }
  return TRUE;
}
static void
nds32_set_crc (fragS *fragP, struct nds32_asm_insn *insn, char *out)
{
  expressionS exp;
  if (strcmp (insn->opcode->opcode, "isps") == 0)
    {
      exp.X_op = O_symbol;
      exp.X_add_symbol = abs_section_sym;
      if (crcing == TRUE)
 {
   exp.X_add_number = NDS32_SECURITY_RESTART;
   fix_new_exp (fragP, out - fragP->fr_literal, 0, &exp,
         0, BFD_RELOC_NDS32_SECURITY_16);
 }
      crcing = TRUE;
      exp.X_add_number = NDS32_SECURITY_START;
      fix_new_exp (fragP, out - fragP->fr_literal, insn->opcode->isize,
     &exp, 0 , BFD_RELOC_NDS32_SECURITY_16);
    }
  else if (crcing && ((insn->attr & NASM_ATTR_BRANCH)
        || insn->opcode->value == MISC (SYSCALL)
        || insn->opcode->value == MISC (TRAP)
        || insn->opcode->value == MISC (TEQZ)
        || insn->opcode->value == MISC (TNEZ)
        || insn->opcode->value == MISC (IRET)))
    {
      crcing = FALSE;
      exp.X_op = O_symbol;
      exp.X_add_symbol = abs_section_sym;
      exp.X_add_number = NDS32_SECURITY_END;
      fix_new_exp (fragP, out - fragP->fr_literal, 0, &exp,
     0, BFD_RELOC_NDS32_SECURITY_16);
    }
}
void
md_assemble (char *str)
{
  struct nds32_asm_insn insn;
  char *out;
  struct nds32_pseudo_opcode *popcode;
  const struct nds32_field *fld = NULL;
  fixS *fixP;
  uint16_t insn_16;
  struct nds32_relocs_pattern *relocs_temp;
  struct nds32_relocs_group *group_temp;
  fragS *fragP;
  int label = label_exist;
  static bfd_boolean pseudo_hint = FALSE;
  popcode = nds32_lookup_pseudo_opcode (str);
  if (popcode && !(verbatim && popcode->physical_op))
    {
      if (relaxing)
 pseudo_hint = TRUE;
      pseudo_opcode = TRUE;
      nds32_pseudo_opcode_wrapper (str, popcode);
      pseudo_opcode = FALSE;
      pseudo_hint = FALSE;
      nds32_elf_append_relax_relocs (NULL, relocs_list);
      while (nds32_relax_hint_current)
 {
   group_temp = nds32_relax_hint_current->next;
   free (nds32_relax_hint_current);
   nds32_relax_hint_current = group_temp;
 }
      relocs_temp = relocs_list;
      while (relocs_temp)
 {
   relocs_list = relocs_list->next;
   free (relocs_temp);
   relocs_temp = relocs_list;
 }
      return;
    }
  label_exist = 0;
  insn.info = (expressionS *) alloca (sizeof (expressionS));
  asm_desc.result = NASM_OK;
  nds32_assemble (&asm_desc, &insn, str);
  switch (asm_desc.result)
    {
    case NASM_ERR_UNKNOWN_OP:
      as_bad (_("Unrecognized opcode, %s."), str);
      return;
    case NASM_ERR_SYNTAX:
      as_bad (_("Incorrect syntax, %s."), str);
      return;
    case NASM_ERR_OPERAND:
      as_bad (_("Unrecognized operand/register, %s."), str);
      return;
    case NASM_ERR_OUT_OF_RANGE:
      as_bad (_("Operand out of range, %s."), str);
      return;
    case NASM_ERR_REG_REDUCED:
      as_bad (_("Prohibited register used for reduced-register, %s."), str);
      return;
    case NASM_ERR_JUNK_EOL:
      as_bad (_("Junk at end of line, %s."), str);
      return;
    }
  gas_assert (insn.opcode);
  nds32_set_elf_flags_by_insn (&insn);
  gas_assert (insn.opcode->isize == 4 || insn.opcode->isize == 2);
  if (!nds32_check_insn_available (insn, str))
    return;
  nds32_adjust_label (1);
  add_mapping_symbol (MAP_CODE, 0, 0);
  fld = insn.field;
  frag_grow (NDS32_MAXCHAR);
  fragP = frag_now;
  if (fld && (insn.attr & NASM_ATTR_BRANCH)
      && (pseudo_opcode || (insn.opcode->value != INSN_JAL
       && insn.opcode->value != INSN_J))
      && (!verbatim || pseudo_opcode))
    {
      dwarf2_emit_insn (0);
      enum nds32_br_range range_type;
      expressionS *pexp = insn.info;
      range_type = get_range_type (fld);
      out = frag_var (rs_machine_dependent, NDS32_MAXCHAR,
        0,
        range_type,
        pexp->X_add_symbol, pexp->X_add_number, 0);
      fragP->fr_fix += insn.opcode->isize;
      fragP->tc_frag_data.opcode = insn.opcode;
      fragP->tc_frag_data.insn = insn.insn;
      if (insn.opcode->isize == 4)
 bfd_putb32 (insn.insn, out);
      else if (insn.opcode->isize == 2)
 bfd_putb16 (insn.insn, out);
      fragP->tc_frag_data.flag |= NDS32_FRAG_BRANCH;
      if (fld->bitsize == 24 && fld->shift == 1
   && pexp->X_md == BFD_RELOC_NDS32_ICT)
 fragP->tc_frag_data.flag |= NDS32_FRAG_ICT_BRANCH;
      nds32_set_crc (fragP, &insn, out);
      return;
    }
  else if (!relaxing && enable_16bit && (optimize || optimize_for_space)
    && ((!fld && !verbatim && insn.opcode->isize == 4
  && nds32_convert_32_to_16 (stdoutput, insn.insn, &insn_16, NULL))
        || (insn.opcode->isize == 2
     && nds32_convert_16_to_32 (stdoutput, insn.insn, NULL))))
    {
      expressionS *pexp = insn.info;
      dwarf2_emit_insn (0);
      if (fld)
 {
   out = frag_var (rs_machine_dependent,
     4,
     0,
     0, pexp->X_add_symbol, pexp->X_add_number, 0);
   fragP->tc_frag_data.flag |= NDS32_FRAG_RELAXABLE_BRANCH;
 }
      else
 out = frag_var (rs_machine_dependent,
   4,
   0,
   0, NULL, 0, NULL);
      fragP->tc_frag_data.flag |= NDS32_FRAG_RELAXABLE;
      fragP->tc_frag_data.opcode = insn.opcode;
      fragP->tc_frag_data.insn = insn.insn;
      fragP->fr_fix += 2;
      if (label)
 fragP->tc_frag_data.flag |= NDS32_FRAG_LABEL;
      if (insn.opcode->isize == 4)
 bfd_putb16 (insn_16, out);
      else if (insn.opcode->isize == 2)
 bfd_putb16 (insn.insn, out);
      nds32_set_crc (fragP, &insn, out);
      return;
    }
  else if ((verbatim || !relaxing) && optimize && label)
    {
      expressionS exp;
      out = frag_var (rs_machine_dependent, insn.opcode->isize,
        0, 0, NULL, 0, NULL);
      fragP->tc_frag_data.flag = NDS32_FRAG_LABEL;
      fragP->tc_frag_data.opcode = insn.opcode;
      fragP->tc_frag_data.insn = insn.insn;
      fragP->fr_fix += insn.opcode->isize;
      if (insn.opcode->isize == 4)
 {
   exp.X_op = O_symbol;
   exp.X_add_symbol = abs_section_sym;
   exp.X_add_number = 0;
   fixP = fix_new_exp (fragP, fragP->fr_fix - 4, 0, &exp,
         0, BFD_RELOC_NDS32_LABEL);
   if (!verbatim)
     fragP->tc_frag_data.flag = NDS32_FRAG_ALIGN;
 }
    }
  else
    out = frag_more (insn.opcode->isize);
  if (insn.opcode->isize == 4)
    bfd_putb32 (insn.insn, out);
  else if (insn.opcode->isize == 2)
    bfd_putb16 (insn.insn, out);
  dwarf2_emit_insn (insn.opcode->isize);
  expressionS *pexp = insn.info;
  fixP = nds32_elf_record_fixup_exp (fragP, str, fld, pexp, out, &insn);
  if (relaxing)
    nds32_elf_build_relax_relation (fixP, pexp, out, &insn, fragP, fld,
        pseudo_hint);
  nds32_set_crc (fragP, &insn, out);
}
void
nds32_macro_start (void)
{
}
void
nds32_macro_info (void *info ATTRIBUTE_UNUSED)
{
}
void
nds32_macro_end (void)
{
}
void
md_operand (expressionS *expressionP)
{
  if (*input_line_pointer == '#')
    {
      input_line_pointer++;
      expression (expressionP);
    }
}
valueT
md_section_align (segT segment, valueT size)
{
  int align = bfd_get_section_alignment (stdoutput, segment);
  return ((size + (1 << align) - 1) & ((valueT) -1 << align));
}
symbolS *
md_undefined_symbol (char *name ATTRIBUTE_UNUSED)
{
  return NULL;
}
static long
nds32_calc_branch_offset (segT segment, fragS *fragP,
     long stretch ATTRIBUTE_UNUSED,
     relax_info_t *relax_info,
     enum nds32_br_range branch_range_type)
{
  struct nds32_opcode *opcode = fragP->tc_frag_data.opcode;
  symbolS *branch_symbol = fragP->fr_symbol;
  offsetT branch_offset = fragP->fr_offset;
  offsetT branch_target_address;
  offsetT branch_insn_address;
  long offset = 0;
  if ((S_GET_SEGMENT (branch_symbol) != segment)
      || S_IS_WEAK (branch_symbol))
    {
      offset = 0x80000000;
    }
  else
    {
      branch_target_address = S_GET_VALUE (branch_symbol) + branch_offset;
      if (S_GET_VALUE (branch_symbol) > fragP->fr_address)
 branch_target_address += stretch;
      branch_insn_address = fragP->fr_address + fragP->fr_fix;
      branch_insn_address -= opcode->isize;
      branch_insn_address += (relax_info->relax_code_size[branch_range_type]
         - relax_info->relax_branch_isize[branch_range_type]);
      offset = branch_target_address - branch_insn_address;
    }
  return offset;
}
static enum nds32_br_range
nds32_convert_to_range_type (long offset)
{
  enum nds32_br_range range_type;
  if (-(0x100) <= offset && offset < 0x100)
    range_type = BR_RANGE_S256;
  else if (-(0x4000) <= offset && offset < 0x4000)
    range_type = BR_RANGE_S16K;
  else if (-(0x10000) <= offset && offset < 0x10000)
    range_type = BR_RANGE_S64K;
  else if (-(0x1000000) <= offset && offset < 0x1000000)
    range_type = BR_RANGE_S16M;
  else
    range_type = BR_RANGE_U4G;
  return range_type;
}
static void
nds32_elf_get_set_cond (relax_info_t *relax_info, int offset, uint32_t *insn,
   uint32_t ori_insn, int range)
{
  nds32_cond_field_t *cond_fields;
  cond_fields = relax_info->cond_field;
  nds32_cond_field_t *code_seq_cond = relax_info->relax_code_condition[range];
  uint32_t mask;
  int i = 0;
  while (code_seq_cond[i].bitmask != 0)
    {
      if (offset == code_seq_cond[i].offset)
 {
   mask = (ori_insn >> cond_fields[i].bitpos) & cond_fields[i].bitmask;
   if (cond_fields[i].signed_extend)
     mask = (mask ^ ((cond_fields[i].bitmask + 1) >> 1)) -
       ((cond_fields[i].bitmask + 1) >> 1);
   *insn |= (mask & code_seq_cond[i].bitmask) << code_seq_cond[i].bitpos;
 }
      i++;
    }
}
static int
nds32_relax_branch_instructions (segT segment, fragS *fragP,
     long stretch ATTRIBUTE_UNUSED,
     int init)
{
  enum nds32_br_range branch_range_type;
  struct nds32_opcode *opcode = fragP->tc_frag_data.opcode;
  long offset = 0;
  enum nds32_br_range real_range_type;
  int adjust = 0;
  relax_info_t *relax_info;
  int diff = 0;
  int i, j, k;
  int code_seq_size;
  uint32_t *code_seq;
  uint32_t insn;
  int insn_size;
  int code_seq_offset;
  if (fragP->fr_symbol == NULL)
    return adjust;
  if (opcode == NULL)
    return adjust;
  if (verbatim && !nds32_pic
      && (strcmp (opcode->opcode, "j") == 0
   || strcmp (opcode->opcode, "jal") == 0))
    {
      fragP->fr_subtype = BR_RANGE_U4G;
      if (init)
 return 8;
      else
 return 0;
    }
  relax_info = hash_find (nds32_relax_info_hash, opcode->opcode);
  if (relax_info == NULL)
    return adjust;
  if (init)
    {
      branch_range_type = relax_info->br_range;
      i = BR_RANGE_S256;
    }
  else
    {
      branch_range_type = fragP->fr_subtype;
      i = branch_range_type;
    }
  offset = nds32_calc_branch_offset (segment, fragP, stretch,
         relax_info, branch_range_type);
  real_range_type = nds32_convert_to_range_type (offset);
  if (real_range_type == branch_range_type)
    {
      fragP->fr_subtype = real_range_type;
      return adjust;
    }
  for (; i < BR_RANGE_NUM; i++)
    {
      if (real_range_type <= (unsigned int) i)
 {
   if (init)
     diff = relax_info->relax_code_size[i] - opcode->isize;
   else
     diff = relax_info->relax_code_size[i]
       - relax_info->relax_code_size[branch_range_type];
   code_seq_offset = 0;
   j = 0;
   k = 0;
   code_seq_size = relax_info->relax_code_size[i];
   code_seq = relax_info->relax_code_seq[i];
   while (code_seq_offset < code_seq_size)
     {
       insn = code_seq[j];
       if (insn & 0x80000000)
  {
    insn_size = 2;
  }
       else
  {
    insn_size = 4;
    while (relax_info->relax_fixup[i][k].size !=0
    && relax_info->relax_fixup[i][k].offset < code_seq_offset)
      k++;
  }
       code_seq_offset += insn_size;
       j++;
     }
   fragP->fr_subtype = i;
   break;
 }
    }
  return diff + adjust;
}
static int
nds32_adjust_relaxable_frag (fragS *startP, fragS *fragP)
{
  int adj;
  if (startP->tc_frag_data.flag & NDS32_FRAG_RELAXED)
    adj = -2;
  else
    adj = 2;
  startP->tc_frag_data.flag ^= NDS32_FRAG_RELAXED;
  while (startP)
    {
      startP = startP->fr_next;
      if (startP)
 {
   startP->fr_address += adj;
   if (startP == fragP)
     break;
 }
    }
  return adj;
}
static addressT
nds32_get_align (addressT address, int align)
{
  addressT mask, new_address;
  mask = ~((addressT) (~0) << align);
  new_address = (address + mask) & (~mask);
  return (new_address - address);
}
static void
invalid_prev_frag (fragS * fragP, fragS **prev_frag)
{
  addressT address;
  fragS *frag_start = *prev_frag;
  if (!frag_start)
    return;
  if (frag_start->last_fr_address >= fragP->last_fr_address)
    {
      *prev_frag = NULL;
      return;
    }
  fragS *frag_t = *prev_frag;
  while (frag_t != fragP)
    {
      if (frag_t->fr_type == rs_align
   || frag_t->fr_type == rs_align_code
   || frag_t->fr_type == rs_align_test)
 {
   if (frag_t->tc_frag_data.flag & NDS32_FRAG_LABEL)
     {
       prev_frag = NULL;
       return;
     }
   address = frag_t->fr_address + frag_t->fr_fix;
   addressT offset = nds32_get_align (address, (int) frag_t->fr_offset);
   if (offset & 0x2)
     {
       if (!((*prev_frag)->tc_frag_data.flag & NDS32_FRAG_LABEL)
    || (((*prev_frag)->fr_address + (*prev_frag)->fr_fix - 2 )
        & 0x2) == 0)
  nds32_adjust_relaxable_frag (*prev_frag, frag_t);
     }
   *prev_frag = NULL;
   return;
 }
      frag_t = frag_t->fr_next;
    }
  if (fragP->tc_frag_data.flag & NDS32_FRAG_ALIGN)
    {
      address = fragP->fr_address;
      addressT offset = nds32_get_align (address, 2);
      if (offset & 0x2)
 {
   if (!((*prev_frag)->tc_frag_data.flag & NDS32_FRAG_LABEL)
       || (((*prev_frag)->fr_address + (*prev_frag)->fr_fix - 2 )
    & 0x2) == 0)
     nds32_adjust_relaxable_frag (*prev_frag, fragP);
 }
      *prev_frag = NULL;
      return;
    }
}
int
nds32_relax_frag (segT segment, fragS *fragP, long stretch ATTRIBUTE_UNUSED)
{
  static fragS *prev_frag = NULL;
  int adjust = 0;
  invalid_prev_frag (fragP, &prev_frag);
  if (fragP->tc_frag_data.flag & NDS32_FRAG_BRANCH)
    adjust = nds32_relax_branch_instructions (segment, fragP, stretch, 0);
  if (fragP->tc_frag_data.flag & NDS32_FRAG_LABEL)
    prev_frag = NULL;
  if (fragP->tc_frag_data.flag & NDS32_FRAG_RELAXABLE
      && (fragP->tc_frag_data.flag & NDS32_FRAG_RELAXED) == 0)
    prev_frag = fragP;
  return adjust;
}
int
md_estimate_size_before_relax (fragS *fragP, segT segment)
{
  static fragS *prev_frag = NULL;
  int adjust = 0;
  invalid_prev_frag (fragP, &prev_frag);
  if (fragP->tc_frag_data.flag & NDS32_FRAG_BRANCH)
    adjust = nds32_relax_branch_instructions (segment, fragP, 0, 1);
  if (fragP->tc_frag_data.flag & NDS32_FRAG_LABEL)
    prev_frag = NULL;
  if (fragP->tc_frag_data.flag & NDS32_FRAG_RELAXED)
    adjust = 2;
  else if (fragP->tc_frag_data.flag & NDS32_FRAG_RELAXABLE)
    prev_frag = fragP;
  return adjust;
}
void
md_convert_frag (bfd *abfd ATTRIBUTE_UNUSED, segT sec, fragS *fragP)
{
  symbolS *branch_symbol = fragP->fr_symbol;
  offsetT branch_offset = fragP->fr_offset;
  enum nds32_br_range branch_range_type = fragP->fr_subtype;
  struct nds32_opcode *opcode = fragP->tc_frag_data.opcode;
  uint32_t origin_insn = fragP->tc_frag_data.insn;
  relax_info_t *relax_info;
  char *fr_buffer;
  int fr_where;
  int addend ATTRIBUTE_UNUSED;
  offsetT branch_target_address, branch_insn_address;
  expressionS exp;
  fixS *fixP;
  uint32_t *code_seq;
  uint32_t insn;
  int code_size, insn_size, offset, fixup_size;
  int buf_offset, pcrel;
  int i, k;
  uint16_t insn_16;
  nds32_relax_fixup_info_t fixup_info[MAX_RELAX_FIX];
  unsigned int branch_size;
  bfd_boolean is_ict_sym;
  enum bfd_reloc_code_real final_r_type;
  if (branch_symbol == NULL && !(fragP->tc_frag_data.flag & NDS32_FRAG_RELAXED))
    return;
  if (opcode == NULL)
    return;
  if (fragP->tc_frag_data.flag & NDS32_FRAG_RELAXABLE_BRANCH)
    {
      relax_info = hash_find (nds32_relax_info_hash, opcode->opcode);
      if (relax_info == NULL)
 return;
      i = BR_RANGE_S256;
      while (i < BR_RANGE_NUM
      && relax_info->relax_code_size[i]
      != (fragP->tc_frag_data.flag & NDS32_FRAG_RELAXED ? 4 : 2))
 i++;
      if (i >= BR_RANGE_NUM)
 as_bad ("Internal error: Cannot find relocation of"
  "relaxable branch.");
      exp.X_op = O_symbol;
      exp.X_add_symbol = branch_symbol;
      exp.X_add_number = branch_offset;
      pcrel = ((relax_info->relax_fixup[i][0].ramp & NDS32_PCREL) != 0) ? 1 : 0;
      fr_where = fragP->fr_fix - 2;
      fixP = fix_new_exp (fragP, fr_where, relax_info->relax_fixup[i][0].size,
     &exp, pcrel, relax_info->relax_fixup[i][0].r_type);
      fixP->fx_addnumber = fixP->fx_offset;
      if (fragP->tc_frag_data.flag & NDS32_FRAG_RELAXED)
 {
   insn_16 = fragP->tc_frag_data.insn;
   nds32_convert_16_to_32 (stdoutput, insn_16, &insn);
   fr_buffer = fragP->fr_literal + fr_where;
   fragP->fr_fix += 2;
   exp.X_op = O_symbol;
   exp.X_add_symbol = abs_section_sym;
   exp.X_add_number = 0;
   fix_new_exp (fragP, fr_where, 4,
         &exp, 0, BFD_RELOC_NDS32_INSN16);
   number_to_chars_bigendian (fr_buffer, insn, 4);
 }
    }
  else if (fragP->tc_frag_data.flag & NDS32_FRAG_RELAXED)
    {
      if (fragP->tc_frag_data.opcode->isize == 2)
 {
   insn_16 = fragP->tc_frag_data.insn;
   nds32_convert_16_to_32 (stdoutput, insn_16, &insn);
 }
      else
 insn = fragP->tc_frag_data.insn;
      fragP->fr_fix += 2;
      fr_where = fragP->fr_fix - 4;
      fr_buffer = fragP->fr_literal + fr_where;
      exp.X_op = O_symbol;
      exp.X_add_symbol = abs_section_sym;
      exp.X_add_number = 0;
      fix_new_exp (fragP, fr_where, 4, &exp, 0,
     BFD_RELOC_NDS32_INSN16);
      number_to_chars_bigendian (fr_buffer, insn, 4);
    }
  else if (fragP->tc_frag_data.flag & NDS32_FRAG_BRANCH)
    {
      relax_info = hash_find (nds32_relax_info_hash, opcode->opcode);
      is_ict_sym = fragP->tc_frag_data.flag & NDS32_FRAG_ICT_BRANCH;
      if (relax_info == NULL)
 return;
      fr_where = fragP->fr_fix - opcode->isize;
      fr_buffer = fragP->fr_literal + fr_where;
      if ((S_GET_SEGMENT (branch_symbol) != sec)
   || S_IS_WEAK (branch_symbol))
 {
   if (fragP->fr_offset & 3)
     as_warn (_("Addend to unresolved symbol is not on word boundary."));
   addend = 0;
 }
      else
 {
   branch_target_address = S_GET_VALUE (branch_symbol) + branch_offset;
   branch_insn_address = fragP->fr_address + fr_where;
   addend = (branch_target_address - branch_insn_address) >> 1;
 }
      code_size = relax_info->relax_code_size[branch_range_type];
      code_seq = relax_info->relax_code_seq[branch_range_type];
      memcpy (fixup_info, relax_info->relax_fixup[branch_range_type],
       sizeof (fixup_info));
      i = 0;
      k = 0;
      offset = 0;
      buf_offset = 0;
      while (offset < code_size)
 {
   insn = code_seq[i];
   if (insn & 0x80000000)
     {
       insn = (insn >> 16) & 0xFFFF;
       insn_size = 2;
     }
   else
     {
       insn_size = 4;
     }
   nds32_elf_get_set_cond (relax_info, offset, &insn,
      origin_insn, branch_range_type);
   while (fixup_info[k].size != 0
   && relax_info->relax_fixup[branch_range_type][k].offset < offset)
     k++;
   number_to_chars_bigendian (fr_buffer + buf_offset, insn, insn_size);
   buf_offset += insn_size;
   offset += insn_size;
   i++;
 }
      exp.X_op = O_symbol;
      for (i = 0; fixup_info[i].size != 0; i++)
 {
   fixup_size = fixup_info[i].size;
   pcrel = ((fixup_info[i].ramp & NDS32_PCREL) != 0) ? 1 : 0;
   if ((fixup_info[i].ramp & NDS32_CREATE_LABEL) != 0)
     {
       exp.X_add_symbol = symbol_temp_new (sec, 0, fragP->fr_next);
       exp.X_add_number = 0;
     }
   else if ((fixup_info[i].ramp & NDS32_PTR) != 0)
     {
       branch_size = fr_where + code_size - 4;
       exp.X_add_symbol = symbol_temp_new (sec, branch_size, fragP);
       exp.X_add_number = 0;
     }
   else if ((fixup_info[i].ramp & NDS32_ABS) != 0)
     {
       exp.X_add_symbol = abs_section_sym;
       exp.X_add_number = 0;
     }
   else if ((fixup_info[i].ramp & NDS32_INSN16) != 0)
     {
       if (!enable_16bit)
  continue;
       exp.X_add_symbol = abs_section_sym;
       exp.X_add_number = 0;
     }
   else
     {
       exp.X_add_symbol = branch_symbol;
       exp.X_add_number = branch_offset;
     }
   if (fixup_info[i].r_type != 0)
     {
       final_r_type = fixup_info[i].r_type;
       if (is_ict_sym && final_r_type == BFD_RELOC_NDS32_HI20)
  final_r_type = BFD_RELOC_NDS32_ICT_HI20;
       else if (is_ict_sym && final_r_type == BFD_RELOC_NDS32_LO12S0_ORI)
  final_r_type = BFD_RELOC_NDS32_ICT_LO12;
       else if (is_ict_sym && fixup_info[i].ramp & NDS32_HINT)
  continue;
       fixP = fix_new_exp (fragP, fr_where + fixup_info[i].offset,
      fixup_size, &exp, pcrel,
      final_r_type);
       fixP->fx_addnumber = fixP->fx_offset;
     }
 }
      fragP->fr_fix = fr_where + buf_offset;
    }
}
void
nds32_frob_file_before_fix (void)
{
}
static bfd_boolean
nds32_relaxable_section (asection *sec)
{
  return ((sec->flags & SEC_DEBUGGING) == 0
   && strcmp (sec->name, ".eh_frame") != 0);
}
int
nds32_force_relocation (fixS * fix)
{
  switch (fix->fx_r_type)
    {
    case BFD_RELOC_NDS32_INSN16:
    case BFD_RELOC_NDS32_LABEL:
    case BFD_RELOC_NDS32_LONGCALL1:
    case BFD_RELOC_NDS32_LONGCALL2:
    case BFD_RELOC_NDS32_LONGCALL3:
    case BFD_RELOC_NDS32_LONGJUMP1:
    case BFD_RELOC_NDS32_LONGJUMP2:
    case BFD_RELOC_NDS32_LONGJUMP3:
    case BFD_RELOC_NDS32_LOADSTORE:
    case BFD_RELOC_NDS32_9_FIXED:
    case BFD_RELOC_NDS32_15_FIXED:
    case BFD_RELOC_NDS32_17_FIXED:
    case BFD_RELOC_NDS32_25_FIXED:
    case BFD_RELOC_NDS32_9_PCREL:
    case BFD_RELOC_NDS32_15_PCREL:
    case BFD_RELOC_NDS32_17_PCREL:
    case BFD_RELOC_NDS32_WORD_9_PCREL:
    case BFD_RELOC_NDS32_10_UPCREL:
    case BFD_RELOC_NDS32_25_PCREL:
    case BFD_RELOC_NDS32_MINUEND:
    case BFD_RELOC_NDS32_SUBTRAHEND:
      return 1;
    case BFD_RELOC_8:
    case BFD_RELOC_16:
    case BFD_RELOC_32:
    case BFD_RELOC_NDS32_DIFF_ULEB128:
      return fix->fx_subsy != NULL
 && nds32_relaxable_section (S_GET_SEGMENT (fix->fx_addsy));
    case BFD_RELOC_64:
      if (fix->fx_subsy)
 as_bad ("Double word for difference between two symbols is not "
  "supported across relaxation.");
    default:
      ;
    }
  if (generic_force_reloc (fix))
    return 1;
  return fix->fx_pcrel;
}
int
nds32_validate_fix_sub (fixS *fix, segT add_symbol_segment)
{
  segT sub_symbol_segment;
  sub_symbol_segment = S_GET_SEGMENT (fix->fx_subsy);
  return (sub_symbol_segment == add_symbol_segment
   && add_symbol_segment != undefined_section);
}
void
md_number_to_chars (char *buf, valueT val, int n)
{
  if (target_big_endian)
    number_to_chars_bigendian (buf, val, n);
  else
    number_to_chars_littleendian (buf, val, n);
}
#define MAX_LITTLENUMS 6
char *
md_atof (int type, char *litP, int *sizeP)
{
  int i;
  int prec;
  LITTLENUM_TYPE words[MAX_LITTLENUMS];
  char *t;
  switch (type)
    {
    case 'f':
    case 'F':
    case 's':
    case 'S':
      prec = 2;
      break;
    case 'd':
    case 'D':
    case 'r':
    case 'R':
      prec = 4;
      break;
    default:
      *sizeP = 0;
      return _("Bad call to md_atof()");
    }
  t = atof_ieee (input_line_pointer, type, words);
  if (t)
    input_line_pointer = t;
  *sizeP = prec * sizeof (LITTLENUM_TYPE);
  if (target_big_endian)
    {
      for (i = 0; i < prec; i++)
 {
   md_number_to_chars (litP, (valueT) words[i],
         sizeof (LITTLENUM_TYPE));
   litP += sizeof (LITTLENUM_TYPE);
 }
    }
  else
    {
      for (i = prec - 1; i >= 0; i--)
 {
   md_number_to_chars (litP, (valueT) words[i],
         sizeof (LITTLENUM_TYPE));
   litP += sizeof (LITTLENUM_TYPE);
 }
    }
  return 0;
}
void
nds32_elf_section_change_hook (void)
{
}
void
nds32_cleanup (void)
{
}
static void
nds32_insert_leb128_fixes (bfd *abfd ATTRIBUTE_UNUSED,
      asection *sec, void *xxx ATTRIBUTE_UNUSED)
{
  segment_info_type *seginfo = seg_info (sec);
  struct frag *fragP;
  subseg_set (sec, 0);
  for (fragP = seginfo->frchainP->frch_root;
       fragP; fragP = fragP->fr_next)
    {
      expressionS *exp;
      if (fragP->fr_type != rs_leb128 || fragP->fr_subtype != 0
   || fragP->fr_symbol == NULL)
 continue;
      exp = symbol_get_value_expression (fragP->fr_symbol);
      if (exp->X_op != O_subtract)
 continue;
      fix_new_exp (fragP, fragP->fr_fix, 0,
     exp, 0, BFD_RELOC_NDS32_DIFF_ULEB128);
    }
}
static void
nds32_insert_relax_entry (bfd *abfd ATTRIBUTE_UNUSED, asection *sec,
     void *xxx ATTRIBUTE_UNUSED)
{
  segment_info_type *seginfo;
  fragS *fragP;
  fixS *fixP;
  expressionS exp;
  fixS *fixp;
  seginfo = seg_info (sec);
  if (symbol_find ("_INDIRECT_CALL_TABLE_BASE_"))
    ict_exist = TRUE;
  if (!seginfo || !symbol_rootP || !subseg_text_p (sec) || sec->size == 0)
    return;
  for (fixp = seginfo->fix_root; fixp; fixp = fixp->fx_next)
    if (!fixp->fx_done)
      break;
  if (!fixp && !verbatim && (!ict_exist || ict_flag == ICT_NONE))
    return;
  subseg_change (sec, 0);
  fragP = seginfo->frchainP->frch_root;
  exp.X_op = O_symbol;
  exp.X_add_symbol = abs_section_sym;
  exp.X_add_number = 0;
  if (!enable_relax_relocs)
    exp.X_add_number |= R_NDS32_RELAX_ENTRY_DISABLE_RELAX_FLAG;
  else
    {
      if (verbatim)
 exp.X_add_number |= R_NDS32_RELAX_ENTRY_VERBATIM_FLAG;
      if (ict_exist && ict_flag == ICT_SMALL)
 exp.X_add_number |= R_NDS32_RELAX_ENTRY_ICT_SMALL;
      else if (ict_exist && ict_flag == ICT_LARGE)
 exp.X_add_number |= R_NDS32_RELAX_ENTRY_ICT_LARGE;
    }
  if (optimize)
    exp.X_add_number |= R_NDS32_RELAX_ENTRY_OPTIMIZE_FLAG;
  if (optimize_for_space)
    exp.X_add_number |= R_NDS32_RELAX_ENTRY_OPTIMIZE_FOR_SPACE_FLAG;
  fixP = fix_new_exp (fragP, 0, 0, &exp, 0, BFD_RELOC_NDS32_RELAX_ENTRY);
  fixP->fx_no_overflow = 1;
}
static void
nds32_elf_analysis_relax_hint (void)
{
  hash_traverse (nds32_hint_hash, nds32_elf_append_relax_relocs);
}
static void
nds32_elf_insert_final_frag (void)
{
  struct frchain *frchainP;
  asection *s;
  fragS *fragP;
  if (!optimize)
    return;
  for (s = stdoutput->sections; s; s = s->next)
    {
      segment_info_type *seginfo = seg_info (s);
      if (!seginfo)
 continue;
      for (frchainP = seginfo->frchainP; frchainP != NULL;
    frchainP = frchainP->frch_next)
 {
   subseg_set (s, frchainP->frch_subseg);
   if (subseg_text_p (now_seg))
     {
       fragP = frag_now;
       frag_var (rs_machine_dependent, 2,
   0, 0, NULL, 0, NULL);
       fragP->tc_frag_data.flag |= NDS32_FRAG_FINAL;
     }
 }
    }
}
static void
nds32_create_section_compatible_abi (void)
{
  segT comp_section = subseg_new (".note.v2abi_compatible", 0);
  bfd_set_section_flags (stdoutput, comp_section, SEC_READONLY | SEC_DATA);
  now_seg = comp_section;
  frag_grow (NDS32_MAXCHAR);
  char *out = frag_more (4);
  if (compatible_abi)
    bfd_putb32 ((bfd_vma) 1, out);
  else
    bfd_putb32 ((bfd_vma) 0, out);
}
void
md_end (void)
{
  if (compatible_abi)
    nds32_create_section_compatible_abi ();
  nds32_elf_insert_final_frag ();
  nds32_elf_analysis_relax_hint ();
  bfd_map_over_sections (stdoutput, nds32_insert_leb128_fixes, NULL);
}
bfd_boolean
nds32_allow_local_subtract (expressionS *expr_l ATTRIBUTE_UNUSED,
       expressionS *expr_r ATTRIBUTE_UNUSED,
       segT sec ATTRIBUTE_UNUSED)
{
  return FALSE;
}
static int
compar_relent (const void *lhs, const void *rhs)
{
  const arelent **l = (const arelent **) lhs;
  const arelent **r = (const arelent **) rhs;
  if ((*l)->address > (*r)->address)
    return 1;
  else if ((*l)->address == (*r)->address)
    return 0;
  else
    return -1;
}
void
nds32_set_section_relocs (asection *sec, arelent ** relocs ATTRIBUTE_UNUSED,
     unsigned int n ATTRIBUTE_UNUSED)
{
  bfd *abfd ATTRIBUTE_UNUSED = sec->owner;
  if (bfd_get_section_flags (abfd, sec) & (flagword) SEC_RELOC)
    nds32_insertion_sort (sec->orelocation, sec->reloc_count,
     sizeof (arelent**), compar_relent);
}
long
nds32_pcrel_from_section (fixS *fixP, segT sec ATTRIBUTE_UNUSED)
{
  if (fixP->fx_addsy == NULL || !S_IS_DEFINED (fixP->fx_addsy)
      || S_IS_EXTERNAL (fixP->fx_addsy) || S_IS_WEAK (fixP->fx_addsy))
    {
      return 0;
    }
  return fixP->fx_frag->fr_address + fixP->fx_where;
}
void
nds32_post_relax_hook (void)
{
  bfd_map_over_sections (stdoutput, nds32_insert_relax_entry, NULL);
}
bfd_boolean
nds32_fix_adjustable (fixS *fixP)
{
  switch (fixP->fx_r_type)
    {
    case BFD_RELOC_NDS32_WORD_9_PCREL:
    case BFD_RELOC_NDS32_9_PCREL:
    case BFD_RELOC_NDS32_15_PCREL:
    case BFD_RELOC_NDS32_17_PCREL:
    case BFD_RELOC_NDS32_25_PCREL:
    case BFD_RELOC_NDS32_HI20:
    case BFD_RELOC_NDS32_LO12S0:
    case BFD_RELOC_8:
    case BFD_RELOC_16:
    case BFD_RELOC_32:
    case BFD_RELOC_NDS32_PTR:
    case BFD_RELOC_NDS32_LONGCALL4:
    case BFD_RELOC_NDS32_LONGCALL5:
    case BFD_RELOC_NDS32_LONGCALL6:
    case BFD_RELOC_NDS32_LONGJUMP4:
    case BFD_RELOC_NDS32_LONGJUMP5:
    case BFD_RELOC_NDS32_LONGJUMP6:
    case BFD_RELOC_NDS32_LONGJUMP7:
      return 1;
    default:
      return 0;
    }
}
void
elf_nds32_final_processing (void)
{
  if (nds32_fpu_com
      && !(nds32_elf_flags & (E_NDS32_HAS_FPU_INST | E_NDS32_HAS_FPU_DP_INST)))
    {
      if (nds32_fpu_dp_ext || nds32_fpu_sp_ext)
 {
   nds32_elf_flags |= nds32_fpu_dp_ext ? E_NDS32_HAS_FPU_DP_INST : 0;
   nds32_elf_flags |= nds32_fpu_sp_ext ? E_NDS32_HAS_FPU_INST : 0;
 }
      else
 {
   as_bad (_("Used FPU instructions requires enabling FPU extension"));
 }
    }
  if (nds32_elf_flags & (E_NDS32_HAS_FPU_INST | E_NDS32_HAS_FPU_DP_INST))
    {
      nds32_elf_flags &= ~E_NDS32_FPU_REG_CONF;
      nds32_elf_flags |= (nds32_freg << E_NDS32_FPU_REG_CONF_SHIFT);
    }
  if (nds32_gpr16)
    nds32_elf_flags |= E_NDS32_HAS_REDUCED_REGS;
  nds32_elf_flags |= (E_NDS32_ELF_VER_1_4 | nds32_abi);
  elf_elfheader (stdoutput)->e_flags |= nds32_elf_flags;
}
void
nds32_apply_fix (fixS *fixP, valueT *valP, segT seg ATTRIBUTE_UNUSED)
{
  char *where = fixP->fx_frag->fr_literal + fixP->fx_where;
  bfd_vma value = *valP;
  if (fixP->fx_r_type < BFD_RELOC_UNUSED
      && fixP->fx_r_type > BFD_RELOC_NONE
      && fixP->fx_r_type != BFD_RELOC_NDS32_DIFF_ULEB128)
    {
      fixP->fx_addnumber = value;
      fixP->tc_fix_data = NULL;
      switch (fixP->fx_r_type)
 {
 case BFD_RELOC_NDS32_TPOFF:
 case BFD_RELOC_NDS32_TLS_LE_HI20:
 case BFD_RELOC_NDS32_TLS_LE_LO12:
 case BFD_RELOC_NDS32_TLS_LE_ADD:
 case BFD_RELOC_NDS32_TLS_LE_LS:
 case BFD_RELOC_NDS32_GOTTPOFF:
 case BFD_RELOC_NDS32_TLS_IE_HI20:
 case BFD_RELOC_NDS32_TLS_IE_LO12S2:
 case BFD_RELOC_NDS32_TLS_DESC_HI20:
 case BFD_RELOC_NDS32_TLS_DESC_LO12:
 case BFD_RELOC_NDS32_TLS_IE_LO12:
 case BFD_RELOC_NDS32_TLS_IEGP_HI20:
 case BFD_RELOC_NDS32_TLS_IEGP_LO12:
 case BFD_RELOC_NDS32_TLS_IEGP_LO12S2:
   S_SET_THREAD_LOCAL (fixP->fx_addsy);
   break;
 default:
   break;
 }
      return;
    }
  if (fixP->fx_addsy == (symbolS *) NULL)
    fixP->fx_done = 1;
  if (fixP->fx_subsy != (symbolS *) NULL)
    {
      value -= S_GET_VALUE (fixP->fx_subsy);
      *valP = value;
      fixP->fx_subsy = NULL;
      fixP->fx_offset -= value;
      switch (fixP->fx_r_type)
 {
 case BFD_RELOC_8:
   fixP->fx_r_type = BFD_RELOC_NDS32_DIFF8;
   md_number_to_chars (where, value, 1);
   break;
 case BFD_RELOC_16:
   fixP->fx_r_type = BFD_RELOC_NDS32_DIFF16;
   md_number_to_chars (where, value, 2);
   break;
 case BFD_RELOC_32:
   fixP->fx_r_type = BFD_RELOC_NDS32_DIFF32;
   md_number_to_chars (where, value, 4);
   break;
 case BFD_RELOC_NDS32_DIFF_ULEB128:
   break;
 default:
   as_bad_where (fixP->fx_file, fixP->fx_line,
   _("expression too complex"));
   return;
 }
    }
  else if (fixP->fx_done)
    {
      switch (fixP->fx_r_type)
 {
 case BFD_RELOC_8:
   md_number_to_chars (where, value, 1);
   break;
 case BFD_RELOC_16:
   md_number_to_chars (where, value, 2);
   break;
 case BFD_RELOC_32:
   md_number_to_chars (where, value, 4);
   break;
 case BFD_RELOC_64:
   md_number_to_chars (where, value, 8);
 default:
   as_bad_where (fixP->fx_file, fixP->fx_line,
   _("Internal error: Unknown fixup type %d (`%s')"),
   fixP->fx_r_type,
   bfd_get_reloc_code_name (fixP->fx_r_type));
   break;
 }
    }
}
arelent *
tc_gen_reloc (asection *section ATTRIBUTE_UNUSED, fixS *fixP)
{
  arelent *reloc;
  bfd_reloc_code_real_type code;
  reloc = (arelent *) xmalloc (sizeof (arelent));
  reloc->sym_ptr_ptr = (asymbol **) xmalloc (sizeof (asymbol *));
  *reloc->sym_ptr_ptr = symbol_get_bfdsym (fixP->fx_addsy);
  reloc->address = fixP->fx_frag->fr_address + fixP->fx_where;
  code = fixP->fx_r_type;
  reloc->howto = bfd_reloc_type_lookup (stdoutput, code);
  if (reloc->howto == (reloc_howto_type *) NULL)
    {
      as_bad_where (fixP->fx_file, fixP->fx_line,
      _("internal error: can't export reloc type %d (`%s')"),
      fixP->fx_r_type, bfd_get_reloc_code_name (code));
      return NULL;
    }
  switch (fixP->fx_r_type)
    {
    default:
      reloc->addend = fixP->fx_offset;
      break;
    case BFD_RELOC_NDS32_DATA:
      reloc->addend = fixP->fx_size;
      break;
    }
  return reloc;
}
static struct suffix_name suffix_table[] =
{
  {"GOTOFF", BFD_RELOC_NDS32_GOTOFF},
  {"GOT", BFD_RELOC_NDS32_GOT20},
  {"TPOFF", BFD_RELOC_NDS32_TPOFF},
  {"PLT", BFD_RELOC_NDS32_25_PLTREL},
  {"GOTTPOFF", BFD_RELOC_NDS32_GOTTPOFF},
  {"TLSDESC", BFD_RELOC_NDS32_TLS_DESC},
  {"ICT", BFD_RELOC_NDS32_ICT}
};
int
nds32_parse_name (char const *name, expressionS *exprP,
    enum expr_mode mode ATTRIBUTE_UNUSED,
    char *nextcharP ATTRIBUTE_UNUSED)
{
  segT segment;
  exprP->X_op_symbol = NULL;
  exprP->X_md = BFD_RELOC_UNUSED;
  exprP->X_add_symbol = symbol_find_or_make (name);
  exprP->X_op = O_symbol;
  exprP->X_add_number = 0;
  segment = S_GET_SEGMENT (exprP->X_add_symbol);
  if ((segment != undefined_section) && (*nextcharP != '@'))
    return 0;
  if (strcmp (name, GOT_NAME) == 0 && *nextcharP != '@')
    {
      exprP->X_md = BFD_RELOC_NDS32_GOTPC20;
    }
  else if (*nextcharP == '@')
    {
      size_t i;
      char *next;
      for (i = 0; i < ARRAY_SIZE (suffix_table); i++)
 {
   next = input_line_pointer + 1 + strlen (suffix_table[i].suffix);
   if (strncasecmp (input_line_pointer + 1, suffix_table[i].suffix,
      strlen (suffix_table[i].suffix)) == 0
       && !is_part_of_name (*next))
     {
       exprP->X_md = suffix_table[i].reloc;
       *input_line_pointer = *nextcharP;
       input_line_pointer = next;
       *nextcharP = *input_line_pointer;
       *input_line_pointer = '\0';
       break;
     }
 }
    }
  if (exprP->X_md == BFD_RELOC_NDS32_ICT)
    ict_exist = TRUE;
  return 1;
}
int
tc_nds32_regname_to_dw2regnum (char *regname)
{
  struct nds32_keyword *sym = hash_find (nds32_gprs_hash, regname);
  if (!sym)
    return -1;
  return sym->value;
}
void
tc_nds32_frame_initial_instructions (void)
{
  cfi_add_CFA_def_cfa (31, 0);
}
