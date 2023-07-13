/* RISC-V ELF specific backend routines.
   Copyright (C) 2011-2019 Free Software Foundation, Inc.

   Contributed by Andrew Waterman (andrew@sifive.com).
   Based on MIPS target.

   This file is part of BFD, the Binary File Descriptor library.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; see the file COPYING3. If not,
   see <http://www.gnu.org/licenses/>.  */

#include "elf/common.h"
#include "elf/internal.h"
#include "opcode/riscv.h"

extern reloc_howto_type *
riscv_reloc_name_lookup (bfd *, const char *);

extern reloc_howto_type *
riscv_reloc_type_lookup (bfd *, bfd_reloc_code_real_type);

extern reloc_howto_type *
riscv_elf_rtype_to_howto (bfd *, unsigned int r_type);

#define RISCV_DONT_CARE_VERSION -1

/* The information of architecture attribute.  */
struct riscv_subset_t
{
  const char *name;
  int major_version;
  int minor_version;
  struct riscv_subset_t *next;
};

typedef struct riscv_subset_t riscv_subset_t;

typedef struct {
  riscv_subset_t *head;
  riscv_subset_t *tail;
} riscv_subset_list_t;

extern void
riscv_release_subset_list (riscv_subset_list_t *);

extern void
riscv_add_subset (riscv_subset_list_t *,
		  const char *,
		  int, int);

bfd_boolean
riscv_lookup_subset (const riscv_subset_list_t *subset_list,
		     const char *subset,
		     riscv_subset_t **current);

extern riscv_subset_t *
riscv_lookup_subset_version (const riscv_subset_list_t *,
			     const char *,
			     int, int);

typedef struct {
  riscv_subset_list_t *subset_list;
  void (*error_handler) (const char *,
			 ...) ATTRIBUTE_PRINTF_1;
  unsigned *xlen;
  void (*get_default_version) (const char *,
			       int *,
			       int *);
} riscv_parse_subset_t;

extern bfd_boolean
riscv_parse_subset (riscv_parse_subset_t *,
		    const char *);

extern const char *
riscv_supported_std_ext (void);

extern void
riscv_release_subset_list (riscv_subset_list_t *);

extern char *
riscv_arch_str (unsigned, const riscv_subset_list_t *);

/* ISA extension name class. E.g. "zbb" corresponds to RV_ISA_CLASS_Z,
   "xargs" corresponds to RV_ISA_CLASS_X, etc.  */

typedef enum riscv_isa_ext_class
{
  RV_ISA_CLASS_S,
  RV_ISA_CLASS_H,
  RV_ISA_CLASS_Z,
  RV_ISA_CLASS_X,
  RV_ISA_CLASS_UNKNOWN
} riscv_isa_ext_class_t;

/* Classify the argument 'ext' into one of riscv_isa_ext_class_t.  */

riscv_isa_ext_class_t
riscv_get_prefix_class (const char *);

extern int
riscv_get_priv_spec_class (const char *, enum riscv_priv_spec_class *);

extern int
riscv_get_priv_spec_class_from_numbers (unsigned int,
					unsigned int,
					unsigned int,
					enum riscv_priv_spec_class *);

extern const char *
riscv_get_priv_spec_name (enum riscv_priv_spec_class);

extern int
riscv_compare_subsets (const char *, const char *);

typedef struct andes_irelx
{
  void *next;
  Elf_Internal_Rela saved_irel;
  bfd_vma tag;
  bfd_vma flags;
} andes_irelx_t;

/* Get the RISC-V ELF linker hash table from a link_info structure.  */
#define riscv_elf_hash_table(p) \
  (elf_hash_table_id ((struct elf_link_hash_table *) ((p)->hash)) \
  == RISCV_ELF_DATA ? ((struct riscv_elf_link_hash_table *) ((p)->hash)) : NULL)

/* EXECIT extention.  */

/* Optimization status mask.  */
#define RISCV_RELAX_EXECIT_DONE	(1 << 1)

/* Optimization turn on mask.  */
#define RISCV_RELAX_EXECIT_ON	(1 << 1)

/* Relocation flags for R_RISCV_ERLAX_ENTRY.  */

/* Set if relax on this section is done or disabled.  */
#define R_RISCV_RELAX_ENTRY_DISABLE_RELAX_FLAG	(1 << 31)
/* EXECIT must be explicitly enabled, so we won't mess up handcraft assembly code.
   Enable EXECIT optimization for this section.  */
#define R_RISCV_RELAX_ENTRY_EXECIT_FLAG		(1 << 2)

/* Relocation flags for R_RISCV_RELAX_REGION_BEGIN/END.  */

/* Suppress EXECIT optimization in the region.  */
#define R_RISCV_RELAX_REGION_NO_EXECIT_FLAG	(1 << 2)
/* A Innermost loop region.  Some optimizations is suppressed in this region
   due to performance drop.  */
#define R_RISCV_RELAX_REGION_LOOP_FLAG		(1 << 4)

extern unsigned int number_of_howto_table;

extern unsigned int ict_table_entries;
extern unsigned int ict_model;
extern bfd_boolean find_imported_ict_table;

/* ICT stuff  */
typedef struct ict_sym_list
{
  struct ict_sym_list *next;
  struct elf_link_hash_entry *h;
  char *name;
  bfd_vma vma;
  int index;
} ict_sym_list_t;

extern ict_sym_list_t *get_ict_sym_list_head (void);
extern int get_ict_sym_list_len (void);
extern ict_sym_list_t *andes_ict_sym_list_add (int index, const char *name,
					       bfd_vma vma);
ict_sym_list_t *andes_ict_sym_list_insert (struct elf_link_hash_entry *h);

/* { Andes */
#define SZ_4K (1u << 12)

/* GP relative insn relaxation */
#define GPR_ABI_GP 3
#define TAG_NONE 0
#define TAG_GPREL_SUBTYPE_FLX 1
#define TAG_GPREL_SUBTYPE_FSX 2
#define TAG_EXECIT_ITE R_RISCV_EXECIT_ITE

#define REL_R_USER_FLG_NONE (0)
#define REL_R_USER_FLG_RAW  (1)

#define MASK_LSB_32 (0xffffffffu)
#define LO_32B(x) ((x >>  0) & MASK_LSB_32)
#define HI_32B(x) ((x >> 32) & MASK_LSB_32)

/* exec.it */

typedef struct execit_itable_entry
{
  Elf_Internal_Rela *irel;      /* with relocation  */
  Elf_Internal_Sym *isym;       /* for local symbol  */
  struct elf_link_hash_entry *h;/* for global symbol  */
  asection *sec;                /* section of insn  */
  asection *isec;               /* section of local symbol  */
  bfd_vma pc;                   /* insn vma  */
  bfd_vma relocation;           /* might keep host-addr of irel instead  */
  bfd_signed_vma bias;          /* hi20 offset  */
  bfd_vma addend;               /* relocation addend  */
  Elf_Internal_Rela irel_copy;
  Elf_Internal_Sym isym_copy;
  int group_id;
  int est_count;        /* when hashing  */
  int ref_count;        /* when replacing  */
  int rank_order;       /* when building itable  */
  int itable_index;	/* when replacing/relocating  */
  int entries;          /* itable slots  */
  uint32_t insn;        /* raw insn  */
  uint32_t fixed;       /* fixed parts of insn  */
} execit_itable_t;

typedef struct execit_irel_entry
{
  struct execit_irel_entry *next;
  execit_itable_t ie;
  uint id;
  uint is_chosen:1;
} execit_irel_t;

typedef struct hi20_group_type
{
  void *next;
  execit_irel_t *head;
  execit_irel_t *tail;
  int insts;
} hi20_group_t;

typedef struct hi20_context
{
  execit_irel_t *p, *q;
  hi20_group_t *hi20s;
  hi20_group_t *uhi20s;
  int id;
} hi20_context_t;

enum execit_rank_type
{
  ET_RK_TYPE_INSN = 0,
  ET_RK_TYPE_HI20,
};

typedef struct execit_vma_entry
{
  struct execit_vma_entry *next;
  bfd_vma vma;
} execit_vma_t;

typedef struct execit_hash_entry
{
  struct bfd_hash_entry root;
  execit_itable_t ie;
  execit_irel_t *irels;
  execit_vma_t *vmas;
  int id;   /* for determined itable entries  */
  int type; /* INSN/AUIPC/LUI/...  */
  uint is_worthy:1;
  uint is_chosen:1;
  uint is_imported:1;
} execit_hash_t;

typedef struct execit_rank_entry
{
  struct execit_rank_entry *next;
  execit_hash_t *he;
  void *data;
  int grade;
  int type;
  uint is_chosen:1;
} execit_rank_t;

/* It used to record the blank information for EXECIT replacement.  */
typedef struct execit_blank_unit
{
  struct execit_blank_unit *next;
  bfd_vma offset;
  bfd_vma size;
} execit_blank_unit_t;

typedef struct execit_blank_section
{
  struct execit_blank_section *next;
  asection *sec;
  execit_blank_unit_t *unit;
} execit_blank_section_t;

typedef struct execit_blank_abfd
{
  struct execit_blank_abfd *next;
  bfd *abfd;
  execit_blank_section_t *sec;
} execit_blank_abfd_t;

typedef struct execit_itable_item
{
  execit_hash_t *he;
  execit_irel_t *grp_hd;
  execit_itable_t *inf_ie;
  bfd_vma relocation;
  int index;
  int next; /* next itable index associated  */
  int type; /* INSN/AUIPC/LUI/...  */
  uint is_worthy:1;
  uint is_final:1;
  uint is_relocated:1;
} execit_item_t;

typedef struct execit_state
{
  /* EXECIT hash table, used to store all patterns of code.  */
  asection *final_sec;
  asection *itable_section;
  execit_rank_t *rank_list;
  execit_blank_abfd_t *blank_list;
  andes_irelx_t *irelx_list;
  execit_item_t *itable_array;
  struct bfd_hash_table code_hash;
  bfd_vma jal_window_end;
  int raw_itable_entries;
  int next_itable_index;
  int import_number;
  uint16_t execit_op;
  uint is_init:1;
  uint is_built:1;
  uint is_replaced:1;
  uint relocate_itable_done:1;
  uint is_itable_finalized:1;
  uint is_determining_auipc:1;
  uint is_itb_base_set:1;
  uint is_itable_relocated:1;
  uint is_replace_again:1;
  uint is_import_ranked:1;
} execit_state_t;

/* */

typedef struct andes_ld_options
{
  /* Export global symbols into linker script.  */
  FILE *sym_ld_script;
  /* Defalut do relax align.  */
  int set_relax_align;
  /* Defalut do target aligned.  */
  int target_aligned;
  /* Support gp relative insn relaxation.  */
  int gp_relative_insn;
  /* Default avoid BTB miss.  */
  int avoid_btb_miss;
  /* Defalut do relax lui.  */
  int set_relax_lui;
  /* Defalut do relax pc.  */
  int set_relax_pc;
  /* Defalut do relax call.  */
  int set_relax_call;
  /* Defalut do relax tls le.  */
  int set_relax_tls_le;
  /* Defalut do relax cross section call.  */
  int set_relax_cross_section_call;
  /* Defalut do workaround.  */
  int set_workaround;
  /* Default page size  */
  int set_relax_page_size;
  /* For EXECIT.  */
  /* exec.it options  */
  FILE *execit_import_file;
  char *execit_export_file;
  int target_optimization;
  int execit_limit;
  int execit_auipc_entry;
  struct
  {
    uint noji:1;      /* exclude JI insns.  */
    uint nols:1;      /* exclude load-store insns.  */
    uint no_auipc:1;  /* exclude AUIPC insns.  */
    uint no_lui:1;    /* exclude LUI insns.  */
    uint rvv:1;
    uint rvp:1;
    uint fls:1;
    uint xdsp:1;
    uint nexecit_op:1;
  } execit_flags;
  uint update_execit_table:1;
  uint keep_import_execit:1;
  uint execit_loop_aware:1;
  uint execit_jal_over_2m:1; /* enable JAL over first 2M window.  */
  /* andes internal options.  */
  uint set_table_jump:1;
  uint set_table_jump_cli:1;
} andes_ld_options_t;

typedef struct andes_linker_state
{
  struct riscv_elf_link_hash_table *htab;
  andes_ld_options_t *opt;
  andes_irelx_t *ext_irel_list;
  bfd_vma prev_aligned_offset;
  int check_start_export_sym : 1;
} andes_linker_state_t;

struct riscv_elf_link_hash_table
{
  struct elf_link_hash_table elf;

  /* Short-cuts to get to dynamic linker sections.  */
  asection *sdyntdata;

  /* Small local sym to section mapping cache.  */
  struct sym_cache sym_cache;

  /* The max alignment of output sections.  */
  bfd_vma max_alignment;

  /* The data segment phase, don't relax the section
     when it is exp_seg_relro_adjust.  */
  int *data_segment_phase;

  andes_ld_options_t option;
};

/* } Andes */

extern void
bfd_elf32_riscv_set_data_segment_info (struct bfd_link_info *, int *);
extern void
bfd_elf64_riscv_set_data_segment_info (struct bfd_link_info *, int *);
