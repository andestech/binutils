#ifndef ELF32_NDS32_H
#define ELF32_NDS32_H 
#define R_NDS32_RELAX_ENTRY_DISABLE_RELAX_FLAG (1 << 31)
#define R_NDS32_RELAX_ENTRY_OPTIMIZE_FLAG (1 << 30)
#define R_NDS32_RELAX_ENTRY_OPTIMIZE_FOR_SPACE_FLAG (1 << 29)
#define R_NDS32_RELAX_ENTRY_VERBATIM_FLAG (1 << 28)
#define R_NDS32_RELAX_ENTRY_ICT_SMALL (0x2 << 4)
#define R_NDS32_RELAX_ENTRY_ICT_LARGE (0x3 << 4)
#define R_NDS32_RELAX_ENTRY_ICT_MASK (0x3 << 4)
#define R_NDS32_INSN16_CONVERT_FLAG (1 << 0)
#define R_NDS32_INSN16_FP7U2_FLAG (1 << 1)
#define R_NDS32_RELAX_REGION_OMIT_FP_FLAG (1 << 0)
#define R_NDS32_RELAX_REGION_NOT_OMIT_FP_FLAG (1 << 1)
#define R_NDS32_RELAX_REGION_INNERMOST_LOOP_FLAG (1 << 4)
enum
{
  NDS32_LOADSTORE_NONE = 0x0,
  NDS32_LOADSTORE_BYTE = 0x1,
  NDS32_LOADSTORE_HALF = 0x2,
  NDS32_LOADSTORE_WORD = 0x4,
  NDS32_LOADSTORE_FLOAT_S = 0x8,
  NDS32_LOADSTORE_FLOAT_D = 0x10,
  NDS32_LOADSTORE_IMM = 0x20
};
enum
{
  NDS32_SECURITY_NONE = 0,
  NDS32_SECURITY_START,
  NDS32_SECURITY_RESTART,
  NDS32_SECURITY_END
};
void nds32_insertion_sort
  (void *base, size_t nmemb, size_t size,
   int (*compar) (const void *lhs, const void *rhs));
struct section_id_list_t
{
  int id;
  struct section_id_list_t *next;
};
struct section_id_list_t *
  elf32_nds32_lookup_section_id (int id, struct section_id_list_t **lst_ptr);
int elf32_nds32_check_relax_group (bfd *bfd, asection *sec);
int elf32_nds32_unify_relax_group (bfd *abfd, asection *asec);
int nds32_elf_unify_tls_model (bfd *inbfd, asection *insec,
          bfd_byte *incontents,
          struct bfd_link_info *lnkinfo);
void bfd_elf32_nds32_set_target_option (struct bfd_link_info *, int, int,
     FILE *, int, int, int, char *);
void bfd_elf32_nds32_append_section (struct bfd_link_info*, bfd *, int);
int nds32_convert_32_to_16
  (bfd *abfd, uint32_t insn, uint16_t *pinsn16, int *pinsn_type);
int nds32_convert_16_to_32 (bfd *abfd, uint16_t insn16, uint32_t *pinsn);
#define nds32_elf_hash_table(info) \
  (elf_hash_table_id ((struct elf_link_hash_table *) ((info)->hash)) \
   == NDS32_ELF_DATA ? ((struct elf_nds32_link_hash_table *) ((info)->hash)) : NULL)
#define elf32_nds32_compute_jump_table_size(htab) \
  ((htab)->next_tls_desc_index * 4)
#define elf32_nds32_local_tlsdesc_gotent(bfd) \
  (elf_nds32_tdata (bfd)->local_tlsdesc_gotent)
struct elf_nds32_link_hash_table
{
  struct elf_link_hash_table root;
  asection *sdynbss;
  asection *srelbss;
  struct sym_cache sym_cache;
  int relax_fp_as_gp;
  int eliminate_gc_relocs;
  FILE *sym_ld_script;
  int load_store_relax;
  bfd_boolean hyper_relax;
  int tls_desc_trampoline;
  bfd_vma dt_tlsdesc_plt;
  bfd_vma dt_tlsdesc_got;
  bfd_vma tls_trampoline;
  bfd_vma next_tls_desc_index;
  bfd_vma num_tls_desc;
  bfd_vma sgotplt_jump_table_size;
  int use_rel;
};
#endif
