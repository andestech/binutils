#include "sysdep.h"
#include "bfd.h"
#include "bfd_stdint.h"
#include "bfdlink.h"
#include "libbfd.h"
#include "elf-bfd.h"
#include "libiberty.h"
#include "bfd_stdint.h"
#include "elf/nds32.h"
#include "opcode/nds32.h"
#include "elf32-nds32.h"
#include "opcode/cgen.h"
#include "../opcodes/nds32-opc.h"
static bfd_reloc_status_type nds32_elf_ignore_reloc
  (bfd *, arelent *, asymbol *, void *, asection *, bfd *, char **);
static bfd_reloc_status_type nds32_elf_9_pcrel_reloc
  (bfd *, arelent *, asymbol *, void *, asection *, bfd *, char **);
static bfd_reloc_status_type nds32_elf_hi20_reloc
  (bfd *, arelent *, asymbol *, void *,
   asection *, bfd *, char **);
static bfd_reloc_status_type nds32_elf_lo12_reloc
  (bfd *, arelent *, asymbol *, void *,
   asection *, bfd *, char **);
static bfd_reloc_status_type nds32_elf_generic_reloc
  (bfd *, arelent *, asymbol *, void *,
   asection *, bfd *, char **);
static bfd_reloc_status_type nds32_elf_sda15_reloc
  (bfd *, arelent *, asymbol *, void *,
   asection *, bfd *, char **);
static bfd_reloc_status_type nds32_elf_do_9_pcrel_reloc
  (bfd *, reloc_howto_type *, asection *, bfd_byte *, bfd_vma,
   asection *, bfd_vma, bfd_vma);
static void nds32_elf_relocate_hi20
  (bfd *, int, Elf_Internal_Rela *, Elf_Internal_Rela *, bfd_byte *, bfd_vma);
static reloc_howto_type *bfd_elf32_bfd_reloc_type_table_lookup
  (enum elf_nds32_reloc_type);
static reloc_howto_type *bfd_elf32_bfd_reloc_type_lookup
  (bfd *, bfd_reloc_code_real_type);
static void nds32_info_to_howto_rel
  (bfd *, arelent *, Elf_Internal_Rela *dst);
static void nds32_info_to_howto
  (bfd *, arelent *, Elf_Internal_Rela *dst);
static bfd_boolean nds32_elf_add_symbol_hook
  (bfd *, struct bfd_link_info *, Elf_Internal_Sym *, const char **,
   flagword *, asection **, bfd_vma *);
static bfd_boolean nds32_elf_relocate_section
  (bfd *, struct bfd_link_info *, bfd *, asection *, bfd_byte *,
   Elf_Internal_Rela *, Elf_Internal_Sym *, asection **);
static bfd_boolean nds32_elf_object_p (bfd *);
static void nds32_elf_final_write_processing (bfd *, bfd_boolean);
static bfd_boolean nds32_elf_set_private_flags (bfd *, flagword);
static bfd_boolean nds32_elf_merge_private_bfd_data (bfd *, bfd *);
static bfd_boolean nds32_elf_print_private_bfd_data (bfd *, void *);
static bfd_boolean nds32_elf_gc_sweep_hook
  (bfd *, struct bfd_link_info *, asection *, const Elf_Internal_Rela *);
static bfd_boolean nds32_elf_check_relocs
  (bfd *, struct bfd_link_info *, asection *, const Elf_Internal_Rela *);
static asection *nds32_elf_gc_mark_hook
  (asection *, struct bfd_link_info *, Elf_Internal_Rela *,
   struct elf_link_hash_entry *, Elf_Internal_Sym *);
static bfd_boolean nds32_elf_adjust_dynamic_symbol
  (struct bfd_link_info *, struct elf_link_hash_entry *);
static bfd_boolean nds32_elf_size_dynamic_sections
  (bfd *, struct bfd_link_info *);
static bfd_boolean nds32_elf_create_dynamic_sections
  (bfd *, struct bfd_link_info *);
static bfd_boolean nds32_elf_finish_dynamic_sections
  (bfd *, struct bfd_link_info *info);
static bfd_boolean nds32_elf_finish_dynamic_symbol
  (bfd *, struct bfd_link_info *, struct elf_link_hash_entry *,
   Elf_Internal_Sym *);
static bfd_boolean nds32_elf_mkobject (bfd *);
static bfd_reloc_status_type nds32_elf_final_sda_base
  (bfd *, struct bfd_link_info *, bfd_vma *, bfd_boolean);
static bfd_boolean allocate_dynrelocs (struct elf_link_hash_entry *, void *);
static bfd_boolean readonly_dynrelocs (struct elf_link_hash_entry *, void *);
static Elf_Internal_Rela *find_relocs_at_address
  (Elf_Internal_Rela *, Elf_Internal_Rela *,
   Elf_Internal_Rela *, enum elf_nds32_reloc_type);
static bfd_vma calculate_memory_address
(bfd *, Elf_Internal_Rela *, Elf_Internal_Sym *, Elf_Internal_Shdr *);
static int nds32_get_section_contents (bfd *, asection *,
           bfd_byte **, bfd_boolean);
static int nds32_get_local_syms (bfd *, asection *ATTRIBUTE_UNUSED,
     Elf_Internal_Sym **);
static bfd_boolean nds32_relax_fp_as_gp
  (struct bfd_link_info *link_info, bfd *abfd, asection *sec,
   Elf_Internal_Rela *internal_relocs, Elf_Internal_Rela *irelend,
   Elf_Internal_Sym *isymbuf);
static bfd_boolean nds32_fag_remove_unused_fpbase
  (bfd *abfd, asection *sec, Elf_Internal_Rela *internal_relocs,
   Elf_Internal_Rela *irelend);
static bfd_byte*
nds32_elf_get_relocated_section_contents (bfd *abfd,
       struct bfd_link_info *link_info,
       struct bfd_link_order *link_order,
       bfd_byte *data,
       bfd_boolean relocatable,
       asymbol **symbols);
static void nds32_elf_ict_hash_init (void);
static void nds32_elf_ict_relocate (bfd *, struct bfd_link_info *);
static asection*
nds32_elf_get_target_section (struct bfd_link_info *, char *);
enum
{
  MACH_V1 = bfd_mach_n1h,
  MACH_V2 = bfd_mach_n1h_v2,
  MACH_V3 = bfd_mach_n1h_v3,
  MACH_V3M = bfd_mach_n1h_v3m,
};
static char *output_abi;
#define MIN(a,b) ((a) > (b) ? (b) : (a))
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#define INSN_32BIT(insn) ((((insn) & 0x80000000) == 0 ? (TRUE) : (FALSE)))
#define ELF_DYNAMIC_INTERPRETER "/usr/lib/ld.so.1"
#define NDS32_GUARD_SEC_P(flags) ((flags) & SEC_ALLOC \
      && (flags) & SEC_LOAD \
      && (flags) & SEC_READONLY)
#define NDS32_NOP32 0x40000009
#define NDS32_NOP16 0x9200
#define PLT_ENTRY_SIZE 24
#define PLT_HEADER_SIZE 24
#define PLT0_ENTRY_WORD0 0x46f00000
#define PLT0_ENTRY_WORD1 0x58f78000
#define PLT0_ENTRY_WORD2 0x05178000
#define PLT0_ENTRY_WORD3 0x04f78001
#define PLT0_ENTRY_WORD4 0x4a003c00
#define PLT0_PIC_ENTRY_WORD0 0x46f00000
#define PLT0_PIC_ENTRY_WORD1 0x58f78000
#define PLT0_PIC_ENTRY_WORD2 0x40f7f400
#define PLT0_PIC_ENTRY_WORD3 0x05178000
#define PLT0_PIC_ENTRY_WORD4 0x04f78001
#define PLT0_PIC_ENTRY_WORD5 0x4a003c00
#define PLT_ENTRY_WORD0 0x46f00000
#define PLT_ENTRY_WORD1 0x04f78000
#define PLT_ENTRY_WORD2 0x4a003c00
#define PLT_ENTRY_WORD3 0x45000000
#define PLT_ENTRY_WORD4 0x48000000
#define PLT_PIC_ENTRY_WORD0 0x46f00000
#define PLT_PIC_ENTRY_WORD1 0x58f78000
#define PLT_PIC_ENTRY_WORD2 0x38febc02
#define PLT_PIC_ENTRY_WORD3 0x4a003c00
#define PLT_PIC_ENTRY_WORD4 0x45000000
#define PLT_PIC_ENTRY_WORD5 0x48000000
#define ACCURATE_8BIT_S1 (0x100)
#define ACCURATE_U9BIT_S1 (0x400)
#define ACCURATE_12BIT_S1 (0x2000)
#define ACCURATE_14BIT_S1 (0x4000)
#define ACCURATE_19BIT (0x40000)
#define CONSERVATIVE_8BIT_S1 (0x100 - 4)
#define CONSERVATIVE_14BIT_S1 (0x4000 - 4)
#define CONSERVATIVE_16BIT_S1 (0x10000 - 4)
#define CONSERVATIVE_24BIT_S1 (0x1000000 - 4)
#define CONSERVATIVE_15BIT (0x4000 - 0x1000)
#define CONSERVATIVE_15BIT_S1 (0x8000 - 0x1000)
#define CONSERVATIVE_15BIT_S2 (0x10000 - 0x1000)
#define CONSERVATIVE_19BIT (0x40000 - 0x1000)
#define CONSERVATIVE_20BIT (0x80000 - 0x1000)
#define NDS32_ICT_SECTION ".nds32.ict"
static long got_size = 0;
static int is_SDA_BASE_set = 0;
static const char *const nds32_elfver_strtab[] = {
  "ELF-1.2",
  "ELF-1.3",
  "ELF-1.4",
};
struct elf_nds32_pcrel_relocs_copied
{
  struct elf_nds32_pcrel_relocs_copied *next;
  asection *section;
  bfd_size_type count;
};
struct elf_nds32_dyn_relocs
{
  struct elf_nds32_dyn_relocs *next;
  asection *sec;
  bfd_size_type count;
  bfd_size_type pc_count;
};
enum elf_nds32_tls_type
{
  GOT_UNKNOWN = (0),
  GOT_NORMAL = (1 << 0),
  GOT_TLS_LE = (1 << 1),
  GOT_TLS_IE = (1 << 2),
  GOT_TLS_IEGP = (1 << 3),
  GOT_TLS_LD = (1 << 4),
  GOT_TLS_GD = (1 << 5),
  GOT_TLS_DESC = (1 << 6),
};
struct elf_nds32_link_hash_entry
{
  struct elf_link_hash_entry root;
  struct elf_nds32_dyn_relocs *dyn_relocs;
  enum elf_nds32_tls_type tls_type;
  int offset_to_gp;
  bfd_boolean indirect_call;
};
#define FP_BASE_NAME "_FP_BASE_"
static int check_start_export_sym = 0;
static FILE *ict_file = NULL;
static unsigned int ict_model = 0;
static bfd_boolean ignore_indirect_call = FALSE;
static bfd_boolean ifc_flag = FALSE;
struct elf_nds32_ict_hash_entry
{
  struct bfd_hash_entry root;
  struct elf_link_hash_entry *h;
  unsigned int order;
};
static struct bfd_hash_table indirect_call_table;
#define TP_OFFSET 0x0
typedef struct
{
  int min_id;
  int max_id;
  int count;
  int bias;
  int init;
} elf32_nds32_relax_group_t;
struct elf_nds32_obj_tdata
{
  struct elf_obj_tdata root;
  char *local_got_tls_type;
  unsigned int hdr_size;
  bfd_vma *local_tlsdesc_gotent;
  int* offset_to_gp;
  elf32_nds32_relax_group_t relax_group;
};
#define elf_nds32_tdata(bfd) \
  ((struct elf_nds32_obj_tdata *) (bfd)->tdata.any)
#define elf32_nds32_local_got_tls_type(bfd) \
  (elf_nds32_tdata (bfd)->local_got_tls_type)
#define elf32_nds32_local_gp_offset(bfd) \
  (elf_nds32_tdata (bfd)->offset_to_gp)
#define elf32_nds32_relax_group_ptr(bfd) \
  &(elf_nds32_tdata (bfd)->relax_group)
#define elf32_nds32_hash_entry(ent) ((struct elf_nds32_link_hash_entry *)(ent))
bfd_boolean
nds32_elf_mkobject (bfd *abfd)
{
  return bfd_elf_allocate_object (abfd, sizeof (struct elf_nds32_obj_tdata),
      NDS32_ELF_DATA);
}
#define HOWTO2(C,R,S,B,P,BI,O,SF,NAME,INPLACE,MASKSRC,MASKDST,PC) \
  [C] = HOWTO(C, R, S, B, P, BI, O, SF, NAME, INPLACE, MASKSRC, MASKDST, PC)
static reloc_howto_type nds32_elf_howto_table[] = {
  HOWTO2 (R_NDS32_NONE,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_bitfield,
  bfd_elf_generic_reloc,
  "R_NDS32_NONE",
  FALSE,
  0,
  0,
  FALSE),
  HOWTO2 (R_NDS32_16,
  0,
  1,
  16,
  FALSE,
  0,
  complain_overflow_bitfield,
  nds32_elf_generic_reloc,
  "R_NDS32_16",
  FALSE,
  0xffff,
  0xffff,
  FALSE),
  HOWTO2 (R_NDS32_32,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_bitfield,
  nds32_elf_generic_reloc,
  "R_NDS32_32",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO2 (R_NDS32_20,
  0,
  2,
  20,
  FALSE,
  0,
  complain_overflow_unsigned,
  nds32_elf_generic_reloc,
  "R_NDS32_20",
  FALSE,
  0xfffff,
  0xfffff,
  FALSE),
  HOWTO2 (R_NDS32_9_PCREL,
  1,
  1,
  8,
  TRUE,
  0,
  complain_overflow_signed,
  nds32_elf_9_pcrel_reloc,
  "R_NDS32_9_PCREL",
  FALSE,
  0xff,
  0xff,
  TRUE),
  HOWTO2 (R_NDS32_15_PCREL,
  1,
  2,
  14,
  TRUE,
  0,
  complain_overflow_signed,
  bfd_elf_generic_reloc,
  "R_NDS32_15_PCREL",
  FALSE,
  0x3fff,
  0x3fff,
  TRUE),
  HOWTO2 (R_NDS32_17_PCREL,
  1,
  2,
  16,
  TRUE,
  0,
  complain_overflow_signed,
  bfd_elf_generic_reloc,
  "R_NDS32_17_PCREL",
  FALSE,
  0xffff,
  0xffff,
  TRUE),
  HOWTO2 (R_NDS32_25_PCREL,
  1,
  2,
  24,
  TRUE,
  0,
  complain_overflow_signed,
  bfd_elf_generic_reloc,
  "R_NDS32_25_PCREL",
  FALSE,
  0xffffff,
  0xffffff,
  TRUE),
  HOWTO2 (R_NDS32_HI20,
  12,
  2,
  20,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_hi20_reloc,
  "R_NDS32_HI20",
  FALSE,
  0x000fffff,
  0x000fffff,
  FALSE),
  HOWTO2 (R_NDS32_LO12S3,
  3,
  2,
  9,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_lo12_reloc,
  "R_NDS32_LO12S3",
  FALSE,
  0x000001ff,
  0x000001ff,
  FALSE),
  HOWTO2 (R_NDS32_LO12S2,
  2,
  2,
  10,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_lo12_reloc,
  "R_NDS32_LO12S2",
  FALSE,
  0x000003ff,
  0x000003ff,
  FALSE),
  HOWTO2 (R_NDS32_LO12S1,
  1,
  2,
  11,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_lo12_reloc,
  "R_NDS32_LO12S1",
  FALSE,
  0x000007ff,
  0x000007ff,
  FALSE),
  HOWTO2 (R_NDS32_LO12S0,
  0,
  2,
  12,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_lo12_reloc,
  "R_NDS32_LO12S0",
  FALSE,
  0x00000fff,
  0x00000fff,
  FALSE),
  HOWTO2 (R_NDS32_SDA15S3,
  3,
  2,
  15,
  FALSE,
  0,
  complain_overflow_signed,
  nds32_elf_sda15_reloc,
  "R_NDS32_SDA15S3",
  FALSE,
  0x00007fff,
  0x00007fff,
  FALSE),
  HOWTO2 (R_NDS32_SDA15S2,
  2,
  2,
  15,
  FALSE,
  0,
  complain_overflow_signed,
  nds32_elf_sda15_reloc,
  "R_NDS32_SDA15S2",
  FALSE,
  0x00007fff,
  0x00007fff,
  FALSE),
  HOWTO2 (R_NDS32_SDA15S1,
  1,
  2,
  15,
  FALSE,
  0,
  complain_overflow_signed,
  nds32_elf_sda15_reloc,
  "R_NDS32_SDA15S1",
  FALSE,
  0x00007fff,
  0x00007fff,
  FALSE),
  HOWTO2 (R_NDS32_SDA15S0,
  0,
  2,
  15,
  FALSE,
  0,
  complain_overflow_signed,
  nds32_elf_sda15_reloc,
  "R_NDS32_SDA15S0",
  FALSE,
  0x00007fff,
  0x00007fff,
  FALSE),
  HOWTO2 (R_NDS32_GNU_VTINHERIT,
  0,
  2,
  0,
  FALSE,
  0,
  complain_overflow_dont,
  NULL,
  "R_NDS32_GNU_VTINHERIT",
  FALSE,
  0,
  0,
  FALSE),
  HOWTO2 (R_NDS32_GNU_VTENTRY,
  0,
  2,
  0,
  FALSE,
  0,
  complain_overflow_dont,
  _bfd_elf_rel_vtable_reloc_fn,
  "R_NDS32_GNU_VTENTRY",
  FALSE,
  0,
  0,
  FALSE),
  HOWTO2 (R_NDS32_16_RELA,
  0,
  1,
  16,
  FALSE,
  0,
  complain_overflow_bitfield,
  bfd_elf_generic_reloc,
  "R_NDS32_16_RELA",
  FALSE,
  0xffff,
  0xffff,
  FALSE),
  HOWTO2 (R_NDS32_32_RELA,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_bitfield,
  bfd_elf_generic_reloc,
  "R_NDS32_32_RELA",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO2 (R_NDS32_20_RELA,
  0,
  2,
  20,
  FALSE,
  0,
  complain_overflow_signed,
  bfd_elf_generic_reloc,
  "R_NDS32_20_RELA",
  FALSE,
  0xfffff,
  0xfffff,
  FALSE),
  HOWTO2 (R_NDS32_9_PCREL_RELA,
  1,
  1,
  8,
  TRUE,
  0,
  complain_overflow_signed,
  bfd_elf_generic_reloc,
  "R_NDS32_9_PCREL_RELA",
  FALSE,
  0xff,
  0xff,
  TRUE),
  HOWTO2 (R_NDS32_15_PCREL_RELA,
  1,
  2,
  14,
  TRUE,
  0,
  complain_overflow_signed,
  bfd_elf_generic_reloc,
  "R_NDS32_15_PCREL_RELA",
  FALSE,
  0x3fff,
  0x3fff,
  TRUE),
  HOWTO2 (R_NDS32_17_PCREL_RELA,
  1,
  2,
  16,
  TRUE,
  0,
  complain_overflow_signed,
  bfd_elf_generic_reloc,
  "R_NDS32_17_PCREL_RELA",
  FALSE,
  0xffff,
  0xffff,
  TRUE),
  HOWTO2 (R_NDS32_25_PCREL_RELA,
  1,
  2,
  24,
  TRUE,
  0,
  complain_overflow_signed,
  bfd_elf_generic_reloc,
  "R_NDS32_25_PCREL_RELA",
  FALSE,
  0xffffff,
  0xffffff,
  TRUE),
  HOWTO2 (R_NDS32_HI20_RELA,
  12,
  2,
  20,
  FALSE,
  0,
  complain_overflow_dont,
  bfd_elf_generic_reloc,
  "R_NDS32_HI20_RELA",
  FALSE,
  0x000fffff,
  0x000fffff,
  FALSE),
  HOWTO2 (R_NDS32_LO12S3_RELA,
  3,
  2,
  9,
  FALSE,
  0,
  complain_overflow_dont,
  bfd_elf_generic_reloc,
  "R_NDS32_LO12S3_RELA",
  FALSE,
  0x000001ff,
  0x000001ff,
  FALSE),
  HOWTO2 (R_NDS32_LO12S2_RELA,
  2,
  2,
  10,
  FALSE,
  0,
  complain_overflow_dont,
  bfd_elf_generic_reloc,
  "R_NDS32_LO12S2_RELA",
  FALSE,
  0x000003ff,
  0x000003ff,
  FALSE),
  HOWTO2 (R_NDS32_LO12S1_RELA,
  1,
  2,
  11,
  FALSE,
  0,
  complain_overflow_dont,
  bfd_elf_generic_reloc,
  "R_NDS32_LO12S1_RELA",
  FALSE,
  0x000007ff,
  0x000007ff,
  FALSE),
  HOWTO2 (R_NDS32_LO12S0_RELA,
  0,
  2,
  12,
  FALSE,
  0,
  complain_overflow_dont,
  bfd_elf_generic_reloc,
  "R_NDS32_LO12S0_RELA",
  FALSE,
  0x00000fff,
  0x00000fff,
  FALSE),
  HOWTO2 (R_NDS32_SDA15S3_RELA,
  3,
  2,
  15,
  FALSE,
  0,
  complain_overflow_signed,
  bfd_elf_generic_reloc,
  "R_NDS32_SDA15S3_RELA",
  FALSE,
  0x00007fff,
  0x00007fff,
  FALSE),
  HOWTO2 (R_NDS32_SDA15S2_RELA,
  2,
  2,
  15,
  FALSE,
  0,
  complain_overflow_signed,
  bfd_elf_generic_reloc,
  "R_NDS32_SDA15S2_RELA",
  FALSE,
  0x00007fff,
  0x00007fff,
  FALSE),
  HOWTO2 (R_NDS32_SDA15S1_RELA,
  1,
  2,
  15,
  FALSE,
  0,
  complain_overflow_signed,
  bfd_elf_generic_reloc,
  "R_NDS32_SDA15S1_RELA",
  FALSE,
  0x00007fff,
  0x00007fff,
  FALSE),
  HOWTO2 (R_NDS32_SDA15S0_RELA,
  0,
  2,
  15,
  FALSE,
  0,
  complain_overflow_signed,
  bfd_elf_generic_reloc,
  "R_NDS32_SDA15S0_RELA",
  FALSE,
  0x00007fff,
  0x00007fff,
  FALSE),
  HOWTO2 (R_NDS32_RELA_GNU_VTINHERIT,
  0,
  2,
  0,
  FALSE,
  0,
  complain_overflow_dont,
  NULL,
  "R_NDS32_RELA_GNU_VTINHERIT",
  FALSE,
  0,
  0,
  FALSE),
  HOWTO2 (R_NDS32_RELA_GNU_VTENTRY,
  0,
  2,
  0,
  FALSE,
  0,
  complain_overflow_dont,
  _bfd_elf_rel_vtable_reloc_fn,
  "R_NDS32_RELA_GNU_VTENTRY",
  FALSE,
  0,
  0,
  FALSE),
  HOWTO2 (R_NDS32_GOT20,
  0,
  2,
  20,
  FALSE,
  0,
  complain_overflow_signed,
  bfd_elf_generic_reloc,
  "R_NDS32_GOT20",
  FALSE,
  0xfffff,
  0xfffff,
  FALSE),
  HOWTO2 (R_NDS32_25_PLTREL,
  1,
  2,
  24,
  TRUE,
  0,
  complain_overflow_signed,
  bfd_elf_generic_reloc,
  "R_NDS32_25_PLTREL",
  FALSE,
  0xffffff,
  0xffffff,
  TRUE),
  HOWTO2 (R_NDS32_COPY,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_bitfield,
  bfd_elf_generic_reloc,
  "R_NDS32_COPY",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO2 (R_NDS32_GLOB_DAT,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_bitfield,
  bfd_elf_generic_reloc,
  "R_NDS32_GLOB_DAT",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO2 (R_NDS32_JMP_SLOT,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_bitfield,
  bfd_elf_generic_reloc,
  "R_NDS32_JMP_SLOT",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO2 (R_NDS32_RELATIVE,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_bitfield,
  bfd_elf_generic_reloc,
  "R_NDS32_RELATIVE",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO2 (R_NDS32_GOTOFF,
  0,
  2,
  20,
  FALSE,
  0,
  complain_overflow_signed,
  bfd_elf_generic_reloc,
  "R_NDS32_GOTOFF",
  FALSE,
  0xfffff,
  0xfffff,
  FALSE),
  HOWTO2 (R_NDS32_GOTPC20,
  0,
  2,
  20,
  TRUE,
  0,
  complain_overflow_signed,
  bfd_elf_generic_reloc,
  "R_NDS32_GOTPC20",
  FALSE,
  0xfffff,
  0xfffff,
  TRUE),
  HOWTO2 (R_NDS32_GOT_HI20,
  12,
  2,
  20,
  FALSE,
  0,
  complain_overflow_dont,
  bfd_elf_generic_reloc,
  "R_NDS32_GOT_HI20",
  FALSE,
  0x000fffff,
  0x000fffff,
  FALSE),
  HOWTO2 (R_NDS32_GOT_LO12,
  0,
  2,
  12,
  FALSE,
  0,
  complain_overflow_dont,
  bfd_elf_generic_reloc,
  "R_NDS32_GOT_LO12",
  FALSE,
  0x00000fff,
  0x00000fff,
  FALSE),
  HOWTO2 (R_NDS32_GOTPC_HI20,
  12,
  2,
  20,
  FALSE,
  0,
  complain_overflow_dont,
  bfd_elf_generic_reloc,
  "R_NDS32_GOTPC_HI20",
  FALSE,
  0x000fffff,
  0x000fffff,
  TRUE),
  HOWTO2 (R_NDS32_GOTPC_LO12,
  0,
  2,
  12,
  FALSE,
  0,
  complain_overflow_dont,
  bfd_elf_generic_reloc,
  "R_NDS32_GOTPC_LO12",
  FALSE,
  0x00000fff,
  0x00000fff,
  TRUE),
  HOWTO2 (R_NDS32_GOTOFF_HI20,
  12,
  2,
  20,
  FALSE,
  0,
  complain_overflow_dont,
  bfd_elf_generic_reloc,
  "R_NDS32_GOTOFF_HI20",
  FALSE,
  0x000fffff,
  0x000fffff,
  FALSE),
  HOWTO2 (R_NDS32_GOTOFF_LO12,
  0,
  2,
  12,
  FALSE,
  0,
  complain_overflow_dont,
  bfd_elf_generic_reloc,
  "R_NDS32_GOTOFF_LO12",
  FALSE,
  0x00000fff,
  0x00000fff,
  FALSE),
  HOWTO2 (R_NDS32_INSN16,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_INSN16",
  FALSE,
  0x00000fff,
  0x00000fff,
  FALSE),
  HOWTO2 (R_NDS32_LABEL,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_LABEL",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO2 (R_NDS32_LONGCALL1,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_LONGCALL1",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO2 (R_NDS32_LONGCALL2,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_LONGCALL2",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO2 (R_NDS32_LONGCALL3,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_LONGCALL3",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO2 (R_NDS32_LONGJUMP1,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_LONGJUMP1",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO2 (R_NDS32_LONGJUMP2,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_LONGJUMP2",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO2 (R_NDS32_LONGJUMP3,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_LONGJUMP3",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO2 (R_NDS32_LOADSTORE,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_LOADSTORE",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO2 (R_NDS32_9_FIXED_RELA,
  0,
  1,
  16,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_9_FIXED_RELA",
  FALSE,
  0x000000ff,
  0x000000ff,
  FALSE),
  HOWTO2 (R_NDS32_15_FIXED_RELA,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_15_FIXED_RELA",
  FALSE,
  0x00003fff,
  0x00003fff,
  FALSE),
  HOWTO2 (R_NDS32_17_FIXED_RELA,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_17_FIXED_RELA",
  FALSE,
  0x0000ffff,
  0x0000ffff,
  FALSE),
  HOWTO2 (R_NDS32_25_FIXED_RELA,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_25_FIXED_RELA",
  FALSE,
  0x00ffffff,
  0x00ffffff,
  FALSE),
  HOWTO2 (R_NDS32_PLTREL_HI20,
  12,
  2,
  20,
  FALSE,
  0,
  complain_overflow_dont,
  bfd_elf_generic_reloc,
  "R_NDS32_PLTREL_HI20",
  FALSE,
  0x000fffff,
  0x000fffff,
  FALSE),
  HOWTO2 (R_NDS32_PLTREL_LO12,
  0,
  2,
  12,
  FALSE,
  0,
  complain_overflow_dont,
  bfd_elf_generic_reloc,
  "R_NDS32_PLTREL_LO12",
  FALSE,
  0x00000fff,
  0x00000fff,
  FALSE),
  HOWTO2 (R_NDS32_PLT_GOTREL_HI20,
  12,
  2,
  20,
  FALSE,
  0,
  complain_overflow_dont,
  bfd_elf_generic_reloc,
  "R_NDS32_PLT_GOTREL_HI20",
  FALSE,
  0x000fffff,
  0x000fffff,
  FALSE),
  HOWTO2 (R_NDS32_PLT_GOTREL_LO12,
  0,
  2,
  12,
  FALSE,
  0,
  complain_overflow_dont,
  bfd_elf_generic_reloc,
  "R_NDS32_PLT_GOTREL_LO12",
  FALSE,
  0x00000fff,
  0x00000fff,
  FALSE),
  HOWTO2 (R_NDS32_SDA12S2_DP_RELA,
  2,
  2,
  12,
  FALSE,
  0,
  complain_overflow_signed,
  bfd_elf_generic_reloc,
  "R_NDS32_SDA12S2_DP_RELA",
  FALSE,
  0x00000fff,
  0x00000fff,
  FALSE),
  HOWTO2 (R_NDS32_SDA12S2_SP_RELA,
  2,
  2,
  12,
  FALSE,
  0,
  complain_overflow_signed,
  bfd_elf_generic_reloc,
  "R_NDS32_SDA12S2_SP_RELA",
  FALSE,
  0x00000fff,
  0x00000fff,
  FALSE),
  HOWTO2 (R_NDS32_LO12S2_DP_RELA,
  2,
  2,
  10,
  FALSE,
  0,
  complain_overflow_dont,
  bfd_elf_generic_reloc,
  "R_NDS32_LO12S2_DP_RELA",
  FALSE,
  0x000003ff,
  0x000003ff,
  FALSE),
  HOWTO2 (R_NDS32_LO12S2_SP_RELA,
  2,
  2,
  10,
  FALSE,
  0,
  complain_overflow_dont,
  bfd_elf_generic_reloc,
  "R_NDS32_LO12S2_SP_RELA",
  FALSE,
  0x000003ff,
  0x000003ff,
  FALSE),
  HOWTO2 (R_NDS32_LO12S0_ORI_RELA,
  0,
  2,
  12,
  FALSE,
  0,
  complain_overflow_dont,
  bfd_elf_generic_reloc,
  "R_NDS32_LO12S0_ORI_RELA",
  FALSE,
  0x00000fff,
  0x00000fff,
  FALSE),
  HOWTO2 (R_NDS32_SDA16S3_RELA,
  3,
  2,
  16,
  FALSE,
  0,
  complain_overflow_signed,
  bfd_elf_generic_reloc,
  "R_NDS32_SDA16S3_RELA",
  FALSE,
  0x0000ffff,
  0x0000ffff,
  FALSE),
  HOWTO2 (R_NDS32_SDA17S2_RELA,
  2,
  2,
  17,
  FALSE,
  0,
  complain_overflow_signed,
  bfd_elf_generic_reloc,
  "R_NDS32_SDA17S2_RELA",
  FALSE,
  0x0001ffff,
  0x0001ffff,
  FALSE),
  HOWTO2 (R_NDS32_SDA18S1_RELA,
  1,
  2,
  18,
  FALSE,
  0,
  complain_overflow_signed,
  bfd_elf_generic_reloc,
  "R_NDS32_SDA18S1_RELA",
  FALSE,
  0x0003ffff,
  0x0003ffff,
  FALSE),
  HOWTO2 (R_NDS32_SDA19S0_RELA,
  0,
  2,
  19,
  FALSE,
  0,
  complain_overflow_signed,
  bfd_elf_generic_reloc,
  "R_NDS32_SDA19S0_RELA",
  FALSE,
  0x0007ffff,
  0x0007ffff,
  FALSE),
  HOWTO2 (R_NDS32_DWARF2_OP1_RELA,
  0,
  0,
  8,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_DWARF2_OP1_RELA",
  FALSE,
  0xff,
  0xff,
  FALSE),
  HOWTO2 (R_NDS32_DWARF2_OP2_RELA,
  0,
  1,
  16,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_DWARF2_OP2_RELA",
  FALSE,
  0xffff,
  0xffff,
  FALSE),
  HOWTO2 (R_NDS32_DWARF2_LEB_RELA,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_DWARF2_LEB_RELA",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO2 (R_NDS32_UPDATE_TA_RELA,
  0,
  1,
  16,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_UPDATE_TA_RELA",
  FALSE,
  0xffff,
  0xffff,
  FALSE),
  HOWTO2 (R_NDS32_9_PLTREL,
  1,
  1,
  8,
  TRUE,
  0,
  complain_overflow_signed,
  bfd_elf_generic_reloc,
  "R_NDS32_9_PLTREL",
  FALSE,
  0xff,
  0xff,
  TRUE),
  HOWTO2 (R_NDS32_PLT_GOTREL_LO20,
  0,
  2,
  20,
  FALSE,
  0,
  complain_overflow_dont,
  bfd_elf_generic_reloc,
  "R_NDS32_PLT_GOTREL_LO20",
  FALSE,
  0x000fffff,
  0x000fffff,
  FALSE),
  HOWTO2 (R_NDS32_PLT_GOTREL_LO15,
  0,
  2,
  15,
  FALSE,
  0,
  complain_overflow_dont,
  bfd_elf_generic_reloc,
  "R_NDS32_PLT_GOTREL_LO15",
  FALSE,
  0x00007fff,
  0x00007fff,
  FALSE),
  HOWTO2 (R_NDS32_PLT_GOTREL_LO19,
  0,
  2,
  19,
  FALSE,
  0,
  complain_overflow_dont,
  bfd_elf_generic_reloc,
  "R_NDS32_PLT_GOTREL_LO19",
  FALSE,
  0x0007ffff,
  0x0007ffff,
  FALSE),
  HOWTO2 (R_NDS32_GOT_LO15,
  0,
  2,
  15,
  FALSE,
  0,
  complain_overflow_dont,
  bfd_elf_generic_reloc,
  "R_NDS32_GOT_LO15",
  FALSE,
  0x00007fff,
  0x00007fff,
  FALSE),
  HOWTO2 (R_NDS32_GOT_LO19,
  0,
  2,
  19,
  FALSE,
  0,
  complain_overflow_dont,
  bfd_elf_generic_reloc,
  "R_NDS32_GOT_LO19",
  FALSE,
  0x0007ffff,
  0x0007ffff,
  FALSE),
  HOWTO2 (R_NDS32_GOTOFF_LO15,
  0,
  2,
  15,
  FALSE,
  0,
  complain_overflow_dont,
  bfd_elf_generic_reloc,
  "R_NDS32_GOTOFF_LO15",
  FALSE,
  0x00007fff,
  0x00007fff,
  FALSE),
  HOWTO2 (R_NDS32_GOTOFF_LO19,
  0,
  2,
  19,
  FALSE,
  0,
  complain_overflow_dont,
  bfd_elf_generic_reloc,
  "R_NDS32_GOTOFF_LO19",
  FALSE,
  0x0007ffff,
  0x0007ffff,
  FALSE),
  HOWTO2 (R_NDS32_GOT15S2_RELA,
  2,
  2,
  15,
  FALSE,
  0,
  complain_overflow_signed,
  bfd_elf_generic_reloc,
  "R_NDS32_GOT15S2_RELA",
  FALSE,
  0x00007fff,
  0x00007fff,
  FALSE),
  HOWTO2 (R_NDS32_GOT17S2_RELA,
  2,
  2,
  17,
  FALSE,
  0,
  complain_overflow_signed,
  bfd_elf_generic_reloc,
  "R_NDS32_GOT17S2_RELA",
  FALSE,
  0x0001ffff,
  0x0001ffff,
  FALSE),
  HOWTO2 (R_NDS32_5_RELA,
  0,
  1,
  5,
  FALSE,
  0,
  complain_overflow_signed,
  bfd_elf_generic_reloc,
  "R_NDS32_5_RELA",
  FALSE,
  0x1f,
  0x1f,
  FALSE),
  HOWTO2 (R_NDS32_10_UPCREL_RELA,
  1,
  1,
  9,
  TRUE,
  0,
  complain_overflow_unsigned,
  bfd_elf_generic_reloc,
  "R_NDS32_10_UPCREL_RELA",
  FALSE,
  0x1ff,
  0x1ff,
  TRUE),
  HOWTO2 (R_NDS32_SDA_FP7U2_RELA,
  2,
  1,
  7,
  FALSE,
  0,
  complain_overflow_unsigned,
  bfd_elf_generic_reloc,
  "R_NDS32_SDA_FP7U2_RELA",
  FALSE,
  0x0000007f,
  0x0000007f,
  FALSE),
  HOWTO2 (R_NDS32_WORD_9_PCREL_RELA,
  1,
  2,
  8,
  TRUE,
  0,
  complain_overflow_signed,
  bfd_elf_generic_reloc,
  "R_NDS32_WORD_9_PCREL_RELA",
  FALSE,
  0xff,
  0xff,
  TRUE),
  HOWTO2 (R_NDS32_25_ABS_RELA,
  1,
  2,
  24,
  FALSE,
  0,
  complain_overflow_dont,
  bfd_elf_generic_reloc,
  "R_NDS32_25_ABS_RELA",
  FALSE,
  0xffffff,
  0xffffff,
  FALSE),
  HOWTO2 (R_NDS32_17IFC_PCREL_RELA,
  1,
  2,
  16,
  TRUE,
  0,
  complain_overflow_signed,
  bfd_elf_generic_reloc,
  "R_NDS32_17IFC_PCREL_RELA",
  FALSE,
  0xffff,
  0xffff,
  TRUE),
  HOWTO2 (R_NDS32_10IFCU_PCREL_RELA,
  1,
  1,
  9,
  TRUE,
  0,
  complain_overflow_unsigned,
  bfd_elf_generic_reloc,
  "R_NDS32_10IFCU_PCREL_RELA",
  FALSE,
  0x1ff,
  0x1ff,
  TRUE),
  HOWTO2 (R_NDS32_LONGCALL4,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_LONGCALL4",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO2 (R_NDS32_LONGCALL5,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_LONGCALL5",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO2 (R_NDS32_LONGCALL6,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_LONGCALL6",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO2 (R_NDS32_LONGJUMP4,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_LONGJUMP4",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO2 (R_NDS32_LONGJUMP5,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_LONGJUMP5",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO2 (R_NDS32_LONGJUMP6,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_LONGJUMP6",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO2 (R_NDS32_LONGJUMP7,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_LONGJUMP7",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO2 (R_NDS32_SECURITY_16,
  0,
  2,
  16,
  FALSE,
  5,
  complain_overflow_dont,
  bfd_elf_generic_reloc,
  "R_NDS32_SECURITY_16",
  FALSE,
  0x1fffe0,
  0x1fffe0,
  TRUE),
  HOWTO2 (R_NDS32_TLS_TPOFF,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_bitfield,
  bfd_elf_generic_reloc,
  "R_NDS32_TLS_TPOFF",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO2 (R_NDS32_TLS_LE_HI20,
  12,
  2,
  20,
  FALSE,
  0,
  complain_overflow_dont,
  bfd_elf_generic_reloc,
  "R_NDS32_TLS_LE_HI20",
  FALSE,
  0x000fffff,
  0x000fffff,
  FALSE),
  HOWTO2 (R_NDS32_TLS_LE_LO12,
  0,
  2,
  12,
  FALSE,
  0,
  complain_overflow_dont,
  bfd_elf_generic_reloc,
  "R_NDS32_TLS_LE_LO12",
  FALSE,
  0x00000fff,
  0x00000fff,
  FALSE),
  HOWTO2 (R_NDS32_TLS_LE_20,
  0,
  2,
  20,
  FALSE,
  0,
  complain_overflow_signed,
  bfd_elf_generic_reloc,
  "R_NDS32_TLS_LE_20",
  FALSE,
  0xfffff,
  0xfffff,
  FALSE),
  HOWTO2 (R_NDS32_TLS_LE_15S0,
  0,
  2,
  15,
  FALSE,
  0,
  complain_overflow_signed,
  bfd_elf_generic_reloc,
  "R_NDS32_TLS_LE_15S0",
  FALSE,
  0x7fff,
  0x7fff,
  FALSE),
  HOWTO2 (R_NDS32_TLS_LE_15S1,
  1,
  2,
  15,
  FALSE,
  0,
  complain_overflow_signed,
  bfd_elf_generic_reloc,
  "R_NDS32_TLS_LE_15S1",
  FALSE,
  0x7fff,
  0x7fff,
  FALSE),
  HOWTO2 (R_NDS32_TLS_LE_15S2,
  2,
  2,
  15,
  FALSE,
  0,
  complain_overflow_signed,
  bfd_elf_generic_reloc,
  "R_NDS32_TLS_LE_15S2",
  FALSE,
  0x7fff,
  0x7fff,
  FALSE),
  HOWTO2 (R_NDS32_TLS_IE_HI20,
  12,
  2,
  20,
  FALSE,
  0,
  complain_overflow_dont,
  bfd_elf_generic_reloc,
  "R_NDS32_TLS_IE_HI20",
  FALSE,
  0x000fffff,
  0x000fffff,
  FALSE),
  HOWTO2 (R_NDS32_TLS_IE_LO12,
  0,
  2,
  12,
  FALSE,
  0,
  complain_overflow_dont,
  bfd_elf_generic_reloc,
  "R_NDS32_TLS_IE_LO12",
  FALSE,
  0x00000fff,
  0x00000fff,
  FALSE),
  HOWTO2 (R_NDS32_TLS_IE_LO12S2,
  2,
  2,
  10,
  FALSE,
  0,
  complain_overflow_dont,
  bfd_elf_generic_reloc,
  "R_NDS32_TLS_IE_LO12S2",
  FALSE,
  0x000003ff,
  0x000003ff,
  FALSE),
  HOWTO2 (R_NDS32_TLS_IEGP_HI20,
  12,
  2,
  20,
  FALSE,
  0,
  complain_overflow_dont,
  bfd_elf_generic_reloc,
  "R_NDS32_TLS_IEGP_HI20",
  FALSE,
  0x000fffff,
  0x000fffff,
  FALSE),
  HOWTO2 (R_NDS32_TLS_IEGP_LO12,
  0,
  2,
  12,
  FALSE,
  0,
  complain_overflow_dont,
  bfd_elf_generic_reloc,
  "R_NDS32_TLS_IEGP_LO12",
  FALSE,
  0x00000fff,
  0x00000fff,
  FALSE),
  HOWTO2 (R_NDS32_TLS_IEGP_LO12S2,
  2,
  2,
  10,
  FALSE,
  0,
  complain_overflow_dont,
  bfd_elf_generic_reloc,
  "R_NDS32_TLS_IEGP_LO12S2",
  FALSE,
  0x000003ff,
  0x000003ff,
  FALSE),
  HOWTO2 (R_NDS32_TLS_DESC,
  12,
  2,
  20,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_hi20_reloc,
  "R_NDS32_TLS_DESC_HI20",
  FALSE,
  0x000fffff,
  0x000fffff,
  FALSE),
  HOWTO2 (R_NDS32_TLS_DESC_HI20,
  12,
  2,
  20,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_hi20_reloc,
  "R_NDS32_TLS_DESC_HI20",
  FALSE,
  0x000fffff,
  0x000fffff,
  FALSE),
  HOWTO2 (R_NDS32_TLS_DESC_LO12,
  0,
  2,
  12,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_lo12_reloc,
  "R_NDS32_TLS_DESC_LO12",
  FALSE,
  0x00000fff,
  0x00000fff,
  FALSE),
  HOWTO2 (R_NDS32_TLS_DESC_20,
  0,
  2,
  20,
  FALSE,
  0,
  complain_overflow_signed,
  bfd_elf_generic_reloc,
  "R_NDS32_TLS_DESC_20",
  FALSE,
  0x000fffff,
  0x000fffff,
  FALSE),
  HOWTO2 (R_NDS32_TLS_DESC_SDA17S2,
  2,
  2,
  17,
  FALSE,
  0,
  complain_overflow_signed,
  bfd_elf_generic_reloc,
  "R_NDS32_TLS_DESC_SDA17S2",
  FALSE,
  0x0001ffff,
  0x0001ffff,
  FALSE),
  HOWTO2 (R_NDS32_ICT_HI20,
  12,
  2,
  20,
  FALSE,
  0,
  complain_overflow_dont,
  bfd_elf_generic_reloc,
  "R_NDS32_ICT_HI20",
  FALSE,
  0x000fffff,
  0x000fffff,
  FALSE),
  HOWTO2 (R_NDS32_ICT_LO12,
  0,
  2,
  12,
  FALSE,
  0,
  complain_overflow_dont,
  bfd_elf_generic_reloc,
  "R_NDS32_ICT_LO12",
  FALSE,
  0x00000fff,
  0x00000fff,
  FALSE),
  HOWTO2 (R_NDS32_ICT_LO12S2,
   2,
   2,
   10,
   FALSE,
   0,
   complain_overflow_dont,
   bfd_elf_generic_reloc,
   "R_NDS32_ICT_LO12S2",
   FALSE,
   0x000003ff,
   0x000003ff,
   FALSE),
  HOWTO2 (R_NDS32_ICT_25PC,
  1,
  2,
  24,
  TRUE,
  0,
  complain_overflow_signed,
  bfd_elf_generic_reloc,
  "R_NDS32_ICT_25PC",
  FALSE,
  0xffffff,
  0xffffff,
  TRUE),
};
#define HOWTO3(C,R,S,B,P,BI,O,SF,NAME,INPLACE,MASKSRC,MASKDST,PC) \
  [C-R_NDS32_RELAX_ENTRY] = HOWTO(C, R, S, B, P, BI, O, SF, NAME, INPLACE, MASKSRC, MASKDST, PC)
static reloc_howto_type nds32_elf_relax_howto_table[] = {
  HOWTO3 (R_NDS32_RELAX_ENTRY,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_RELAX_ENTRY",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO3 (R_NDS32_GOT_SUFF,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_GOT_SUFF",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO3 (R_NDS32_GOTOFF_SUFF,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_bitfield,
  nds32_elf_ignore_reloc,
  "R_NDS32_GOTOFF_SUFF",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO3 (R_NDS32_PLT_GOT_SUFF,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_PLT_GOT_SUFF",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO3 (R_NDS32_MULCALL_SUFF,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_MULCALL_SUFF",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO3 (R_NDS32_PTR,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_PTR",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO3 (R_NDS32_PTR_COUNT,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_PTR_COUNT",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO3 (R_NDS32_PTR_RESOLVED,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_PTR_RESOLVED",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO3 (R_NDS32_PLTBLOCK,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_PLTBLOCK",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO3 (R_NDS32_RELAX_REGION_BEGIN,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_RELAX_REGION_BEGIN",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO3 (R_NDS32_RELAX_REGION_END,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_RELAX_REGION_END",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO3 (R_NDS32_MINUEND,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_MINUEND",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO3 (R_NDS32_SUBTRAHEND,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_SUBTRAHEND",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO3 (R_NDS32_DIFF8,
  0,
  0,
  8,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_DIFF8",
  FALSE,
  0x000000ff,
  0x000000ff,
  FALSE),
  HOWTO3 (R_NDS32_DIFF16,
  0,
  1,
  16,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_DIFF16",
  FALSE,
  0x0000ffff,
  0x0000ffff,
  FALSE),
  HOWTO3 (R_NDS32_DIFF32,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_DIFF32",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO3 (R_NDS32_DIFF_ULEB128,
  0,
  0,
  0,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_DIFF_ULEB128",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO3 (R_NDS32_DATA,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_DATA",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO3 (R_NDS32_TRAN,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_TRAN",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO3 (R_NDS32_EMPTY,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_EMPTY",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO3 (R_NDS32_TLS_LE_ADD,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_TLS_LE_ADD",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO3 (R_NDS32_TLS_LE_LS,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_TLS_LE_LS",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO3 (R_NDS32_TLS_IEGP_LW,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_TLS_IEGP_LW",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO3 (R_NDS32_TLS_DESC_ADD,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_TLS_DESC_ADD",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO3 (R_NDS32_TLS_DESC_FUNC,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_TLS_DESC_FUNC",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO3 (R_NDS32_TLS_DESC_CALL,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_TLS_DESC_CALL",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO3 (R_NDS32_TLS_DESC_MEM,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_TLS_DESC_MEM",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO3 (R_NDS32_RELAX_REMOVE,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_REMOVE",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO3 (R_NDS32_RELAX_GROUP,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_GROUP",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
  HOWTO3 (R_NDS32_LSI,
  0,
  2,
  32,
  FALSE,
  0,
  complain_overflow_dont,
  nds32_elf_ignore_reloc,
  "R_NDS32_LSI",
  FALSE,
  0xffffffff,
  0xffffffff,
  FALSE),
};
static unsigned long dl_tlsdesc_lazy_trampoline[] =
{
  0x46200000,
  0x58210000,
  0x40217400,
  0x04210000,
  0x46300000,
  0x58318000,
  0x4031f400,
  0x4a000800,
};
static void
nds32_put_trampoline (void *contents, const unsigned long *template,
        unsigned count)
{
  unsigned ix;
  for (ix = 0; ix != count; ix++)
    {
      unsigned long insn = template[ix];
      bfd_putb32 (insn, (char *) contents + ix * 4);
    }
}
void
nds32_insertion_sort (void *base, size_t nmemb, size_t size,
        int (*compar) (const void *lhs, const void *rhs))
{
  char *ptr = (char *) base;
  int i, j;
  char *tmp = alloca (size);
  for (i = 1; i < (int) nmemb; i++)
    {
      for (j = (i - 1); j >= 0; j--)
 if (compar (ptr + i * size, ptr + j * size) >= 0)
   break;
      j++;
      if (i == j)
 continue;
      memcpy (tmp, ptr + i * size, size);
      memmove (ptr + (j + 1) * size, ptr + j * size, (i - j) * size);
      memcpy (ptr + j * size, tmp, size);
    }
}
static int
compar_reloc (const void *lhs, const void *rhs)
{
  const Elf_Internal_Rela *l = (const Elf_Internal_Rela *) lhs;
  const Elf_Internal_Rela *r = (const Elf_Internal_Rela *) rhs;
  if (l->r_offset > r->r_offset)
    return 1;
  else if (l->r_offset == r->r_offset)
    return 0;
  else
    return -1;
}
static bfd_reloc_status_type
nds32_elf_9_pcrel_reloc (bfd *abfd, arelent *reloc_entry, asymbol *symbol,
    void *data, asection *input_section, bfd *output_bfd,
    char **error_message ATTRIBUTE_UNUSED)
{
  if (output_bfd != (bfd *) NULL
      && (symbol->flags & BSF_SECTION_SYM) == 0
      && (!reloc_entry->howto->partial_inplace || reloc_entry->addend == 0))
    {
      reloc_entry->address += input_section->output_offset;
      return bfd_reloc_ok;
    }
  if (output_bfd != NULL)
    {
      return bfd_reloc_continue;
    }
  return nds32_elf_do_9_pcrel_reloc (abfd, reloc_entry->howto,
         input_section,
         data, reloc_entry->address,
         symbol->section,
         (symbol->value
          + symbol->section->output_section->vma
          + symbol->section->output_offset),
         reloc_entry->addend);
}
#define N_ONES(n) (((((bfd_vma) 1 << ((n) - 1)) - 1) << 1) | 1)
static bfd_reloc_status_type
nds32_elf_do_9_pcrel_reloc (bfd *abfd, reloc_howto_type *howto,
       asection *input_section, bfd_byte *data,
       bfd_vma offset,
       asection *symbol_section ATTRIBUTE_UNUSED,
       bfd_vma symbol_value, bfd_vma addend)
{
  bfd_signed_vma relocation;
  unsigned short x;
  bfd_reloc_status_type status;
  if (offset > bfd_get_section_limit (abfd, input_section))
    return bfd_reloc_outofrange;
  relocation = symbol_value + addend;
  relocation -= (input_section->output_section->vma
   + input_section->output_offset);
  relocation -= (offset & -(bfd_vma) 2);
  if (relocation < -ACCURATE_8BIT_S1 || relocation >= ACCURATE_8BIT_S1)
    status = bfd_reloc_overflow;
  else
    status = bfd_reloc_ok;
  x = bfd_getb16 (data + offset);
  relocation >>= howto->rightshift;
  relocation <<= howto->bitpos;
  x = (x & ~howto->dst_mask)
      | (((x & howto->src_mask) + relocation) & howto->dst_mask);
  bfd_putb16 ((bfd_vma) x, data + offset);
  return status;
}
struct nds32_hi20
{
  struct nds32_hi20 *next;
  bfd_byte *addr;
  bfd_vma addend;
};
static struct nds32_hi20 *nds32_hi20_list;
static bfd_reloc_status_type
nds32_elf_hi20_reloc (bfd *abfd ATTRIBUTE_UNUSED, arelent *reloc_entry,
        asymbol *symbol, void *data, asection *input_section,
        bfd *output_bfd, char **error_message ATTRIBUTE_UNUSED)
{
  bfd_reloc_status_type ret;
  bfd_vma relocation;
  struct nds32_hi20 *n;
  if (output_bfd != (bfd *) NULL
      && (symbol->flags & BSF_SECTION_SYM) == 0 && reloc_entry->addend == 0)
    {
      reloc_entry->address += input_section->output_offset;
      return bfd_reloc_ok;
    }
  if (reloc_entry->address > bfd_get_section_limit (abfd, input_section))
    return bfd_reloc_outofrange;
  ret = bfd_reloc_ok;
  if (bfd_is_und_section (symbol->section) && output_bfd == (bfd *) NULL)
    ret = bfd_reloc_undefined;
  if (bfd_is_com_section (symbol->section))
    relocation = 0;
  else
    relocation = symbol->value;
  relocation += symbol->section->output_section->vma;
  relocation += symbol->section->output_offset;
  relocation += reloc_entry->addend;
  n = (struct nds32_hi20 *) bfd_malloc ((bfd_size_type) sizeof *n);
  if (n == NULL)
    return bfd_reloc_outofrange;
  n->addr = (bfd_byte *) data + reloc_entry->address;
  n->addend = relocation;
  n->next = nds32_hi20_list;
  nds32_hi20_list = n;
  if (output_bfd != (bfd *) NULL)
    reloc_entry->address += input_section->output_offset;
  return ret;
}
static void
nds32_elf_relocate_hi20 (bfd *input_bfd ATTRIBUTE_UNUSED,
    int type ATTRIBUTE_UNUSED, Elf_Internal_Rela *relhi,
    Elf_Internal_Rela *rello, bfd_byte *contents,
    bfd_vma addend)
{
  unsigned long insn;
  bfd_vma addlo;
  insn = bfd_getb32 (contents + relhi->r_offset);
  addlo = bfd_getb32 (contents + rello->r_offset);
  addlo &= 0xfff;
  addend += ((insn & 0xfffff) << 20) + addlo;
  insn = (insn & 0xfff00000) | ((addend >> 12) & 0xfffff);
  bfd_putb32 (insn, contents + relhi->r_offset);
}
static bfd_reloc_status_type
nds32_elf_lo12_reloc (bfd *input_bfd, arelent *reloc_entry, asymbol *symbol,
        void *data, asection *input_section, bfd *output_bfd,
        char **error_message)
{
  if (output_bfd != NULL && (symbol->flags & BSF_SECTION_SYM) == 0
      && reloc_entry->addend == 0)
    {
      reloc_entry->address += input_section->output_offset;
      return bfd_reloc_ok;
    }
  if (nds32_hi20_list != NULL)
    {
      struct nds32_hi20 *l;
      l = nds32_hi20_list;
      while (l != NULL)
 {
   unsigned long insn;
   unsigned long val;
   unsigned long vallo;
   struct nds32_hi20 *next;
   insn = bfd_getb32 (l->addr);
   vallo = bfd_getb32 ((bfd_byte *) data + reloc_entry->address);
   vallo &= 0xfff;
   switch (reloc_entry->howto->type)
     {
     case R_NDS32_LO12S3:
       vallo <<= 3;
       break;
     case R_NDS32_LO12S2:
       vallo <<= 2;
       break;
     case R_NDS32_LO12S1:
       vallo <<= 1;
       break;
     case R_NDS32_LO12S0:
       vallo <<= 0;
       break;
     }
   val = ((insn & 0xfffff) << 12) + vallo;
   val += l->addend;
   insn = (insn & ~(bfd_vma) 0xfffff) | ((val >> 12) & 0xfffff);
   bfd_putb32 ((bfd_vma) insn, l->addr);
   next = l->next;
   free (l);
   l = next;
 }
      nds32_hi20_list = NULL;
    }
  return nds32_elf_generic_reloc (input_bfd, reloc_entry, symbol, data,
      input_section, output_bfd, error_message);
}
static bfd_reloc_status_type
nds32_elf_generic_reloc (bfd *input_bfd, arelent *reloc_entry,
    asymbol *symbol, void *data, asection *input_section,
    bfd *output_bfd, char **error_message ATTRIBUTE_UNUSED)
{
  bfd_reloc_status_type ret;
  bfd_vma relocation;
  bfd_byte *inplace_address;
  if (output_bfd != NULL && (symbol->flags & BSF_SECTION_SYM) == 0
      && reloc_entry->addend == 0)
    {
      reloc_entry->address += input_section->output_offset;
      return bfd_reloc_ok;
    }
  if (reloc_entry->address > bfd_get_section_limit (input_bfd, input_section))
    return bfd_reloc_outofrange;
  ret = bfd_reloc_ok;
  if (bfd_is_und_section (symbol->section) && output_bfd == (bfd *) NULL)
    ret = bfd_reloc_undefined;
  if (bfd_is_com_section (symbol->section) || output_bfd != (bfd *) NULL)
    relocation = 0;
  else
    relocation = symbol->value;
  if (output_bfd == (bfd *) NULL)
    {
      relocation += symbol->section->output_section->vma;
      relocation += symbol->section->output_offset;
    }
  relocation += reloc_entry->addend;
  switch (reloc_entry->howto->type)
    {
    case R_NDS32_LO12S3:
      relocation >>= 3;
      break;
    case R_NDS32_LO12S2:
      relocation >>= 2;
      break;
    case R_NDS32_LO12S1:
      relocation >>= 1;
      break;
    case R_NDS32_LO12S0:
    default:
      relocation >>= 0;
      break;
    }
  inplace_address = (bfd_byte *) data + reloc_entry->address;
#define DOIT(x) \
  x = ((x & ~reloc_entry->howto->dst_mask) | \
  (((x & reloc_entry->howto->src_mask) + relocation) & \
  reloc_entry->howto->dst_mask))
  switch (reloc_entry->howto->size)
    {
    case 1:
      {
 short x = bfd_getb16 (inplace_address);
 DOIT (x);
 bfd_putb16 ((bfd_vma) x, inplace_address);
      }
      break;
    case 2:
      {
 unsigned long x = bfd_getb32 (inplace_address);
 DOIT (x);
 bfd_putb32 ((bfd_vma) x, inplace_address);
      }
      break;
    default:
      BFD_ASSERT (0);
    }
  if (output_bfd != (bfd *) NULL)
    reloc_entry->address += input_section->output_offset;
  return ret;
}
static bfd_reloc_status_type
nds32_elf_sda15_reloc (bfd *abfd ATTRIBUTE_UNUSED, arelent *reloc_entry,
         asymbol *symbol, void *data ATTRIBUTE_UNUSED,
         asection *input_section, bfd *output_bfd,
         char **error_message ATTRIBUTE_UNUSED)
{
  if (output_bfd != (bfd *) NULL
      && (symbol->flags & BSF_SECTION_SYM) == 0
      && (!reloc_entry->howto->partial_inplace || reloc_entry->addend == 0))
    {
      reloc_entry->address += input_section->output_offset;
      return bfd_reloc_ok;
    }
  if (output_bfd != NULL)
    {
      return bfd_reloc_continue;
    }
  abort ();
}
static bfd_reloc_status_type
nds32_elf_ignore_reloc (bfd *abfd ATTRIBUTE_UNUSED, arelent *reloc_entry,
   asymbol *symbol ATTRIBUTE_UNUSED,
   void *data ATTRIBUTE_UNUSED, asection *input_section,
   bfd *output_bfd, char **error_message ATTRIBUTE_UNUSED)
{
  if (output_bfd != NULL)
    reloc_entry->address += input_section->output_offset;
  return bfd_reloc_ok;
}
struct nds32_reloc_map_entry
{
  bfd_reloc_code_real_type bfd_reloc_val;
  unsigned char elf_reloc_val;
};
static const struct nds32_reloc_map_entry nds32_reloc_map[] = {
  {BFD_RELOC_NONE, R_NDS32_NONE},
  {BFD_RELOC_16, R_NDS32_16_RELA},
  {BFD_RELOC_32, R_NDS32_32_RELA},
  {BFD_RELOC_NDS32_20, R_NDS32_20_RELA},
  {BFD_RELOC_NDS32_5, R_NDS32_5_RELA},
  {BFD_RELOC_NDS32_9_PCREL, R_NDS32_9_PCREL_RELA},
  {BFD_RELOC_NDS32_WORD_9_PCREL, R_NDS32_WORD_9_PCREL_RELA},
  {BFD_RELOC_NDS32_15_PCREL, R_NDS32_15_PCREL_RELA},
  {BFD_RELOC_NDS32_17_PCREL, R_NDS32_17_PCREL_RELA},
  {BFD_RELOC_NDS32_25_PCREL, R_NDS32_25_PCREL_RELA},
  {BFD_RELOC_NDS32_10_UPCREL, R_NDS32_10_UPCREL_RELA},
  {BFD_RELOC_NDS32_HI20, R_NDS32_HI20_RELA},
  {BFD_RELOC_NDS32_LO12S3, R_NDS32_LO12S3_RELA},
  {BFD_RELOC_NDS32_LO12S2, R_NDS32_LO12S2_RELA},
  {BFD_RELOC_NDS32_LO12S1, R_NDS32_LO12S1_RELA},
  {BFD_RELOC_NDS32_LO12S0, R_NDS32_LO12S0_RELA},
  {BFD_RELOC_NDS32_LO12S0_ORI, R_NDS32_LO12S0_ORI_RELA},
  {BFD_RELOC_NDS32_SDA15S3, R_NDS32_SDA15S3_RELA},
  {BFD_RELOC_NDS32_SDA15S2, R_NDS32_SDA15S2_RELA},
  {BFD_RELOC_NDS32_SDA15S1, R_NDS32_SDA15S1_RELA},
  {BFD_RELOC_NDS32_SDA15S0, R_NDS32_SDA15S0_RELA},
  {BFD_RELOC_VTABLE_INHERIT, R_NDS32_RELA_GNU_VTINHERIT},
  {BFD_RELOC_VTABLE_ENTRY, R_NDS32_RELA_GNU_VTENTRY},
  {BFD_RELOC_NDS32_GOT20, R_NDS32_GOT20},
  {BFD_RELOC_NDS32_9_PLTREL, R_NDS32_9_PLTREL},
  {BFD_RELOC_NDS32_25_PLTREL, R_NDS32_25_PLTREL},
  {BFD_RELOC_NDS32_COPY, R_NDS32_COPY},
  {BFD_RELOC_NDS32_GLOB_DAT, R_NDS32_GLOB_DAT},
  {BFD_RELOC_NDS32_JMP_SLOT, R_NDS32_JMP_SLOT},
  {BFD_RELOC_NDS32_RELATIVE, R_NDS32_RELATIVE},
  {BFD_RELOC_NDS32_GOTOFF, R_NDS32_GOTOFF},
  {BFD_RELOC_NDS32_GOTPC20, R_NDS32_GOTPC20},
  {BFD_RELOC_NDS32_GOT_HI20, R_NDS32_GOT_HI20},
  {BFD_RELOC_NDS32_GOT_LO12, R_NDS32_GOT_LO12},
  {BFD_RELOC_NDS32_GOT_LO15, R_NDS32_GOT_LO15},
  {BFD_RELOC_NDS32_GOT_LO19, R_NDS32_GOT_LO19},
  {BFD_RELOC_NDS32_GOTPC_HI20, R_NDS32_GOTPC_HI20},
  {BFD_RELOC_NDS32_GOTPC_LO12, R_NDS32_GOTPC_LO12},
  {BFD_RELOC_NDS32_GOTOFF_HI20, R_NDS32_GOTOFF_HI20},
  {BFD_RELOC_NDS32_GOTOFF_LO12, R_NDS32_GOTOFF_LO12},
  {BFD_RELOC_NDS32_GOTOFF_LO15, R_NDS32_GOTOFF_LO15},
  {BFD_RELOC_NDS32_GOTOFF_LO19, R_NDS32_GOTOFF_LO19},
  {BFD_RELOC_NDS32_INSN16, R_NDS32_INSN16},
  {BFD_RELOC_NDS32_LABEL, R_NDS32_LABEL},
  {BFD_RELOC_NDS32_LONGCALL1, R_NDS32_LONGCALL1},
  {BFD_RELOC_NDS32_LONGCALL2, R_NDS32_LONGCALL2},
  {BFD_RELOC_NDS32_LONGCALL3, R_NDS32_LONGCALL3},
  {BFD_RELOC_NDS32_LONGCALL4, R_NDS32_LONGCALL4},
  {BFD_RELOC_NDS32_LONGCALL5, R_NDS32_LONGCALL5},
  {BFD_RELOC_NDS32_LONGCALL6, R_NDS32_LONGCALL6},
  {BFD_RELOC_NDS32_LONGJUMP1, R_NDS32_LONGJUMP1},
  {BFD_RELOC_NDS32_LONGJUMP2, R_NDS32_LONGJUMP2},
  {BFD_RELOC_NDS32_LONGJUMP3, R_NDS32_LONGJUMP3},
  {BFD_RELOC_NDS32_LONGJUMP4, R_NDS32_LONGJUMP4},
  {BFD_RELOC_NDS32_LONGJUMP5, R_NDS32_LONGJUMP5},
  {BFD_RELOC_NDS32_LONGJUMP6, R_NDS32_LONGJUMP6},
  {BFD_RELOC_NDS32_LONGJUMP7, R_NDS32_LONGJUMP7},
  {BFD_RELOC_NDS32_SECURITY_16, R_NDS32_SECURITY_16},
  {BFD_RELOC_NDS32_LOADSTORE, R_NDS32_LOADSTORE},
  {BFD_RELOC_NDS32_9_FIXED, R_NDS32_9_FIXED_RELA},
  {BFD_RELOC_NDS32_15_FIXED, R_NDS32_15_FIXED_RELA},
  {BFD_RELOC_NDS32_17_FIXED, R_NDS32_17_FIXED_RELA},
  {BFD_RELOC_NDS32_25_FIXED, R_NDS32_25_FIXED_RELA},
  {BFD_RELOC_NDS32_PLTREL_HI20, R_NDS32_PLTREL_HI20},
  {BFD_RELOC_NDS32_PLTREL_LO12, R_NDS32_PLTREL_LO12},
  {BFD_RELOC_NDS32_PLT_GOTREL_HI20, R_NDS32_PLT_GOTREL_HI20},
  {BFD_RELOC_NDS32_PLT_GOTREL_LO12, R_NDS32_PLT_GOTREL_LO12},
  {BFD_RELOC_NDS32_PLT_GOTREL_LO15, R_NDS32_PLT_GOTREL_LO15},
  {BFD_RELOC_NDS32_PLT_GOTREL_LO19, R_NDS32_PLT_GOTREL_LO19},
  {BFD_RELOC_NDS32_PLT_GOTREL_LO20, R_NDS32_PLT_GOTREL_LO20},
  {BFD_RELOC_NDS32_SDA12S2_DP, R_NDS32_SDA12S2_DP_RELA},
  {BFD_RELOC_NDS32_SDA12S2_SP, R_NDS32_SDA12S2_SP_RELA},
  {BFD_RELOC_NDS32_LO12S2_DP, R_NDS32_LO12S2_DP_RELA},
  {BFD_RELOC_NDS32_LO12S2_SP, R_NDS32_LO12S2_SP_RELA},
  {BFD_RELOC_NDS32_SDA16S3, R_NDS32_SDA16S3_RELA},
  {BFD_RELOC_NDS32_SDA17S2, R_NDS32_SDA17S2_RELA},
  {BFD_RELOC_NDS32_SDA18S1, R_NDS32_SDA18S1_RELA},
  {BFD_RELOC_NDS32_SDA19S0, R_NDS32_SDA19S0_RELA},
  {BFD_RELOC_NDS32_SDA_FP7U2_RELA, R_NDS32_SDA_FP7U2_RELA},
  {BFD_RELOC_NDS32_DWARF2_OP1, R_NDS32_DWARF2_OP1_RELA},
  {BFD_RELOC_NDS32_DWARF2_OP2, R_NDS32_DWARF2_OP2_RELA},
  {BFD_RELOC_NDS32_DWARF2_LEB, R_NDS32_DWARF2_LEB_RELA},
  {BFD_RELOC_NDS32_UPDATE_TA, R_NDS32_UPDATE_TA_RELA},
  {BFD_RELOC_NDS32_GOT_SUFF, R_NDS32_GOT_SUFF},
  {BFD_RELOC_NDS32_GOTOFF_SUFF, R_NDS32_GOTOFF_SUFF},
  {BFD_RELOC_NDS32_GOT15S2, R_NDS32_GOT15S2_RELA},
  {BFD_RELOC_NDS32_GOT17S2, R_NDS32_GOT17S2_RELA},
  {BFD_RELOC_NDS32_PTR, R_NDS32_PTR},
  {BFD_RELOC_NDS32_PTR_COUNT, R_NDS32_PTR_COUNT},
  {BFD_RELOC_NDS32_PLT_GOT_SUFF, R_NDS32_PLT_GOT_SUFF},
  {BFD_RELOC_NDS32_PTR_RESOLVED, R_NDS32_PTR_RESOLVED},
  {BFD_RELOC_NDS32_RELAX_ENTRY, R_NDS32_RELAX_ENTRY},
  {BFD_RELOC_NDS32_MULCALL_SUFF, R_NDS32_MULCALL_SUFF},
  {BFD_RELOC_NDS32_PLTBLOCK, R_NDS32_PLTBLOCK},
  {BFD_RELOC_NDS32_RELAX_REGION_BEGIN, R_NDS32_RELAX_REGION_BEGIN},
  {BFD_RELOC_NDS32_RELAX_REGION_END, R_NDS32_RELAX_REGION_END},
  {BFD_RELOC_NDS32_MINUEND, R_NDS32_MINUEND},
  {BFD_RELOC_NDS32_SUBTRAHEND, R_NDS32_SUBTRAHEND},
  {BFD_RELOC_NDS32_EMPTY, R_NDS32_EMPTY},
  {BFD_RELOC_NDS32_DIFF8, R_NDS32_DIFF8},
  {BFD_RELOC_NDS32_DIFF16, R_NDS32_DIFF16},
  {BFD_RELOC_NDS32_DIFF32, R_NDS32_DIFF32},
  {BFD_RELOC_NDS32_DIFF_ULEB128, R_NDS32_DIFF_ULEB128},
  {BFD_RELOC_NDS32_25_ABS, R_NDS32_25_ABS_RELA},
  {BFD_RELOC_NDS32_DATA, R_NDS32_DATA},
  {BFD_RELOC_NDS32_TRAN, R_NDS32_TRAN},
  {BFD_RELOC_NDS32_17IFC_PCREL, R_NDS32_17IFC_PCREL_RELA},
  {BFD_RELOC_NDS32_10IFCU_PCREL, R_NDS32_10IFCU_PCREL_RELA},
  {BFD_RELOC_NDS32_TLS_LE_HI20, R_NDS32_TLS_LE_HI20},
  {BFD_RELOC_NDS32_TLS_LE_LO12, R_NDS32_TLS_LE_LO12},
  {BFD_RELOC_NDS32_TLS_LE_ADD, R_NDS32_TLS_LE_ADD},
  {BFD_RELOC_NDS32_TLS_LE_LS, R_NDS32_TLS_LE_LS},
  {BFD_RELOC_NDS32_TLS_IE_HI20, R_NDS32_TLS_IE_HI20},
  {BFD_RELOC_NDS32_TLS_IE_LO12S2, R_NDS32_TLS_IE_LO12S2},
  {BFD_RELOC_NDS32_TLS_LE_20, R_NDS32_TLS_LE_20},
  {BFD_RELOC_NDS32_TLS_LE_15S0, R_NDS32_TLS_LE_15S0},
  {BFD_RELOC_NDS32_TLS_LE_15S1, R_NDS32_TLS_LE_15S1},
  {BFD_RELOC_NDS32_TLS_LE_15S2, R_NDS32_TLS_LE_15S2},
  {BFD_RELOC_NDS32_TLS_DESC, R_NDS32_TLS_DESC},
  {BFD_RELOC_NDS32_TLS_DESC_HI20, R_NDS32_TLS_DESC_HI20},
  {BFD_RELOC_NDS32_TLS_DESC_LO12, R_NDS32_TLS_DESC_LO12},
  {BFD_RELOC_NDS32_TLS_DESC_ADD, R_NDS32_TLS_DESC_ADD},
  {BFD_RELOC_NDS32_TLS_DESC_FUNC, R_NDS32_TLS_DESC_FUNC},
  {BFD_RELOC_NDS32_TLS_DESC_CALL, R_NDS32_TLS_DESC_CALL},
  {BFD_RELOC_NDS32_TLS_DESC_MEM, R_NDS32_TLS_DESC_MEM},
  {BFD_RELOC_NDS32_TLS_DESC_20, R_NDS32_TLS_DESC_20},
  {BFD_RELOC_NDS32_TLS_DESC_SDA17S2, R_NDS32_TLS_DESC_SDA17S2},
  {BFD_RELOC_NDS32_TLS_IE_LO12, R_NDS32_TLS_IE_LO12},
  {BFD_RELOC_NDS32_TLS_IEGP_HI20, R_NDS32_TLS_IEGP_HI20},
  {BFD_RELOC_NDS32_TLS_IEGP_LO12, R_NDS32_TLS_IEGP_LO12},
  {BFD_RELOC_NDS32_TLS_IEGP_LO12S2, R_NDS32_TLS_IEGP_LO12S2},
  {BFD_RELOC_NDS32_TLS_IEGP_LW, R_NDS32_TLS_IEGP_LW},
  {BFD_RELOC_NDS32_REMOVE, R_NDS32_RELAX_REMOVE},
  {BFD_RELOC_NDS32_GROUP, R_NDS32_RELAX_GROUP},
  {BFD_RELOC_NDS32_ICT_HI20, R_NDS32_ICT_HI20},
  {BFD_RELOC_NDS32_ICT_LO12, R_NDS32_ICT_LO12},
  {BFD_RELOC_NDS32_ICT_25PC, R_NDS32_ICT_25PC},
  {BFD_RELOC_NDS32_ICT_LO12S2, R_NDS32_ICT_LO12S2},
  {BFD_RELOC_NDS32_LSI, R_NDS32_LSI},
};
static inline void
elf32_nds32_allocate_dynrelocs (struct bfd_link_info *info, asection *sreloc,
    bfd_size_type count)
{
  BFD_ASSERT (elf_hash_table (info)->dynamic_sections_created);
  if (sreloc == NULL)
    abort ();
  sreloc->size += sizeof (Elf32_External_Rela) * count;
}
static reloc_howto_type *
bfd_elf32_bfd_reloc_name_lookup (bfd *abfd ATTRIBUTE_UNUSED,
     const char *r_name)
{
  unsigned int i;
  for (i = 0; i < ARRAY_SIZE (nds32_elf_howto_table); i++)
    if (nds32_elf_howto_table[i].name != NULL
 && strcasecmp (nds32_elf_howto_table[i].name, r_name) == 0)
      return &nds32_elf_howto_table[i];
  for (i = 0; i < ARRAY_SIZE (nds32_elf_relax_howto_table); i++)
    if (nds32_elf_relax_howto_table[i].name != NULL
 && strcasecmp (nds32_elf_relax_howto_table[i].name, r_name) == 0)
      return &nds32_elf_relax_howto_table[i];
  return NULL;
}
static reloc_howto_type *
bfd_elf32_bfd_reloc_type_table_lookup (enum elf_nds32_reloc_type code)
{
  if (code < R_NDS32_RELAX_ENTRY)
    {
      BFD_ASSERT (code < ARRAY_SIZE (nds32_elf_howto_table));
      return &nds32_elf_howto_table[code];
    }
  else
    {
      if ((size_t) (code - R_NDS32_RELAX_ENTRY) >=
   ARRAY_SIZE (nds32_elf_relax_howto_table))
 {
   int i = code;
   i += 1;
 }
      BFD_ASSERT ((size_t) (code - R_NDS32_RELAX_ENTRY)
    < ARRAY_SIZE (nds32_elf_relax_howto_table));
      return &nds32_elf_relax_howto_table[code - R_NDS32_RELAX_ENTRY];
    }
}
static reloc_howto_type *
bfd_elf32_bfd_reloc_type_lookup (bfd *abfd ATTRIBUTE_UNUSED,
     bfd_reloc_code_real_type code)
{
  unsigned int i;
  for (i = 0; i < ARRAY_SIZE (nds32_reloc_map); i++)
    {
      if (nds32_reloc_map[i].bfd_reloc_val == code)
 return bfd_elf32_bfd_reloc_type_table_lookup
   (nds32_reloc_map[i].elf_reloc_val);
    }
  return NULL;
}
static void
nds32_info_to_howto_rel (bfd *abfd ATTRIBUTE_UNUSED, arelent *cache_ptr,
    Elf_Internal_Rela *dst)
{
  enum elf_nds32_reloc_type r_type;
  r_type = ELF32_R_TYPE (dst->r_info);
  BFD_ASSERT (ELF32_R_TYPE (dst->r_info) <= R_NDS32_GNU_VTENTRY);
  cache_ptr->howto = bfd_elf32_bfd_reloc_type_table_lookup (r_type);
}
static void
nds32_info_to_howto (bfd *abfd ATTRIBUTE_UNUSED, arelent *cache_ptr,
       Elf_Internal_Rela *dst)
{
  BFD_ASSERT ((ELF32_R_TYPE (dst->r_info) == R_NDS32_NONE)
       || ((ELF32_R_TYPE (dst->r_info) > R_NDS32_GNU_VTENTRY)
    && (ELF32_R_TYPE (dst->r_info) < R_NDS32_max)));
  cache_ptr->howto =
    bfd_elf32_bfd_reloc_type_table_lookup (ELF32_R_TYPE (dst->r_info));
}
static bfd_boolean
nds32_elf_grok_prstatus (bfd *abfd, Elf_Internal_Note *note)
{
  int offset;
  size_t size;
  switch (note->descsz)
    {
    case 0x114:
      elf_tdata (abfd)->core->signal = bfd_get_16 (abfd, note->descdata + 12);
      elf_tdata (abfd)->core->pid = bfd_get_32 (abfd, note->descdata + 24);
      offset = 72;
      size = 200;
      break;
    case 0xfc:
      elf_tdata (abfd)->core->signal = bfd_get_16 (abfd, note->descdata + 12);
      elf_tdata (abfd)->core->pid = bfd_get_32 (abfd, note->descdata + 24);
      offset = 72;
      size = 176;
      break;
    default:
      return FALSE;
    }
  return _bfd_elfcore_make_pseudosection (abfd, ".reg",
       size, note->descpos + offset);
}
static bfd_boolean
nds32_elf_grok_psinfo (bfd *abfd, Elf_Internal_Note *note)
{
  switch (note->descsz)
    {
    case 124:
      elf_tdata (abfd)->core->program =
 _bfd_elfcore_strndup (abfd, note->descdata + 28, 16);
      elf_tdata (abfd)->core->command =
 _bfd_elfcore_strndup (abfd, note->descdata + 44, 80);
    default:
      return FALSE;
    }
  {
    char *command = elf_tdata (abfd)->core->command;
    int n = strlen (command);
    if (0 < n && command[n - 1] == ' ')
      command[n - 1] = '\0';
  }
  return TRUE;
}
static bfd_boolean
nds32_elf_add_symbol_hook (bfd *abfd,
      struct bfd_link_info *info ATTRIBUTE_UNUSED,
      Elf_Internal_Sym *sym,
      const char **namep ATTRIBUTE_UNUSED,
      flagword *flagsp ATTRIBUTE_UNUSED,
      asection **secp, bfd_vma *valp)
{
  switch (sym->st_shndx)
    {
    case SHN_COMMON:
      if (sym->st_size > elf_gp_size (abfd)
   || ELF_ST_TYPE (sym->st_info) == STT_TLS)
 break;
      switch (sym->st_value)
 {
 case 1:
   *secp = bfd_make_section_old_way (abfd, ".scommon_b");
   break;
 case 2:
   *secp = bfd_make_section_old_way (abfd, ".scommon_h");
   break;
 case 4:
   *secp = bfd_make_section_old_way (abfd, ".scommon_w");
   break;
 case 8:
   *secp = bfd_make_section_old_way (abfd, ".scommon_d");
   break;
 default:
   return TRUE;
 }
      (*secp)->flags |= SEC_IS_COMMON;
      *valp = sym->st_size;
      break;
    }
  return TRUE;
}
static asection *sda_rela_sec = NULL;
#define SDA_SECTION_NUM 10
static bfd_reloc_status_type
nds32_elf_final_sda_base (bfd *output_bfd, struct bfd_link_info *info,
     bfd_vma *psb, bfd_boolean add_symbol)
{
  int relax_fp_as_gp;
  struct elf_nds32_link_hash_table *table;
  struct bfd_link_hash_entry *h, *h2;
  long unsigned int total = 0;
  asection *first = NULL, *final = NULL, *temp;
  bfd_vma sda_base = 0;
  h = bfd_link_hash_lookup (info->hash, "_SDA_BASE_", FALSE, FALSE, TRUE);
  if (!h || (h->type != bfd_link_hash_defined && h->type != bfd_link_hash_defweak))
    {
      static const char sec_name[SDA_SECTION_NUM][10] = {
 ".data", ".got", ".sdata_d", ".sdata_w", ".sdata_h", ".sdata_b",
 ".sbss_b", ".sbss_h", ".sbss_w", ".sbss_d"
      };
      size_t i = 0;
      if (output_bfd->sections == NULL)
 {
   *psb = elf_gp (output_bfd);
   return bfd_reloc_ok;
 }
      while (i < ARRAY_SIZE (sec_name))
 {
   temp = bfd_get_section_by_name (output_bfd, sec_name[i]);
   if (temp && !first && (temp->size != 0 || temp->rawsize != 0))
     first = temp;
   if (temp && (temp->size != 0 || temp->rawsize != 0))
     final = temp;
   if (temp && temp->size != 0)
     total += temp->size;
   else if (temp && temp->rawsize != 0)
     total += temp->rawsize;
   i++;
 }
      temp = bfd_get_section_by_name (output_bfd, ".bss");
      if (temp)
 {
   if (temp->size != 0)
     total += temp->size;
   else if (temp->rawsize != 0)
     total += temp->rawsize;
   if (total < 0x80000)
     {
       if (!first && (temp->size != 0 || temp->rawsize != 0))
  first = temp;
       if ((temp->size != 0 || temp->rawsize != 0))
  final = temp;
     }
 }
      if (first && final)
 {
   sda_base = final->vma / 2 + final->rawsize / 2 + first->vma / 2;
   i = 0;
   while (i < ARRAY_SIZE (sec_name))
     {
       final = bfd_get_section_by_name (output_bfd, sec_name[i]);
       if (final && (final->size != 0 || final->rawsize != 0)
    && sda_base >= final->vma)
  {
    first = final;
    i++;
  }
       else
  break;
     }
 }
      else
 {
   temp = output_bfd->sections;
   while (temp)
     {
       if (temp->flags & SEC_ALLOC
    && (((temp->flags & SEC_DATA)
         && ((temp->flags & SEC_READONLY) == 0))
        || (temp->flags & SEC_LOAD) == 0)
    && (temp->size != 0 || temp->rawsize != 0))
  {
    if (!first)
      first = temp;
    final = temp;
  }
       temp = temp->next;
     }
   if (!first || (first->size == 0 && first->rawsize == 0))
     {
       first = output_bfd->sections;
       while (first && first->size == 0 && first->rawsize == 0)
  first = first->next;
     }
   if (!first)
     {
       *psb = elf_gp (output_bfd);
       return bfd_reloc_ok;
     }
   if (final && (final->vma + final->rawsize - first->vma) <= 0x4000)
     sda_base = final->vma / 2 + final->rawsize / 2 + first->vma / 2;
   else
     sda_base = first->vma + 0x2000;
 }
      sda_base -= first->vma;
      sda_base = sda_base & (~7);
      if (!_bfd_generic_link_add_one_symbol
      (info, output_bfd, "_SDA_BASE_", BSF_GLOBAL | BSF_WEAK, first,
       (bfd_vma) sda_base, (const char *) NULL, FALSE,
       get_elf_backend_data (output_bfd)->collect, &h))
 return FALSE;
      sda_rela_sec = first;
    }
  table = nds32_elf_hash_table (info);
  relax_fp_as_gp = table->relax_fp_as_gp;
  h2 = bfd_link_hash_lookup (info->hash, FP_BASE_NAME, FALSE, FALSE, FALSE);
  if (!first)
    {
      first = h->u.def.section;
      sda_base = h->u.def.value;
    }
  if (relax_fp_as_gp && h2
      && (h2->type == bfd_link_hash_undefweak
   || h2->type == bfd_link_hash_undefined))
    {
      if (!_bfd_generic_link_add_one_symbol
   (info, output_bfd, FP_BASE_NAME, BSF_GLOBAL | BSF_WEAK,
    first, sda_base, (const char *) NULL,
    FALSE, get_elf_backend_data (output_bfd)->collect, &h2))
 return FALSE;
    }
  if (add_symbol == TRUE)
    {
      if (h)
 {
   elf_gp (output_bfd) = (h->u.def.value
     + h->u.def.section->output_section->vma
     + h->u.def.section->output_offset);
 }
      else
 {
   (*_bfd_error_handler) (_("error: Can't find symbol: _SDA_BASE_."));
   return bfd_reloc_dangerous;
 }
    }
  *psb = h->u.def.value + h->u.def.section->output_section->vma
  + h->u.def.section->output_offset;
  return bfd_reloc_ok;
}
#define elf_nds32_sizeof_plt(info) PLT_ENTRY_SIZE
static struct bfd_hash_entry *
nds32_elf_link_hash_newfunc (struct bfd_hash_entry *entry,
        struct bfd_hash_table *table,
        const char *string)
{
  struct elf_nds32_link_hash_entry *ret;
  ret = (struct elf_nds32_link_hash_entry *) entry;
  if (ret == NULL)
    ret = (struct elf_nds32_link_hash_entry *)
       bfd_hash_allocate (table, sizeof (struct elf_nds32_link_hash_entry));
  if (ret == NULL)
    return (struct bfd_hash_entry *) ret;
  ret = (struct elf_nds32_link_hash_entry *)
    _bfd_elf_link_hash_newfunc ((struct bfd_hash_entry *) ret, table, string);
  if (ret != NULL)
    {
      struct elf_nds32_link_hash_entry *eh;
      eh = (struct elf_nds32_link_hash_entry *) ret;
      eh->dyn_relocs = NULL;
      eh->tls_type = GOT_UNKNOWN;
      eh->offset_to_gp = 0;
      eh->indirect_call = FALSE;
    }
  return (struct bfd_hash_entry *) ret;
}
static struct bfd_link_hash_table *
nds32_elf_link_hash_table_create (bfd *abfd)
{
  struct elf_nds32_link_hash_table *ret;
  bfd_size_type amt = sizeof (struct elf_nds32_link_hash_table);
  ret = (struct elf_nds32_link_hash_table *) bfd_zmalloc (amt);
  if (ret == NULL)
    return NULL;
  if (!_bfd_elf_link_hash_table_init (&ret->root, abfd,
          nds32_elf_link_hash_newfunc,
          sizeof (struct elf_nds32_link_hash_entry),
          NDS32_ELF_DATA))
    {
      free (ret);
      return NULL;
    }
  ret->sdynbss = NULL;
  ret->srelbss = NULL;
  ret->sym_ld_script = NULL;
  return &ret->root.root;
}
static bfd_boolean
create_got_section (bfd *dynobj, struct bfd_link_info *info)
{
  struct elf_link_hash_table *ehtab;
  if (!_bfd_elf_create_got_section (dynobj, info))
    return FALSE;
  ehtab = elf_hash_table (info);
  ehtab->sgot = bfd_get_section_by_name (dynobj, ".got");
  ehtab->sgotplt = bfd_get_section_by_name (dynobj, ".got.plt");
  if (!ehtab->sgot || !ehtab->sgotplt)
    abort ();
  ehtab->srelgot = bfd_get_section_by_name (dynobj, ".rela.got");
  if (ehtab->srelgot == NULL
      || !bfd_set_section_flags (dynobj, ehtab->srelgot,
     (SEC_ALLOC | SEC_LOAD | SEC_HAS_CONTENTS
      | SEC_IN_MEMORY | SEC_LINKER_CREATED
      | SEC_READONLY))
      || !bfd_set_section_alignment (dynobj, ehtab->srelgot, 2))
    return FALSE;
  return TRUE;
}
static bfd_boolean
nds32_elf_create_dynamic_sections (bfd *abfd, struct bfd_link_info *info)
{
  struct elf_link_hash_table *ehtab;
  struct elf_nds32_link_hash_table *htab;
  flagword flags, pltflags;
  register asection *s;
  const struct elf_backend_data *bed;
  int ptralign = 2;
  const char *secname;
  char *relname;
  flagword secflags;
  asection *sec;
  bed = get_elf_backend_data (abfd);
  ehtab = elf_hash_table (info);
  htab = nds32_elf_hash_table (info);
  flags = (SEC_ALLOC | SEC_LOAD | SEC_HAS_CONTENTS | SEC_IN_MEMORY
    | SEC_LINKER_CREATED);
  pltflags = flags;
  pltflags |= SEC_CODE;
  if (bed->plt_not_loaded)
    pltflags &= ~(SEC_LOAD | SEC_HAS_CONTENTS);
  if (bed->plt_readonly)
    pltflags |= SEC_READONLY;
  s = bfd_make_section (abfd, ".plt");
  ehtab->splt = s;
  if (s == NULL
      || !bfd_set_section_flags (abfd, s, pltflags)
      || !bfd_set_section_alignment (abfd, s, bed->plt_alignment))
    return FALSE;
  if (bed->want_plt_sym)
    {
      struct bfd_link_hash_entry *bh = NULL;
      struct elf_link_hash_entry *h;
      if (!(_bfd_generic_link_add_one_symbol
     (info, abfd, "_PROCEDURE_LINKAGE_TABLE_", BSF_GLOBAL, s,
      (bfd_vma) 0, (const char *) NULL, FALSE,
      get_elf_backend_data (abfd)->collect, &bh)))
 return FALSE;
      h = (struct elf_link_hash_entry *) bh;
      h->def_regular = 1;
      h->type = STT_OBJECT;
      if (info->shared && !bfd_elf_link_record_dynamic_symbol (info, h))
 return FALSE;
    }
  s = bfd_make_section (abfd,
   bed->default_use_rela_p ? ".rela.plt" : ".rel.plt");
  ehtab->srelplt = s;
  if (s == NULL
      || !bfd_set_section_flags (abfd, s, flags | SEC_READONLY)
      || !bfd_set_section_alignment (abfd, s, ptralign))
    return FALSE;
  if (ehtab->sgot == NULL && !create_got_section (abfd, info))
    return FALSE;
  for (sec = abfd->sections; sec; sec = sec->next)
    {
      secflags = bfd_get_section_flags (abfd, sec);
      if ((secflags & (SEC_DATA | SEC_LINKER_CREATED))
   || ((secflags & SEC_HAS_CONTENTS) != SEC_HAS_CONTENTS))
 continue;
      secname = bfd_get_section_name (abfd, sec);
      relname = (char *) bfd_malloc ((bfd_size_type) strlen (secname) + 6);
      strcpy (relname, ".rela");
      strcat (relname, secname);
      if (bfd_get_section_by_name (abfd, secname))
 continue;
      s = bfd_make_section (abfd, relname);
      if (s == NULL
   || !bfd_set_section_flags (abfd, s, flags | SEC_READONLY)
   || !bfd_set_section_alignment (abfd, s, ptralign))
 return FALSE;
    }
  if (bed->want_dynbss)
    {
      s = bfd_make_section (abfd, ".dynbss");
      htab->sdynbss = s;
      if (s == NULL
   || !bfd_set_section_flags (abfd, s, SEC_ALLOC | SEC_LINKER_CREATED))
 return FALSE;
      if (!info->shared)
 {
   s = bfd_make_section (abfd, (bed->default_use_rela_p
           ? ".rela.bss" : ".rel.bss"));
   htab->srelbss = s;
   if (s == NULL
       || !bfd_set_section_flags (abfd, s, flags | SEC_READONLY)
       || !bfd_set_section_alignment (abfd, s, ptralign))
     return FALSE;
 }
    }
  return TRUE;
}
static void
nds32_elf_copy_indirect_symbol (struct bfd_link_info *info,
    struct elf_link_hash_entry *dir,
    struct elf_link_hash_entry *ind)
{
  struct elf_nds32_link_hash_entry *edir, *eind;
  edir = (struct elf_nds32_link_hash_entry *) dir;
  eind = (struct elf_nds32_link_hash_entry *) ind;
  if (eind->dyn_relocs != NULL)
    {
      if (edir->dyn_relocs != NULL)
 {
   struct elf_nds32_dyn_relocs **pp;
   struct elf_nds32_dyn_relocs *p;
   if (ind->root.type == bfd_link_hash_indirect)
     abort ();
   for (pp = &eind->dyn_relocs; (p = *pp) != NULL;)
     {
       struct elf_nds32_dyn_relocs *q;
       for (q = edir->dyn_relocs; q != NULL; q = q->next)
  if (q->sec == p->sec)
    {
      q->pc_count += p->pc_count;
      q->count += p->count;
      *pp = p->next;
      break;
    }
       if (q == NULL)
  pp = &p->next;
     }
   *pp = edir->dyn_relocs;
 }
      edir->dyn_relocs = eind->dyn_relocs;
      eind->dyn_relocs = NULL;
    }
  if (ind->root.type == bfd_link_hash_indirect)
    {
      if (dir->got.refcount <= 0)
 {
   edir->tls_type = eind->tls_type;
   eind->tls_type = GOT_UNKNOWN;
 }
    }
  _bfd_elf_link_hash_copy_indirect (info, dir, ind);
}
static bfd_boolean
nds32_elf_adjust_dynamic_symbol (struct bfd_link_info *info,
     struct elf_link_hash_entry *h)
{
  struct elf_nds32_link_hash_table *htab;
  struct elf_nds32_link_hash_entry *eh;
  struct elf_nds32_dyn_relocs *p;
  bfd *dynobj;
  asection *s;
  unsigned int power_of_two;
  dynobj = elf_hash_table (info)->dynobj;
  BFD_ASSERT (dynobj != NULL
       && (h->needs_plt
    || h->u.weakdef != NULL
    || (h->def_dynamic && h->ref_regular && !h->def_regular)));
  if (h->type == STT_FUNC || h->needs_plt)
    {
      if (!info->shared
   && !h->def_dynamic
   && !h->ref_dynamic
   && h->root.type != bfd_link_hash_undefweak
   && h->root.type != bfd_link_hash_undefined)
 {
   h->plt.offset = (bfd_vma) - 1;
   h->needs_plt = 0;
 }
      return TRUE;
    }
  else
    h->plt.offset = (bfd_vma) - 1;
  if (h->u.weakdef != NULL)
    {
      BFD_ASSERT (h->u.weakdef->root.type == bfd_link_hash_defined
    || h->u.weakdef->root.type == bfd_link_hash_defweak);
      h->root.u.def.section = h->u.weakdef->root.u.def.section;
      h->root.u.def.value = h->u.weakdef->root.u.def.value;
      return TRUE;
    }
  if (info->shared)
    return TRUE;
  if (!h->non_got_ref)
    return TRUE;
  if (info->nocopyreloc)
    {
      h->non_got_ref = 0;
      return TRUE;
    }
  eh = (struct elf_nds32_link_hash_entry *) h;
  for (p = eh->dyn_relocs; p != NULL; p = p->next)
    {
      s = p->sec->output_section;
      if (s != NULL && (s->flags & (SEC_READONLY | SEC_HAS_CONTENTS)) != 0)
 break;
    }
  if (p == NULL)
    {
      h->non_got_ref = 0;
      return TRUE;
    }
  htab = nds32_elf_hash_table (info);
  s = htab->sdynbss;
  BFD_ASSERT (s != NULL);
  if ((h->root.u.def.section->flags & SEC_ALLOC) != 0)
    {
      asection *srel;
      srel = htab->srelbss;
      BFD_ASSERT (srel != NULL);
      srel->size += sizeof (Elf32_External_Rela);
      h->needs_copy = 1;
    }
  power_of_two = bfd_log2 (h->size);
  if (power_of_two > 3)
    power_of_two = 3;
  s->size = BFD_ALIGN (s->size, (bfd_size_type) (1 << power_of_two));
  if (power_of_two > bfd_get_section_alignment (dynobj, s))
    {
      if (!bfd_set_section_alignment (dynobj, s, power_of_two))
 return FALSE;
    }
  h->root.u.def.section = s;
  h->root.u.def.value = s->size;
  s->size += h->size;
  return TRUE;
}
static bfd_boolean
allocate_dynrelocs (struct elf_link_hash_entry *h, void *inf)
{
  struct bfd_link_info *info;
  struct elf_link_hash_table *ehtab;
  struct elf_nds32_link_hash_table *htab;
  struct elf_nds32_link_hash_entry *eh;
  struct elf_nds32_dyn_relocs *p;
  if (h->root.type == bfd_link_hash_indirect)
    return TRUE;
  if (h->root.type == bfd_link_hash_warning)
    h = (struct elf_link_hash_entry *) h->root.u.i.link;
  eh = (struct elf_nds32_link_hash_entry *) h;
  info = (struct bfd_link_info *) inf;
  ehtab = elf_hash_table (info);
  htab = nds32_elf_hash_table (info);
  if (htab == NULL)
    return FALSE;
  if ((htab->root.dynamic_sections_created || h->type == STT_GNU_IFUNC)
      && h->plt.refcount > 0
      && !(info->pie && h->def_regular))
    {
      if (h->dynindx == -1 && !h->forced_local)
 {
   if (!bfd_elf_link_record_dynamic_symbol (info, h))
     return FALSE;
 }
      if (WILL_CALL_FINISH_DYNAMIC_SYMBOL (1, info->shared, h))
 {
   asection *s = ehtab->splt;
   if (s->size == 0)
     s->size += PLT_ENTRY_SIZE;
   h->plt.offset = s->size;
   if (!info->shared && !h->def_regular)
     {
       h->root.u.def.section = s;
       h->root.u.def.value = h->plt.offset;
     }
   s->size += PLT_ENTRY_SIZE;
   ehtab->sgotplt->size += 4;
   ehtab->srelplt->size += sizeof (Elf32_External_Rela);
   if (htab->tls_desc_trampoline)
     htab->next_tls_desc_index++;
 }
      else
 {
   h->plt.offset = (bfd_vma) - 1;
   h->needs_plt = 0;
 }
    }
  else
    {
      h->plt.offset = (bfd_vma) - 1;
      h->needs_plt = 0;
    }
  if (h->got.refcount > 0)
    {
      asection *sgot;
      bfd_boolean dyn;
      int tls_type = elf32_nds32_hash_entry (h)->tls_type;
      if (h->dynindx == -1 && !h->forced_local)
 {
   if (!bfd_elf_link_record_dynamic_symbol (info, h))
     return FALSE;
 }
      sgot = elf_hash_table (info)->sgot;
      h->got.offset = sgot->size;
      if (tls_type == GOT_UNKNOWN)
 abort ();
      if (tls_type & (GOT_NORMAL | GOT_TLS_IE | GOT_TLS_IEGP))
 sgot->size += 4;
      else
 {
   if (tls_type & GOT_TLS_DESC)
     sgot->size += 8;
 }
      dyn = htab->root.dynamic_sections_created;
      if (WILL_CALL_FINISH_DYNAMIC_SYMBOL (dyn, info->shared, h))
 {
   if (tls_type == GOT_TLS_DESC && htab->tls_desc_trampoline)
     {
       htab->num_tls_desc++;
       ehtab->srelplt->size += sizeof (Elf32_External_Rela);
       htab->tls_trampoline = -1;
     }
   else
     {
       ehtab->srelgot->size += sizeof (Elf32_External_Rela);
     }
 }
    }
  else
    h->got.offset = (bfd_vma) -1;
  if (eh->dyn_relocs == NULL)
    return TRUE;
  if (info->shared)
    {
      if (h->def_regular && (h->forced_local || info->symbolic))
 {
   struct elf_nds32_dyn_relocs **pp;
   for (pp = &eh->dyn_relocs; (p = *pp) != NULL;)
     {
       p->count -= p->pc_count;
       p->pc_count = 0;
       if (p->count == 0)
  *pp = p->next;
       else
  pp = &p->next;
     }
 }
    }
  else
    {
      if (!h->non_got_ref
   && ((h->def_dynamic
        && !h->def_regular)
       || (htab->root.dynamic_sections_created
    && (h->root.type == bfd_link_hash_undefweak
        || h->root.type == bfd_link_hash_undefined))))
 {
   if (h->dynindx == -1 && !h->forced_local)
     {
       if (!bfd_elf_link_record_dynamic_symbol (info, h))
  return FALSE;
     }
   if (h->dynindx != -1)
     goto keep;
 }
      eh->dyn_relocs = NULL;
keep:;
    }
  for (p = eh->dyn_relocs; p != NULL; p = p->next)
    {
      asection *sreloc = elf_section_data (p->sec)->sreloc;
      sreloc->size += p->count * sizeof (Elf32_External_Rela);
    }
  return TRUE;
}
static void
elf32_nds32_add_dynreloc (bfd *output_bfd,
     struct bfd_link_info *info ATTRIBUTE_UNUSED,
     asection *sreloc, Elf_Internal_Rela *rel)
{
  bfd_byte *loc;
  if (sreloc == NULL)
    abort ();
  loc = sreloc->contents;
  loc += sreloc->reloc_count++ * sizeof (Elf32_External_Rela);
  if (sreloc->reloc_count * sizeof (Elf32_External_Rela) > sreloc->size)
    abort ();
  bfd_elf32_swap_reloca_out (output_bfd, rel, loc);
}
static bfd_boolean
readonly_dynrelocs (struct elf_link_hash_entry *h, void *inf)
{
  struct elf_nds32_link_hash_entry *eh;
  struct elf_nds32_dyn_relocs *p;
  if (h->root.type == bfd_link_hash_warning)
    h = (struct elf_link_hash_entry *) h->root.u.i.link;
  eh = (struct elf_nds32_link_hash_entry *) h;
  for (p = eh->dyn_relocs; p != NULL; p = p->next)
    {
      asection *s = p->sec->output_section;
      if (s != NULL && (s->flags & SEC_READONLY) != 0)
 {
   struct bfd_link_info *info = (struct bfd_link_info *) inf;
   info->flags |= DF_TEXTREL;
   return FALSE;
 }
    }
  return TRUE;
}
static bfd_boolean
nds32_elf_size_dynamic_sections (bfd *output_bfd ATTRIBUTE_UNUSED,
     struct bfd_link_info *info)
{
  bfd *dynobj;
  asection *s;
  bfd_boolean plt;
  bfd_boolean relocs;
  bfd *ibfd;
  struct elf_nds32_link_hash_table *htab;
  htab = nds32_elf_hash_table (info);
  if (htab == NULL)
    return FALSE;
  dynobj = elf_hash_table (info)->dynobj;
  BFD_ASSERT (dynobj != NULL);
  if (elf_hash_table (info)->dynamic_sections_created)
    {
      if (info->executable)
 {
   s = bfd_get_section_by_name (dynobj, ".interp");
   BFD_ASSERT (s != NULL);
   s->size = sizeof ELF_DYNAMIC_INTERPRETER;
   s->contents = (unsigned char *) ELF_DYNAMIC_INTERPRETER;
 }
    }
  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link_next)
    {
      bfd_signed_vma *local_got;
      bfd_signed_vma *end_local_got;
      bfd_size_type locsymcount;
      Elf_Internal_Shdr *symtab_hdr;
      asection *sgot;
      char *local_tls_type;
      unsigned long symndx;
      bfd_vma *local_tlsdesc_gotent;
      if (bfd_get_flavour (ibfd) != bfd_target_elf_flavour)
 continue;
      for (s = ibfd->sections; s != NULL; s = s->next)
 {
   struct elf_nds32_dyn_relocs *p;
   for (p = ((struct elf_nds32_dyn_relocs *)
      elf_section_data (s)->local_dynrel);
        p != NULL; p = p->next)
     {
       if (!bfd_is_abs_section (p->sec)
    && bfd_is_abs_section (p->sec->output_section))
  {
  }
       else if (p->count != 0)
  {
    asection *sreloc = elf_section_data (p->sec)->sreloc;
    sreloc->size += p->count * sizeof (Elf32_External_Rela);
    if ((p->sec->output_section->flags & SEC_READONLY) != 0)
      info->flags |= DF_TEXTREL;
  }
     }
 }
      local_got = elf_local_got_refcounts (ibfd);
      if (!local_got)
 continue;
      symtab_hdr = &elf_tdata (ibfd)->symtab_hdr;
      locsymcount = symtab_hdr->sh_info;
      end_local_got = local_got + locsymcount;
      sgot = elf_hash_table (info)->sgot;
      local_tls_type = elf32_nds32_local_got_tls_type (ibfd);
      local_tlsdesc_gotent = elf32_nds32_local_tlsdesc_gotent (ibfd);
      for (symndx = 0; local_got < end_local_got;
    ++local_got, ++local_tls_type, ++local_tlsdesc_gotent, ++symndx)
 {
   if (*local_got > 0)
     {
       int num_of_got_entry_needed = 0;
       *local_got = sgot->size;
       *local_tlsdesc_gotent = sgot->size;
       if (*local_tls_type & (GOT_NORMAL | GOT_TLS_IE | GOT_TLS_IEGP))
  num_of_got_entry_needed = 1;
       else if (*local_tls_type & GOT_TLS_DESC)
  num_of_got_entry_needed = 2;
       sgot->size += (num_of_got_entry_needed << 2);
       if (*local_tls_type == GOT_TLS_DESC)
  {
    if (info->shared)
      {
        if (htab->tls_desc_trampoline)
   {
     htab->num_tls_desc++;
     htab->root.srelplt->size += sizeof (Elf32_External_Rela);
     htab->tls_trampoline = -1;
   }
        else
   htab->root.srelgot->size += sizeof (Elf32_External_Rela);
      }
    else
      {
      }
  }
       else
  {
    htab->root.srelgot->size += sizeof (Elf32_External_Rela);
  }
     }
   else
     {
       *local_got = (bfd_vma) -1;
       *local_tlsdesc_gotent = (bfd_vma) -1;
     }
 }
    }
  elf_link_hash_traverse (&htab->root, allocate_dynrelocs, (void *) info);
  if (htab->tls_desc_trampoline && htab->root.srelplt)
    htab->sgotplt_jump_table_size = elf32_nds32_compute_jump_table_size (htab);
  if (htab->tls_trampoline)
    {
      htab->tls_trampoline = htab->root.splt->size;
      if (!(info->flags & DF_BIND_NOW))
 {
   htab->dt_tlsdesc_got = htab->root.sgot->size;
   htab->root.sgot->size += 4;
   htab->dt_tlsdesc_plt = htab->root.splt->size;
   htab->root.splt->size += 4 * ARRAY_SIZE (dl_tlsdesc_lazy_trampoline);
 }
    }
  plt = FALSE;
  relocs = FALSE;
  for (s = dynobj->sections; s != NULL; s = s->next)
    {
      if ((s->flags & SEC_LINKER_CREATED) == 0)
 continue;
      if (s == htab->root.splt)
 {
   plt = s->size != 0;
 }
      else if (s == elf_hash_table (info)->sgot)
 {
   got_size += s->size;
 }
      else if (s == elf_hash_table (info)->sgotplt)
 {
   got_size += s->size;
 }
      else if (strncmp (bfd_get_section_name (dynobj, s), ".rela", 5) == 0)
 {
   if (s->size != 0 && s != elf_hash_table (info)->srelplt)
     relocs = TRUE;
   s->reloc_count = 0;
 }
      else
 {
   continue;
 }
      if (s->size == 0)
 {
   s->flags |= SEC_EXCLUDE;
   continue;
 }
      s->contents = (bfd_byte *) bfd_zalloc (dynobj, s->size);
      if (s->contents == NULL)
 return FALSE;
    }
  if (htab->root.dynamic_sections_created)
    {
#define add_dynamic_entry(TAG,VAL) _bfd_elf_add_dynamic_entry (info, TAG, VAL)
      if (info->executable)
 {
   if (!add_dynamic_entry (DT_DEBUG, 0))
     return FALSE;
 }
      if (elf_hash_table (info)->splt->size != 0)
 {
   if (!add_dynamic_entry (DT_PLTGOT, 0)
       || !add_dynamic_entry (DT_PLTRELSZ, 0)
       || !add_dynamic_entry (DT_PLTREL, DT_RELA)
       || !add_dynamic_entry (DT_JMPREL, 0))
     return FALSE;
 }
      if (htab->tls_desc_trampoline && plt)
 {
   if (htab->dt_tlsdesc_plt
       && (!add_dynamic_entry (DT_TLSDESC_PLT, 0)
    || !add_dynamic_entry (DT_TLSDESC_GOT, 0)))
     return FALSE;
 }
      if (relocs)
 {
   if (!add_dynamic_entry (DT_RELA, 0)
       || !add_dynamic_entry (DT_RELASZ, 0)
       || !add_dynamic_entry (DT_RELAENT, sizeof (Elf32_External_Rela)))
     return FALSE;
   if ((info->flags & DF_TEXTREL) == 0)
     elf_link_hash_traverse (&htab->root, readonly_dynrelocs,
        (void *) info);
   if ((info->flags & DF_TEXTREL) != 0)
     {
       if (!add_dynamic_entry (DT_TEXTREL, 0))
  return FALSE;
     }
 }
    }
#undef add_dynamic_entry
  return TRUE;
}
static bfd_reloc_status_type
nds32_relocate_contents (reloc_howto_type *howto, bfd *input_bfd,
    bfd_vma relocation, bfd_byte *location)
{
  int size;
  bfd_vma x = 0;
  bfd_reloc_status_type flag;
  unsigned int rightshift = howto->rightshift;
  unsigned int bitpos = howto->bitpos;
  if (howto->size < 0)
    relocation = -relocation;
  size = bfd_get_reloc_size (howto);
  switch (size)
    {
    default:
    case 0:
    case 1:
    case 8:
      abort ();
      break;
    case 2:
      x = bfd_getb16 (location);
      break;
    case 4:
      x = bfd_getb32 (location);
      break;
    }
  flag = bfd_reloc_ok;
  if (howto->complain_on_overflow != complain_overflow_dont)
    {
      bfd_vma addrmask, fieldmask, signmask, ss;
      bfd_vma a, b, sum;
      fieldmask = N_ONES (howto->bitsize);
      signmask = ~fieldmask;
      addrmask = N_ONES (bfd_arch_bits_per_address (input_bfd)) | fieldmask;
      a = (relocation & addrmask) >> rightshift;
      b = (x & howto->src_mask & addrmask) >> bitpos;
      switch (howto->complain_on_overflow)
 {
 case complain_overflow_signed:
   signmask = ~(fieldmask >> 1);
 case complain_overflow_bitfield:
   ss = a & signmask;
   if (ss != 0 && ss != ((addrmask >> rightshift) & signmask))
     flag = bfd_reloc_overflow;
   ss = ((~howto->src_mask) >> 1) & howto->src_mask;
   ss >>= bitpos;
   b = (b ^ ss) - ss;
   sum = a + b;
   if (((~(a ^ b)) & (a ^ sum)) & signmask & addrmask)
     flag = bfd_reloc_overflow;
   break;
 case complain_overflow_unsigned:
   sum = (a + b) & addrmask;
   if ((a | b | sum) & signmask)
     flag = bfd_reloc_overflow;
   break;
 default:
   abort ();
 }
    }
  relocation >>= (bfd_vma) rightshift;
  relocation <<= (bfd_vma) bitpos;
  if (howto->partial_inplace)
    x = ((x & ~howto->dst_mask)
  | (((x & howto->src_mask) + relocation) & howto->dst_mask));
  else
    x = ((x & ~howto->dst_mask) | ((relocation) & howto->dst_mask));
  switch (size)
    {
    default:
    case 0:
    case 1:
    case 8:
      abort ();
      break;
    case 2:
      bfd_putb16 (x, location);
      break;
    case 4:
      bfd_putb32 (x, location);
      break;
    }
  return flag;
}
static bfd_reloc_status_type
nds32_elf_final_link_relocate (reloc_howto_type *howto, bfd *input_bfd,
          asection *input_section, bfd_byte *contents,
          bfd_vma address, bfd_vma value, bfd_vma addend)
{
  bfd_vma relocation;
  if (address > bfd_get_section_limit (input_bfd, input_section))
    return bfd_reloc_outofrange;
  relocation = value + addend;
  if (howto->pc_relative)
    {
      relocation -= (input_section->output_section->vma
       + input_section->output_offset);
      if (howto->pcrel_offset)
 relocation -= address;
    }
  return nds32_relocate_contents (howto, input_bfd, relocation,
      contents + address);
}
static bfd_boolean
nds32_elf_output_symbol_hook (struct bfd_link_info *info,
         const char *name,
         Elf_Internal_Sym *elfsym ATTRIBUTE_UNUSED,
         asection *input_sec,
         struct elf_link_hash_entry *h ATTRIBUTE_UNUSED)
{
  const char *source;
  FILE *sym_ld_script = NULL;
  struct elf_nds32_link_hash_table *table;
  table = nds32_elf_hash_table (info);
  sym_ld_script = table->sym_ld_script;
  if (!sym_ld_script)
    return TRUE;
  if (!h || !name || *name == '\0')
    return TRUE;
  if (input_sec->flags & SEC_EXCLUDE)
    return TRUE;
  if (!check_start_export_sym)
    {
      fprintf (sym_ld_script, "SECTIONS\n{\n");
      check_start_export_sym = 1;
    }
  if (h->root.type == bfd_link_hash_defined
      || h->root.type == bfd_link_hash_defweak)
    {
      if (!h->root.u.def.section->output_section)
 return TRUE;
      if (bfd_is_const_section (input_sec))
 source = input_sec->name;
      else
 source = input_sec->owner->filename;
      fprintf (sym_ld_script, "\t%s = 0x%08lx;\t /* %s  */\n",
        h->root.root.string,
        (h->root.u.def.value
  + h->root.u.def.section->output_section->vma
  + h->root.u.def.section->output_offset), source);
    }
  return TRUE;
}
static bfd_vma
gottpoff (struct bfd_link_info *info, bfd_vma address)
{
  bfd_vma tp_base;
  bfd_vma tp_offset;
  if (elf_hash_table (info)->tls_sec == NULL)
    return 0;
  tp_base = elf_hash_table (info)->tls_sec->vma;
  tp_offset = address - tp_base;
  return tp_offset;
}
static void
nds32_elf_crc_adjust_reloc (Elf_Internal_Rela *relocs,
       Elf_Internal_Rela *relend)
{
  Elf_Internal_Rela *rel, *crc_rel = NULL;
  Elf_Internal_Rela rel_temp;
  for (rel = relocs; rel < relend; rel++)
    {
      if (crc_rel && crc_rel->r_offset == rel->r_offset)
 {
   memcpy (&rel_temp, rel, sizeof (Elf_Internal_Rela));
   memcpy (rel, crc_rel, sizeof (Elf_Internal_Rela));
   memcpy (crc_rel, &rel_temp, sizeof (Elf_Internal_Rela));
   crc_rel = rel;
 }
      else if (ELF32_R_TYPE (rel->r_info) == R_NDS32_SECURITY_16)
 {
   crc_rel = rel;
   continue;
 }
    }
}
static bfd_boolean
patch_tls_desc_to_ie (bfd_byte *contents, Elf_Internal_Rela *rel, bfd *ibfd)
{
  bfd_boolean rz = FALSE;
  typedef struct
  {
    uint32_t opcode;
    uint32_t mask;
  } pat_t;
  uint32_t patch[3] =
    {
      0x40007400,
      0x04000001,
      0x40006400,
    };
  pat_t mode0[3] =
    {
      { 0x40000000, 0xfe0003ff },
      { 0x04000000, 0xfe000000 },
      { 0x4be00001, 0xffff83ff },
    };
  pat_t mode1[3] =
    {
      { 0x38007402, 0xfe007fff },
      { 0x40007400, 0xfe007fff },
      { 0x4be00001, 0xffff83ff },
    };
  unsigned char *p = contents + rel->r_offset;
  uint32_t insn;
  uint32_t regidx = 0;
  insn = bfd_getb32 (p);
  if (INSN_SETHI == (0xfe0fffffu & insn))
    {
      regidx = 0x1f & (insn >> 20);
      p += 4;
    }
  insn = bfd_getb32 (p);
  if (INSN_ORI == (0xfe007fffu & insn))
    {
      regidx = 0x1f & (insn >> 20);
      p += 4;
    }
  if (patch[2] == bfd_getb32 (p + 8))
    {
      if ((patch[0] == (0xfff07fffu & bfd_getb32 (p + 0))) &&
   (patch[1] == bfd_getb32 (p + 4)))
 rz = TRUE;
    }
  else if (mode0[0].opcode == (mode0[0].mask & bfd_getb32 (p + 0)))
    {
      if ((mode0[1].opcode == (mode0[1].mask & bfd_getb32 (p + 4))) &&
   (mode0[2].opcode == (mode0[2].mask & bfd_getb32 (p + 8))))
 {
   bfd_putb32 (patch[0] | (regidx << 15), p + 0);
   bfd_putb32 (patch[1], p + 4);
   bfd_putb32 (patch[2], p + 8);
   rz = TRUE;
 }
    }
  else if (mode1[0].opcode == (mode1[0].mask & bfd_getb32 (p + 0)))
    {
      if ((mode1[1].opcode == (mode1[1].mask & bfd_getb32 (p + 4))) &&
   (mode1[2].opcode == (mode1[2].mask & bfd_getb32 (p + 8))))
 {
   bfd_putb32 (patch[0] | (regidx << 15), p + 0);
   bfd_putb32 (patch[1], p + 4);
   bfd_putb32 (patch[2], p + 8);
   rz = TRUE;
 }
    }
  if (!rz)
    {
      printf ("%s: %s @ 0x%08x\n", __func__, ibfd->filename,
       (int) rel->r_offset);
      BFD_ASSERT(0);
    }
  return rz;
}
static enum elf_nds32_tls_type
get_tls_type (enum elf_nds32_reloc_type r_type, struct elf_link_hash_entry *h);
static unsigned int
ones32 (register unsigned int x)
{
  x -= ((x >> 1) & 0x55555555);
  x = (((x >> 2) & 0x33333333) + (x & 0x33333333));
  x = (((x >> 4) + x) & 0x0f0f0f0f);
  x += (x >> 8);
  x += (x >> 16);
  return (x & 0x0000003f);
}
static unsigned int
fls (register unsigned int x)
{
  return ffs (x & (-x));
}
#define nds32_elf_local_tlsdesc_gotent(bfd) \
  (elf_nds32_tdata (bfd)->local_tlsdesc_gotent)
static bfd_boolean
nds32_elf_relocate_section (bfd *output_bfd ATTRIBUTE_UNUSED,
       struct bfd_link_info *info, bfd *input_bfd,
       asection *input_section, bfd_byte *contents,
       Elf_Internal_Rela *relocs,
       Elf_Internal_Sym *local_syms,
       asection **local_sections)
{
  Elf_Internal_Shdr *symtab_hdr;
  struct elf_link_hash_entry **sym_hashes;
  Elf_Internal_Rela *rel, *relend;
  bfd_boolean ret = TRUE;
  int align = 0;
  bfd_reloc_status_type r;
  const char *errmsg = NULL;
  bfd_vma gp;
  struct elf_link_hash_table *ehtab;
  struct elf_nds32_link_hash_table *htab;
  bfd *dynobj;
  bfd_vma *local_got_offsets;
  asection *sgot, *splt, *sreloc;
  bfd_vma high_address;
  struct elf_nds32_link_hash_table *table;
  int eliminate_gc_relocs;
  bfd_vma fpbase_addr;
  Elf_Internal_Rela *crc_rel = NULL;
  symtab_hdr = &elf_tdata (input_bfd)->symtab_hdr;
  sym_hashes = elf_sym_hashes (input_bfd);
  ehtab = elf_hash_table (info);
  htab = nds32_elf_hash_table (info);
  high_address = bfd_get_section_limit (input_bfd, input_section);
  dynobj = htab->root.dynobj;
  local_got_offsets = elf_local_got_offsets (input_bfd);
  sgot = ehtab->sgot;
  splt = ehtab->splt;
  sreloc = NULL;
  rel = relocs;
  relend = relocs + input_section->reloc_count;
  table = nds32_elf_hash_table (info);
  eliminate_gc_relocs = table->eliminate_gc_relocs;
  if ((!info->relocatable))
    {
      is_SDA_BASE_set = 1;
      r = nds32_elf_final_sda_base (output_bfd, info, &gp, TRUE);
      if (r != bfd_reloc_ok)
 return FALSE;
    }
#ifdef NDS32_LINUX_TOOLCHAIN
  nds32_elf_unify_tls_model (input_bfd, input_section, contents, info);
#endif
  if (indirect_call_table.count > 0)
    nds32_elf_ict_relocate (output_bfd, info);
  fpbase_addr = elf_gp (output_bfd);
  nds32_elf_crc_adjust_reloc (relocs, relend);
  for (rel = relocs; rel < relend; rel++)
    {
      enum elf_nds32_reloc_type r_type;
      reloc_howto_type *howto = NULL;
      unsigned long r_symndx;
      struct elf_link_hash_entry *h = NULL;
      struct bfd_link_hash_entry *h2;
      Elf_Internal_Sym *sym = NULL;
      asection *sec;
      bfd_vma relocation;
      struct elf_nds32_ict_hash_entry *entry;
      bfd_vma relocation_sym = 0xdeadbeef;
      Elf_Internal_Rela *lorel;
      bfd_vma off;
      bfd_vma addend = rel->r_addend;
      bfd_vma offset = rel->r_offset;
      r_type = ELF32_R_TYPE (rel->r_info);
      if (r_type >= R_NDS32_max)
 {
   (*_bfd_error_handler) (_("%B: error: unknown relocation type %d."),
     input_bfd, r_type);
   bfd_set_error (bfd_error_bad_value);
   ret = FALSE;
   continue;
 }
      if (r_type == R_NDS32_GNU_VTENTRY
   || r_type == R_NDS32_GNU_VTINHERIT
   || r_type == R_NDS32_NONE
   || r_type == R_NDS32_RELA_GNU_VTENTRY
   || r_type == R_NDS32_RELA_GNU_VTINHERIT
   || (r_type >= R_NDS32_INSN16 && r_type <= R_NDS32_25_FIXED_RELA)
   || r_type == R_NDS32_DATA
   || r_type == R_NDS32_TRAN
   || (r_type >= R_NDS32_LONGCALL4 && r_type <= R_NDS32_LONGJUMP7))
 continue;
      if (r_type == R_NDS32_SECURITY_16 && crc_rel == NULL)
 {
   crc_rel = rel;
   continue;
 }
      if (ELF32_R_TYPE (rel->r_info) == R_NDS32_RELAX_REGION_BEGIN
   && (rel->r_addend & R_NDS32_RELAX_REGION_OMIT_FP_FLAG))
 {
   int dist;
   dist = rel->r_addend >> 16;
   fpbase_addr = calculate_memory_address (input_bfd, rel + dist,
        local_syms, symtab_hdr);
 }
      else if (ELF32_R_TYPE (rel->r_info) == R_NDS32_RELAX_REGION_END
        && (rel->r_addend & R_NDS32_RELAX_REGION_OMIT_FP_FLAG))
 {
   fpbase_addr = elf_gp (output_bfd);
 }
      if (r_type >= R_NDS32_RELAX_ENTRY && !info->relocatable)
 continue;
      howto = bfd_elf32_bfd_reloc_type_table_lookup (r_type);
      r_symndx = ELF32_R_SYM (rel->r_info);
      sym = NULL;
      sec = NULL;
      h = NULL;
      if (r_symndx < symtab_hdr->sh_info)
 {
   sym = local_syms + r_symndx;
   sec = local_sections[r_symndx];
   relocation = _bfd_elf_rela_local_sym (output_bfd, sym, &sec, rel);
   addend = rel->r_addend;
   relocation_sym = relocation;
   if (info->relocatable)
     {
       if (sym != NULL && ELF_ST_TYPE (sym->st_info) == STT_SECTION)
  rel->r_addend += sec->output_offset + sym->st_value;
       continue;
     }
 }
      else
 {
   if (info->relocatable)
     continue;
   bfd_boolean warned, unresolved_reloc;
   int symndx = r_symndx - symtab_hdr->sh_info;
   RELOC_FOR_GLOBAL_SYMBOL (info, input_bfd, input_section, rel,
       r_symndx, symtab_hdr, sym_hashes, h, sec,
       relocation, unresolved_reloc, warned);
   relocation_sym = relocation;
   switch ((int) r_type)
     {
     case R_NDS32_HI20_RELA:
     case R_NDS32_LO12S0_RELA:
       if (strcmp (elf_sym_hashes (input_bfd)[symndx]->root.root.string,
     FP_BASE_NAME) == 0)
  {
  if (!info->pie)
    {
      (*_bfd_error_handler)
        ("%B: warning: _FP_BASE_ setting insns relaxation failed.",
        input_bfd);
    }
    relocation = fpbase_addr;
    break;
  }
     case R_NDS32_SDA19S0_RELA:
     case R_NDS32_SDA15S0_RELA:
     case R_NDS32_20_RELA:
       if (strcmp (elf_sym_hashes (input_bfd)[symndx]->root.root.string,
     FP_BASE_NAME) == 0)
  {
    relocation = fpbase_addr;
    break;
  }
     }
 }
      if (offset > high_address)
 {
   r = bfd_reloc_outofrange;
   goto check_reloc;
 }
      if (r_type >= R_NDS32_RELAX_ENTRY)
 continue;
      switch ((int) r_type)
 {
 case R_NDS32_GOTOFF:
 case R_NDS32_GOTOFF_HI20:
 case R_NDS32_GOTOFF_LO12:
 case R_NDS32_GOTOFF_LO15:
 case R_NDS32_GOTOFF_LO19:
   BFD_ASSERT (sgot != NULL);
   relocation -= elf_gp (output_bfd);
   break;
 case R_NDS32_9_PLTREL:
 case R_NDS32_25_PLTREL:
   if (h == NULL)
     break;
   if (h->forced_local)
     break;
   if (h->plt.offset == (bfd_vma) - 1)
     break;
   relocation = (splt->output_section->vma
   + splt->output_offset + h->plt.offset);
   break;
 case R_NDS32_PLT_GOTREL_HI20:
 case R_NDS32_PLT_GOTREL_LO12:
 case R_NDS32_PLT_GOTREL_LO15:
 case R_NDS32_PLT_GOTREL_LO19:
 case R_NDS32_PLT_GOTREL_LO20:
   if (h == NULL
       || h->forced_local
       || h->plt.offset == (bfd_vma) -1
       || (info->pie && h->def_regular))
     {
       if (h)
  h->plt.offset = (bfd_vma) -1;
       relocation -= elf_gp(output_bfd);
       break;
     }
   relocation = (splt->output_section->vma
   + splt->output_offset + h->plt.offset);
   relocation -= elf_gp (output_bfd);
   break;
 case R_NDS32_PLTREL_HI20:
 case R_NDS32_PLTREL_LO12:
   if (h == NULL)
     break;
   if (h->forced_local)
     break;
   if (h->plt.offset == (bfd_vma) - 1)
     break;
   if (splt == NULL)
     break;
   relocation = (splt->output_section->vma
   + splt->output_offset
   + h->plt.offset + 4)
         - (input_section->output_section->vma
     + input_section->output_offset
     + rel->r_offset);
   break;
 case R_NDS32_GOTPC20:
   relocation = elf_gp (output_bfd);
   break;
 case R_NDS32_GOTPC_HI20:
 case R_NDS32_GOTPC_LO12:
   relocation = elf_gp (output_bfd);
   relocation -= (input_section->output_section->vma
    + input_section->output_offset + rel->r_offset);
   break;
 case R_NDS32_GOT20:
 case R_NDS32_GOT_HI20:
 case R_NDS32_GOT_LO12:
 case R_NDS32_GOT_LO15:
 case R_NDS32_GOT_LO19:
   BFD_ASSERT (sgot != NULL);
   if (h != NULL)
     {
       bfd_boolean dyn;
       off = h->got.offset;
       BFD_ASSERT (off != (bfd_vma) - 1);
       dyn = htab->root.dynamic_sections_created;
       if (!WILL_CALL_FINISH_DYNAMIC_SYMBOL (dyn, info->shared, h)
    || (info->shared
        && (info->symbolic
     || h->dynindx == -1
     || h->forced_local) && h->def_regular))
  {
    if ((off & 1) != 0)
      off &= ~1;
    else
      {
        bfd_put_32 (output_bfd, relocation, sgot->contents + off);
        h->got.offset |= 1;
      }
  }
       relocation = sgot->output_section->vma + sgot->output_offset + off
  - elf_gp (output_bfd);
     }
   else
     {
       bfd_byte *loc;
       BFD_ASSERT (local_got_offsets != NULL
     && local_got_offsets[r_symndx] != (bfd_vma) - 1);
       off = local_got_offsets[r_symndx];
       if ((off & 1) != 0)
  off &= ~1;
       else
  {
    bfd_put_32 (output_bfd, relocation, sgot->contents + off);
    if (info->shared)
      {
        asection *srelgot;
        Elf_Internal_Rela outrel;
        srelgot = bfd_get_section_by_name (dynobj, ".rela.got");
        BFD_ASSERT (srelgot != NULL);
        outrel.r_offset = (elf_gp (output_bfd)
      + sgot->output_offset + off);
        outrel.r_info = ELF32_R_INFO (0, R_NDS32_RELATIVE);
        outrel.r_addend = relocation;
        loc = srelgot->contents;
        loc +=
   srelgot->reloc_count * sizeof (Elf32_External_Rela);
        bfd_elf32_swap_reloca_out (output_bfd, &outrel, loc);
        ++srelgot->reloc_count;
      }
    local_got_offsets[r_symndx] |= 1;
  }
       relocation = sgot->output_section->vma + sgot->output_offset + off
  - elf_gp (output_bfd);
     }
   break;
 case R_NDS32_25_PCREL_RELA:
 case R_NDS32_HI20_RELA:
 case R_NDS32_LO12S0_RELA:
 case R_NDS32_LO12S2_RELA:
   if (!ignore_indirect_call && h
       && elf32_nds32_hash_entry (h)->indirect_call)
     {
       if (ict_model == R_NDS32_RELAX_ENTRY_ICT_LARGE)
  {
    (*_bfd_error_handler)
      (_("%B: Error: there are mixed indirect call function in"
         " ICT large model\'%s\'\n"),
       input_bfd, h->root.root.string);
    bfd_set_error (bfd_error_bad_value);
    return FALSE;
  }
       else
  (*_bfd_error_handler)
    (_("%B: Warning: there are mixed indirect call function"
       " \'%s\'\n"), input_bfd, h->root.root.string);
       entry = (struct elf_nds32_ict_hash_entry*)
  bfd_hash_lookup (&indirect_call_table, h->root.root.string,
     FALSE, FALSE);
       if (!entry)
  {
    (*_bfd_error_handler)
      (_("%B %A: internal error indirect call relocation "
         "0x%lx without hash.\n"),
       input_bfd, sec, rel->r_offset);
    bfd_set_error (bfd_error_bad_value);
    return FALSE;
  }
       h2 = bfd_link_hash_lookup (info->hash,
      "_INDIRECT_CALL_TABLE_BASE_",
      FALSE, FALSE, FALSE);
       relocation = ((h2->u.def.value
        + h2->u.def.section->output_section->vma
        + h2->u.def.section->output_offset)
       + (entry->order * 4));
       break;
     }
 case R_NDS32_16_RELA:
 case R_NDS32_20_RELA:
 case R_NDS32_5_RELA:
 case R_NDS32_32_RELA:
 case R_NDS32_9_PCREL_RELA:
 case R_NDS32_WORD_9_PCREL_RELA:
 case R_NDS32_10_UPCREL_RELA:
 case R_NDS32_15_PCREL_RELA:
 case R_NDS32_17_PCREL_RELA:
 case R_NDS32_LO12S3_RELA:
 case R_NDS32_LO12S2_DP_RELA:
 case R_NDS32_LO12S2_SP_RELA:
 case R_NDS32_LO12S1_RELA:
 case R_NDS32_LO12S0_ORI_RELA:
   if (info->shared && r_symndx != 0
       && (input_section->flags & SEC_ALLOC) != 0
       && (eliminate_gc_relocs == 0
    || (sec && (sec->flags & SEC_EXCLUDE) == 0))
       && ((r_type != R_NDS32_9_PCREL_RELA
     && r_type != R_NDS32_WORD_9_PCREL_RELA
     && r_type != R_NDS32_10_UPCREL_RELA
     && r_type != R_NDS32_15_PCREL_RELA
     && r_type != R_NDS32_17_PCREL_RELA
     && r_type != R_NDS32_25_PCREL_RELA
     && !(r_type == R_NDS32_32_RELA
   && strcmp (input_section->name, ".eh_frame") == 0))
    || (h != NULL && h->dynindx != -1
        && (!info->symbolic || !h->def_regular))))
     {
       Elf_Internal_Rela outrel;
       bfd_boolean skip, relocate;
       bfd_byte *loc;
       if (sreloc == NULL)
  {
    const char *name;
    name = bfd_elf_string_from_elf_section
      (input_bfd, elf_elfheader (input_bfd)->e_shstrndx,
       elf_section_data (input_section)->rela.hdr->sh_name);
    if (name == NULL)
      return FALSE;
    BFD_ASSERT (strncmp (name, ".rela", 5) == 0
         && strcmp (bfd_get_section_name (input_bfd,
              input_section),
      name + 5) == 0);
    sreloc = bfd_get_section_by_name (dynobj, name);
    BFD_ASSERT (sreloc != NULL);
  }
       skip = FALSE;
       relocate = FALSE;
       outrel.r_offset = _bfd_elf_section_offset (output_bfd,
        info,
        input_section,
        rel->r_offset);
       if (outrel.r_offset == (bfd_vma) - 1)
  skip = TRUE;
       else if (outrel.r_offset == (bfd_vma) - 2)
  skip = TRUE, relocate = TRUE;
       outrel.r_offset += (input_section->output_section->vma
      + input_section->output_offset);
       if (skip)
  memset (&outrel, 0, sizeof outrel);
       else if (r_type == R_NDS32_17_PCREL_RELA
         || r_type == R_NDS32_15_PCREL_RELA
         || r_type == R_NDS32_25_PCREL_RELA)
  {
    BFD_ASSERT (h != NULL && h->dynindx != -1);
    outrel.r_info = ELF32_R_INFO (h->dynindx, r_type);
    outrel.r_addend = rel->r_addend;
  }
       else
  {
    if (h == NULL
        || ((info->symbolic || h->dynindx == -1)
     && h->def_regular)
        || (info->pie && h->def_regular))
      {
        relocate = TRUE;
        outrel.r_info = ELF32_R_INFO (0, R_NDS32_RELATIVE);
        outrel.r_addend = relocation + rel->r_addend;
        if (h)
   {
     h->plt.offset = (bfd_vma) -1;
     BFD_ASSERT (sgot != NULL);
     if (h->got.offset != (bfd_vma) -1 && (h->got.offset & 1) == 0)
       {
         bfd_put_32 (output_bfd, outrel.r_addend,
       sgot->contents + h->got.offset);
       }
   }
      }
    else
      {
        if (h->dynindx == -1)
   {
     (*_bfd_error_handler)
       (_("%B: relocation %s against `%s' can not be used when"
          "making a shared object; recompile with -fPIC"),
        input_bfd, nds32_elf_howto_table[r_type].name, h->root.root.string);
     bfd_set_error (bfd_error_bad_value);
     return FALSE;
   }
        outrel.r_info = ELF32_R_INFO (h->dynindx, r_type);
        outrel.r_addend = rel->r_addend;
      }
  }
       loc = sreloc->contents;
       loc += sreloc->reloc_count * sizeof (Elf32_External_Rela);
       bfd_elf32_swap_reloca_out (output_bfd, &outrel, loc);
       ++sreloc->reloc_count;
       if (!relocate)
  continue;
     }
   break;
 case R_NDS32_25_ABS_RELA:
   if (info->shared)
     {
       (*_bfd_error_handler)
  (_("%s: warning: cannot deal R_NDS32_25_ABS_RELA in shared mode."),
   bfd_get_filename (input_bfd));
       return FALSE;
     }
   break;
 case R_NDS32_9_PCREL:
   r = nds32_elf_do_9_pcrel_reloc (input_bfd, howto, input_section,
       contents, offset,
       sec, relocation, addend);
   goto check_reloc;
 case R_NDS32_HI20:
   for (lorel = rel + 1;
        (lorel < relend
  && ELF32_R_TYPE (lorel->r_info) == R_NDS32_HI20); lorel++)
     continue;
   if (lorel < relend
       && (ELF32_R_TYPE (lorel->r_info) == R_NDS32_LO12S3
    || ELF32_R_TYPE (lorel->r_info) == R_NDS32_LO12S2
    || ELF32_R_TYPE (lorel->r_info) == R_NDS32_LO12S1
    || ELF32_R_TYPE (lorel->r_info) == R_NDS32_LO12S0))
     {
       nds32_elf_relocate_hi20 (input_bfd, r_type, rel, lorel,
           contents, relocation + addend);
       r = bfd_reloc_ok;
     }
   else
     r = _bfd_final_link_relocate (howto, input_bfd, input_section,
       contents, offset, relocation,
       addend);
   goto check_reloc;
 case R_NDS32_GOT17S2_RELA:
 case R_NDS32_GOT15S2_RELA:
   BFD_ASSERT (sgot != NULL);
   if (h != NULL)
     {
       bfd_boolean dyn;
       off = h->got.offset;
       BFD_ASSERT (off != (bfd_vma) - 1);
       dyn = htab->root.dynamic_sections_created;
       if (!WILL_CALL_FINISH_DYNAMIC_SYMBOL
    (dyn, info->shared, h) || (info->shared
          && (info->symbolic
       || h->dynindx == -1
       || h->forced_local)
          && h->def_regular))
  {
    if ((off & 1) != 0)
      off &= ~1;
    else
      {
        bfd_put_32 (output_bfd, relocation,
      sgot->contents + off);
        h->got.offset |= 1;
      }
  }
     }
   else
     {
       bfd_byte *loc;
       BFD_ASSERT (local_got_offsets != NULL
     && local_got_offsets[r_symndx] != (bfd_vma) - 1);
       off = local_got_offsets[r_symndx];
       if ((off & 1) != 0)
  off &= ~1;
       else
  {
    bfd_put_32 (output_bfd, relocation, sgot->contents + off);
    if (info->shared)
      {
        asection *srelgot;
        Elf_Internal_Rela outrel;
        srelgot = bfd_get_section_by_name (dynobj, ".rela.got");
        BFD_ASSERT (srelgot != NULL);
        outrel.r_offset = (elf_gp (output_bfd)
      + sgot->output_offset + off);
        outrel.r_info = ELF32_R_INFO (0, R_NDS32_RELATIVE);
        outrel.r_addend = relocation;
        loc = srelgot->contents;
        loc +=
   srelgot->reloc_count * sizeof (Elf32_External_Rela);
        bfd_elf32_swap_reloca_out (output_bfd, &outrel, loc);
        ++srelgot->reloc_count;
      }
    local_got_offsets[r_symndx] |= 1;
  }
     }
   relocation = sgot->output_section->vma + sgot->output_offset + off
     - elf_gp (output_bfd);
   if (relocation & align)
     {
       (*_bfd_error_handler)
  (_("%B: warning: unaligned access to GOT entry."), input_bfd);
       ret = FALSE;
       r = bfd_reloc_dangerous;
       goto check_reloc;
     }
   break;
 case R_NDS32_SDA16S3_RELA:
 case R_NDS32_SDA15S3_RELA:
 case R_NDS32_SDA15S3:
   align = 0x7;
   goto handle_sda;
 case R_NDS32_SDA17S2_RELA:
 case R_NDS32_SDA15S2_RELA:
 case R_NDS32_SDA12S2_SP_RELA:
 case R_NDS32_SDA12S2_DP_RELA:
 case R_NDS32_SDA15S2:
 case R_NDS32_SDA_FP7U2_RELA:
   align = 0x3;
   goto handle_sda;
 case R_NDS32_SDA18S1_RELA:
 case R_NDS32_SDA15S1_RELA:
 case R_NDS32_SDA15S1:
   align = 0x1;
   goto handle_sda;
 case R_NDS32_SDA19S0_RELA:
 case R_NDS32_SDA15S0_RELA:
 case R_NDS32_SDA15S0:
   align = 0x0;
handle_sda:
   BFD_ASSERT (sec != NULL);
   r = nds32_elf_final_sda_base (output_bfd, info, &gp, FALSE);
   if (r != bfd_reloc_ok)
     {
       (*_bfd_error_handler)
  (_("%B: warning: relocate SDA_BASE failed."), input_bfd);
       ret = FALSE;
       goto check_reloc;
     }
   if (r_type == R_NDS32_SDA_FP7U2_RELA)
     {
       relocation -= fpbase_addr;
     }
   else
     relocation -= gp;
   if (relocation & align)
     {
       (*_bfd_error_handler)
  (_("%B(%A): warning: unaligned small data access of type %d."),
   input_bfd, input_section, r_type);
       ret = FALSE;
       goto check_reloc;
     }
   break;
 case R_NDS32_17IFC_PCREL_RELA:
 case R_NDS32_10IFCU_PCREL_RELA:
   ifc_flag = TRUE;
   break;
 case R_NDS32_TLS_LE_HI20:
 case R_NDS32_TLS_LE_LO12:
 case R_NDS32_TLS_LE_20:
 case R_NDS32_TLS_LE_15S0:
 case R_NDS32_TLS_LE_15S1:
 case R_NDS32_TLS_LE_15S2:
   if (elf_hash_table (info)->tls_sec != NULL)
     relocation -= (elf_hash_table (info)->tls_sec->vma + TP_OFFSET);
   break;
 case R_NDS32_TLS_IE_HI20:
 case R_NDS32_TLS_IE_LO12S2:
 case R_NDS32_TLS_DESC_HI20:
 case R_NDS32_TLS_DESC_LO12:
 case R_NDS32_TLS_IE_LO12:
 case R_NDS32_TLS_IEGP_HI20:
 case R_NDS32_TLS_IEGP_LO12:
 case R_NDS32_TLS_IEGP_LO12S2:
   {
     enum elf_nds32_tls_type tls_type, org_tls_type, eff_tls_type;
     asection *srelgot;
     Elf_Internal_Rela outrel;
     bfd_byte *loc;
     int indx = 0;
     eff_tls_type = org_tls_type = get_tls_type (r_type, h);
     BFD_ASSERT (sgot != NULL);
     if (h != NULL)
       {
  bfd_boolean dyn;
  off = h->got.offset;
  BFD_ASSERT (off != (bfd_vma) -1);
  dyn = htab->root.dynamic_sections_created;
  tls_type = ((struct elf_nds32_link_hash_entry *) h)->tls_type;
  if (WILL_CALL_FINISH_DYNAMIC_SYMBOL (dyn, info->shared, h)
      && (!info->shared
   || !SYMBOL_REFERENCES_LOCAL (info, h)))
    indx = h->dynindx;
       }
     else
       {
  BFD_ASSERT (local_got_offsets != NULL
       && local_got_offsets[r_symndx] != (bfd_vma) - 1);
  off = local_got_offsets[r_symndx];
  tls_type = elf32_nds32_local_got_tls_type (input_bfd)[r_symndx];
       }
     relocation = sgot->output_section->vma + sgot->output_offset + off;
     if (1 < ones32 (tls_type))
       {
  eff_tls_type = 1 << (fls (tls_type) - 1);
  if (eff_tls_type == GOT_TLS_LE)
    {
      eff_tls_type = 1 << (fls (tls_type ^ eff_tls_type) - 1);
    }
       }
     bfd_boolean need_relocs = FALSE;
     srelgot = ehtab->srelgot;
     if ((info->shared || indx != 0)
  && (h == NULL || ELF_ST_VISIBILITY (h->other) == STV_DEFAULT
      || h->root.type != bfd_link_hash_undefweak))
       {
  need_relocs = TRUE;
  BFD_ASSERT (srelgot != NULL);
       }
     if (off & 1)
       {
  off &= ~1;
  relocation &= ~1;
  if (eff_tls_type & GOT_TLS_DESC)
    {
      relocation -= elf_gp (output_bfd);
      if ((R_NDS32_TLS_DESC_HI20 == r_type) && (!need_relocs))
        {
   BFD_ASSERT(0);
        }
    }
  else if (eff_tls_type & GOT_TLS_IEGP)
    {
        relocation -= elf_gp (output_bfd);
    }
       }
     else
       {
  if ((eff_tls_type & GOT_TLS_LE) && (tls_type ^ eff_tls_type))
    {
      BFD_ASSERT(0);
    }
  else if (eff_tls_type & (GOT_TLS_IE | GOT_TLS_IEGP))
    {
      if (eff_tls_type & GOT_TLS_IEGP)
        relocation -= elf_gp(output_bfd);
      if (need_relocs)
        {
   if (indx == 0)
     outrel.r_addend = gottpoff (info, relocation_sym);
   else
     outrel.r_addend = 0;
   outrel.r_offset = (sgot->output_section->vma
        + sgot->output_offset + off);
   outrel.r_info = ELF32_R_INFO (indx, R_NDS32_TLS_TPOFF);
   elf32_nds32_add_dynreloc (output_bfd, info, srelgot,
        &outrel);
        }
      else
        {
   bfd_put_32 (output_bfd, gottpoff (info, relocation_sym),
        sgot->contents + off);
        }
    }
  else if (eff_tls_type & GOT_TLS_DESC)
    {
      relocation -= elf_gp (output_bfd);
      if (need_relocs)
        {
   if (indx == 0)
     outrel.r_addend = gottpoff (info, relocation_sym);
   else
     outrel.r_addend = 0;
   outrel.r_offset = (sgot->output_section->vma
        + sgot->output_offset + off);
   outrel.r_info = ELF32_R_INFO (indx, R_NDS32_TLS_DESC);
   if (htab->tls_desc_trampoline)
     {
       asection *srelplt;
       srelplt = ehtab->srelplt;
       loc = srelplt->contents;
       loc += htab->next_tls_desc_index++ * sizeof (Elf32_External_Rela);
       BFD_ASSERT (loc + sizeof (Elf32_External_Rela)
     <= srelplt->contents + srelplt->size);
       bfd_elf32_swap_reloca_out (output_bfd, &outrel, loc);
     }
   else
     {
       loc = srelgot->contents;
       loc += srelgot->reloc_count * sizeof (Elf32_External_Rela);
       bfd_elf32_swap_reloca_out (output_bfd, &outrel, loc);
       ++srelgot->reloc_count;
     }
        }
      else
        {
   bfd_put_32 (output_bfd, 0xdeadbeef,
        sgot->contents + off);
   bfd_put_32 (output_bfd, gottpoff (info, relocation_sym),
        sgot->contents + off + 4);
   patch_tls_desc_to_ie (contents, rel, input_bfd);
   BFD_ASSERT(0);
        }
    }
  else
    {
      BFD_ASSERT(0);
    }
  if (h != NULL)
    h->got.offset |= 1;
  else
    local_got_offsets[r_symndx] |= 1;
       }
   }
   break;
 case R_NDS32_SECURITY_16:
   relocation = 0;
   crc_rel->r_addend = NDS32_SECURITY_NONE;
   r = nds32_elf_final_link_relocate (howto, input_bfd,
          input_section, contents,
          crc_rel->r_offset, relocation,
          crc_rel->r_addend);
   crc_rel = NULL;
   goto check_reloc;
   break;
 case R_NDS32_ICT_HI20:
 case R_NDS32_ICT_LO12:
 case R_NDS32_ICT_25PC:
 case R_NDS32_ICT_LO12S2:
   entry = (struct elf_nds32_ict_hash_entry*)
     bfd_hash_lookup (&indirect_call_table, h->root.root.string,
        FALSE, FALSE);
   if (!entry)
     {
       (*_bfd_error_handler)
  (_("%B %A: internal error indirect call relocation "
     "0x%lx without hash.\n"),
   input_bfd, sec, rel->r_offset);
       bfd_set_error (bfd_error_bad_value);
       return FALSE;
     }
   h2 = bfd_link_hash_lookup (info->hash,
         "_INDIRECT_CALL_TABLE_BASE_",
         FALSE, FALSE, FALSE);
   relocation = ((h2->u.def.value
    + h2->u.def.section->output_section->vma
    + h2->u.def.section->output_offset)
   + (entry->order * 4));
   break;
 default:
   r = _bfd_final_link_relocate (howto, input_bfd, input_section,
     contents, offset, relocation, addend);
   goto check_reloc;
 }
      switch ((int) r_type)
 {
 case R_NDS32_20_RELA:
 case R_NDS32_5_RELA:
 case R_NDS32_9_PCREL_RELA:
 case R_NDS32_WORD_9_PCREL_RELA:
 case R_NDS32_10_UPCREL_RELA:
 case R_NDS32_15_PCREL_RELA:
 case R_NDS32_17_PCREL_RELA:
 case R_NDS32_25_PCREL_RELA:
 case R_NDS32_25_ABS_RELA:
 case R_NDS32_HI20_RELA:
 case R_NDS32_LO12S3_RELA:
 case R_NDS32_LO12S2_RELA:
 case R_NDS32_LO12S2_DP_RELA:
 case R_NDS32_LO12S2_SP_RELA:
 case R_NDS32_LO12S1_RELA:
 case R_NDS32_LO12S0_RELA:
 case R_NDS32_LO12S0_ORI_RELA:
 case R_NDS32_SDA16S3_RELA:
 case R_NDS32_SDA17S2_RELA:
 case R_NDS32_SDA18S1_RELA:
 case R_NDS32_SDA19S0_RELA:
 case R_NDS32_SDA15S3_RELA:
 case R_NDS32_SDA15S2_RELA:
 case R_NDS32_SDA12S2_DP_RELA:
 case R_NDS32_SDA12S2_SP_RELA:
 case R_NDS32_SDA15S1_RELA:
 case R_NDS32_SDA15S0_RELA:
 case R_NDS32_SDA_FP7U2_RELA:
 case R_NDS32_9_PLTREL:
 case R_NDS32_25_PLTREL:
 case R_NDS32_GOT20:
 case R_NDS32_GOT_HI20:
 case R_NDS32_GOT_LO12:
 case R_NDS32_GOT_LO15:
 case R_NDS32_GOT_LO19:
 case R_NDS32_GOT15S2_RELA:
 case R_NDS32_GOT17S2_RELA:
 case R_NDS32_GOTPC20:
 case R_NDS32_GOTPC_HI20:
 case R_NDS32_GOTPC_LO12:
 case R_NDS32_GOTOFF:
 case R_NDS32_GOTOFF_HI20:
 case R_NDS32_GOTOFF_LO12:
 case R_NDS32_GOTOFF_LO15:
 case R_NDS32_GOTOFF_LO19:
 case R_NDS32_PLTREL_HI20:
 case R_NDS32_PLTREL_LO12:
 case R_NDS32_PLT_GOTREL_HI20:
 case R_NDS32_PLT_GOTREL_LO12:
 case R_NDS32_PLT_GOTREL_LO15:
 case R_NDS32_PLT_GOTREL_LO19:
 case R_NDS32_PLT_GOTREL_LO20:
 case R_NDS32_17IFC_PCREL_RELA:
 case R_NDS32_10IFCU_PCREL_RELA:
 case R_NDS32_TLS_LE_HI20:
 case R_NDS32_TLS_LE_LO12:
 case R_NDS32_TLS_IE_HI20:
 case R_NDS32_TLS_IE_LO12S2:
 case R_NDS32_TLS_LE_20:
 case R_NDS32_TLS_LE_15S0:
 case R_NDS32_TLS_LE_15S1:
 case R_NDS32_TLS_LE_15S2:
 case R_NDS32_TLS_DESC_HI20:
 case R_NDS32_TLS_DESC_LO12:
 case R_NDS32_TLS_IE_LO12:
 case R_NDS32_TLS_IEGP_HI20:
 case R_NDS32_TLS_IEGP_LO12:
 case R_NDS32_TLS_IEGP_LO12S2:
   r = nds32_elf_final_link_relocate (howto, input_bfd,
          input_section, contents,
          rel->r_offset, relocation,
          rel->r_addend);
   break;
 case R_NDS32_ICT_HI20:
 case R_NDS32_ICT_LO12:
 case R_NDS32_ICT_25PC:
 case R_NDS32_ICT_LO12S2:
   r = nds32_elf_final_link_relocate (howto, input_bfd, input_section,
          contents, rel->r_offset,
          relocation, 0);
   break;
 default:
   r = _bfd_final_link_relocate (howto, input_bfd, input_section,
     contents, rel->r_offset,
     relocation, rel->r_addend);
   break;
 }
check_reloc:
      if (r != bfd_reloc_ok)
 {
   const char *name;
   if (h != NULL)
     name = h->root.root.string;
   else
     {
       name = bfd_elf_string_from_elf_section
        (input_bfd, symtab_hdr->sh_link, sym->st_name);
       if (name == NULL || *name == '\0')
  name = bfd_section_name (input_bfd, sec);
     }
   if (errmsg != NULL)
     goto common_error;
   switch (r)
     {
     case bfd_reloc_overflow:
       if (r_type == R_NDS32_17IFC_PCREL_RELA)
  {
    (*_bfd_error_handler)
      (_("\n%B: (%A+0x%x): The IFC optimization range exceeded.\n"
         "Please turn off the IFC optimization (-mno-ifc) when "
         "compiling the file %s.\n"),
       input_bfd, sec, rel->r_offset,
       h->root.u.def.section->owner->filename);
    bfd_set_error (bfd_error_bad_value);
  }
       if (!((*info->callbacks->reloc_overflow)
      (info, (h ? &h->root : NULL), name, howto->name,
       (bfd_vma) 0, input_bfd, input_section, offset)))
  return FALSE;
       break;
     case bfd_reloc_undefined:
       if (!((*info->callbacks->undefined_symbol)
      (info, name, input_bfd, input_section, offset, TRUE)))
  return FALSE;
       break;
     case bfd_reloc_outofrange:
       errmsg = _("internal error: out of range error");
       goto common_error;
     case bfd_reloc_notsupported:
       errmsg = _("internal error: unsupported relocation error");
       goto common_error;
     case bfd_reloc_dangerous:
       errmsg = _("internal error: dangerous error");
       goto common_error;
     default:
       errmsg = _("internal error: unknown error");
common_error:
       if (!((*info->callbacks->warning)
      (info, errmsg, name, input_bfd, input_section, offset)))
  return FALSE;
       break;
     }
 }
    }
  if (elf_nds32_tdata (input_bfd)->hdr_size != 0)
    symtab_hdr->sh_size = elf_nds32_tdata (input_bfd)->hdr_size;
  return ret;
}
static bfd_boolean
nds32_elf_finish_dynamic_symbol (bfd *output_bfd, struct bfd_link_info *info,
     struct elf_link_hash_entry *h,
     Elf_Internal_Sym *sym)
{
  struct elf_link_hash_table *ehtab;
  struct elf_nds32_link_hash_entry *hent;
  bfd_byte *loc;
  ehtab = elf_hash_table (info);
  hent = (struct elf_nds32_link_hash_entry *) h;
  if (h->plt.offset != (bfd_vma) - 1)
    {
      asection *splt;
      asection *sgot;
      asection *srela;
      bfd_vma plt_index;
      bfd_vma got_offset;
      bfd_vma local_plt_offset;
      Elf_Internal_Rela rela;
      BFD_ASSERT (h->dynindx != -1);
      splt = ehtab->splt;
      sgot = ehtab->sgotplt;
      srela = ehtab->srelplt;
      BFD_ASSERT (splt != NULL && sgot != NULL && srela != NULL);
      plt_index = h->plt.offset / PLT_ENTRY_SIZE - 1;
      got_offset = (plt_index + 3) * 4;
      if (!info->shared)
 {
   unsigned long insn;
   insn = PLT_ENTRY_WORD0 + (((sgot->output_section->vma
          + sgot->output_offset + got_offset) >> 12)
        & 0xfffff);
   bfd_putb32 (insn, splt->contents + h->plt.offset);
   insn = PLT_ENTRY_WORD1 + (((sgot->output_section->vma
          + sgot->output_offset + got_offset) & 0x0fff)
        >> 2);
   bfd_putb32 (insn, splt->contents + h->plt.offset + 4);
   insn = PLT_ENTRY_WORD2;
   bfd_putb32 (insn, splt->contents + h->plt.offset + 8);
   insn = PLT_ENTRY_WORD3 + (plt_index & 0x7ffff);
   bfd_putb32 (insn, splt->contents + h->plt.offset + 12);
   insn = PLT_ENTRY_WORD4
     + (((unsigned int) ((-(h->plt.offset + 16)) >> 1)) & 0xffffff);
   bfd_putb32 (insn, splt->contents + h->plt.offset + 16);
   local_plt_offset = 12;
 }
      else
 {
   unsigned long insn;
   long offset;
   offset = sgot->output_section->vma + sgot->output_offset + got_offset
     - elf_gp (output_bfd);
   insn = PLT_PIC_ENTRY_WORD0 + ((offset >> 12) & 0xfffff);
   bfd_putb32 (insn, splt->contents + h->plt.offset);
   insn = PLT_PIC_ENTRY_WORD1 + (offset & 0xfff);
   bfd_putb32 (insn, splt->contents + h->plt.offset + 4);
   insn = PLT_PIC_ENTRY_WORD2;
   bfd_putb32 (insn, splt->contents + h->plt.offset + 8);
   insn = PLT_PIC_ENTRY_WORD3;
   bfd_putb32 (insn, splt->contents + h->plt.offset + 12);
   insn = PLT_PIC_ENTRY_WORD4 + (plt_index & 0x7fffff);
   bfd_putb32 (insn, splt->contents + h->plt.offset + 16);
   insn = PLT_PIC_ENTRY_WORD5
     + (((unsigned int) ((-(h->plt.offset + 20)) >> 1)) & 0xffffff);
   bfd_putb32 (insn, splt->contents + h->plt.offset + 20);
   local_plt_offset = 16;
 }
      bfd_put_32 (output_bfd,
    (splt->output_section->vma + splt->output_offset
     + h->plt.offset + local_plt_offset),
    sgot->contents + got_offset);
      rela.r_offset = (sgot->output_section->vma
         + sgot->output_offset + got_offset);
      rela.r_info = ELF32_R_INFO (h->dynindx, R_NDS32_JMP_SLOT);
      rela.r_addend = 0;
      loc = srela->contents;
      loc += plt_index * sizeof (Elf32_External_Rela);
      bfd_elf32_swap_reloca_out (output_bfd, &rela, loc);
      if (!h->def_regular)
 {
   sym->st_shndx = SHN_UNDEF;
   if (!h->ref_regular_nonweak)
     sym->st_value = 0;
 }
    }
  if ((h->got.offset != (bfd_vma) -1) && (hent->tls_type == GOT_NORMAL))
    {
      asection *sgot;
      asection *srelagot;
      Elf_Internal_Rela rela;
      sgot = ehtab->sgot;
      srelagot = ehtab->srelgot;
      BFD_ASSERT (sgot != NULL && srelagot != NULL);
      rela.r_offset = (sgot->output_section->vma
         + sgot->output_offset + (h->got.offset & ~1));
      if ((info->shared
     && (info->symbolic || h->dynindx == -1 || h->forced_local)
     && h->def_regular)
   || (info->pie && h->def_regular))
 {
   rela.r_info = ELF32_R_INFO (0, R_NDS32_RELATIVE);
   rela.r_addend = (h->root.u.def.value
       + h->root.u.def.section->output_section->vma
       + h->root.u.def.section->output_offset);
   if ((h->got.offset & 1) == 0)
     {
       bfd_put_32 (output_bfd, rela.r_addend,
     sgot->contents + h->got.offset);
     }
 }
      else
 {
   BFD_ASSERT ((h->got.offset & 1) == 0);
   bfd_put_32 (output_bfd, (bfd_vma) 0,
        sgot->contents + h->got.offset);
   rela.r_info = ELF32_R_INFO (h->dynindx, R_NDS32_GLOB_DAT);
   rela.r_addend = 0;
 }
      loc = srelagot->contents;
      loc += srelagot->reloc_count * sizeof (Elf32_External_Rela);
      bfd_elf32_swap_reloca_out (output_bfd, &rela, loc);
      ++srelagot->reloc_count;
      BFD_ASSERT (loc < (srelagot->contents + srelagot->size));
    }
  if (h->needs_copy)
    {
      asection *s;
      Elf_Internal_Rela rela;
      BFD_ASSERT (h->dynindx != -1
    && (h->root.type == bfd_link_hash_defined
        || h->root.type == bfd_link_hash_defweak));
      s = bfd_get_section_by_name (h->root.u.def.section->owner, ".rela.bss");
      BFD_ASSERT (s != NULL);
      rela.r_offset = (h->root.u.def.value
         + h->root.u.def.section->output_section->vma
         + h->root.u.def.section->output_offset);
      rela.r_info = ELF32_R_INFO (h->dynindx, R_NDS32_COPY);
      rela.r_addend = 0;
      loc = s->contents;
      loc += s->reloc_count * sizeof (Elf32_External_Rela);
      bfd_elf32_swap_reloca_out (output_bfd, &rela, loc);
      ++s->reloc_count;
    }
  if (strcmp (h->root.root.string, "_DYNAMIC") == 0
      || strcmp (h->root.root.string, "_GLOBAL_OFFSET_TABLE_") == 0)
    sym->st_shndx = SHN_ABS;
  return TRUE;
}
static bfd_boolean
nds32_elf_finish_dynamic_sections (bfd *output_bfd, struct bfd_link_info *info)
{
  bfd *dynobj;
  asection *sdyn;
  asection *sgotplt;
  struct elf_link_hash_table *ehtab;
  struct elf_nds32_link_hash_table *htab;
  ehtab = elf_hash_table (info);
  htab = nds32_elf_hash_table (info);
  if (htab == NULL)
    return FALSE;
  dynobj = elf_hash_table (info)->dynobj;
  sgotplt = ehtab->sgotplt;
  if (sgotplt != NULL && bfd_is_abs_section (sgotplt->output_section))
    return FALSE;
  sdyn = bfd_get_section_by_name (dynobj, ".dynamic");
  if (elf_hash_table (info)->dynamic_sections_created)
    {
      asection *splt;
      Elf32_External_Dyn *dyncon, *dynconend;
      BFD_ASSERT (sgotplt != NULL && sdyn != NULL);
      dyncon = (Elf32_External_Dyn *) sdyn->contents;
      dynconend = (Elf32_External_Dyn *) (sdyn->contents + sdyn->size);
      for (; dyncon < dynconend; dyncon++)
 {
   Elf_Internal_Dyn dyn;
   asection *s;
   bfd_elf32_swap_dyn_in (dynobj, dyncon, &dyn);
   switch (dyn.d_tag)
     {
     default:
       break;
     case DT_PLTGOT:
       s = ehtab->sgot->output_section;
       goto get_vma;
     case DT_JMPREL:
       s = ehtab->srelplt->output_section;
get_vma:
       BFD_ASSERT (s != NULL);
       dyn.d_un.d_ptr = s->vma;
       bfd_elf32_swap_dyn_out (output_bfd, &dyn, dyncon);
       break;
     case DT_PLTRELSZ:
       s = ehtab->srelplt->output_section;
       BFD_ASSERT (s != NULL);
       dyn.d_un.d_val = s->size;
       bfd_elf32_swap_dyn_out (output_bfd, &dyn, dyncon);
       break;
     case DT_RELASZ:
       if (ehtab->srelplt != NULL)
  {
    s = ehtab->srelplt->output_section;
    dyn.d_un.d_val -= s->size;
  }
       bfd_elf32_swap_dyn_out (output_bfd, &dyn, dyncon);
       break;
     case DT_TLSDESC_PLT:
       s = htab->root.splt;
       dyn.d_un.d_ptr = (s->output_section->vma + s->output_offset
    + htab->dt_tlsdesc_plt);
       bfd_elf32_swap_dyn_out (output_bfd, &dyn, dyncon);
       break;
     case DT_TLSDESC_GOT:
       s = htab->root.sgot;
       dyn.d_un.d_ptr = (s->output_section->vma + s->output_offset
    + htab->dt_tlsdesc_got);
       bfd_elf32_swap_dyn_out (output_bfd, &dyn, dyncon);
       break;
     }
 }
      splt = ehtab->splt;
      if (splt && splt->size > 0)
 {
   if (info->shared)
     {
       unsigned long insn;
       long offset;
       offset = sgotplt->output_section->vma + sgotplt->output_offset + 4
  - elf_gp (output_bfd);
       insn = PLT0_PIC_ENTRY_WORD0 | ((offset >> 12) & 0xfffff);
       bfd_putb32 (insn, splt->contents);
       insn = PLT0_PIC_ENTRY_WORD1 | (offset & 0xfff);
       bfd_putb32 (insn, splt->contents + 4);
       insn = PLT0_PIC_ENTRY_WORD2;
       bfd_putb32 (insn, splt->contents + 8);
       insn = PLT0_PIC_ENTRY_WORD3;
       bfd_putb32 (insn, splt->contents + 12);
       insn = PLT0_PIC_ENTRY_WORD4;
       bfd_putb32 (insn, splt->contents + 16);
       insn = PLT0_PIC_ENTRY_WORD5;
       bfd_putb32 (insn, splt->contents + 20);
     }
   else
     {
       unsigned long insn;
       unsigned long addr;
       addr = sgotplt->output_section->vma + sgotplt->output_offset + 4;
       insn = PLT0_ENTRY_WORD0 | ((addr >> 12) & 0xfffff);
       bfd_putb32 (insn, splt->contents);
       insn = PLT0_ENTRY_WORD1 | (addr & 0x0fff);
       bfd_putb32 (insn, splt->contents + 4);
       insn = PLT0_ENTRY_WORD2;
       bfd_putb32 (insn, splt->contents + 8);
       insn = PLT0_ENTRY_WORD3;
       bfd_putb32 (insn, splt->contents + 12);
       insn = PLT0_ENTRY_WORD4;
       bfd_putb32 (insn, splt->contents + 16);
     }
   elf_section_data (splt->output_section)->this_hdr.sh_entsize =
     PLT_ENTRY_SIZE;
 }
      if (htab->dt_tlsdesc_plt)
 {
   asection *sgot = sgot = ehtab->sgot;
   bfd_vma pltgot = sgotplt->output_section->vma
     + sgotplt->output_offset;
   bfd_vma tlsdesc_got = sgot->output_section->vma + sgot->output_offset
     + htab->dt_tlsdesc_got;
   pltgot -= elf_gp (output_bfd) - 4;
   tlsdesc_got -= elf_gp (output_bfd);
   dl_tlsdesc_lazy_trampoline[0] += ((1 << 20) - 1) & (tlsdesc_got >> 12);
   dl_tlsdesc_lazy_trampoline[1] += 0xfff & tlsdesc_got;
   dl_tlsdesc_lazy_trampoline[4] += ((1 << 20) - 1) & (pltgot >> 12);
   dl_tlsdesc_lazy_trampoline[5] += 0xfff & pltgot;
   nds32_put_trampoline (splt->contents + htab->dt_tlsdesc_plt,
    dl_tlsdesc_lazy_trampoline,
    ARRAY_SIZE (dl_tlsdesc_lazy_trampoline));
 }
    }
  if (sgotplt && sgotplt->size > 0)
    {
      if (sdyn == NULL)
 bfd_put_32 (output_bfd, (bfd_vma) 0, sgotplt->contents);
      else
 bfd_put_32 (output_bfd,
      sdyn->output_section->vma + sdyn->output_offset,
      sgotplt->contents);
      bfd_put_32 (output_bfd, (bfd_vma) 0, sgotplt->contents + 4);
      bfd_put_32 (output_bfd, (bfd_vma) 0, sgotplt->contents + 8);
      elf_section_data (sgotplt->output_section)->this_hdr.sh_entsize = 4;
    }
  return TRUE;
}
static bfd_boolean
nds32_elf_object_p (bfd *abfd)
{
  static unsigned int cur_arch = 0;
  if (E_N1_ARCH != (elf_elfheader (abfd)->e_flags & EF_NDS_ARCH))
    {
      cur_arch = (elf_elfheader (abfd)->e_flags & EF_NDS_ARCH);
    }
  switch (cur_arch)
    {
    default:
    case E_N1_ARCH:
      bfd_default_set_arch_mach (abfd, bfd_arch_nds32, bfd_mach_n1);
      break;
    case E_N1H_ARCH:
      bfd_default_set_arch_mach (abfd, bfd_arch_nds32, bfd_mach_n1h);
      break;
    case E_NDS_ARCH_STAR_V2_0:
      bfd_default_set_arch_mach (abfd, bfd_arch_nds32, bfd_mach_n1h_v2);
      break;
    case E_NDS_ARCH_STAR_V3_0:
      bfd_default_set_arch_mach (abfd, bfd_arch_nds32, bfd_mach_n1h_v3);
      break;
    case E_NDS_ARCH_STAR_V3_M:
      bfd_default_set_arch_mach (abfd, bfd_arch_nds32, bfd_mach_n1h_v3m);
      break;
    }
  return TRUE;
}
static void
nds32_elf_final_write_processing (bfd *abfd,
      bfd_boolean linker ATTRIBUTE_UNUSED)
{
  unsigned long val;
  static unsigned int cur_mach = 0;
  unsigned int i;
  if (bfd_mach_n1 != bfd_get_mach (abfd))
    {
      cur_mach = bfd_get_mach (abfd);
    }
  switch (cur_mach)
    {
    case bfd_mach_n1:
      val = E_N1_ARCH;
      val |= E_NDS_ABI_AABI;
      val |= E_NDS32_ELF_VER_1_4;
      break;
    case bfd_mach_n1h:
      val = E_N1H_ARCH;
      break;
    case bfd_mach_n1h_v2:
      val = E_NDS_ARCH_STAR_V2_0;
      break;
    case bfd_mach_n1h_v3:
      val = E_NDS_ARCH_STAR_V3_0;
      break;
    case bfd_mach_n1h_v3m:
      val = E_NDS_ARCH_STAR_V3_M;
      break;
    default:
      val = 0;
      break;
    }
  elf_elfheader (abfd)->e_flags &= ~EF_NDS_ARCH;
  elf_elfheader (abfd)->e_flags |= val;
  if (ifc_flag)
    elf_elfheader (abfd)->e_flags |= E_NDS32_HAS_IFC_INST ;
  if (ict_file)
    {
 fprintf (ict_file, ".section " NDS32_ICT_SECTION ", \"ax\"\n");
      if (ict_model == R_NDS32_RELAX_ENTRY_ICT_LARGE)
 fprintf (ict_file, ".ict_model\tlarge\n");
      else
 fprintf (ict_file, ".ict_model\tsmall\n");
      fprintf (ict_file, ".globl _INDIRECT_CALL_TABLE_BASE_\n"
        "_INDIRECT_CALL_TABLE_BASE_:\n");
      indirect_call_table.frozen = 1;
      for (i = 0; i < indirect_call_table.size; i++)
 {
   struct bfd_hash_entry *p;
   struct elf_nds32_ict_hash_entry *entry;
   for (p = indirect_call_table.table[i]; p != NULL; p = p->next)
     {
       entry = (struct elf_nds32_ict_hash_entry *) p;
       if (ict_model == R_NDS32_RELAX_ENTRY_ICT_LARGE)
  fprintf (ict_file, "\t.word\t%s\n", entry->root.string);
       else
  fprintf (ict_file, "\tj\t%s\n", entry->root.string);
     }
 }
      indirect_call_table.frozen = 0;
    }
}
static bfd_boolean
nds32_elf_set_private_flags (bfd *abfd, flagword flags)
{
  BFD_ASSERT (!elf_flags_init (abfd)
       || elf_elfheader (abfd)->e_flags == flags);
  elf_elfheader (abfd)->e_flags = flags;
  elf_flags_init (abfd) = TRUE;
  return TRUE;
}
static unsigned int
convert_e_flags (unsigned int e_flags, unsigned int arch)
{
  if ((e_flags & EF_NDS_ARCH) == E_NDS_ARCH_STAR_V0_9)
    {
      e_flags = (e_flags & (~EF_NDS_ARCH)) | E_NDS_ARCH_STAR_V1_0;
      e_flags ^= E_NDS32_HAS_NO_MAC_INST;
      if (arch == E_NDS_ARCH_STAR_V1_0)
 {
   return e_flags;
 }
    }
  e_flags = (e_flags & (~EF_NDS_ARCH)) | E_NDS_ARCH_STAR_V2_0;
  e_flags &= ~E_NDS32_HAS_MFUSR_PC_INST;
  e_flags ^= E_NDS32_HAS_NO_MAC_INST;
  return e_flags;
}
static bfd_boolean
nds32_check_vec_size (bfd *ibfd)
{
  static unsigned int nds32_vec_size = 0;
  asection *sec_t = NULL;
  bfd_byte *contents = NULL;
  sec_t = bfd_get_section_by_name (ibfd, ".nds32_e_flags");
  if (sec_t && sec_t->size >= 4)
    {
      unsigned int flag_t;
      nds32_get_section_contents (ibfd, sec_t, &contents, TRUE);
      flag_t = bfd_get_32 (ibfd, contents);
      if (!nds32_vec_size)
 nds32_vec_size = (flag_t & 0x3);
      else if (nds32_vec_size != (flag_t & 0x3))
 {
   (*_bfd_error_handler) (_("%B: ISR vector size mismatch"
       " with previous modules, previous %u-byte, current %u-byte"),
     ibfd,
     nds32_vec_size == 1 ? 4 : nds32_vec_size == 2 ? 16 : 0xffffffff,
     (flag_t & 0x3) == 1 ? 4 : (flag_t & 0x3) == 2 ? 16 : 0xffffffff);
   return FALSE;
 }
      else
 sec_t->flags |= SEC_EXCLUDE;
    }
  return TRUE;
}
static unsigned int
nds32_elf_force_to_set_output_abi (char *str)
{
  flagword flags;
  if (strcmp (str, "AABI") == 0)
    flags = E_NDS_ABI_AABI;
  else if (strcmp (str, "V2FP+") == 0)
    flags = E_NDS_ABI_V2FP_PLUS;
  else
    flags = 0;
  return flags;
}
static bfd_boolean
nds32_elf_merge_private_bfd_data (bfd *ibfd, bfd *obfd)
{
  flagword out_flags;
  flagword in_flags;
  flagword out_16regs;
  flagword in_no_mac;
  flagword out_no_mac;
  flagword in_16regs;
  flagword out_version;
  flagword in_version;
  flagword out_fpu_config;
  flagword in_fpu_config;
  if (!nds32_check_vec_size (ibfd))
    return FALSE;
  if (bfd_get_flavour (ibfd) != bfd_target_elf_flavour
      || bfd_get_flavour (obfd) != bfd_target_elf_flavour)
    return TRUE;
  if (bfd_little_endian (ibfd) != bfd_little_endian (obfd))
    {
      (*_bfd_error_handler)
 (_("%B: warning: Endian mismatch with previous modules."), ibfd);
      bfd_set_error (bfd_error_bad_value);
      return FALSE;
    }
  if (elf_elfheader (ibfd)->e_flags)
    {
      in_version = elf_elfheader (ibfd)->e_flags & EF_NDS32_ELF_VERSION;
      if (in_version == E_NDS32_ELF_VER_1_2)
 {
   (*_bfd_error_handler)
     (_("%B: warning: Older version of object file encountered, "
        "Please recompile with current tool chain."), ibfd);
 }
      if (output_abi != NULL)
 {
   elf_elfheader (ibfd)->e_flags &= ~(EF_NDS_ABI);
   elf_elfheader (ibfd)->e_flags
     |= nds32_elf_force_to_set_output_abi (output_abi);
   elf_elfheader (obfd)->e_flags &= ~(EF_NDS_ABI);
   elf_elfheader (obfd)->e_flags
     |= nds32_elf_force_to_set_output_abi (output_abi);
 }
      if ((elf_elfheader (ibfd)->e_flags & EF_NDS_ARCH)
   != (elf_elfheader (obfd)->e_flags & EF_NDS_ARCH))
 {
   if ((elf_elfheader (ibfd)->e_flags & EF_NDS_ARCH)
       == E_NDS_ARCH_STAR_RESERVED)
     {
       elf_elfheader (obfd)->e_flags = elf_elfheader (ibfd)->e_flags;
     }
   else if ((elf_elfheader (ibfd)->e_flags & EF_NDS_ARCH)
     == E_NDS_ARCH_STAR_V3_M
     && (elf_elfheader (obfd)->e_flags & EF_NDS_ARCH)
     == E_NDS_ARCH_STAR_V3_0)
     {
       elf_elfheader (ibfd)->e_flags =
  (elf_elfheader (ibfd)->e_flags & (~EF_NDS_ARCH))
   | E_NDS_ARCH_STAR_V3_0;
     }
   else if ((elf_elfheader (obfd)->e_flags & EF_NDS_ARCH)
     == E_NDS_ARCH_STAR_V0_9
     || (elf_elfheader (ibfd)->e_flags & EF_NDS_ARCH)
     > (elf_elfheader (obfd)->e_flags & EF_NDS_ARCH))
     {
       elf_elfheader (obfd)->e_flags =
  convert_e_flags (elf_elfheader (obfd)->e_flags,
     (elf_elfheader (ibfd)->e_flags & EF_NDS_ARCH));
     }
   else
     {
       elf_elfheader (ibfd)->e_flags =
  convert_e_flags (elf_elfheader (ibfd)->e_flags,
     (elf_elfheader (obfd)->e_flags & EF_NDS_ARCH));
     }
 }
      in_flags = elf_elfheader (ibfd)->e_flags
   & (~(E_NDS32_HAS_REDUCED_REGS | EF_NDS32_ELF_VERSION
        | E_NDS32_HAS_NO_MAC_INST | E_NDS32_FPU_REG_CONF));
      in_16regs = elf_elfheader (ibfd)->e_flags & E_NDS32_HAS_REDUCED_REGS;
      in_no_mac = elf_elfheader (ibfd)->e_flags & E_NDS32_HAS_NO_MAC_INST;
      in_fpu_config = elf_elfheader (ibfd)->e_flags & E_NDS32_FPU_REG_CONF;
      out_flags = elf_elfheader (obfd)->e_flags
    & (~(E_NDS32_HAS_REDUCED_REGS | EF_NDS32_ELF_VERSION
         | E_NDS32_HAS_NO_MAC_INST | E_NDS32_FPU_REG_CONF));
      out_16regs = elf_elfheader (obfd)->e_flags & E_NDS32_HAS_REDUCED_REGS;
      out_no_mac = elf_elfheader (obfd)->e_flags & E_NDS32_HAS_NO_MAC_INST;
      out_fpu_config = elf_elfheader (obfd)->e_flags & E_NDS32_FPU_REG_CONF;
      out_version = elf_elfheader (obfd)->e_flags & EF_NDS32_ELF_VERSION;
      if (!elf_flags_init (obfd))
 {
   if (bfd_get_arch_info (ibfd)->the_default)
     return TRUE;
   elf_flags_init (obfd) = TRUE;
   elf_elfheader (obfd)->e_flags = elf_elfheader (ibfd)->e_flags;
   if (bfd_get_arch (obfd) == bfd_get_arch (ibfd)
       && bfd_get_arch_info (obfd)->the_default)
     {
       return bfd_set_arch_mach (obfd, bfd_get_arch (ibfd),
     bfd_get_mach (ibfd));
     }
   return TRUE;
 }
      if ((in_flags & EF_NDS_ABI) != (out_flags & EF_NDS_ABI))
 {
   asection *section = NULL;
   bfd_byte *contents = NULL;
   section = bfd_get_section_by_name (ibfd, ".note.v2abi_compatible");
   if (section)
     bfd_get_full_section_contents (ibfd, section, &contents);
   if ((contents == NULL)
       || bfd_getb32 (contents) != 1
       || (out_flags & EF_NDS_ABI) != E_NDS_ABI_V2FP_PLUS)
     {
       (*_bfd_error_handler)
  (_("%B: error: ABI mismatch with previous modules."), ibfd);
       bfd_set_error (bfd_error_bad_value);
       return FALSE;
     }
   if (section)
     section->flags = SEC_EXCLUDE;
 }
      if ((in_flags & EF_NDS_ARCH) != (out_flags & EF_NDS_ARCH))
 {
   if (((in_flags & EF_NDS_ARCH) != E_N1_ARCH))
     {
       (*_bfd_error_handler)
  (_("%B: error: Instruction set mismatch with previous modules."), ibfd);
       bfd_set_error (bfd_error_bad_value);
       return FALSE;
     }
 }
      if (in_version == E_NDS32_ELF_VER_1_2 || out_version == E_NDS32_ELF_VER_1_2)
 {
   elf_elfheader (obfd)->e_flags =
     (in_flags & (~(E_NDS32_HAS_EXT_INST | E_NDS32_HAS_DIV_INST)))
     | (out_flags & (~(E_NDS32_HAS_EXT_INST | E_NDS32_HAS_DIV_INST)))
     | (((in_flags & (E_NDS32_HAS_EXT_INST | E_NDS32_HAS_DIV_INST)))
        ? E_NDS32_HAS_EXT_INST : 0)
     | (((out_flags & (E_NDS32_HAS_EXT_INST | E_NDS32_HAS_DIV_INST)))
        ? E_NDS32_HAS_EXT_INST : 0)
     | (in_16regs & out_16regs) | (in_no_mac & out_no_mac)
     | ((in_version > out_version) ? out_version : in_version);
 }
      else
 {
   if (in_version != out_version)
     (*_bfd_error_handler) (
  _("%B: warning: Incompatible elf-versions %s and  %s."), ibfd,
  nds32_elfver_strtab[out_version],
  nds32_elfver_strtab[in_version]);
   elf_elfheader (obfd)->e_flags = in_flags | out_flags
     | (in_16regs & out_16regs) | (in_no_mac & out_no_mac)
     | (in_fpu_config > out_fpu_config ? in_fpu_config : out_fpu_config)
     | (in_version > out_version ? out_version : in_version);
 }
    }
  return TRUE;
}
static bfd_boolean
nds32_elf_print_private_bfd_data (bfd *abfd, void *ptr)
{
  FILE *file = (FILE *) ptr;
  BFD_ASSERT (abfd != NULL && ptr != NULL);
  _bfd_elf_print_private_bfd_data (abfd, ptr);
  fprintf (file, _("private flags = %lx"), elf_elfheader (abfd)->e_flags);
  switch (elf_elfheader (abfd)->e_flags & EF_NDS_ARCH)
    {
    default:
    case E_N1_ARCH:
      fprintf (file, _(": n1 instructions"));
      break;
    case E_N1H_ARCH:
      fprintf (file, _(": n1h instructions"));
      break;
    }
  fputc ('\n', file);
  return TRUE;
}
static unsigned int
nds32_elf_action_discarded (asection *sec)
{
  if (strncmp
      (".gcc_except_table", sec->name, sizeof (".gcc_except_table") - 1) == 0)
    return 0;
  return _bfd_elf_default_action_discarded (sec);
}
static asection *
nds32_elf_gc_mark_hook (asection *sec, struct bfd_link_info *info,
   Elf_Internal_Rela *rel, struct elf_link_hash_entry *h,
   Elf_Internal_Sym *sym)
{
  if (h != NULL)
    switch (ELF32_R_TYPE (rel->r_info))
      {
      case R_NDS32_GNU_VTINHERIT:
      case R_NDS32_GNU_VTENTRY:
      case R_NDS32_RELA_GNU_VTINHERIT:
      case R_NDS32_RELA_GNU_VTENTRY:
 return NULL;
      }
  return _bfd_elf_gc_mark_hook (sec, info, rel, h, sym);
}
static bfd_boolean
nds32_elf_gc_sweep_hook (bfd *abfd, struct bfd_link_info *info, asection *sec,
    const Elf_Internal_Rela *relocs)
{
  Elf_Internal_Shdr *symtab_hdr;
  struct elf_link_hash_entry **sym_hashes;
  bfd_signed_vma *local_got_refcounts;
  const Elf_Internal_Rela *rel, *relend;
  elf_section_data (sec)->local_dynrel = NULL;
  symtab_hdr = &elf_tdata (abfd)->symtab_hdr;
  sym_hashes = elf_sym_hashes (abfd);
  local_got_refcounts = elf_local_got_refcounts (abfd);
  relend = relocs + sec->reloc_count;
  for (rel = relocs; rel < relend; rel++)
    {
      unsigned long r_symndx;
      struct elf_link_hash_entry *h = NULL;
      r_symndx = ELF32_R_SYM (rel->r_info);
      if (r_symndx >= symtab_hdr->sh_info)
 {
   h = sym_hashes[r_symndx - symtab_hdr->sh_info];
   while (h->root.type == bfd_link_hash_indirect
   || h->root.type == bfd_link_hash_warning)
     h = (struct elf_link_hash_entry *) h->root.u.i.link;
 }
      switch (ELF32_R_TYPE (rel->r_info))
 {
 case R_NDS32_GOT_HI20:
 case R_NDS32_GOT_LO12:
 case R_NDS32_GOT_LO15:
 case R_NDS32_GOT_LO19:
 case R_NDS32_GOT17S2_RELA:
 case R_NDS32_GOT15S2_RELA:
 case R_NDS32_GOTOFF:
 case R_NDS32_GOTOFF_HI20:
 case R_NDS32_GOTOFF_LO12:
 case R_NDS32_GOTOFF_LO15:
 case R_NDS32_GOTOFF_LO19:
 case R_NDS32_GOT20:
 case R_NDS32_GOTPC_HI20:
 case R_NDS32_GOTPC_LO12:
 case R_NDS32_GOTPC20:
   if (h != NULL)
     {
       if (h->got.refcount > 0)
  h->got.refcount--;
     }
   else
     {
       if (local_got_refcounts && local_got_refcounts[r_symndx] > 0)
  local_got_refcounts[r_symndx]--;
     }
   break;
 case R_NDS32_16_RELA:
 case R_NDS32_20_RELA:
 case R_NDS32_5_RELA:
 case R_NDS32_32_RELA:
 case R_NDS32_HI20_RELA:
 case R_NDS32_LO12S3_RELA:
 case R_NDS32_LO12S2_RELA:
 case R_NDS32_LO12S2_DP_RELA:
 case R_NDS32_LO12S2_SP_RELA:
 case R_NDS32_LO12S1_RELA:
 case R_NDS32_LO12S0_RELA:
 case R_NDS32_LO12S0_ORI_RELA:
 case R_NDS32_SDA16S3_RELA:
 case R_NDS32_SDA17S2_RELA:
 case R_NDS32_SDA18S1_RELA:
 case R_NDS32_SDA19S0_RELA:
 case R_NDS32_SDA15S3_RELA:
 case R_NDS32_SDA15S2_RELA:
 case R_NDS32_SDA12S2_DP_RELA:
 case R_NDS32_SDA12S2_SP_RELA:
 case R_NDS32_SDA15S1_RELA:
 case R_NDS32_SDA15S0_RELA:
 case R_NDS32_SDA_FP7U2_RELA:
 case R_NDS32_15_PCREL_RELA:
 case R_NDS32_17_PCREL_RELA:
 case R_NDS32_25_PCREL_RELA:
   if (h != NULL)
     {
       struct elf_nds32_link_hash_entry *eh;
       struct elf_nds32_dyn_relocs **pp;
       struct elf_nds32_dyn_relocs *p;
       if (!info->shared && h->plt.refcount > 0)
  h->plt.refcount -= 1;
       eh = (struct elf_nds32_link_hash_entry *) h;
       for (pp = &eh->dyn_relocs; (p = *pp) != NULL; pp = &p->next)
  if (p->sec == sec)
    {
      if (ELF32_R_TYPE (rel->r_info) == R_NDS32_15_PCREL_RELA
   || ELF32_R_TYPE (rel->r_info) == R_NDS32_17_PCREL_RELA
   || ELF32_R_TYPE (rel->r_info) == R_NDS32_25_PCREL_RELA)
        p->pc_count -= 1;
      p->count -= 1;
      if (p->count == 0)
        *pp = p->next;
      break;
    }
     }
   break;
 case R_NDS32_9_PLTREL:
 case R_NDS32_25_PLTREL:
   if (h != NULL)
     {
       if (h->plt.refcount > 0)
  h->plt.refcount--;
     }
   break;
 default:
   break;
 }
    }
  return TRUE;
}
static enum elf_nds32_tls_type
get_tls_type (enum elf_nds32_reloc_type r_type,
       struct elf_link_hash_entry *h ATTRIBUTE_UNUSED)
{
  enum elf_nds32_tls_type tls_type;
  switch (r_type)
    {
    case R_NDS32_TLS_LE_HI20:
    case R_NDS32_TLS_LE_LO12:
      tls_type = GOT_TLS_LE;
      break;
    case R_NDS32_TLS_IE_HI20:
    case R_NDS32_TLS_IE_LO12S2:
    case R_NDS32_TLS_IE_LO12:
      tls_type = GOT_TLS_IE;
      break;
    case R_NDS32_TLS_IEGP_HI20:
    case R_NDS32_TLS_IEGP_LO12:
    case R_NDS32_TLS_IEGP_LO12S2:
      tls_type = GOT_TLS_IEGP;
      break;
    case R_NDS32_TLS_DESC_HI20:
    case R_NDS32_TLS_DESC_LO12:
    case R_NDS32_TLS_DESC_ADD:
    case R_NDS32_TLS_DESC_FUNC:
    case R_NDS32_TLS_DESC_CALL:
      tls_type = GOT_TLS_DESC;
      break;
    default:
      tls_type = GOT_NORMAL;
      break;
    }
  return tls_type;
}
static bfd_boolean
elf32_nds32_allocate_local_sym_info (bfd *abfd)
{
  if (elf_local_got_refcounts (abfd) == NULL)
    {
      bfd_size_type num_syms;
      bfd_size_type size;
      char *data;
      num_syms = elf_tdata (abfd)->symtab_hdr.sh_info;
      size = num_syms * (sizeof (bfd_signed_vma) + sizeof (char)
    + sizeof (bfd_vma) + sizeof (int)
    + sizeof (bfd_boolean) + sizeof (bfd_vma));
      data = bfd_zalloc (abfd, size);
      if (data == NULL)
 return FALSE;
      elf_local_got_refcounts (abfd) = (bfd_signed_vma *) data;
      data += num_syms * sizeof (bfd_signed_vma);
      elf32_nds32_local_got_tls_type (abfd) = (char *) data;
      data += num_syms * sizeof (char);
      elf32_nds32_local_tlsdesc_gotent (abfd) = (bfd_vma *) data;
      data += num_syms * sizeof (bfd_vma);
      elf32_nds32_local_gp_offset (abfd) = (int *) data;
      data += num_syms * sizeof (int);
    }
  return TRUE;
}
static bfd_boolean
nds32_elf_check_relocs (bfd *abfd, struct bfd_link_info *info,
   asection *sec, const Elf_Internal_Rela *relocs)
{
  Elf_Internal_Shdr *symtab_hdr;
  struct elf_link_hash_entry **sym_hashes, **sym_hashes_end;
  const Elf_Internal_Rela *rel;
  const Elf_Internal_Rela *rel_end;
  struct elf_link_hash_table *ehtab;
  struct elf_nds32_link_hash_table *htab;
  bfd *dynobj;
  asection *sreloc = NULL;
  if (info->relocatable)
    {
      elf32_nds32_check_relax_group (abfd, sec);
      return TRUE;
    }
  symtab_hdr = &elf_tdata (abfd)->symtab_hdr;
  sym_hashes = elf_sym_hashes (abfd);
  sym_hashes_end =
    sym_hashes + symtab_hdr->sh_size / sizeof (Elf32_External_Sym);
  if (!elf_bad_symtab (abfd))
    sym_hashes_end -= symtab_hdr->sh_info;
  ehtab = elf_hash_table (info);
  htab = nds32_elf_hash_table (info);
  dynobj = htab->root.dynobj;
  rel_end = relocs + sec->reloc_count;
  for (rel = relocs; rel < rel_end; rel++)
    {
      enum elf_nds32_reloc_type r_type;
      struct elf_link_hash_entry *h;
      unsigned long r_symndx;
      enum elf_nds32_tls_type tls_type, old_tls_type;
      struct elf_nds32_ict_hash_entry *entry;
      r_symndx = ELF32_R_SYM (rel->r_info);
      r_type = ELF32_R_TYPE (rel->r_info);
      if (r_symndx < symtab_hdr->sh_info)
 h = NULL;
      else
 {
   h = sym_hashes[r_symndx - symtab_hdr->sh_info];
   while (h->root.type == bfd_link_hash_indirect
   || h->root.type == bfd_link_hash_warning)
     h = (struct elf_link_hash_entry *) h->root.u.i.link;
 }
      if (ehtab->sgot == NULL)
 {
   switch (r_type)
     {
     case R_NDS32_GOT_HI20:
     case R_NDS32_GOT_LO12:
     case R_NDS32_GOT_LO15:
     case R_NDS32_GOT_LO19:
     case R_NDS32_GOT17S2_RELA:
     case R_NDS32_GOT15S2_RELA:
     case R_NDS32_GOTOFF:
     case R_NDS32_GOTOFF_HI20:
     case R_NDS32_GOTOFF_LO12:
     case R_NDS32_GOTOFF_LO15:
     case R_NDS32_GOTOFF_LO19:
     case R_NDS32_GOTPC20:
     case R_NDS32_GOTPC_HI20:
     case R_NDS32_GOTPC_LO12:
     case R_NDS32_GOT20:
     case R_NDS32_TLS_IE_HI20:
     case R_NDS32_TLS_IE_LO12:
     case R_NDS32_TLS_IE_LO12S2:
     case R_NDS32_TLS_IEGP_HI20:
     case R_NDS32_TLS_IEGP_LO12:
     case R_NDS32_TLS_IEGP_LO12S2:
     case R_NDS32_TLS_DESC_HI20:
     case R_NDS32_TLS_DESC_LO12:
       if (dynobj == NULL)
  htab->root.dynobj = dynobj = abfd;
       if (!create_got_section (dynobj, info))
  return FALSE;
       break;
     default:
       break;
     }
 }
      switch ((int) r_type)
 {
 case R_NDS32_TLS_LE_HI20:
 case R_NDS32_TLS_LE_LO12:
 case R_NDS32_GOT_HI20:
 case R_NDS32_GOT_LO12:
 case R_NDS32_GOT_LO15:
 case R_NDS32_GOT_LO19:
 case R_NDS32_GOT20:
 case R_NDS32_TLS_IE_HI20:
 case R_NDS32_TLS_IE_LO12:
 case R_NDS32_TLS_IE_LO12S2:
 case R_NDS32_TLS_IEGP_HI20:
 case R_NDS32_TLS_IEGP_LO12:
 case R_NDS32_TLS_IEGP_LO12S2:
 case R_NDS32_TLS_DESC_HI20:
 case R_NDS32_TLS_DESC_LO12:
   tls_type = get_tls_type (r_type, h);
   if (h)
     {
       if (tls_type != GOT_TLS_LE)
  h->got.refcount += 1;
       old_tls_type = elf32_nds32_hash_entry (h)->tls_type;
     }
   else
     {
       if (!elf32_nds32_allocate_local_sym_info (abfd))
  return FALSE;
       BFD_ASSERT (r_symndx < symtab_hdr->sh_info);
       if (tls_type != GOT_TLS_LE)
  elf_local_got_refcounts (abfd)[r_symndx] += 1;
       old_tls_type = elf32_nds32_local_got_tls_type (abfd)[r_symndx];
     }
   if (old_tls_type != GOT_UNKNOWN && old_tls_type != GOT_NORMAL
       && tls_type != GOT_NORMAL)
     tls_type |= old_tls_type;
   if ((tls_type & (GOT_TLS_DESC | GOT_TLS_IEGP)) && (info->executable))
     tls_type |= (info->pie ? GOT_TLS_IEGP : GOT_TLS_IE);
   if (old_tls_type != tls_type)
     {
       if (h != NULL)
  elf32_nds32_hash_entry (h)->tls_type = tls_type;
       else
  elf32_nds32_local_got_tls_type (abfd)[r_symndx] = tls_type;
     }
   break;
 case R_NDS32_9_PLTREL:
 case R_NDS32_25_PLTREL:
 case R_NDS32_PLTREL_HI20:
 case R_NDS32_PLTREL_LO12:
 case R_NDS32_PLT_GOTREL_HI20:
 case R_NDS32_PLT_GOTREL_LO12:
 case R_NDS32_PLT_GOTREL_LO15:
 case R_NDS32_PLT_GOTREL_LO19:
 case R_NDS32_PLT_GOTREL_LO20:
   if (h == NULL)
     continue;
   if (h->forced_local
       || (info->pie && h->def_regular))
     break;
   elf32_nds32_hash_entry (h)->tls_type = GOT_NORMAL;
   h->needs_plt = 1;
   h->plt.refcount += 1;
   break;
 case R_NDS32_16_RELA:
 case R_NDS32_20_RELA:
 case R_NDS32_5_RELA:
 case R_NDS32_32_RELA:
 case R_NDS32_HI20_RELA:
 case R_NDS32_LO12S3_RELA:
 case R_NDS32_LO12S2_RELA:
 case R_NDS32_LO12S2_DP_RELA:
 case R_NDS32_LO12S2_SP_RELA:
 case R_NDS32_LO12S1_RELA:
 case R_NDS32_LO12S0_RELA:
 case R_NDS32_LO12S0_ORI_RELA:
 case R_NDS32_SDA16S3_RELA:
 case R_NDS32_SDA17S2_RELA:
 case R_NDS32_SDA18S1_RELA:
 case R_NDS32_SDA19S0_RELA:
 case R_NDS32_SDA15S3_RELA:
 case R_NDS32_SDA15S2_RELA:
 case R_NDS32_SDA12S2_DP_RELA:
 case R_NDS32_SDA12S2_SP_RELA:
 case R_NDS32_SDA15S1_RELA:
 case R_NDS32_SDA15S0_RELA:
 case R_NDS32_SDA_FP7U2_RELA:
 case R_NDS32_15_PCREL_RELA:
 case R_NDS32_17_PCREL_RELA:
 case R_NDS32_25_PCREL_RELA:
   if (h != NULL && !info->shared)
     {
       h->non_got_ref = 1;
       h->plt.refcount += 1;
     }
   if ((info->shared
        && (sec->flags & SEC_ALLOC) != 0
        && ((r_type != R_NDS32_25_PCREL_RELA
      && r_type != R_NDS32_15_PCREL_RELA
      && r_type != R_NDS32_17_PCREL_RELA
      && !(r_type == R_NDS32_32_RELA
    && strcmp (sec->name, ".eh_frame") == 0))
     || (h != NULL
         && (!info->symbolic
      || h->root.type == bfd_link_hash_defweak
      || !h->def_regular))))
       || (!info->shared
    && (sec->flags & SEC_ALLOC) != 0
    && h != NULL
    && (h->root.type == bfd_link_hash_defweak
        || !h->def_regular)))
     {
       struct elf_nds32_dyn_relocs *p;
       struct elf_nds32_dyn_relocs **head;
       if (dynobj == NULL)
  htab->root.dynobj = dynobj = abfd;
       if (sreloc == NULL)
  {
    const char *name;
    name = bfd_elf_string_from_elf_section
      (abfd, elf_elfheader (abfd)->e_shstrndx,
       elf_section_data (sec)->rela.hdr->sh_name);
    if (name == NULL)
      return FALSE;
    BFD_ASSERT (strncmp (name, ".rela", 5) == 0
         && strcmp (bfd_get_section_name (abfd, sec),
      name + 5) == 0);
    sreloc = bfd_get_section_by_name (dynobj, name);
    if (sreloc == NULL)
      {
        flagword flags;
        sreloc = bfd_make_section (dynobj, name);
        flags = (SEC_HAS_CONTENTS | SEC_READONLY
          | SEC_IN_MEMORY | SEC_LINKER_CREATED);
        if ((sec->flags & SEC_ALLOC) != 0)
   flags |= SEC_ALLOC | SEC_LOAD;
        if (sreloc == NULL
     || !bfd_set_section_flags (dynobj, sreloc, flags)
     || !bfd_set_section_alignment (dynobj, sreloc, 2))
   return FALSE;
        elf_section_type (sreloc) = SHT_RELA;
      }
    elf_section_data (sec)->sreloc = sreloc;
  }
       if (h != NULL)
  head = &((struct elf_nds32_link_hash_entry *) h)->dyn_relocs;
       else
  {
    asection *s;
    Elf_Internal_Sym *isym;
    isym = bfd_sym_from_r_symndx (&htab->sym_cache, abfd, r_symndx);
    if (isym == NULL)
      return FALSE;
    s = bfd_section_from_elf_index (abfd, isym->st_shndx);
    if (s == NULL)
      return FALSE;
    head = ((struct elf_nds32_dyn_relocs **)
     &elf_section_data (s)->local_dynrel);
  }
       p = *head;
       if (p == NULL || p->sec != sec)
  {
    bfd_size_type amt = sizeof (*p);
    p = (struct elf_nds32_dyn_relocs *) bfd_alloc (dynobj, amt);
    if (p == NULL)
      return FALSE;
    p->next = *head;
    *head = p;
    p->sec = sec;
    p->count = 0;
    p->pc_count = 0;
  }
       p->count += 1;
       if (ELF32_R_TYPE (rel->r_info) == R_NDS32_25_PCREL_RELA
    || ELF32_R_TYPE (rel->r_info) == R_NDS32_15_PCREL_RELA
    || ELF32_R_TYPE (rel->r_info) == R_NDS32_17_PCREL_RELA)
  p->pc_count += 1;
     }
   break;
 case R_NDS32_ICT_HI20:
 case R_NDS32_ICT_LO12:
 case R_NDS32_ICT_25PC:
   if (rel->r_addend != 0)
     {
       (*_bfd_error_handler)
  (_("%B %s: Error: Rom-patch relocation offset: 0x%lx "
     "with addend 0x%lx\n"),
   abfd, sec->name, rel->r_offset, rel->r_addend);
       bfd_set_error (bfd_error_bad_value);
       return FALSE;
     }
   if (h)
     {
       elf32_nds32_hash_entry (h)->indirect_call = TRUE;
       entry = (struct elf_nds32_ict_hash_entry *)
  bfd_hash_lookup (&indirect_call_table, h->root.root.string,
     TRUE, TRUE);
       entry->h = h;
       if (entry == NULL)
  {
    (*_bfd_error_handler)
      (_("%B: failed creating indirect call %s hash table\n"),
       abfd, h->root.root.string);
    bfd_set_error (bfd_error_bad_value);
    return FALSE;
  }
     }
   else
     {
       (*_bfd_error_handler)
  (_("%B: indirect call relocation with local symbol.\n"), abfd);
       bfd_set_error (bfd_error_bad_value);
       return FALSE;
     }
   break;
 case R_NDS32_RELA_GNU_VTINHERIT:
 case R_NDS32_GNU_VTINHERIT:
   if (!bfd_elf_gc_record_vtinherit (abfd, sec, h, rel->r_offset))
     return FALSE;
   break;
 case R_NDS32_GNU_VTENTRY:
   if (!bfd_elf_gc_record_vtentry (abfd, sec, h, rel->r_offset))
     return FALSE;
   break;
 case R_NDS32_RELA_GNU_VTENTRY:
   if (!bfd_elf_gc_record_vtentry (abfd, sec, h, rel->r_addend))
     return FALSE;
   break;
 case R_NDS32_RELAX_ENTRY:
   if (ict_model == 0)
     ict_model = rel->r_addend & R_NDS32_RELAX_ENTRY_ICT_MASK;
   else if (ict_model != (rel->r_addend & R_NDS32_RELAX_ENTRY_ICT_MASK)
     && (rel->r_addend & R_NDS32_RELAX_ENTRY_ICT_MASK) != 0)
     {
       (*_bfd_error_handler)
  (_("%B Error: mixed ict model objects.\n"), abfd);
       bfd_set_error (bfd_error_bad_value);
       return FALSE;
     }
   break;
 }
    }
  return TRUE;
}
static bfd_byte *
write_uleb128 (bfd_byte *p, unsigned int val)
{
  bfd_byte c;
  do
    {
      c = val & 0x7f;
      val >>= 7;
      if (val)
 c |= 0x80;
      *(p++) = c;
    }
  while (val);
  return p;
}
static bfd_signed_vma
calculate_offset (bfd *abfd, asection *sec, Elf_Internal_Rela *irel,
    Elf_Internal_Sym *isymbuf, Elf_Internal_Shdr *symtab_hdr)
{
  bfd_signed_vma foff;
  bfd_vma symval, addend;
  asection *sym_sec;
  if (ELF32_R_SYM (irel->r_info) < symtab_hdr->sh_info)
    {
      Elf_Internal_Sym *isym;
      isym = isymbuf + ELF32_R_SYM (irel->r_info);
      if (isym->st_shndx == SHN_UNDEF)
 sym_sec = bfd_und_section_ptr;
      else if (isym->st_shndx == SHN_ABS)
 sym_sec = bfd_abs_section_ptr;
      else if (isym->st_shndx == SHN_COMMON)
 sym_sec = bfd_com_section_ptr;
      else
 sym_sec = bfd_section_from_elf_index (abfd, isym->st_shndx);
      symval = isym->st_value + sym_sec->output_section->vma
        + sym_sec->output_offset;
    }
  else
    {
      unsigned long indx;
      struct elf_link_hash_entry *h;
      indx = ELF32_R_SYM (irel->r_info) - symtab_hdr->sh_info;
      h = elf_sym_hashes (abfd)[indx];
      BFD_ASSERT (h != NULL);
      if (h->root.type != bfd_link_hash_defined
   && h->root.type != bfd_link_hash_defweak)
 return 0;
      if (h->root.u.def.section->flags & SEC_MERGE)
 {
   sym_sec = h->root.u.def.section;
   symval = _bfd_merged_section_offset (abfd, &sym_sec,
            elf_section_data (sym_sec)->sec_info,
            h->root.u.def.value);
   symval = symval + sym_sec->output_section->vma
     + sym_sec->output_offset;
 }
      else
 symval = (h->root.u.def.value
    + h->root.u.def.section->output_section->vma
    + h->root.u.def.section->output_offset);
    }
  addend = irel->r_addend;
  foff = (symval + addend
   - (irel->r_offset + sec->output_section->vma + sec->output_offset));
  return foff;
}
static bfd_vma
calculate_plt_memory_address (bfd *abfd, struct bfd_link_info *link_info,
         Elf_Internal_Sym *isymbuf,
         Elf_Internal_Rela *irel,
         Elf_Internal_Shdr *symtab_hdr)
{
  bfd_vma symval;
  if (ELF32_R_SYM (irel->r_info) < symtab_hdr->sh_info)
    {
      Elf_Internal_Sym *isym;
      asection *sym_sec;
      isym = isymbuf + ELF32_R_SYM (irel->r_info);
      if (isym->st_shndx == SHN_UNDEF)
 sym_sec = bfd_und_section_ptr;
      else if (isym->st_shndx == SHN_ABS)
 sym_sec = bfd_abs_section_ptr;
      else if (isym->st_shndx == SHN_COMMON)
 sym_sec = bfd_com_section_ptr;
      else
 sym_sec = bfd_section_from_elf_index (abfd, isym->st_shndx);
      symval = isym->st_value + sym_sec->output_section->vma
        + sym_sec->output_offset;
    }
  else
    {
      unsigned long indx;
      struct elf_link_hash_entry *h;
      struct elf_link_hash_table *ehtab;
      asection *splt;
      indx = ELF32_R_SYM (irel->r_info) - symtab_hdr->sh_info;
      h = elf_sym_hashes (abfd)[indx];
      BFD_ASSERT (h != NULL);
      ehtab = elf_hash_table (link_info);
      splt = ehtab->splt;
      while (h->root.type == bfd_link_hash_indirect
      || h->root.type == bfd_link_hash_warning)
 h = (struct elf_link_hash_entry *) h->root.u.i.link;
      if (h->plt.offset == (bfd_vma) - 1)
 {
   if (h->root.type != bfd_link_hash_defined
       && h->root.type != bfd_link_hash_defweak)
     return 0;
   symval = (h->root.u.def.value
      + h->root.u.def.section->output_section->vma
      + h->root.u.def.section->output_offset);
 }
      else
 symval = splt->output_section->vma + h->plt.offset;
    }
  return symval;
}
static bfd_signed_vma
calculate_plt_offset (bfd *abfd, asection *sec, struct bfd_link_info *link_info,
        Elf_Internal_Sym *isymbuf, Elf_Internal_Rela *irel,
        Elf_Internal_Shdr *symtab_hdr)
{
  bfd_vma foff;
  if ((foff = calculate_plt_memory_address (abfd, link_info, isymbuf, irel,
         symtab_hdr)) == 0)
    return 0;
  else
    return foff - (irel->r_offset
     + sec->output_section->vma + sec->output_offset);
}
static int
nds32_convert_32_to_16_alu1 (bfd *abfd, uint32_t insn, uint16_t *pinsn16,
        int *pinsn_type)
{
  uint16_t insn16 = 0;
  int insn_type;
  unsigned long mach = bfd_get_mach (abfd);
  if (N32_SH5 (insn) != 0)
    return 0;
  switch (N32_SUB5 (insn))
    {
    case N32_ALU1_ADD_SLLI:
    case N32_ALU1_ADD_SRLI:
      if (N32_IS_RT3 (insn) && N32_IS_RA3 (insn) && N32_IS_RB3 (insn))
 {
   insn16 = N16_TYPE333 (ADD333, N32_RT5 (insn), N32_RA5 (insn),
    N32_RB5 (insn));
   insn_type = NDS32_INSN_ADD333;
 }
      else if (N32_IS_RT4 (insn))
 {
   if (N32_RT5 (insn) == N32_RA5 (insn))
     insn16 = N16_TYPE45 (ADD45, N32_RT54 (insn), N32_RB5 (insn));
   else if (N32_RT5 (insn) == N32_RB5 (insn))
     insn16 = N16_TYPE45 (ADD45, N32_RT54 (insn), N32_RA5 (insn));
   insn_type = NDS32_INSN_ADD45;
 }
      break;
    case N32_ALU1_SUB_SLLI:
    case N32_ALU1_SUB_SRLI:
      if (N32_IS_RT3 (insn) && N32_IS_RA3 (insn) && N32_IS_RB3 (insn))
 {
   insn16 = N16_TYPE333 (SUB333, N32_RT5 (insn), N32_RA5 (insn),
    N32_RB5 (insn));
   insn_type = NDS32_INSN_SUB333;
 }
      else if (N32_IS_RT4 (insn) && N32_RT5 (insn) == N32_RA5 (insn))
 {
   insn16 = N16_TYPE45 (SUB45, N32_RT54 (insn), N32_RB5 (insn));
   insn_type = NDS32_INSN_SUB45;
 }
      break;
    case N32_ALU1_AND_SLLI:
    case N32_ALU1_AND_SRLI:
      if (mach >= MACH_V3 && N32_IS_RT3 (insn) && N32_IS_RA3 (insn)
   && N32_IS_RB3 (insn))
 {
   if (N32_RT5 (insn) == N32_RA5 (insn))
     insn16 = N16_MISC33 (AND33, N32_RT5 (insn), N32_RB5 (insn));
   else if (N32_RT5 (insn) == N32_RB5 (insn))
     insn16 = N16_MISC33 (AND33, N32_RT5 (insn), N32_RA5 (insn));
   if (insn16)
     insn_type = NDS32_INSN_AND33;
 }
      break;
    case N32_ALU1_XOR_SLLI:
    case N32_ALU1_XOR_SRLI:
      if (mach >= MACH_V3 && N32_IS_RT3 (insn) && N32_IS_RA3 (insn)
   && N32_IS_RB3 (insn))
 {
   if (N32_RT5 (insn) == N32_RA5 (insn))
     insn16 = N16_MISC33 (XOR33, N32_RT5 (insn), N32_RB5 (insn));
   else if (N32_RT5 (insn) == N32_RB5 (insn))
     insn16 = N16_MISC33 (XOR33, N32_RT5 (insn), N32_RA5 (insn));
   if (insn16)
     insn_type = NDS32_INSN_XOR33;
 }
      break;
    case N32_ALU1_OR_SLLI:
    case N32_ALU1_OR_SRLI:
      if (mach >= MACH_V3 && N32_IS_RT3 (insn) && N32_IS_RA3 (insn)
   && N32_IS_RB3 (insn))
 {
   if (N32_RT5 (insn) == N32_RA5 (insn))
     insn16 = N16_MISC33 (OR33, N32_RT5 (insn), N32_RB5 (insn));
   else if (N32_RT5 (insn) == N32_RB5 (insn))
     insn16 = N16_MISC33 (OR33, N32_RT5 (insn), N32_RA5 (insn));
   if (insn16)
     insn_type = NDS32_INSN_OR33;
 }
      break;
    case N32_ALU1_NOR:
      if (mach >= MACH_V3 && N32_IS_RT3 (insn) && N32_IS_RB3 (insn)
   && N32_RA5 (insn) == N32_RB5 (insn))
 {
   insn16 = N16_MISC33 (NOT33, N32_RT5 (insn), N32_RA5 (insn));
   insn_type = NDS32_INSN_NOT33;
 }
      break;
    case N32_ALU1_SRAI:
      if (N32_IS_RT4 (insn) && N32_RT5 (insn) == N32_RA5 (insn))
 {
   insn16 = N16_TYPE45 (SRAI45, N32_RT54 (insn), N32_UB5 (insn));
   insn_type = NDS32_INSN_SRAI45;
 }
      break;
    case N32_ALU1_SRLI:
      if (N32_IS_RT4 (insn) && N32_RT5 (insn) == N32_RA5 (insn))
 {
   insn16 = N16_TYPE45 (SRLI45, N32_RT54 (insn), N32_UB5 (insn));
   insn_type = NDS32_INSN_SRLI45;
 }
      break;
    case N32_ALU1_SLLI:
      if (N32_IS_RT3 (insn) && N32_IS_RA3 (insn) && N32_UB5 (insn) < 8)
 {
   insn16 = N16_TYPE333 (SLLI333, N32_RT5 (insn), N32_RA5 (insn),
    N32_UB5 (insn));
   insn_type = NDS32_INSN_SLLI333;
 }
      break;
    case N32_ALU1_ZEH:
      if (N32_IS_RT3 (insn) && N32_IS_RA3 (insn))
 {
   insn16 = N16_BFMI333 (ZEH33, N32_RT5 (insn), N32_RA5 (insn));
   insn_type = NDS32_INSN_ZEH33;
 }
      break;
    case N32_ALU1_SEB:
      if (N32_IS_RT3 (insn) && N32_IS_RA3 (insn))
 {
   insn16 = N16_BFMI333 (SEB33, N32_RT5 (insn), N32_RA5 (insn));
   insn_type = NDS32_INSN_SEB33;
 }
      break;
    case N32_ALU1_SEH:
      if (N32_IS_RT3 (insn) && N32_IS_RA3 (insn))
 {
   insn16 = N16_BFMI333 (SEH33, N32_RT5 (insn), N32_RA5 (insn));
   insn_type = NDS32_INSN_SEH33;
 }
      break;
    case N32_ALU1_SLT:
      if (N32_RT5 (insn) == REG_R15 && N32_IS_RA4 (insn))
 {
   insn16 = N16_TYPE45 (SLT45, N32_RA54 (insn), N32_RB5 (insn));
   insn_type = NDS32_INSN_SLT45;
 }
      break;
    case N32_ALU1_SLTS:
      if (N32_RT5 (insn) == REG_R15 && N32_IS_RA4 (insn))
 {
   insn16 = N16_TYPE45 (SLTS45, N32_RA54 (insn), N32_RB5 (insn));
   insn_type = NDS32_INSN_SLTS45;
 }
      break;
    }
  if ((insn16 & 0x8000) == 0)
    return 0;
  if (pinsn16)
    *pinsn16 = insn16;
  if (pinsn_type)
    *pinsn_type = insn_type;
  return 1;
}
static int
nds32_convert_32_to_16_alu2 (bfd *abfd, uint32_t insn, uint16_t *pinsn16,
        int *pinsn_type)
{
  uint16_t insn16 = 0;
  int insn_type;
  unsigned long mach = bfd_get_mach (abfd);
  if (__GF (insn, 6, 4) != 0)
    return 0;
  switch (N32_IMMU (insn, 6))
    {
    case N32_ALU2_MUL:
      if (mach >= MACH_V3 && N32_IS_RT3 (insn) && N32_IS_RA3 (insn)
   && N32_IS_RB3 (insn))
 {
   if (N32_RT5 (insn) == N32_RA5 (insn))
     insn16 = N16_MISC33 (MUL33, N32_RT5 (insn), N32_RB5 (insn));
   else if (N32_RT5 (insn) == N32_RB5 (insn))
     insn16 = N16_MISC33 (MUL33, N32_RT5 (insn), N32_RA5 (insn));
   if (insn16)
     insn_type = NDS32_INSN_MUL33;
 }
    }
  if ((insn16 & 0x8000) == 0)
    return 0;
  if (pinsn16)
    *pinsn16 = insn16;
  if (pinsn_type)
    *pinsn_type = insn_type;
  return 1;
}
int
nds32_convert_32_to_16 (bfd *abfd, uint32_t insn, uint16_t *pinsn16,
   int *pinsn_type)
{
  int op6;
  uint16_t insn16 = 0;
  int insn_type;
  unsigned long mach = bfd_get_mach (abfd);
  if (insn & 0x80000000)
    {
      return 0;
    }
  op6 = N32_OP6 (insn);
  switch (op6)
    {
    case N32_OP6_MOVI:
      if (IS_WITHIN_S (N32_IMM20S (insn), 5))
 {
   insn16 = N16_TYPE55 (MOVI55, N32_RT5 (insn), N32_IMM20S (insn));
   insn_type = NDS32_INSN_MOVI55;
 }
      else if (mach >= MACH_V3 && N32_IMM20S (insn) >= 16
        && N32_IMM20S (insn) < 48 && N32_IS_RT4 (insn))
 {
   insn16 = N16_TYPE45 (MOVPI45, N32_RT54 (insn),
          N32_IMM20S (insn) - 16);
   insn_type = NDS32_INSN_MOVPI45;
 }
      break;
    case N32_OP6_ADDI:
      if (N32_IMM15S (insn) == 0)
 {
   if (mach <= MACH_V2
       || N32_RT5 (insn) != REG_SP || N32_RA5 (insn) != REG_SP)
     {
       insn16 = N16_TYPE55 (MOV55, N32_RT5 (insn), N32_RA5 (insn));
       insn_type = NDS32_INSN_MOV55;
     }
 }
      else if (N32_IMM15S (insn) > 0)
 {
   if (N32_IS_RT3 (insn) && N32_IS_RA3 (insn) && N32_IMM15S (insn) < 8)
     {
       insn16 = N16_TYPE333 (ADDI333, N32_RT5 (insn), N32_RA5 (insn),
        N32_IMM15S (insn));
       insn_type = NDS32_INSN_ADDI333;
     }
   else if (N32_IS_RT4 (insn) && N32_RT5 (insn) == N32_RA5 (insn)
     && N32_IMM15S (insn) < 32)
     {
       insn16 = N16_TYPE45 (ADDI45, N32_RT54 (insn), N32_IMM15S (insn));
       insn_type = NDS32_INSN_ADDI45;
     }
   else if (mach >= MACH_V2 && N32_RT5 (insn) == REG_SP
     && N32_RT5 (insn) == N32_RA5 (insn)
     && N32_IMM15S (insn) < 512)
     {
       insn16 = N16_TYPE10 (ADDI10S, N32_IMM15S (insn));
       insn_type = NDS32_INSN_ADDI10_SP;
     }
   else if (mach >= MACH_V3 && N32_IS_RT3 (insn)
     && N32_RA5 (insn) == REG_SP && N32_IMM15S (insn) < 256
     && (N32_IMM15S (insn) % 4 == 0))
     {
       insn16 = N16_TYPE36 (ADDRI36_SP, N32_RT5 (insn),
       N32_IMM15S (insn) >> 2);
       insn_type = NDS32_INSN_ADDRI36_SP;
     }
 }
      else
 {
   if (N32_IS_RT3 (insn) && N32_IS_RA3 (insn) && N32_IMM15S (insn) > -8)
     {
       insn16 = N16_TYPE333 (SUBI333, N32_RT5 (insn), N32_RA5 (insn),
        0 - N32_IMM15S (insn));
       insn_type = NDS32_INSN_SUBI333;
     }
   else if (N32_IS_RT4 (insn) && N32_RT5 (insn) == N32_RA5 (insn)
     && N32_IMM15S (insn) > -32)
     {
       insn16 = N16_TYPE45 (SUBI45, N32_RT54 (insn), 0 - N32_IMM15S (insn));
       insn_type = NDS32_INSN_SUBI45;
     }
   else if (mach >= MACH_V2 && N32_RT5 (insn) == REG_SP
     && N32_RT5 (insn) == N32_RA5 (insn)
     && N32_IMM15S (insn) >= -512)
     {
       insn16 = N16_TYPE10 (ADDI10S, N32_IMM15S (insn));
       insn_type = NDS32_INSN_ADDI10_SP;
     }
 }
      break;
    case N32_OP6_ORI:
      if (N32_IMM15S (insn) == 0)
 {
   if (mach <= MACH_V2
       || N32_RT5 (insn) != REG_SP || N32_RA5 (insn) != REG_SP)
     {
       insn16 = N16_TYPE55 (MOV55, N32_RT5 (insn), N32_RA5 (insn));
       insn_type = NDS32_INSN_MOV55;
     }
 }
      break;
    case N32_OP6_SUBRI:
      if (mach >= MACH_V3 && N32_IS_RT3 (insn)
   && N32_IS_RA3 (insn) && N32_IMM15S (insn) == 0)
 {
   insn16 = N16_MISC33 (NEG33, N32_RT5 (insn), N32_RA5 (insn));
   insn_type = NDS32_INSN_NEG33;
 }
      break;
    case N32_OP6_ANDI:
      if (N32_IS_RT3 (insn) && N32_IS_RA3 (insn))
 {
   if (N32_IMM15U (insn) == 1)
     {
       insn16 = N16_BFMI333 (XLSB33, N32_RT5 (insn), N32_RA5 (insn));
       insn_type = NDS32_INSN_XLSB33;
     }
   else if (N32_IMM15U (insn) == 0x7ff)
     {
       insn16 = N16_BFMI333 (X11B33, N32_RT5 (insn), N32_RA5 (insn));
       insn_type = NDS32_INSN_X11B33;
     }
   else if (N32_IMM15U (insn) == 0xff)
     {
       insn16 = N16_BFMI333 (ZEB33, N32_RT5 (insn), N32_RA5 (insn));
       insn_type = NDS32_INSN_ZEB33;
     }
   else if (mach >= MACH_V3 && N32_RT5 (insn) == N32_RA5 (insn)
     && N32_IMM15U (insn) < 256)
     {
       int imm15u = N32_IMM15U (insn);
       if (__builtin_popcount (imm15u) == 1)
  {
    int imm3u = __builtin_ctz (imm15u);
    insn16 = N16_BFMI333 (BMSKI33, N32_RT5 (insn), imm3u);
    insn_type = NDS32_INSN_BMSKI33;
  }
       else if (imm15u != 0 && __builtin_popcount (imm15u + 1) == 1)
  {
    int imm3u = __builtin_ctz (imm15u + 1) - 1;
    insn16 = N16_BFMI333 (FEXTI33, N32_RT5 (insn), imm3u);
    insn_type = NDS32_INSN_FEXTI33;
  }
     }
 }
      break;
    case N32_OP6_SLTI:
      if (N32_RT5 (insn) == REG_R15 && N32_IS_RA4 (insn)
   && IS_WITHIN_U (N32_IMM15S (insn), 5))
 {
   insn16 = N16_TYPE45 (SLTI45, N32_RA54 (insn), N32_IMM15S (insn));
   insn_type = NDS32_INSN_SLTI45;
 }
      break;
    case N32_OP6_SLTSI:
      if (N32_RT5 (insn) == REG_R15 && N32_IS_RA4 (insn)
   && IS_WITHIN_U (N32_IMM15S (insn), 5))
 {
   insn16 = N16_TYPE45 (SLTSI45, N32_RA54 (insn), N32_IMM15S (insn));
   insn_type = NDS32_INSN_SLTSI45;
 }
      break;
    case N32_OP6_LWI:
      if (N32_IS_RT4 (insn) && N32_IMM15S (insn) == 0)
 {
   insn16 = N16_TYPE45 (LWI450, N32_RT54 (insn), N32_RA5 (insn));
   insn_type = NDS32_INSN_LWI450;
 }
      else if (N32_IS_RT3 (insn) && N32_IS_RA3 (insn)
        && IS_WITHIN_U (N32_IMM15S (insn), 3))
 {
   insn16 = N16_TYPE333 (LWI333, N32_RT5 (insn), N32_RA5 (insn),
    N32_IMM15S (insn));
   insn_type = NDS32_INSN_LWI333;
 }
      else if (N32_IS_RT3 (insn) && N32_RA5 (insn) == REG_FP
        && IS_WITHIN_U (N32_IMM15S (insn), 7))
 {
   insn16 = N16_TYPE37 (XWI37, N32_RT5 (insn), 0, N32_IMM15S (insn));
   insn_type = NDS32_INSN_LWI37;
 }
      else if (mach >= MACH_V2 && N32_IS_RT3 (insn) && N32_RA5 (insn) == REG_SP
        && IS_WITHIN_U (N32_IMM15S (insn), 7))
 {
   insn16 = N16_TYPE37 (XWI37SP, N32_RT5 (insn), 0, N32_IMM15S (insn));
   insn_type = NDS32_INSN_LWI37_SP;
 }
      else if (mach >= MACH_V2 && N32_IS_RT4 (insn) && N32_RA5 (insn) == REG_R8
        && -32 <= N32_IMM15S (insn) && N32_IMM15S (insn) < 0)
 {
   insn16 = N16_TYPE45 (LWI45_FE, N32_RT54 (insn),
          N32_IMM15S (insn) + 32);
   insn_type = NDS32_INSN_LWI45_FE;
 }
      break;
    case N32_OP6_SWI:
      if (N32_IS_RT4 (insn) && N32_IMM15S (insn) == 0)
 {
   insn16 = N16_TYPE45 (SWI450, N32_RT54 (insn), N32_RA5 (insn));
   insn_type = NDS32_INSN_SWI450;
 }
      else if (N32_IS_RT3 (insn) && N32_IS_RA3 (insn)
        && IS_WITHIN_U (N32_IMM15S (insn), 3))
 {
   insn16 = N16_TYPE333 (SWI333, N32_RT5 (insn), N32_RA5 (insn),
    N32_IMM15S (insn));
   insn_type = NDS32_INSN_SWI333;
 }
      else if (N32_IS_RT3 (insn) && N32_RA5 (insn) == REG_FP
        && IS_WITHIN_U (N32_IMM15S (insn), 7))
 {
   insn16 = N16_TYPE37 (XWI37, N32_RT5 (insn), 1, N32_IMM15S (insn));
   insn_type = NDS32_INSN_SWI37;
 }
      else if (mach >= MACH_V2 && N32_IS_RT3 (insn) && N32_RA5 (insn) == REG_SP
        && IS_WITHIN_U (N32_IMM15S (insn), 7))
 {
   insn16 = N16_TYPE37 (XWI37SP, N32_RT5 (insn), 1, N32_IMM15S (insn));
   insn_type = NDS32_INSN_SWI37_SP;
 }
      break;
    case N32_OP6_LWI_BI:
      if (N32_IS_RT3 (insn) && N32_IS_RA3 (insn)
   && IS_WITHIN_U (N32_IMM15S (insn), 3))
 {
   insn16 = N16_TYPE333 (LWI333_BI, N32_RT5 (insn), N32_RA5 (insn),
    N32_IMM15S (insn));
   insn_type = NDS32_INSN_LWI333_BI;
 }
      break;
    case N32_OP6_SWI_BI:
      if (N32_IS_RT3 (insn) && N32_IS_RA3 (insn)
   && IS_WITHIN_U (N32_IMM15S (insn), 3))
 {
   insn16 = N16_TYPE333 (SWI333_BI, N32_RT5 (insn), N32_RA5 (insn),
    N32_IMM15S (insn));
   insn_type = NDS32_INSN_SWI333_BI;
 }
      break;
    case N32_OP6_LHI:
      if (N32_IS_RT3 (insn) && N32_IS_RA3 (insn)
   && IS_WITHIN_U (N32_IMM15S (insn), 3))
 {
   insn16 = N16_TYPE333 (LHI333, N32_RT5 (insn), N32_RA5 (insn),
    N32_IMM15S (insn));
   insn_type = NDS32_INSN_LHI333;
 }
      break;
    case N32_OP6_SHI:
      if (N32_IS_RT3 (insn) && N32_IS_RA3 (insn)
   && IS_WITHIN_U (N32_IMM15S (insn), 3))
 {
   insn16 = N16_TYPE333 (SHI333, N32_RT5 (insn), N32_RA5 (insn),
    N32_IMM15S (insn));
   insn_type = NDS32_INSN_SHI333;
 }
      break;
    case N32_OP6_LBI:
      if (N32_IS_RT3 (insn) && N32_IS_RA3 (insn)
   && IS_WITHIN_U (N32_IMM15S (insn), 3))
 {
   insn16 = N16_TYPE333 (LBI333, N32_RT5 (insn), N32_RA5 (insn),
    N32_IMM15S (insn));
   insn_type = NDS32_INSN_LBI333;
 }
      break;
    case N32_OP6_SBI:
      if (N32_IS_RT3 (insn) && N32_IS_RA3 (insn)
   && IS_WITHIN_U (N32_IMM15S (insn), 3))
 {
   insn16 = N16_TYPE333 (SBI333, N32_RT5 (insn), N32_RA5 (insn),
    N32_IMM15S (insn));
   insn_type = NDS32_INSN_SBI333;
 }
      break;
    case N32_OP6_ALU1:
      return nds32_convert_32_to_16_alu1 (abfd, insn, pinsn16, pinsn_type);
    case N32_OP6_ALU2:
      return nds32_convert_32_to_16_alu2 (abfd, insn, pinsn16, pinsn_type);
    case N32_OP6_BR1:
      if (!IS_WITHIN_S (N32_IMM14S (insn), 8))
 goto done;
      if ((insn & __BIT (14)) == 0)
 {
   if (N32_IS_RT3 (insn) && N32_RA5 (insn) == REG_R5
       && N32_RT5 (insn) != REG_R5)
     insn16 = N16_TYPE38 (BEQS38, N32_RT5 (insn), N32_IMM14S (insn));
   else if (N32_IS_RA3 (insn) && N32_RT5 (insn) == REG_R5
     && N32_RA5 (insn) != REG_R5)
     insn16 = N16_TYPE38 (BEQS38, N32_RA5 (insn), N32_IMM14S (insn));
   insn_type = NDS32_INSN_BEQS38;
   break;
 }
      else
 {
   if (N32_IS_RT3 (insn) && N32_RA5 (insn) == REG_R5
       && N32_RT5 (insn) != REG_R5)
     insn16 = N16_TYPE38 (BNES38, N32_RT5 (insn), N32_IMM14S (insn));
   else if (N32_IS_RA3 (insn) && N32_RT5 (insn) == REG_R5
     && N32_RA5 (insn) != REG_R5)
     insn16 = N16_TYPE38 (BNES38, N32_RA5 (insn), N32_IMM14S (insn));
   insn_type = NDS32_INSN_BNES38;
   break;
 }
      break;
    case N32_OP6_BR2:
      switch (N32_BR2_SUB (insn))
 {
 case N32_BR2_BEQZ:
   if (N32_IS_RT3 (insn) && IS_WITHIN_S (N32_IMM16S (insn), 8))
     {
       insn16 = N16_TYPE38 (BEQZ38, N32_RT5 (insn), N32_IMM16S (insn));
       insn_type = NDS32_INSN_BEQZ38;
     }
   else if (N32_RT5 (insn) == REG_R15 && IS_WITHIN_S (N32_IMM16S (insn), 8))
     {
       insn16 = N16_TYPE8 (BEQZS8, N32_IMM16S (insn));
       insn_type = NDS32_INSN_BEQZS8;
     }
   break;
 case N32_BR2_BNEZ:
   if (N32_IS_RT3 (insn) && IS_WITHIN_S (N32_IMM16S (insn), 8))
     {
       insn16 = N16_TYPE38 (BNEZ38, N32_RT5 (insn), N32_IMM16S (insn));
       insn_type = NDS32_INSN_BNEZ38;
     }
   else if (N32_RT5 (insn) == REG_R15 && IS_WITHIN_S (N32_IMM16S (insn), 8))
     {
       insn16 = N16_TYPE8 (BNEZS8, N32_IMM16S (insn));
       insn_type = NDS32_INSN_BNEZS8;
     }
   break;
 case N32_BR2_SOP0:
   if (__GF (insn, 20, 5) == 0 && IS_WITHIN_U (N32_IMM16S (insn), 9))
     {
       insn16 = N16_TYPE9 (IFCALL9, N32_IMM16S (insn));
       insn_type = NDS32_INSN_IFCALL9;
     }
   break;
 }
      break;
    case N32_OP6_JI:
      if ((insn & __BIT (24)) == 0)
 {
   if (IS_WITHIN_S (N32_IMM24S (insn), 8))
     {
       insn16 = N16_TYPE8 (J8, N32_IMM24S (insn));
       insn_type = NDS32_INSN_J8;
     }
 }
      break;
    case N32_OP6_JREG:
      if (__GF (insn, 8, 2) != 0)
 goto done;
      switch (N32_IMMU (insn, 5))
 {
 case N32_JREG_JR:
   if (N32_JREG_HINT (insn) == 0)
     {
       insn16 = N16_TYPE5 (JR5, N32_RB5 (insn));
       insn_type = NDS32_INSN_JR5;
     }
   else if (N32_JREG_HINT (insn) == 1)
     {
       insn16 = N16_TYPE5 (RET5, N32_RB5 (insn));
       insn_type = NDS32_INSN_RET5;
     }
   else if (N32_JREG_HINT (insn) == 3)
     {
       insn16 = N16_TYPE55 (MOV55, REG_SP, REG_SP);
       insn_type = NDS32_INSN_IFRET;
     }
   break;
 case N32_JREG_JRAL:
   if (N32_RT5 (insn) == REG_LP && N32_JREG_HINT (insn) == 0)
     {
       insn16 = N16_TYPE5 (JRAL5, N32_RB5 (insn));
       insn_type = NDS32_INSN_JRAL5;
     }
   break;
 }
      break;
    case N32_OP6_MISC:
      if (N32_SUB5 (insn) == N32_MISC_BREAK && N32_SWID (insn) < 32)
 {
   insn16 = N16_TYPE5 (BREAK16, N32_SWID (insn));
   insn_type = NDS32_INSN_BREAK16;
 }
      break;
    default:
      goto done;
    }
done:
  if ((insn16 & 0x8000) == 0)
    return 0;
  if (pinsn16)
    *pinsn16 = insn16;
  if (pinsn_type)
    *pinsn_type = insn_type;
  return 1;
}
static int
special_convert_32_to_16 (unsigned long insn, uint16_t *pinsn16,
     Elf_Internal_Rela *reloc)
{
  uint16_t insn16 = 0;
  if ((reloc->r_addend & R_NDS32_INSN16_FP7U2_FLAG) == 0
      || (ELF32_R_TYPE (reloc->r_info) != R_NDS32_INSN16))
    return 0;
  if (!N32_IS_RT3 (insn))
    return 0;
  switch (N32_OP6 (insn))
    {
    case N32_OP6_LWI:
      if (N32_RA5 (insn) == REG_GP && IS_WITHIN_U (N32_IMM15S (insn), 7))
 insn16 = N16_TYPE37 (XWI37, N32_RT5 (insn), 0, N32_IMM15S (insn));
      break;
    case N32_OP6_SWI:
      if (N32_RA5 (insn) == REG_GP && IS_WITHIN_U (N32_IMM15S (insn), 7))
 insn16 = N16_TYPE37 (XWI37, N32_RT5 (insn), 1, N32_IMM15S (insn));
      break;
    case N32_OP6_HWGP:
      if (!IS_WITHIN_U (N32_IMM17S (insn), 7))
 break;
      if (__GF (insn, 17, 3) == 6)
 insn16 = N16_TYPE37 (XWI37, N32_RT5 (insn), 0, N32_IMM17S (insn));
      else if (__GF (insn, 17, 3) == 7)
 insn16 = N16_TYPE37 (XWI37, N32_RT5 (insn), 1, N32_IMM17S (insn));
      break;
    }
  if ((insn16 & 0x8000) == 0)
    return 0;
  *pinsn16 = insn16;
  return 1;
}
int
nds32_convert_16_to_32 (bfd *abfd, uint16_t insn16, uint32_t *pinsn)
{
  uint32_t insn = 0xffffffff;
  unsigned long mach = bfd_get_mach (abfd);
  switch (__GF (insn16, 9, 6))
    {
    case 0x4:
      insn = N32_ALU1 (ADD, N16_RT4 (insn16), N16_RT4 (insn16), N16_RA5 (insn16));
      goto done;
    case 0x5:
      insn = N32_ALU1 (SUB, N16_RT4 (insn16), N16_RT4 (insn16), N16_RA5 (insn16));
      goto done;
    case 0x6:
      insn = N32_TYPE2 (ADDI, N16_RT4 (insn16), N16_RT4 (insn16), N16_IMM5U (insn16));
      goto done;
    case 0x7:
      insn = N32_TYPE2 (ADDI, N16_RT4 (insn16), N16_RT4 (insn16), -N16_IMM5U (insn16));
      goto done;
    case 0x8:
      insn = N32_ALU1 (SRAI, N16_RT4 (insn16), N16_RT4 (insn16), N16_IMM5U (insn16));
      goto done;
    case 0x9:
      insn = N32_ALU1 (SRLI, N16_RT4 (insn16), N16_RT4 (insn16), N16_IMM5U (insn16));
      goto done;
    case 0xa:
      insn = N32_ALU1 (SLLI, N16_RT3 (insn16), N16_RA3 (insn16), N16_IMM3U (insn16));
      goto done;
    case 0xc:
      insn = N32_ALU1 (ADD, N16_RT3 (insn16), N16_RA3 (insn16), N16_RB3 (insn16));
      goto done;
    case 0xd:
      insn = N32_ALU1 (SUB, N16_RT3 (insn16), N16_RA3 (insn16), N16_RB3 (insn16));
      goto done;
    case 0xe:
      insn = N32_TYPE2 (ADDI, N16_RT3 (insn16), N16_RA3 (insn16), N16_IMM3U (insn16));
      goto done;
    case 0xf:
      insn = N32_TYPE2 (ADDI, N16_RT3 (insn16), N16_RA3 (insn16), -N16_IMM3U (insn16));
      goto done;
    case 0x10:
      insn = N32_TYPE2 (LWI, N16_RT3 (insn16), N16_RA3 (insn16), N16_IMM3U (insn16));
      goto done;
    case 0x12:
      insn = N32_TYPE2 (LHI, N16_RT3 (insn16), N16_RA3 (insn16), N16_IMM3U (insn16));
      goto done;
    case 0x13:
      insn = N32_TYPE2 (LBI, N16_RT3 (insn16), N16_RA3 (insn16), N16_IMM3U (insn16));
      goto done;
    case 0x11:
      insn = N32_TYPE2 (LWI_BI, N16_RT3 (insn16), N16_RA3 (insn16), N16_IMM3U (insn16));
      goto done;
    case 0x14:
      insn = N32_TYPE2 (SWI, N16_RT3 (insn16), N16_RA3 (insn16), N16_IMM3U (insn16));
      goto done;
    case 0x16:
      insn = N32_TYPE2 (SHI, N16_RT3 (insn16), N16_RA3 (insn16), N16_IMM3U (insn16));
      goto done;
    case 0x17:
      insn = N32_TYPE2 (SBI, N16_RT3 (insn16), N16_RA3 (insn16), N16_IMM3U (insn16));
      goto done;
    case 0x15:
      insn = N32_TYPE2 (SWI_BI, N16_RT3 (insn16), N16_RA3 (insn16), N16_IMM3U (insn16));
      goto done;
    case 0x18:
      insn = N32_TYPE2 (ADDI, N16_RT3 (insn16), REG_SP, N16_IMM6U (insn16) << 2);
      goto done;
    case 0x19:
      insn = N32_TYPE2 (LWI, N16_RT4 (insn16), REG_R8, (N16_IMM5U (insn16) - 32));
      goto done;
    case 0x1a:
      insn = N32_TYPE2 (LWI, N16_RT4 (insn16), N16_RA5 (insn16), 0);
      goto done;
    case 0x1b:
      insn = N32_TYPE2 (SWI, N16_RT4 (insn16), N16_RA5 (insn16), 0);
      goto done;
    case 0x30:
      insn = N32_ALU1 (SLTS, REG_TA, N16_RT4 (insn16), N16_RA5 (insn16));
      goto done;
    case 0x31:
      insn = N32_ALU1 (SLT, REG_TA, N16_RT4 (insn16), N16_RA5 (insn16));
      goto done;
    case 0x32:
      insn = N32_TYPE2 (SLTSI, REG_TA, N16_RT4 (insn16), N16_IMM5U (insn16));
      goto done;
    case 0x33:
      insn = N32_TYPE2 (SLTI, REG_TA, N16_RT4 (insn16), N16_IMM5U (insn16));
      goto done;
    case 0x34:
      if (insn16 & __BIT (8))
 insn = N32_BR2 (BNEZ, REG_TA, N16_IMM8S (insn16));
      else
 insn = N32_BR2 (BEQZ, REG_TA, N16_IMM8S (insn16));
      goto done;
    case 0x35:
      insn = N32_TYPE0 (MISC, (N16_IMM5U (insn16) << 5) | N32_MISC_BREAK);
      goto done;
    case 0x3c:
      insn = N32_BR2 (SOP0, 0, N16_IMM9U (insn16));
      goto done;
    case 0x3d:
      insn = N32_TYPE1 (MOVI, N16_RT4 (insn16), N16_IMM5U (insn16) + 16);
      goto done;
    case 0x3f:
      switch (insn16 & 0x7)
 {
 case 2:
   insn = N32_TYPE2 (SUBRI, N16_RT3 (insn16), N16_RA3 (insn16), 0);
   break;
 case 3:
   insn = N32_ALU1 (NOR, N16_RT3 (insn16), N16_RA3 (insn16), N16_RA3 (insn16));
   break;
 case 4:
   insn = N32_ALU2 (MUL, N16_RT3 (insn16), N16_RT3 (insn16), N16_RA3 (insn16));
   break;
 case 5:
   insn = N32_ALU1 (XOR, N16_RT3 (insn16), N16_RT3 (insn16), N16_RA3 (insn16));
   break;
 case 6:
   insn = N32_ALU1 (AND, N16_RT3 (insn16), N16_RT3 (insn16), N16_RA3 (insn16));
   break;
 case 7:
   insn = N32_ALU1 (OR, N16_RT3 (insn16), N16_RT3 (insn16), N16_RA3 (insn16));
   break;
 }
      goto done;
    case 0xb:
      switch (insn16 & 0x7)
 {
 case 0:
   insn = N32_TYPE2 (ANDI, N16_RT3 (insn16), N16_RA3 (insn16), 0xff);
   break;
 case 1:
   insn = N32_ALU1 (ZEH, N16_RT3 (insn16), N16_RA3 (insn16), 0);
   break;
 case 2:
   insn = N32_ALU1 (SEB, N16_RT3 (insn16), N16_RA3 (insn16), 0);
   break;
 case 3:
   insn = N32_ALU1 (SEH, N16_RT3 (insn16), N16_RA3 (insn16), 0);
   break;
 case 4:
   insn = N32_TYPE2 (ANDI, N16_RT3 (insn16), N16_RA3 (insn16), 1);
   break;
 case 5:
   insn = N32_TYPE2 (ANDI, N16_RT3 (insn16), N16_RA3 (insn16), 0x7ff);
   break;
 case 6:
   insn = N32_TYPE2 (ANDI, N16_RT3 (insn16), N16_RT3 (insn16),
       1 << __GF (insn16, 3, 3));
   break;
 case 7:
   insn = N32_TYPE2 (ANDI, N16_RT3 (insn16), N16_RT3 (insn16),
       (1 << (__GF (insn16, 3, 3) + 1)) - 1);
   break;
 }
      goto done;
    }
  switch (__GF (insn16, 10, 5))
    {
    case 0x0:
      if (mach >= MACH_V3 && N16_RT5 (insn16) == REG_SP
   && N16_RT5 (insn16) == N16_RA5 (insn16))
   insn = N32_JREG (JR, 0, 0, 0, 3);
      else
   insn = N32_TYPE2 (ADDI, N16_RT5 (insn16), N16_RA5 (insn16), 0);
      goto done;
    case 0x1:
      insn = N32_TYPE1 (MOVI, N16_RT5 (insn16), N16_IMM5S (insn16));
      goto done;
    case 0x1b:
      insn = N32_TYPE2 (ADDI, REG_SP, REG_SP, N16_IMM10S (insn16));
      goto done;
    }
  switch (__GF (insn16, 11, 4))
    {
    case 0x7:
      if (insn16 & __BIT (7))
 insn = N32_TYPE2 (SWI, N16_RT38 (insn16), REG_FP, N16_IMM7U (insn16));
      else
 insn = N32_TYPE2 (LWI, N16_RT38 (insn16), REG_FP, N16_IMM7U (insn16));
      goto done;
    case 0x8:
      insn = N32_BR2 (BEQZ, N16_RT38 (insn16), N16_IMM8S (insn16));
      goto done;
    case 0x9:
      insn = N32_BR2 (BNEZ, N16_RT38 (insn16), N16_IMM8S (insn16));
      goto done;
    case 0xa:
      if (N16_RT38 (insn16) == 5)
 insn = N32_JI (J, N16_IMM8S (insn16));
      else
 insn = N32_BR1 (BEQ, N16_RT38 (insn16), REG_R5, N16_IMM8S (insn16));
      goto done;
    case 0xb:
      if (N16_RT38 (insn16) == 5)
 {
   switch (__GF (insn16, 5, 3))
     {
     case 0:
       insn = N32_JREG (JR, 0, N16_RA5 (insn16), 0, 0);
       break;
     case 4:
       insn = N32_JREG (JR, 0, N16_RA5 (insn16), 0, 1);
       break;
     case 1:
       insn = N32_JREG (JRAL, REG_LP, N16_RA5 (insn16), 0, 0);
       break;
     case 2:
       break;
     case 5:
       break;
     }
 }
      else
 insn = N32_BR1 (BNE, N16_RT38 (insn16), REG_R5, N16_IMM8S (insn16));
      goto done;
    case 0xe:
      if (insn16 & (1 << 7))
 insn = N32_TYPE2 (SWI, N16_RT38 (insn16), REG_SP, N16_IMM7U (insn16));
      else
 insn = N32_TYPE2 (LWI, N16_RT38 (insn16), REG_SP, N16_IMM7U (insn16));
      goto done;
    }
done:
  if (insn & 0x80000000)
    return 0;
  if (pinsn)
    *pinsn = insn;
  return 1;
}
static bfd_boolean
is_sda_access_insn (unsigned long insn)
{
  switch (N32_OP6 (insn))
    {
    case N32_OP6_LWI:
    case N32_OP6_LHI:
    case N32_OP6_LHSI:
    case N32_OP6_LBI:
    case N32_OP6_LBSI:
    case N32_OP6_SWI:
    case N32_OP6_SHI:
    case N32_OP6_SBI:
    case N32_OP6_LWC:
    case N32_OP6_LDC:
    case N32_OP6_SWC:
    case N32_OP6_SDC:
      return TRUE;
    default:
      ;
    }
  return FALSE;
}
static unsigned long
turn_insn_to_sda_access (uint32_t insn, bfd_signed_vma type, uint32_t *pinsn)
{
  uint32_t oinsn = 0;
  switch (type)
    {
    case R_NDS32_GOT_LO12:
    case R_NDS32_GOTOFF_LO12:
    case R_NDS32_PLTREL_LO12:
    case R_NDS32_PLT_GOTREL_LO12:
    case R_NDS32_LO12S0_RELA:
      switch (N32_OP6 (insn))
 {
 case N32_OP6_LBI:
   oinsn = N32_TYPE1 (LBGP, N32_RT5 (insn), 0);
   break;
 case N32_OP6_LBSI:
   oinsn = N32_TYPE1 (LBGP, N32_RT5 (insn), __BIT (19));
   break;
 case N32_OP6_SBI:
   oinsn = N32_TYPE1 (SBGP, N32_RT5 (insn), 0);
   break;
 case N32_OP6_ORI:
   oinsn = N32_TYPE1 (SBGP, N32_RT5 (insn), __BIT (19));
   break;
 }
      break;
    case R_NDS32_LO12S1_RELA:
      switch (N32_OP6 (insn))
 {
 case N32_OP6_LHI:
   oinsn = N32_TYPE1 (HWGP, N32_RT5 (insn), 0);
   break;
 case N32_OP6_LHSI:
   oinsn = N32_TYPE1 (HWGP, N32_RT5 (insn), __BIT (18));
   break;
 case N32_OP6_SHI:
   oinsn = N32_TYPE1 (HWGP, N32_RT5 (insn), __BIT (19));
   break;
 }
      break;
    case R_NDS32_LO12S2_RELA:
      switch (N32_OP6 (insn))
 {
 case N32_OP6_LWI:
   oinsn = N32_TYPE1 (HWGP, N32_RT5 (insn), __MF (6, 17, 3));
   break;
 case N32_OP6_SWI:
   oinsn = N32_TYPE1 (HWGP, N32_RT5 (insn), __MF (7, 17, 3));
   break;
 }
      break;
    case R_NDS32_LO12S2_DP_RELA:
    case R_NDS32_LO12S2_SP_RELA:
      oinsn = (insn & 0x7ff07000) | (REG_GP << 15);
      break;
    }
  if (oinsn)
    *pinsn = oinsn;
  return oinsn != 0;
}
static bfd_vma
nds32_elf_rela_local_sym (bfd *abfd, Elf_Internal_Sym *sym,
     asection **psec, Elf_Internal_Rela *rel)
{
  asection *sec = *psec;
  bfd_vma relocation;
  relocation = (sec->output_section->vma
  + sec->output_offset + sym->st_value);
  if ((sec->flags & SEC_MERGE) && sec->sec_info_type == SEC_INFO_TYPE_MERGE)
    {
      if (ELF_ST_TYPE (sym->st_info) == STT_SECTION)
 rel->r_addend =
   _bfd_merged_section_offset (abfd, psec,
          elf_section_data (sec)->sec_info,
          sym->st_value + rel->r_addend);
      else
 rel->r_addend =
   _bfd_merged_section_offset (abfd, psec,
          elf_section_data (sec)->sec_info,
          sym->st_value) + rel->r_addend;
      if (sec != *psec)
 {
   if ((sec->flags & SEC_EXCLUDE) != 0)
     sec->kept_section = *psec;
   sec = *psec;
 }
      rel->r_addend -= relocation;
      rel->r_addend += sec->output_section->vma + sec->output_offset;
    }
  return relocation;
}
static bfd_vma
calculate_memory_address (bfd *abfd, Elf_Internal_Rela *irel,
     Elf_Internal_Sym *isymbuf,
     Elf_Internal_Shdr *symtab_hdr)
{
  bfd_signed_vma foff;
  bfd_vma symval, addend;
  Elf_Internal_Rela irel_fn;
  Elf_Internal_Sym *isym;
  asection *sym_sec;
  if (ELF32_R_SYM (irel->r_info) < symtab_hdr->sh_info)
    {
      isym = isymbuf + ELF32_R_SYM (irel->r_info);
      if (isym->st_shndx == SHN_UNDEF)
 sym_sec = bfd_und_section_ptr;
      else if (isym->st_shndx == SHN_ABS)
 sym_sec = bfd_abs_section_ptr;
      else if (isym->st_shndx == SHN_COMMON)
 sym_sec = bfd_com_section_ptr;
      else
 sym_sec = bfd_section_from_elf_index (abfd, isym->st_shndx);
      memcpy (&irel_fn, irel, sizeof (Elf_Internal_Rela));
      symval = nds32_elf_rela_local_sym (abfd, isym, &sym_sec, &irel_fn);
      addend = irel_fn.r_addend;
    }
  else
    {
      unsigned long indx;
      struct elf_link_hash_entry *h;
      indx = ELF32_R_SYM (irel->r_info) - symtab_hdr->sh_info;
      h = elf_sym_hashes (abfd)[indx];
      BFD_ASSERT (h != NULL);
      while (h->root.type == bfd_link_hash_indirect
      || h->root.type == bfd_link_hash_warning)
 h = (struct elf_link_hash_entry *) h->root.u.i.link;
      if (h->root.type != bfd_link_hash_defined
   && h->root.type != bfd_link_hash_defweak)
 return 0;
      if (h->root.u.def.section->flags & SEC_MERGE)
 {
   sym_sec = h->root.u.def.section;
   symval = _bfd_merged_section_offset (abfd, &sym_sec, elf_section_data
            (sym_sec)->sec_info, h->root.u.def.value);
   symval = symval + sym_sec->output_section->vma
     + sym_sec->output_offset;
 }
      else
 symval = (h->root.u.def.value
    + h->root.u.def.section->output_section->vma
    + h->root.u.def.section->output_offset);
      addend = irel->r_addend;
    }
  foff = symval + addend;
  return foff;
}
static bfd_vma
calculate_got_memory_address (bfd *abfd, struct bfd_link_info *link_info,
         Elf_Internal_Rela *irel,
         Elf_Internal_Shdr *symtab_hdr)
{
  int symndx;
  bfd_vma *local_got_offsets;
  struct elf_link_hash_entry *h;
  struct elf_link_hash_table *ehtab = elf_hash_table (link_info);
  symndx = ELF32_R_SYM (irel->r_info) - symtab_hdr->sh_info;
  h = elf_sym_hashes (abfd)[symndx];
  while (h->root.type == bfd_link_hash_indirect
  || h->root.type == bfd_link_hash_warning)
    h = (struct elf_link_hash_entry *) h->root.u.i.link;
  if (symndx >= 0)
    {
      BFD_ASSERT (h != NULL);
      return ehtab->sgot->output_section->vma + ehtab->sgot->output_offset
 + h->got.offset;
    }
  local_got_offsets = elf_local_got_offsets (abfd);
  BFD_ASSERT (local_got_offsets != NULL);
  return ehtab->sgot->output_section->vma + ehtab->sgot->output_offset
    + local_got_offsets[ELF32_R_SYM (irel->r_info)];
}
static int
is_16bit_NOP (bfd *abfd ATTRIBUTE_UNUSED,
       asection *sec, Elf_Internal_Rela *rel)
{
  bfd_byte *contents;
  unsigned short insn16;
  if (!(rel->r_addend & R_NDS32_INSN16_CONVERT_FLAG))
    return FALSE;
  contents = elf_section_data (sec)->this_hdr.contents;
  insn16 = bfd_getb16 (contents + rel->r_offset);
  if (insn16 == NDS32_NOP16)
    return TRUE;
  return FALSE;
}
static int
is_convert_32_to_16 (bfd *abfd, asection *sec,
       Elf_Internal_Rela *reloc,
       Elf_Internal_Rela *internal_relocs,
       Elf_Internal_Rela *irelend,
       uint16_t *insn16)
{
#define NORMAL_32_TO_16 (1 << 0)
#define SPECIAL_32_TO_16 (1 << 1)
  bfd_byte *contents = NULL;
  bfd_signed_vma off;
  bfd_vma mem_addr;
  uint32_t insn = 0;
  Elf_Internal_Rela *pc_rel;
  Elf_Internal_Shdr *symtab_hdr;
  Elf_Internal_Sym *isymbuf = NULL;
  int convert_type;
  bfd_vma offset;
  if (reloc->r_offset + 4 > sec->size)
    return FALSE;
  offset = reloc->r_offset;
  if (!nds32_get_section_contents (abfd, sec, &contents, TRUE))
    return FALSE;
  insn = bfd_getb32 (contents + offset);
  if (nds32_convert_32_to_16 (abfd, insn, insn16, NULL))
    convert_type = NORMAL_32_TO_16;
  else if (special_convert_32_to_16 (insn, insn16, reloc))
    convert_type = SPECIAL_32_TO_16;
  else
    return FALSE;
  symtab_hdr = &elf_tdata (abfd)->symtab_hdr;
  if (!nds32_get_local_syms (abfd, sec, &isymbuf))
    return FALSE;
  pc_rel = reloc;
  while ((pc_rel - 1) >= internal_relocs && pc_rel[-1].r_offset == offset)
    pc_rel--;
  for (; pc_rel < irelend && pc_rel->r_offset == offset; pc_rel++)
    {
      if (ELF32_R_TYPE (pc_rel->r_info) == R_NDS32_15_PCREL_RELA
   || ELF32_R_TYPE (pc_rel->r_info) == R_NDS32_17_PCREL_RELA
   || ELF32_R_TYPE (pc_rel->r_info) == R_NDS32_25_PCREL_RELA
   || ELF32_R_TYPE (pc_rel->r_info) == R_NDS32_25_PLTREL)
 {
   off = calculate_offset (abfd, sec, pc_rel, isymbuf, symtab_hdr);
   if (off >= ACCURATE_8BIT_S1 || off < -ACCURATE_8BIT_S1
       || off == 0)
     return FALSE;
   break;
 }
      else if (ELF32_R_TYPE (pc_rel->r_info) == R_NDS32_20_RELA)
 {
   mem_addr = calculate_memory_address (abfd, pc_rel, isymbuf, symtab_hdr);
   if ((mem_addr + 0x10) >> 5)
     return FALSE;
   break;
 }
      else if ((ELF32_R_TYPE (pc_rel->r_info) == R_NDS32_TLS_LE_20)
        || (ELF32_R_TYPE (pc_rel->r_info) == R_NDS32_TLS_LE_LO12))
 {
   return FALSE;
 }
      else if ((ELF32_R_TYPE (pc_rel->r_info) == R_NDS32_SDA15S2_RELA
  || ELF32_R_TYPE (pc_rel->r_info) == R_NDS32_SDA17S2_RELA)
        && (reloc->r_addend & R_NDS32_INSN16_FP7U2_FLAG)
        && convert_type == SPECIAL_32_TO_16)
 {
   break;
 }
      else if ((ELF32_R_TYPE (pc_rel->r_info) > R_NDS32_NONE
  && (ELF32_R_TYPE (pc_rel->r_info) < R_NDS32_RELA_GNU_VTINHERIT))
        || ((ELF32_R_TYPE (pc_rel->r_info) > R_NDS32_RELA_GNU_VTENTRY)
     && (ELF32_R_TYPE (pc_rel->r_info) < R_NDS32_INSN16))
        || ((ELF32_R_TYPE (pc_rel->r_info) > R_NDS32_LOADSTORE)
     && (ELF32_R_TYPE (pc_rel->r_info) < R_NDS32_DWARF2_OP1_RELA)))
 {
   return FALSE;
 }
      else if ((ELF32_R_TYPE (pc_rel->r_info) == R_NDS32_17IFC_PCREL_RELA))
 {
   off = calculate_offset (abfd, sec, pc_rel, isymbuf, symtab_hdr);
   if (off >= ACCURATE_U9BIT_S1 || off <= 0)
     return FALSE;
   break;
 }
    }
  return TRUE;
}
static void
nds32_elf_write_16 (bfd *abfd ATTRIBUTE_UNUSED, bfd_byte *contents,
      Elf_Internal_Rela *reloc,
      Elf_Internal_Rela *internal_relocs,
      Elf_Internal_Rela *irelend,
      unsigned short insn16)
{
  Elf_Internal_Rela *pc_rel;
  bfd_vma offset;
  offset = reloc->r_offset;
  bfd_putb16 (insn16, contents + offset);
  pc_rel = reloc;
  while ((pc_rel - 1) > internal_relocs && pc_rel[-1].r_offset == offset)
    pc_rel--;
  for (; pc_rel < irelend && pc_rel->r_offset == offset; pc_rel++)
    {
      if (ELF32_R_TYPE (pc_rel->r_info) == R_NDS32_15_PCREL_RELA
   || ELF32_R_TYPE (pc_rel->r_info) == R_NDS32_17_PCREL_RELA
   || ELF32_R_TYPE (pc_rel->r_info) == R_NDS32_25_PCREL_RELA)
 {
   pc_rel->r_info =
     ELF32_R_INFO (ELF32_R_SYM (pc_rel->r_info), R_NDS32_9_PCREL_RELA);
 }
      else if (ELF32_R_TYPE (pc_rel->r_info) == R_NDS32_25_PLTREL)
 pc_rel->r_info =
   ELF32_R_INFO (ELF32_R_SYM (pc_rel->r_info), R_NDS32_9_PLTREL);
      else if (ELF32_R_TYPE (pc_rel->r_info) == R_NDS32_20_RELA)
 pc_rel->r_info =
   ELF32_R_INFO (ELF32_R_SYM (pc_rel->r_info), R_NDS32_5_RELA);
      else if (ELF32_R_TYPE (pc_rel->r_info) == R_NDS32_SDA15S2_RELA
        || ELF32_R_TYPE (pc_rel->r_info) == R_NDS32_SDA17S2_RELA)
 pc_rel->r_info =
   ELF32_R_INFO (ELF32_R_SYM (pc_rel->r_info), R_NDS32_SDA_FP7U2_RELA);
      else if ((ELF32_R_TYPE (pc_rel->r_info) == R_NDS32_17IFC_PCREL_RELA))
 pc_rel->r_info =
   ELF32_R_INFO (ELF32_R_SYM (pc_rel->r_info), R_NDS32_10IFCU_PCREL_RELA);
    }
}
static Elf_Internal_Rela *
find_relocs_at_address (Elf_Internal_Rela *reloc,
   Elf_Internal_Rela *relocs,
   Elf_Internal_Rela *irelend,
   enum elf_nds32_reloc_type reloc_type)
{
  Elf_Internal_Rela *rel_t;
  for (rel_t = reloc;
       rel_t >= relocs && rel_t->r_offset == reloc->r_offset;
       rel_t--)
    if (ELF32_R_TYPE (rel_t->r_info) == reloc_type)
      return rel_t;
  for (rel_t = reloc;
       rel_t < irelend && rel_t->r_offset == reloc->r_offset;
       rel_t++)
    if (ELF32_R_TYPE (rel_t->r_info) == reloc_type)
      return rel_t;
  return irelend;
}
static Elf_Internal_Rela *
find_relocs_at_address_addr (Elf_Internal_Rela *reloc,
        Elf_Internal_Rela *relocs,
        Elf_Internal_Rela *irelend,
        unsigned char reloc_type,
        bfd_vma offset_p)
{
  Elf_Internal_Rela *rel_t = NULL;
  if (reloc->r_offset > offset_p)
    {
      for (rel_t = reloc;
    rel_t >= relocs && rel_t->r_offset > offset_p; rel_t--)
                   ;
    }
  else if (reloc->r_offset < offset_p)
    {
      for (rel_t = reloc;
    rel_t < irelend && rel_t->r_offset < offset_p; rel_t++)
                   ;
    }
  else
    rel_t = reloc;
  if (rel_t < relocs || rel_t == irelend || rel_t->r_offset != offset_p)
    return irelend;
  return find_relocs_at_address (rel_t, relocs, irelend, reloc_type);
}
static bfd_boolean
nds32_elf_check_dup_relocs (Elf_Internal_Rela *reloc,
       Elf_Internal_Rela *internal_relocs,
       Elf_Internal_Rela *irelend,
       unsigned char reloc_type)
{
  Elf_Internal_Rela *rel_t;
  for (rel_t = reloc;
       rel_t >= internal_relocs && rel_t->r_offset == reloc->r_offset;
       rel_t--)
    if (ELF32_R_TYPE (rel_t->r_info) == reloc_type)
      {
 if (ELF32_R_SYM (rel_t->r_info) == ELF32_R_SYM (reloc->r_info)
     && rel_t->r_addend == reloc->r_addend)
   continue;
 return TRUE;
      }
  for (rel_t = reloc; rel_t < irelend && rel_t->r_offset == reloc->r_offset;
       rel_t++)
    if (ELF32_R_TYPE (rel_t->r_info) == reloc_type)
      {
 if (ELF32_R_SYM (rel_t->r_info) == ELF32_R_SYM (reloc->r_info)
     && rel_t->r_addend == reloc->r_addend)
   continue;
 return TRUE;
      }
  return FALSE;
}
typedef struct nds32_elf_blank nds32_elf_blank_t;
struct nds32_elf_blank
{
  bfd_vma offset;
  bfd_vma size;
  bfd_vma total_size;
  nds32_elf_blank_t *next;
  nds32_elf_blank_t *prev;
};
static nds32_elf_blank_t *blank_free_list = NULL;
static nds32_elf_blank_t *
create_nds32_elf_blank (bfd_vma offset_p, bfd_vma size_p)
{
  nds32_elf_blank_t *blank_t;
  if (blank_free_list)
    {
      blank_t = blank_free_list;
      blank_free_list = blank_free_list->next;
    }
  else
    blank_t = bfd_malloc (sizeof (nds32_elf_blank_t));
  if (blank_t == NULL)
    return NULL;
  blank_t->offset = offset_p;
  blank_t->size = size_p;
  blank_t->total_size = 0;
  blank_t->next = NULL;
  blank_t->prev = NULL;
  return blank_t;
}
static void
remove_nds32_elf_blank (nds32_elf_blank_t *blank_p)
{
  if (blank_free_list)
    {
      blank_free_list->prev = blank_p;
      blank_p->next = blank_free_list;
    }
  else
    blank_p->next = NULL;
  blank_p->prev = NULL;
  blank_free_list = blank_p;
}
static void
clean_nds32_elf_blank (void)
{
  nds32_elf_blank_t *blank_t;
  while (blank_free_list)
    {
      blank_t = blank_free_list;
      blank_free_list = blank_free_list->next;
      free (blank_t);
    }
}
static nds32_elf_blank_t *
search_nds32_elf_blank (nds32_elf_blank_t *blank_p, bfd_vma addr)
{
  nds32_elf_blank_t *blank_t;
  if (!blank_p)
    return NULL;
  blank_t = blank_p;
  while (blank_t && addr < blank_t->offset)
    blank_t = blank_t->prev;
  while (blank_t && blank_t->next && addr >= blank_t->next->offset)
    blank_t = blank_t->next;
  return blank_t;
}
static bfd_vma
get_nds32_elf_blank_total (nds32_elf_blank_t **blank_p, bfd_vma addr,
      int overwrite)
{
  nds32_elf_blank_t *blank_t;
  blank_t = search_nds32_elf_blank (*blank_p, addr);
  if (!blank_t)
    return 0;
  if (overwrite)
    *blank_p = blank_t;
  if (addr < blank_t->offset + blank_t->size)
    return blank_t->total_size + (addr - blank_t->offset);
  else
    return blank_t->total_size + blank_t->size;
}
static bfd_boolean
insert_nds32_elf_blank (nds32_elf_blank_t **blank_p, bfd_vma addr, bfd_vma len)
{
  nds32_elf_blank_t *blank_t, *blank_t2;
  if (!*blank_p)
    {
      *blank_p = create_nds32_elf_blank (addr, len);
      return *blank_p ? TRUE : FALSE;
    }
  blank_t = search_nds32_elf_blank (*blank_p, addr);
  if (blank_t == NULL)
    {
      blank_t = create_nds32_elf_blank (addr, len);
      if (!blank_t)
 return FALSE;
      while ((*blank_p)->prev != NULL)
 *blank_p = (*blank_p)->prev;
      blank_t->next = *blank_p;
      (*blank_p)->prev = blank_t;
      (*blank_p) = blank_t;
      return TRUE;
    }
  if (addr < blank_t->offset + blank_t->size)
    {
      if (addr + len > blank_t->offset + blank_t->size)
 blank_t->size = addr + len - blank_t->offset;
    }
  else
    {
      blank_t2 = create_nds32_elf_blank (addr, len);
      if (!blank_t2)
 return FALSE;
      if (blank_t->next)
 {
   blank_t->next->prev = blank_t2;
   blank_t2->next = blank_t->next;
 }
      blank_t2->prev = blank_t;
      blank_t->next = blank_t2;
      *blank_p = blank_t2;
    }
  return TRUE;
}
static bfd_boolean
insert_nds32_elf_blank_recalc_total (nds32_elf_blank_t **blank_p, bfd_vma addr,
         bfd_vma len)
{
  nds32_elf_blank_t *blank_t;
  if (!insert_nds32_elf_blank (blank_p, addr, len))
    return FALSE;
  blank_t = *blank_p;
  if (!blank_t->prev)
    {
      blank_t->total_size = 0;
      blank_t = blank_t->next;
    }
  while (blank_t)
    {
      blank_t->total_size = blank_t->prev->total_size + blank_t->prev->size;
      blank_t = blank_t->next;
    }
  return TRUE;
}
static void
calc_nds32_blank_total (nds32_elf_blank_t *blank_p)
{
  nds32_elf_blank_t *blank_t;
  bfd_vma total_size = 0;
  if (!blank_p)
    return;
  blank_t = blank_p;
  while (blank_t->prev)
    blank_t = blank_t->prev;
  while (blank_t)
    {
      blank_t->total_size = total_size;
      total_size += blank_t->size;
      blank_t = blank_t->next;
    }
}
static bfd_boolean
nds32_elf_relax_delete_blanks (bfd *abfd, asection *sec,
          nds32_elf_blank_t *blank_p)
{
  Elf_Internal_Shdr *symtab_hdr;
  Elf_Internal_Sym *isym = NULL;
  Elf_Internal_Sym *isymend;
  unsigned int sec_shndx;
  bfd_byte *contents;
  Elf_Internal_Rela *internal_relocs;
  Elf_Internal_Rela *irel;
  Elf_Internal_Rela *irelend;
  struct elf_link_hash_entry **sym_hashes;
  struct elf_link_hash_entry **end_hashes;
  unsigned int symcount;
  asection *sect;
  nds32_elf_blank_t *blank_t;
  nds32_elf_blank_t *blank_t2;
  nds32_elf_blank_t *blank_head;
  blank_head = blank_t = blank_p;
  while (blank_head->prev != NULL)
    blank_head = blank_head->prev;
  while (blank_t->next != NULL)
    blank_t = blank_t->next;
  if (blank_t->offset + blank_t->size <= sec->size)
    {
      blank_t->next = create_nds32_elf_blank (sec->size + 4, 0);
      blank_t->next->prev = blank_t;
    }
  if (blank_head->offset > 0)
    {
      blank_head->prev = create_nds32_elf_blank (0, 0);
      blank_head->prev->next = blank_head;
      blank_head = blank_head->prev;
    }
  sec_shndx = _bfd_elf_section_from_bfd_section (abfd, sec);
  symtab_hdr = &elf_tdata (abfd)->symtab_hdr;
  if (!nds32_get_local_syms (abfd, sec, &isym))
    return FALSE;
  if (isym == NULL)
    {
      isym = bfd_elf_get_elf_syms (abfd, symtab_hdr,
       symtab_hdr->sh_info, 0, NULL, NULL, NULL);
      symtab_hdr->contents = (bfd_byte *) isym;
    }
  if (isym == NULL || symtab_hdr->sh_info == 0)
    return FALSE;
  blank_t = blank_head;
  calc_nds32_blank_total (blank_head);
  for (sect = abfd->sections; sect != NULL; sect = sect->next)
    {
      internal_relocs = _bfd_elf_link_read_relocs (abfd, sect, NULL, NULL,
         TRUE );
      irelend = internal_relocs + sect->reloc_count;
      blank_t = blank_head;
      blank_t2 = blank_head;
      if (!(sect->flags & SEC_RELOC))
 continue;
      nds32_get_section_contents (abfd, sect, &contents, TRUE);
      for (irel = internal_relocs; irel < irelend; irel++)
 {
   bfd_vma raddr;
   if (ELF32_R_TYPE (irel->r_info) >= R_NDS32_DIFF8
       && ELF32_R_TYPE (irel->r_info) <= R_NDS32_DIFF32
       && isym[ELF32_R_SYM (irel->r_info)].st_shndx == sec_shndx)
     {
       unsigned long val = 0;
       unsigned long mask;
       long before, between;
       long offset;
       switch (ELF32_R_TYPE (irel->r_info))
  {
  case R_NDS32_DIFF8:
    offset = bfd_get_8 (abfd, contents + irel->r_offset);
    break;
  case R_NDS32_DIFF16:
    offset = bfd_get_16 (abfd, contents + irel->r_offset);
    break;
  case R_NDS32_DIFF32:
    val = bfd_get_32 (abfd, contents + irel->r_offset);
    mask = 0 - (val >> 31);
    if (mask)
      offset = (val | (mask - 0xffffffff));
    else
      offset = val;
    break;
  default:
    BFD_ASSERT (0);
  }
       before = get_nds32_elf_blank_total (&blank_t, irel->r_addend, 0);
       between = get_nds32_elf_blank_total (&blank_t, irel->r_addend + offset, 0);
       if (between == before)
  goto done_adjust_diff;
       switch (ELF32_R_TYPE (irel->r_info))
  {
  case R_NDS32_DIFF8:
    bfd_put_8 (abfd, offset - (between - before), contents + irel->r_offset);
    break;
  case R_NDS32_DIFF16:
    bfd_put_16 (abfd, offset - (between - before), contents + irel->r_offset);
    break;
  case R_NDS32_DIFF32:
    bfd_put_32 (abfd, offset - (between - before), contents + irel->r_offset);
    break;
  }
     }
   else if (ELF32_R_TYPE (irel->r_info) == R_NDS32_DIFF_ULEB128
       && isym[ELF32_R_SYM (irel->r_info)].st_shndx == sec_shndx)
     {
       bfd_vma val = 0;
       unsigned int len = 0;
       unsigned long before, between;
       bfd_byte *endp, *p;
       val = read_unsigned_leb128 (abfd, contents + irel->r_offset, &len);
       before = get_nds32_elf_blank_total (&blank_t, irel->r_addend, 0);
       between = get_nds32_elf_blank_total (&blank_t, irel->r_addend + val, 0);
       if (between == before)
  goto done_adjust_diff;
       p = contents + irel->r_offset;
       endp = p + len -1;
       memset (p, 0x80, len);
       *(endp) = 0;
       p = write_uleb128 (p, val - (between - before)) - 1;
       if (p < endp)
  *p |= 0x80;
     }
done_adjust_diff:
   if (sec == sect)
     {
       raddr = irel->r_offset;
       irel->r_offset -= get_nds32_elf_blank_total (&blank_t2, irel->r_offset, 1);
       if (ELF32_R_TYPE (irel->r_info) == R_NDS32_NONE)
  continue;
       if (blank_t2 && blank_t2->next
    && (blank_t2->offset > raddr || blank_t2->next->offset <= raddr))
  (*_bfd_error_handler) (_("%B: %s\n"), abfd,
           "Error: search_nds32_elf_blank reports wrong node");
       if (raddr >= blank_t2->offset
    && raddr < blank_t2->offset + blank_t2->size
    && ELF32_R_TYPE (irel->r_info) != R_NDS32_LABEL
    && ELF32_R_TYPE (irel->r_info) != R_NDS32_RELAX_REGION_BEGIN
    && ELF32_R_TYPE (irel->r_info) != R_NDS32_RELAX_REGION_END
    && ELF32_R_TYPE (irel->r_info) != R_NDS32_RELAX_ENTRY
    && ELF32_R_TYPE (irel->r_info) != R_NDS32_SUBTRAHEND
    && ELF32_R_TYPE (irel->r_info) != R_NDS32_MINUEND)
  {
    irel->r_info = ELF32_R_INFO (ELF32_R_SYM (irel->r_info),
            R_NDS32_NONE);
    continue;
  }
     }
   if (ELF32_R_TYPE (irel->r_info) == R_NDS32_NONE
       || ELF32_R_TYPE (irel->r_info) == R_NDS32_LABEL
       || ELF32_R_TYPE (irel->r_info) == R_NDS32_RELAX_ENTRY)
     continue;
   if (ELF32_R_SYM (irel->r_info) < symtab_hdr->sh_info
       && isym[ELF32_R_SYM (irel->r_info)].st_shndx == sec_shndx
       && ELF_ST_TYPE (isym[ELF32_R_SYM (irel->r_info)].st_info) == STT_SECTION)
     {
       if (irel->r_addend <= sec->size)
  irel->r_addend -=
    get_nds32_elf_blank_total (&blank_t, irel->r_addend, 1);
     }
 }
    }
  blank_t = blank_head;
  for (isymend = isym + symtab_hdr->sh_info; isym < isymend; isym++)
    {
      if (isym->st_shndx == sec_shndx)
 {
   if (isym->st_value <= sec->size)
     {
       bfd_vma ahead;
       bfd_vma orig_addr = isym->st_value;
       ahead = get_nds32_elf_blank_total (&blank_t, isym->st_value, 1);
       isym->st_value -= ahead;
       if (ELF32_ST_TYPE (isym->st_info) == STT_FUNC && isym->st_size > 0)
  isym->st_size -= get_nds32_elf_blank_total
       (&blank_t, orig_addr + isym->st_size, 0) - ahead;
     }
 }
    }
  symcount = (symtab_hdr->sh_size / sizeof (Elf32_External_Sym)
       - symtab_hdr->sh_info);
  sym_hashes = elf_sym_hashes (abfd);
  end_hashes = sym_hashes + symcount;
  blank_t = blank_head;
  for (; sym_hashes < end_hashes; sym_hashes++)
    {
      struct elf_link_hash_entry *sym_hash = *sym_hashes;
      if ((sym_hash->root.type == bfd_link_hash_defined
    || sym_hash->root.type == bfd_link_hash_defweak)
   && sym_hash->root.u.def.section == sec)
 {
   if (sym_hash->root.u.def.value <= sec->size)
     {
       bfd_vma ahead;
       bfd_vma orig_addr = sym_hash->root.u.def.value;
       ahead = get_nds32_elf_blank_total (&blank_t, sym_hash->root.u.def.value, 1);
       sym_hash->root.u.def.value -= ahead;
       if (sym_hash->type == STT_FUNC)
  sym_hash->size -= get_nds32_elf_blank_total
        (&blank_t, orig_addr + sym_hash->size, 0) - ahead;
     }
 }
    }
  contents = elf_section_data (sec)->this_hdr.contents;
  blank_t = blank_head;
  while (blank_t->next)
    {
      if (sec->size <= (blank_t->next->offset))
 break;
      memmove (contents + blank_t->offset - blank_t->total_size,
        contents + blank_t->offset + blank_t->size,
        blank_t->next->offset - (blank_t->offset + blank_t->size));
      blank_t = blank_t->next;
    }
  if (sec->size > (blank_t->offset + blank_t->size))
    {
      memmove (contents + blank_t->offset - blank_t->total_size,
        contents + blank_t->offset + blank_t->size,
        sec->size - (blank_t->offset + blank_t->size));
      sec->size -= blank_t->total_size + blank_t->size;
    }
  else
    sec->size -= blank_t->total_size + (sec->size - blank_t->offset);
  while (blank_head)
    {
      blank_t = blank_head;
      blank_head = blank_head->next;
      remove_nds32_elf_blank (blank_t);
    }
  return TRUE;
}
static int
nds32_get_section_contents (bfd *abfd, asection *sec,
       bfd_byte **contents_p, bfd_boolean cache)
{
  if (elf_section_data (sec)->this_hdr.contents != NULL)
    *contents_p = elf_section_data (sec)->this_hdr.contents;
  else
    {
      if (!bfd_malloc_and_get_section (abfd, sec, contents_p))
 return FALSE;
      if (cache)
 elf_section_data (sec)->this_hdr.contents = *contents_p;
    }
  return TRUE;
}
static int
nds32_get_local_syms (bfd *abfd, asection *sec ATTRIBUTE_UNUSED,
        Elf_Internal_Sym **isymbuf_p)
{
  Elf_Internal_Shdr *symtab_hdr;
  symtab_hdr = &elf_tdata (abfd)->symtab_hdr;
  if (*isymbuf_p == NULL && symtab_hdr->sh_info != 0)
    {
      *isymbuf_p = (Elf_Internal_Sym *) symtab_hdr->contents;
      if (*isymbuf_p == NULL)
 {
   *isymbuf_p = bfd_elf_get_elf_syms (abfd, symtab_hdr,
          symtab_hdr->sh_info, 0,
          NULL, NULL, NULL);
   if (*isymbuf_p == NULL)
     return FALSE;
 }
    }
  symtab_hdr->contents = (bfd_byte *) (*isymbuf_p);
  return TRUE;
}
static bfd_vma sdata_range[2][2];
static bfd_vma const sdata_init_range[2] =
{ ACCURATE_12BIT_S1, ACCURATE_19BIT };
static int
nds32_elf_insn_size (bfd *abfd ATTRIBUTE_UNUSED,
       bfd_byte *contents, bfd_vma addr)
{
  unsigned long insn = bfd_getb32 (contents + addr);
  if (insn & 0x80000000)
    return 2;
  return 4;
}
static void
relax_range_measurement (bfd *abfd)
{
  asection *sec_f, *sec_b;
  bfd_vma maxpgsz = get_elf_backend_data (abfd)->maxpagesize;
  bfd_vma align;
  static int decide_relax_range = 0;
  int i;
  int range_number = ARRAY_SIZE (sdata_init_range);
  if (decide_relax_range)
    return;
  decide_relax_range = 1;
  if (sda_rela_sec == NULL)
    {
      for (i = 0; i < range_number; i++)
 {
   sdata_range[i][0] = sdata_init_range[i] - 0x1000;
   sdata_range[i][1] = sdata_init_range[i] - 0x1000;
 }
      return;
    }
  sec_f = sda_rela_sec->output_section;
  sec_b = sec_f->next;
  align = 0;
  while (sec_b != NULL)
    {
      if ((unsigned)(1 << sec_b->alignment_power) > align)
 align = (1 << sec_b->alignment_power);
      sec_b = sec_b->next;
    }
  for (i = 0; i < range_number; i++)
    {
      sdata_range[i][1] = sdata_init_range[i] - align;
      BFD_ASSERT (sdata_range[i][1] <= sdata_init_range[i]);
      sdata_range[i][0] = sdata_init_range[i] - maxpgsz;
      BFD_ASSERT (sdata_range[i][0] <= sdata_init_range[i]);
    }
}
#define GET_SEQ_LEN(addend) ((addend) & 0x000000ff)
#define IS_1ST_CONVERT(addend) ((addend) & 0x80000000)
#define IS_OPTIMIZE(addend) ((addend) & 0x40000000)
#define IS_16BIT_ON(addend) ((addend) & 0x20000000)
static bfd_boolean
nds32_elf_relax_longcall1 (bfd *abfd, asection *sec, Elf_Internal_Rela *irel,
      Elf_Internal_Rela *internal_relocs, int *insn_len,
      bfd_byte *contents, Elf_Internal_Sym *isymbuf,
      Elf_Internal_Shdr *symtab_hdr)
{
  bfd_vma laddr;
  int seq_len;
  uint32_t insn;
  Elf_Internal_Rela *hi_irelfn, *lo_irelfn, *irelend;
  bfd_signed_vma foff;
  uint16_t insn16;
  irelend = internal_relocs + sec->reloc_count;
  seq_len = GET_SEQ_LEN (irel->r_addend);
  laddr = irel->r_offset;
  *insn_len = seq_len;
  hi_irelfn = find_relocs_at_address_addr (irel, internal_relocs, irelend,
        R_NDS32_HI20_RELA, laddr);
  lo_irelfn = find_relocs_at_address_addr (irel, internal_relocs, irelend,
        R_NDS32_LO12S0_ORI_RELA,
        laddr + 4);
  if (hi_irelfn == irelend || lo_irelfn == irelend)
    {
      (*_bfd_error_handler)
 ("%B: warning: R_NDS32_LONGCALL1 points to unrecognized "
  "reloc at 0x%lx.", abfd, (long) irel->r_offset);
      return FALSE;
    }
  foff = calculate_offset (abfd, sec, hi_irelfn, isymbuf, symtab_hdr);
  if (foff == 0 || foff < -CONSERVATIVE_24BIT_S1
      || foff >= CONSERVATIVE_24BIT_S1)
    return FALSE;
  irel->r_info = ELF32_R_INFO (ELF32_R_SYM (hi_irelfn->r_info),
          R_NDS32_25_PCREL_RELA);
  irel->r_addend = hi_irelfn->r_addend;
  insn = INSN_JAL;
  bfd_putb32 (insn, contents + irel->r_offset);
  hi_irelfn->r_info =
    ELF32_R_INFO (ELF32_R_SYM (hi_irelfn->r_info), R_NDS32_NONE);
  lo_irelfn->r_info =
    ELF32_R_INFO (ELF32_R_SYM (lo_irelfn->r_info), R_NDS32_NONE);
  *insn_len = 4;
  if (seq_len & 0x2)
    {
      insn16 = NDS32_NOP16;
      bfd_putb16 (insn16, contents + irel->r_offset + *insn_len);
      lo_irelfn->r_info =
 ELF32_R_INFO (ELF32_R_SYM (lo_irelfn->r_info), R_NDS32_INSN16);
      lo_irelfn->r_addend = R_NDS32_INSN16_CONVERT_FLAG;
      *insn_len += 2;
    }
  return TRUE;
}
#define CONVERT_CONDITION_CALL(insn) (((insn) & 0xffff0000) ^ 0x90000)
static bfd_boolean
nds32_elf_relax_longcall2 (bfd *abfd, asection *sec, Elf_Internal_Rela *irel,
      Elf_Internal_Rela *internal_relocs, int *insn_len,
      bfd_byte *contents, Elf_Internal_Sym *isymbuf,
      Elf_Internal_Shdr *symtab_hdr)
{
  bfd_vma laddr;
  uint32_t insn;
  Elf_Internal_Rela *i1_irelfn, *cond_irelfn, *irelend;
  bfd_signed_vma foff;
  irelend = internal_relocs + sec->reloc_count;
  laddr = irel->r_offset;
  i1_irelfn =
    find_relocs_at_address_addr (irel, internal_relocs, irelend,
     R_NDS32_25_PCREL_RELA, laddr + 4);
  if (i1_irelfn == irelend)
    {
      (*_bfd_error_handler)
 ("%B: warning: R_NDS32_LONGCALL2 points to unrecognized "
  "reloc at 0x%lx.", abfd, (long) irel->r_offset);
      return FALSE;
    }
  insn = bfd_getb32 (contents + laddr);
  foff = calculate_offset (abfd, sec, i1_irelfn, isymbuf, symtab_hdr);
  if (foff == 0 || foff < -CONSERVATIVE_16BIT_S1
      || foff >= CONSERVATIVE_16BIT_S1)
    return FALSE;
  insn = CONVERT_CONDITION_CALL (insn);
  i1_irelfn->r_info =
    ELF32_R_INFO (ELF32_R_SYM (i1_irelfn->r_info), R_NDS32_NONE);
  cond_irelfn =
    find_relocs_at_address_addr (irel, internal_relocs, irelend,
     R_NDS32_17_PCREL_RELA, laddr);
  if (cond_irelfn != irelend)
    cond_irelfn->r_info =
      ELF32_R_INFO (ELF32_R_SYM (cond_irelfn->r_info), R_NDS32_NONE);
  irel->r_info = ELF32_R_INFO (ELF32_R_SYM (i1_irelfn->r_info),
          R_NDS32_17_PCREL_RELA);
  irel->r_addend = i1_irelfn->r_addend;
  bfd_putb32 (insn, contents + irel->r_offset);
  *insn_len = 4;
  return TRUE;
}
static bfd_boolean
nds32_elf_relax_longcall3 (bfd *abfd, asection *sec, Elf_Internal_Rela *irel,
      Elf_Internal_Rela *internal_relocs, int *insn_len,
      bfd_byte *contents, Elf_Internal_Sym *isymbuf,
      Elf_Internal_Shdr *symtab_hdr)
{
  bfd_vma laddr;
  int seq_len;
  uint32_t insn;
  Elf_Internal_Rela *hi_irelfn, *lo_irelfn, *cond_irelfn, *irelend;
  bfd_signed_vma foff;
  uint16_t insn16;
  irelend = internal_relocs + sec->reloc_count;
  seq_len = GET_SEQ_LEN (irel->r_addend);
  laddr = irel->r_offset;
  *insn_len = seq_len;
  hi_irelfn =
    find_relocs_at_address_addr (irel, internal_relocs, irelend,
     R_NDS32_HI20_RELA, laddr + 4);
  lo_irelfn =
    find_relocs_at_address_addr (irel, internal_relocs, irelend,
     R_NDS32_LO12S0_ORI_RELA, laddr + 8);
  if (hi_irelfn == irelend || lo_irelfn == irelend)
    {
      (*_bfd_error_handler)
 ("%B: warning: R_NDS32_LONGCALL3 points to unrecognized "
  "reloc at 0x%lx.", abfd, (long) irel->r_offset);
      return FALSE;
    }
  foff = calculate_offset (abfd, sec, hi_irelfn, isymbuf, symtab_hdr);
  if (foff == 0 || foff < -CONSERVATIVE_24BIT_S1
      || foff >= CONSERVATIVE_24BIT_S1)
    return FALSE;
  insn = bfd_getb32 (contents + laddr);
  if (foff >= -CONSERVATIVE_16BIT_S1 && foff < CONSERVATIVE_16BIT_S1)
    {
      insn = CONVERT_CONDITION_CALL (insn);
      bfd_putb32 (insn, contents + irel->r_offset);
      *insn_len = 4;
      irel->r_info =
 ELF32_R_INFO (ELF32_R_SYM (hi_irelfn->r_info), R_NDS32_NONE);
      hi_irelfn->r_info =
 ELF32_R_INFO (ELF32_R_SYM (hi_irelfn->r_info), R_NDS32_NONE);
      lo_irelfn->r_info =
 ELF32_R_INFO (ELF32_R_SYM (lo_irelfn->r_info), R_NDS32_NONE);
      cond_irelfn =
 find_relocs_at_address_addr (irel, internal_relocs, irelend,
         R_NDS32_17_PCREL_RELA, laddr);
      if (cond_irelfn != irelend)
 {
   cond_irelfn->r_info = ELF32_R_INFO (ELF32_R_SYM (hi_irelfn->r_info),
           R_NDS32_17_PCREL_RELA);
   cond_irelfn->r_addend = hi_irelfn->r_addend;
 }
      if (seq_len & 0x2)
 {
   insn16 = NDS32_NOP16;
   bfd_putb16 (insn16, contents + irel->r_offset + *insn_len);
   hi_irelfn->r_info = ELF32_R_INFO (ELF32_R_SYM (hi_irelfn->r_info),
         R_NDS32_INSN16);
   hi_irelfn->r_addend = R_NDS32_INSN16_CONVERT_FLAG;
   insn_len += 2;
 }
    }
  else if (foff >= -CONSERVATIVE_24BIT_S1 && foff < CONSERVATIVE_24BIT_S1)
    {
      *insn_len = 8;
      insn = INSN_JAL;
      bfd_putb32 (insn, contents + hi_irelfn->r_offset);
      hi_irelfn->r_info = ELF32_R_INFO (ELF32_R_SYM (hi_irelfn->r_info),
     R_NDS32_25_PCREL_RELA);
      irel->r_info =
 ELF32_R_INFO (ELF32_R_SYM (irel->r_info), R_NDS32_LONGCALL2);
      lo_irelfn->r_info =
 ELF32_R_INFO (ELF32_R_SYM (lo_irelfn->r_info), R_NDS32_NONE);
      if (seq_len & 0x2)
 {
   insn16 = NDS32_NOP16;
   bfd_putb16 (insn16, contents + irel->r_offset + *insn_len);
   lo_irelfn->r_info =
     ELF32_R_INFO (ELF32_R_SYM (lo_irelfn->r_info), R_NDS32_INSN16);
   lo_irelfn->r_addend = R_NDS32_INSN16_CONVERT_FLAG;
   insn_len += 2;
 }
    }
  return TRUE;
}
static bfd_boolean
nds32_elf_relax_longjump1 (bfd *abfd, asection *sec, Elf_Internal_Rela *irel,
      Elf_Internal_Rela *internal_relocs, int *insn_len,
      bfd_byte *contents, Elf_Internal_Sym *isymbuf,
      Elf_Internal_Shdr *symtab_hdr)
{
  bfd_vma laddr;
  int seq_len;
  int insn16_on;
  uint32_t insn;
  Elf_Internal_Rela *hi_irelfn, *lo_irelfn, *irelend;
  bfd_signed_vma foff;
  uint16_t insn16;
  unsigned long reloc;
  irelend = internal_relocs + sec->reloc_count;
  seq_len = GET_SEQ_LEN (irel->r_addend);
  laddr = irel->r_offset;
  *insn_len = seq_len;
  insn16_on = IS_16BIT_ON (irel->r_addend);
  hi_irelfn =
    find_relocs_at_address_addr (irel, internal_relocs, irelend,
     R_NDS32_HI20_RELA, laddr);
  lo_irelfn =
    find_relocs_at_address_addr (irel, internal_relocs, irelend,
     R_NDS32_LO12S0_ORI_RELA, laddr + 4);
  if (hi_irelfn == irelend || lo_irelfn == irelend)
    {
      (*_bfd_error_handler)
 ("%B: warning: R_NDS32_LONGJUMP1 points to unrecognized "
  "reloc at 0x%lx.", abfd, (long) irel->r_offset);
      return FALSE;
    }
  foff = calculate_offset (abfd, sec, hi_irelfn, isymbuf, symtab_hdr);
  if (foff == 0 || foff >= CONSERVATIVE_24BIT_S1
      || foff < -CONSERVATIVE_24BIT_S1)
    return FALSE;
  if (insn16_on && foff >= -ACCURATE_8BIT_S1
      && foff < ACCURATE_8BIT_S1 && (seq_len & 0x2))
    {
      reloc = R_NDS32_9_PCREL_RELA;
      insn16 = INSN_J8;
      bfd_putb16 (insn16, contents + irel->r_offset);
      *insn_len = 2;
      irel->r_info =
 ELF32_R_INFO (ELF32_R_SYM (irel->r_info), R_NDS32_NONE);
    }
  else
    {
      reloc = R_NDS32_25_PCREL_RELA;
      insn = INSN_J;
      bfd_putb32 (insn, contents + irel->r_offset);
      *insn_len = 4;
      irel->r_info =
 ELF32_R_INFO (ELF32_R_SYM (irel->r_info), R_NDS32_INSN16);
      irel->r_addend = 0;
    }
  hi_irelfn->r_info =
    ELF32_R_INFO (ELF32_R_SYM (hi_irelfn->r_info), reloc);
  lo_irelfn->r_info =
    ELF32_R_INFO (ELF32_R_SYM (lo_irelfn->r_info), R_NDS32_NONE);
  if ((seq_len & 0x2) && ((*insn_len & 2) == 0))
    {
      insn16 = NDS32_NOP16;
      bfd_putb16 (insn16, contents + irel->r_offset + *insn_len);
      lo_irelfn->r_info =
 ELF32_R_INFO (ELF32_R_SYM (lo_irelfn->r_info),
        R_NDS32_INSN16);
      lo_irelfn->r_addend = R_NDS32_INSN16_CONVERT_FLAG;
      *insn_len += 2;
    }
  return TRUE;
}
static void
nds32_elf_convert_branch (uint16_t insn16, uint32_t insn,
      uint16_t *re_insn16, uint32_t *re_insn)
{
  uint32_t comp_insn = 0;
  uint16_t comp_insn16 = 0;
  if (insn)
    {
      if (N32_OP6 (insn) == N32_OP6_BR1)
 {
   comp_insn = (insn ^ 0x4000) & 0xffffc000;
   if (N32_IS_RT3 (insn) && N32_RA5 (insn) == REG_R5)
     {
       comp_insn16 =
  (comp_insn & 0x4000) ? INSN_BNES38 : INSN_BEQS38;
       comp_insn16 |= (N32_RT5 (insn) & 0x7) << 8;
     }
 }
      else if (N32_OP6 (insn) == N32_OP6_BR3)
 {
   comp_insn = (insn ^ 0x80000) & 0xffffff00;
 }
      else
 {
   comp_insn = (insn ^ 0x10000) & 0xffffc000;
   if (N32_BR2_SUB (insn) == N32_BR2_BEQZ
       || N32_BR2_SUB (insn) == N32_BR2_BNEZ)
     {
       if (N32_IS_RT3 (insn))
  {
    comp_insn16 =
      (comp_insn & 0x10000) ? INSN_BNEZ38 : INSN_BEQZ38;
    comp_insn16 |= (N32_RT5 (insn) & 0x7) << 8;
  }
       else if (N32_RT5 (insn) == REG_R15)
  {
    comp_insn16 =
      (comp_insn & 0x10000) ? INSN_BNES38 : INSN_BEQS38;
  }
     }
 }
    }
  else
    {
      switch ((insn16 & 0xf000) >> 12)
 {
 case 0xc:
   comp_insn16 = (insn16 ^ 0x0800) & 0xff00;
   comp_insn = (comp_insn16 & 0x0800) ? INSN_BNEZ : INSN_BEQZ;
   comp_insn |= ((comp_insn16 & 0x0700) >> 8) << 20;
   break;
 case 0xd:
   comp_insn16 = (insn16 ^ 0x0800) & 0xff00;
   comp_insn = (comp_insn16 & 0x0800) ? INSN_BNE : INSN_BEQ;
   comp_insn |= (((comp_insn16 & 0x0700) >> 8) << 20)
     | (REG_R5 << 15);
   break;
 case 0xe:
   comp_insn16 = (insn16 ^ 0x0100) & 0xff00;
   comp_insn = (comp_insn16 & 0x0100) ? INSN_BNEZ : INSN_BEQZ;
   comp_insn |= REG_R15 << 20;
   break;
 default:
   break;
 }
    }
  if (comp_insn && re_insn)
    *re_insn = comp_insn;
  if (comp_insn16 && re_insn16)
    *re_insn16 = comp_insn16;
}
static bfd_boolean
nds32_elf_relax_longjump2 (bfd *abfd, asection *sec, Elf_Internal_Rela *irel,
      Elf_Internal_Rela *internal_relocs, int *insn_len,
      bfd_byte *contents, Elf_Internal_Sym *isymbuf,
      Elf_Internal_Shdr *symtab_hdr)
{
  bfd_vma laddr;
  int seq_len;
  Elf_Internal_Rela *i2_irelfn, *cond_irelfn, *irelend;
  int first_size;
  unsigned int i;
  bfd_signed_vma foff;
  uint32_t insn, re_insn = 0;
  uint16_t insn16, re_insn16 = 0;
  unsigned long reloc, cond_reloc;
  enum elf_nds32_reloc_type checked_types[] =
    { R_NDS32_15_PCREL_RELA, R_NDS32_9_PCREL_RELA };
  irelend = internal_relocs + sec->reloc_count;
  seq_len = GET_SEQ_LEN (irel->r_addend);
  laddr = irel->r_offset;
  *insn_len = seq_len;
  first_size = (seq_len == 6) ? 2 : 4;
  i2_irelfn =
    find_relocs_at_address_addr (irel, internal_relocs,
     irelend, R_NDS32_25_PCREL_RELA,
     laddr + first_size);
  for (i = 0; i < ARRAY_SIZE (checked_types); i++)
    {
      cond_irelfn =
 find_relocs_at_address_addr (irel, internal_relocs, irelend,
         checked_types[i], laddr);
      if (cond_irelfn != irelend)
 break;
    }
  if (i2_irelfn == irelend || cond_irelfn == irelend)
    {
      (*_bfd_error_handler)
 ("%B: warning: R_NDS32_LONGJUMP2 points to unrecognized "
  "reloc at 0x%lx.", abfd, (long) irel->r_offset);
      return FALSE;
    }
  foff =
    calculate_offset (abfd, sec, i2_irelfn, isymbuf, symtab_hdr);
  if (foff == 0 || foff < -CONSERVATIVE_16BIT_S1
      || foff >= CONSERVATIVE_16BIT_S1)
    return FALSE;
  if (first_size == 4)
    {
      insn = bfd_getb32 (contents + laddr);
      nds32_elf_convert_branch (0, insn, &re_insn16, &re_insn);
    }
  else
    {
      insn16 = bfd_getb16 (contents + laddr);
      nds32_elf_convert_branch (insn16, 0, &re_insn16, &re_insn);
    }
  if (re_insn16 && foff >= -(ACCURATE_8BIT_S1 - first_size)
      && foff < ACCURATE_8BIT_S1 - first_size)
    {
      if (first_size == 4)
 {
   bfd_putb32 (re_insn, contents + irel->r_offset);
   *insn_len = 4;
   reloc = (N32_OP6 (re_insn) == N32_OP6_BR1) ?
     R_NDS32_15_PCREL_RELA : R_NDS32_17_PCREL_RELA;
   cond_reloc = R_NDS32_INSN16;
 }
      else
 {
   bfd_putb16 (re_insn16, contents + irel->r_offset);
   *insn_len = 2;
   reloc = R_NDS32_9_PCREL_RELA;
   cond_reloc = R_NDS32_NONE;
 }
    }
  else if (N32_OP6 (re_insn) == N32_OP6_BR1
    && (foff >= -(ACCURATE_14BIT_S1 - first_size)
        && foff < ACCURATE_14BIT_S1 - first_size))
    {
      bfd_putb32 (re_insn, contents + irel->r_offset);
      *insn_len = 4;
      reloc = R_NDS32_15_PCREL_RELA;
      cond_reloc = R_NDS32_NONE;
    }
  else if (N32_OP6 (re_insn) == N32_OP6_BR2
    && foff >= -CONSERVATIVE_16BIT_S1
    && foff < CONSERVATIVE_16BIT_S1)
    {
      bfd_putb32 (re_insn, contents + irel->r_offset);
      *insn_len = 4;
      reloc = R_NDS32_17_PCREL_RELA;
      cond_reloc = R_NDS32_NONE;
    }
  else
    return FALSE;
  irel->r_info = ELF32_R_INFO (ELF32_R_SYM (i2_irelfn->r_info), reloc);
  irel->r_addend = i2_irelfn->r_addend;
  cond_irelfn->r_info = ELF32_R_INFO (ELF32_R_SYM (cond_irelfn->r_info),
          cond_reloc);
  cond_irelfn->r_addend = 0;
  if ((seq_len ^ *insn_len ) & 0x2)
    {
      insn16 = NDS32_NOP16;
      bfd_putb16 (insn16, contents + irel->r_offset + 4);
      i2_irelfn->r_offset = 4;
      i2_irelfn->r_info = ELF32_R_INFO (ELF32_R_SYM (i2_irelfn->r_info),
     R_NDS32_INSN16);
      i2_irelfn->r_addend = R_NDS32_INSN16_CONVERT_FLAG;
      *insn_len += 2;
    }
  else
    i2_irelfn->r_info = ELF32_R_INFO (ELF32_R_SYM (i2_irelfn->r_info),
          R_NDS32_NONE);
  return TRUE;
}
static bfd_boolean
nds32_elf_relax_longjump3 (bfd *abfd, asection *sec, Elf_Internal_Rela *irel,
      Elf_Internal_Rela *internal_relocs, int *insn_len,
      bfd_byte *contents, Elf_Internal_Sym *isymbuf,
      Elf_Internal_Shdr *symtab_hdr)
{
  enum elf_nds32_reloc_type checked_types[] =
    { R_NDS32_15_PCREL_RELA, R_NDS32_9_PCREL_RELA };
  int reloc_off = 0, cond_removed = 0, convertible;
  bfd_vma laddr;
  int seq_len;
  Elf_Internal_Rela *hi_irelfn, *lo_irelfn, *cond_irelfn, *irelend;
  int first_size;
  unsigned int i;
  bfd_signed_vma foff;
  uint32_t insn, re_insn = 0;
  uint16_t insn16, re_insn16 = 0;
  unsigned long reloc, cond_reloc;
  irelend = internal_relocs + sec->reloc_count;
  seq_len = GET_SEQ_LEN (irel->r_addend);
  laddr = irel->r_offset;
  *insn_len = seq_len;
  convertible = IS_1ST_CONVERT (irel->r_addend);
  if (convertible)
    first_size = 2;
  else
    first_size = 4;
  hi_irelfn =
    find_relocs_at_address_addr (irel, internal_relocs, irelend,
     R_NDS32_HI20_RELA, laddr + first_size);
  lo_irelfn =
    find_relocs_at_address_addr (irel, internal_relocs, irelend,
     R_NDS32_LO12S0_ORI_RELA,
     laddr + first_size + 4);
  for (i = 0; i < ARRAY_SIZE (checked_types); i++)
    {
      cond_irelfn =
 find_relocs_at_address_addr (irel, internal_relocs, irelend,
         checked_types[i], laddr);
      if (cond_irelfn != irelend)
 break;
    }
  if (hi_irelfn == irelend || lo_irelfn == irelend || cond_irelfn == irelend)
    {
      (*_bfd_error_handler)
 ("%B: warning: R_NDS32_LONGJUMP3 points to unrecognized "
  "reloc at 0x%lx.", abfd, (long) irel->r_offset);
      return FALSE;
    }
  foff = calculate_offset (abfd, sec, hi_irelfn, isymbuf, symtab_hdr);
  if (foff == 0 || foff < -CONSERVATIVE_24BIT_S1
      || foff >= CONSERVATIVE_24BIT_S1)
    return FALSE;
  if (first_size == 4)
    {
      insn = bfd_getb32 (contents + laddr);
      nds32_elf_convert_branch (0, insn, &re_insn16, &re_insn);
    }
  else
    {
      insn16 = bfd_getb16 (contents + laddr);
      nds32_elf_convert_branch (insn16, 0, &re_insn16, &re_insn);
    }
  if (re_insn16 && foff >= -ACCURATE_8BIT_S1 - first_size
      && foff < ACCURATE_8BIT_S1 - first_size)
    {
      if (!(seq_len & 0x2))
 {
   bfd_putb32 (re_insn, contents + irel->r_offset);
   *insn_len = 4;
   reloc = (N32_OP6 (re_insn) == N32_OP6_BR1) ?
     R_NDS32_15_PCREL_RELA : R_NDS32_17_PCREL_RELA;
   cond_reloc = R_NDS32_INSN16;
 }
      else
 {
   bfd_putb16 (re_insn16, contents + irel->r_offset);
   *insn_len = 2;
   reloc = R_NDS32_9_PCREL_RELA;
   cond_reloc = R_NDS32_NONE;
 }
      cond_removed = 1;
    }
  else if (N32_OP6 (re_insn) == N32_OP6_BR1
    && (foff >= -(ACCURATE_14BIT_S1 - first_size)
        && foff < ACCURATE_14BIT_S1 - first_size))
    {
      bfd_putb32 (re_insn, contents + irel->r_offset);
      *insn_len = 4;
      reloc = R_NDS32_15_PCREL_RELA;
      cond_reloc = R_NDS32_NONE;
      cond_removed = 1;
    }
  else if (N32_OP6 (re_insn) == N32_OP6_BR2
    && foff >= -CONSERVATIVE_16BIT_S1
    && foff < CONSERVATIVE_16BIT_S1)
    {
      bfd_putb32 (re_insn, contents + irel->r_offset);
      *insn_len = 4;
      reloc = R_NDS32_17_PCREL_RELA;
      cond_reloc = R_NDS32_NONE;
      cond_removed = 1;
    }
  else if (foff >= -CONSERVATIVE_24BIT_S1 - reloc_off
    && foff < CONSERVATIVE_24BIT_S1 - reloc_off)
    {
      *insn_len = 4 + first_size;
      insn = INSN_J;
      bfd_putb32 (insn, contents + hi_irelfn->r_offset);
      reloc = R_NDS32_LONGJUMP2;
      cond_reloc = R_NDS32_25_PLTREL;
    }
    else
      return FALSE;
    if (cond_removed == 1)
      {
 irel->r_info = ELF32_R_INFO (ELF32_R_SYM (hi_irelfn->r_info), reloc);
 irel->r_addend = hi_irelfn->r_addend;
 cond_irelfn->r_info = ELF32_R_INFO (ELF32_R_SYM (cond_irelfn->r_info),
         cond_reloc);
 cond_irelfn->r_addend = 0;
 hi_irelfn->r_info = ELF32_R_INFO (ELF32_R_SYM (hi_irelfn->r_info),
       R_NDS32_NONE);
      }
    else
      {
 irel->r_info = ELF32_R_INFO (ELF32_R_SYM (irel->r_info), reloc);
 irel->r_addend = irel->r_addend;
 hi_irelfn->r_info = ELF32_R_INFO (ELF32_R_SYM (hi_irelfn->r_info),
       cond_reloc);
      }
  if ((seq_len ^ *insn_len ) & 0x2)
    {
      insn16 = NDS32_NOP16;
      bfd_putb16 (insn16, contents + irel->r_offset + *insn_len);
      lo_irelfn->r_offset = *insn_len;
      lo_irelfn->r_info = ELF32_R_INFO (ELF32_R_SYM (lo_irelfn->r_info),
     R_NDS32_INSN16);
      lo_irelfn->r_addend = R_NDS32_INSN16_CONVERT_FLAG;
      *insn_len += 2;
    }
  else
    lo_irelfn->r_info = ELF32_R_INFO (ELF32_R_SYM (lo_irelfn->r_info),
          R_NDS32_NONE);
  return TRUE;
}
static bfd_boolean
nds32_elf_relax_longcall4 (bfd *abfd, asection *sec, Elf_Internal_Rela *irel,
      Elf_Internal_Rela *internal_relocs, int *insn_len,
      bfd_byte *contents, Elf_Internal_Sym *isymbuf,
      Elf_Internal_Shdr *symtab_hdr)
{
  bfd_vma laddr;
  uint32_t insn;
  Elf_Internal_Rela *hi_irel, *ptr_irel, *insn_irel, *em_irel, *call_irel;
  Elf_Internal_Rela *irelend;
  bfd_signed_vma foff;
  irelend = internal_relocs + sec->reloc_count;
  laddr = irel->r_offset;
  hi_irel = find_relocs_at_address_addr (irel, internal_relocs, irelend,
      R_NDS32_HI20_RELA, laddr);
  if (hi_irel == irelend)
    {
      (*_bfd_error_handler)
 ("%B: warning: R_NDS32_LONGCALL4 points to unrecognized "
  "reloc at 0x%lx.", abfd, (long) irel->r_offset);
      return FALSE;
    }
  foff = calculate_offset (abfd, sec, hi_irel, isymbuf, symtab_hdr);
  if (foff == 0 || foff < -CONSERVATIVE_24BIT_S1
      || foff >= CONSERVATIVE_24BIT_S1)
    return FALSE;
  ptr_irel = find_relocs_at_address_addr (irel, internal_relocs, irelend,
       R_NDS32_PTR_RESOLVED, irel->r_addend);
  em_irel = find_relocs_at_address_addr (irel, internal_relocs, irelend,
       R_NDS32_EMPTY, irel->r_addend);
  if (ptr_irel == irelend || em_irel == irelend)
    {
      (*_bfd_error_handler)
 ("%B: warning: R_NDS32_LONGCALL4 points to unrecognized "
  "reloc at 0x%lx.", abfd, (long) irel->r_offset);
      return FALSE;
    }
  insn = bfd_getb32 (contents + irel->r_addend);
  if (insn & 0x80000000)
    return FALSE;
  em_irel->r_info = ELF32_R_INFO (ELF32_R_SYM (em_irel->r_info),
      R_NDS32_25_PCREL_RELA);
  ptr_irel->r_addend = 1;
  insn = INSN_JAL;
  bfd_putb32 (insn, contents + em_irel->r_offset);
  irel->r_info =
    ELF32_R_INFO (ELF32_R_SYM (irel->r_info), R_NDS32_NONE);
  call_irel = find_relocs_at_address_addr (irel, internal_relocs, irelend,
        R_NDS32_LONGCALL4, laddr);
  if (call_irel == irelend)
    {
      *insn_len = 0;
      hi_irel->r_info =
 ELF32_R_INFO (ELF32_R_SYM (hi_irel->r_info), R_NDS32_NONE);
    }
  insn_irel = find_relocs_at_address_addr (irel, internal_relocs, irelend,
       R_NDS32_INSN16, irel->r_addend);
  if (insn_irel != irelend)
    insn_irel->r_info =
      ELF32_R_INFO (ELF32_R_SYM (irel->r_info), R_NDS32_NONE);
  return TRUE;
}
static bfd_boolean
nds32_elf_relax_longcall5 (bfd *abfd, asection *sec, Elf_Internal_Rela *irel,
      Elf_Internal_Rela *internal_relocs, int *insn_len,
      bfd_byte *contents, Elf_Internal_Sym *isymbuf,
      Elf_Internal_Shdr *symtab_hdr)
{
  bfd_vma laddr;
  uint32_t insn;
  Elf_Internal_Rela *cond_irel, *irelend;
  bfd_signed_vma foff;
  irelend = internal_relocs + sec->reloc_count;
  laddr = irel->r_offset;
  insn = bfd_getb32 (contents + laddr);
  cond_irel =
    find_relocs_at_address_addr (irel, internal_relocs, irelend,
     R_NDS32_25_PCREL_RELA, irel->r_addend);
  if (cond_irel == irelend)
    {
      (*_bfd_error_handler)
 ("%B: warning: R_NDS32_LONGCALL5 points to unrecognized "
  "reloc at 0x%lx.", abfd, (long) irel->r_offset);
      return FALSE;
    }
  foff = calculate_offset (abfd, sec, cond_irel, isymbuf, symtab_hdr);
  if (foff == 0 || foff < -CONSERVATIVE_16BIT_S1
      || foff >= CONSERVATIVE_16BIT_S1)
    return FALSE;
  insn = CONVERT_CONDITION_CALL (insn);
  cond_irel->r_info =
    ELF32_R_INFO (ELF32_R_SYM (cond_irel->r_info), R_NDS32_17_PCREL_RELA);
  bfd_putb32 (insn, contents + cond_irel->r_offset);
  *insn_len = 0;
  irel->r_info = ELF32_R_INFO (ELF32_R_SYM (irel->r_info), R_NDS32_NONE);
  cond_irel = find_relocs_at_address_addr (irel, internal_relocs, irelend,
        R_NDS32_17_PCREL_RELA, laddr);
  cond_irel->r_info =
    ELF32_R_INFO (ELF32_R_SYM (cond_irel->r_info), R_NDS32_NONE);
  return TRUE;
}
static bfd_boolean
nds32_elf_relax_longcall6 (bfd *abfd, asection *sec, Elf_Internal_Rela *irel,
      Elf_Internal_Rela *internal_relocs, int *insn_len,
      bfd_byte *contents, Elf_Internal_Sym *isymbuf,
      Elf_Internal_Shdr *symtab_hdr)
{
  bfd_vma laddr;
  uint32_t insn;
  Elf_Internal_Rela *em_irel, *cond_irel, *irelend;
  bfd_signed_vma foff;
  irelend = internal_relocs + sec->reloc_count;
  laddr = irel->r_offset;
  em_irel = find_relocs_at_address_addr (irel, internal_relocs, irelend,
      R_NDS32_EMPTY, irel->r_addend);
  if (em_irel == irelend)
    {
      (*_bfd_error_handler)
 ("%B: warning: R_NDS32_LONGCALL6 points to unrecognized "
  "reloc at 0x%lx.", abfd, (long) irel->r_offset);
      return FALSE;
    }
  foff = calculate_offset (abfd, sec, em_irel, isymbuf, symtab_hdr);
  if (foff == 0 || foff < -CONSERVATIVE_24BIT_S1
      || foff >= CONSERVATIVE_24BIT_S1)
    return FALSE;
  insn = bfd_getb32 (contents + irel->r_addend);
  if (insn & 0x80000000)
    return FALSE;
  insn = bfd_getb32 (contents + laddr);
  if (foff >= -CONSERVATIVE_16BIT_S1 && foff < CONSERVATIVE_16BIT_S1)
    {
      *insn_len = 0;
      insn = CONVERT_CONDITION_CALL (insn);
      bfd_putb32 (insn, contents + em_irel->r_offset);
      em_irel->r_info =
 ELF32_R_INFO (ELF32_R_SYM (em_irel->r_info), R_NDS32_17_PCREL_RELA);
      cond_irel =
 find_relocs_at_address_addr (irel, internal_relocs, irelend,
         R_NDS32_PTR_RESOLVED, irel->r_addend);
      if (cond_irel == irelend)
 {
   (*_bfd_error_handler)
     ("%B: warning: R_NDS32_LONGCALL6 points to unrecognized "
      "reloc at 0x%lx.", abfd, (long) irel->r_offset);
   return FALSE;
 }
      cond_irel->r_addend = 1;
      irel->r_info =
 ELF32_R_INFO (ELF32_R_SYM (irel->r_info), R_NDS32_NONE);
      cond_irel =
 find_relocs_at_address_addr (irel, internal_relocs, irelend,
         R_NDS32_17_PCREL_RELA, laddr);
      if (cond_irel != irelend)
 cond_irel->r_info =
   ELF32_R_INFO (ELF32_R_SYM (cond_irel->r_info), R_NDS32_NONE);
      cond_irel =
 find_relocs_at_address_addr (irel, internal_relocs, irelend,
         R_NDS32_INSN16, irel->r_addend);
      if (cond_irel != irelend)
 cond_irel->r_info =
   ELF32_R_INFO (ELF32_R_SYM (cond_irel->r_info), R_NDS32_NONE);
    }
  else if (foff >= -CONSERVATIVE_24BIT_S1 && foff < CONSERVATIVE_24BIT_S1)
    {
      *insn_len = 4;
      insn = INSN_JAL;
      bfd_putb32 (insn, contents + em_irel->r_offset);
      em_irel->r_info = ELF32_R_INFO (ELF32_R_SYM (em_irel->r_info),
          R_NDS32_25_PCREL_RELA);
      irel->r_info =
 ELF32_R_INFO (ELF32_R_SYM (irel->r_info), R_NDS32_LONGCALL5);
      cond_irel =
 find_relocs_at_address_addr (irel, internal_relocs, irelend,
         R_NDS32_PTR_RESOLVED, irel->r_addend);
      if (cond_irel == irelend)
 {
   (*_bfd_error_handler)
     ("%B: warning: R_NDS32_LONGCALL6 points to unrecognized "
      "reloc at 0x%lx.", abfd, (long) irel->r_offset);
   return FALSE;
 }
      cond_irel->r_addend = 1;
      cond_irel =
 find_relocs_at_address_addr (irel, internal_relocs, irelend,
         R_NDS32_INSN16, irel->r_addend);
      if (cond_irel != irelend)
 cond_irel->r_info =
   ELF32_R_INFO (ELF32_R_SYM (cond_irel->r_info), R_NDS32_NONE);
    }
  return TRUE;
}
static bfd_boolean
nds32_elf_relax_longjump4 (bfd *abfd, asection *sec, Elf_Internal_Rela *irel,
      Elf_Internal_Rela *internal_relocs, int *insn_len,
      bfd_byte *contents, Elf_Internal_Sym *isymbuf,
      Elf_Internal_Shdr *symtab_hdr)
{
  bfd_vma laddr;
  int seq_len;
  uint32_t insn;
  Elf_Internal_Rela *hi_irel, *ptr_irel, *em_irel, *call_irel, *irelend;
  bfd_signed_vma foff;
  irelend = internal_relocs + sec->reloc_count;
  seq_len = GET_SEQ_LEN (irel->r_addend);
  laddr = irel->r_offset;
  *insn_len = seq_len;
  hi_irel = find_relocs_at_address_addr (irel, internal_relocs, irelend,
      R_NDS32_HI20_RELA, laddr);
  if (hi_irel == irelend)
    {
      (*_bfd_error_handler)
 ("%B: warning: R_NDS32_LONGJUMP4 points to unrecognized "
  "reloc at 0x%lx.", abfd, (long) irel->r_offset);
      return FALSE;
    }
  foff = calculate_offset (abfd, sec, hi_irel, isymbuf, symtab_hdr);
  if (foff == 0 || foff >= CONSERVATIVE_24BIT_S1
      || foff < -CONSERVATIVE_24BIT_S1)
    return FALSE;
  ptr_irel = find_relocs_at_address_addr (irel, internal_relocs, irelend,
       R_NDS32_PTR_RESOLVED, irel->r_addend);
  em_irel = find_relocs_at_address_addr (irel, internal_relocs, irelend,
      R_NDS32_EMPTY, irel->r_addend);
  if (ptr_irel == irelend || em_irel == irelend)
    {
      (*_bfd_error_handler)
 ("%B: warning: R_NDS32_LONGJUMP4 points to unrecognized "
  "reloc at 0x%lx.", abfd, (long) irel->r_offset);
      return FALSE;
    }
  em_irel->r_info =
    ELF32_R_INFO (ELF32_R_SYM (em_irel->r_info), R_NDS32_25_PCREL_RELA);
  ptr_irel->r_addend = 1;
  insn = INSN_J;
  bfd_putb32 (insn, contents + em_irel->r_offset);
  irel->r_info = ELF32_R_INFO (ELF32_R_SYM (irel->r_info), R_NDS32_NONE);
  call_irel = find_relocs_at_address_addr (irel, internal_relocs, irelend,
        R_NDS32_LONGJUMP4, laddr);
  if (call_irel == irelend)
    {
      *insn_len = 0;
      hi_irel->r_info =
 ELF32_R_INFO (ELF32_R_SYM (hi_irel->r_info), R_NDS32_NONE);
    }
  return TRUE;
}
static bfd_boolean
nds32_elf_relax_longjump5 (bfd *abfd, asection *sec, Elf_Internal_Rela *irel,
      Elf_Internal_Rela *internal_relocs, int *insn_len,
      int *seq_len, bfd_byte *contents,
      Elf_Internal_Sym *isymbuf,
      Elf_Internal_Shdr *symtab_hdr)
{
  bfd_vma laddr;
  Elf_Internal_Rela *cond_irel, *irelend;
  unsigned int i;
  bfd_signed_vma foff;
  uint32_t insn, re_insn = 0;
  uint16_t insn16, re_insn16 = 0;
  unsigned long reloc;
  enum elf_nds32_reloc_type checked_types[] =
    { R_NDS32_17_PCREL_RELA, R_NDS32_15_PCREL_RELA,
      R_NDS32_9_PCREL_RELA, R_NDS32_INSN16 };
  irelend = internal_relocs + sec->reloc_count;
  laddr = irel->r_offset;
  cond_irel =
    find_relocs_at_address_addr (irel, internal_relocs, irelend,
     R_NDS32_25_PCREL_RELA, irel->r_addend);
  if (cond_irel == irelend)
    {
      (*_bfd_error_handler)
 ("%B: warning: R_NDS32_LONGJUMP5 points to unrecognized "
  "reloc at 0x%lx.", abfd, (long) irel->r_offset);
      return FALSE;
    }
  foff = calculate_offset (abfd, sec, cond_irel, isymbuf, symtab_hdr);
  if (foff == 0 || foff < -CONSERVATIVE_16BIT_S1
      || foff >= CONSERVATIVE_16BIT_S1)
    return FALSE;
  insn = bfd_getb32 (contents + laddr);
  if (insn & 0x80000000)
    {
      *seq_len = 0;
      insn16 = insn >> 16;
      nds32_elf_convert_branch (insn16, 0, &re_insn16, &re_insn);
    }
  else
    nds32_elf_convert_branch (0, insn, &re_insn16, &re_insn);
  if (N32_OP6 (re_insn) == N32_OP6_BR1
      && (foff >= -CONSERVATIVE_14BIT_S1 && foff < CONSERVATIVE_14BIT_S1))
    {
      bfd_putb32 (re_insn, contents + cond_irel->r_offset);
      reloc = R_NDS32_15_PCREL_RELA;
    }
  else if (N32_OP6 (re_insn) == N32_OP6_BR2
    && foff >= -CONSERVATIVE_16BIT_S1 && foff < CONSERVATIVE_16BIT_S1)
    {
      bfd_putb32 (re_insn, contents + cond_irel->r_offset);
      reloc = R_NDS32_17_PCREL_RELA;
    }
  else if ( N32_OP6 (re_insn) == N32_OP6_BR3
    && foff >= -CONSERVATIVE_8BIT_S1 && foff < CONSERVATIVE_8BIT_S1)
    {
      bfd_putb32 (re_insn, contents + cond_irel->r_offset);
      reloc = R_NDS32_WORD_9_PCREL_RELA;
    }
  else
    return FALSE;
  cond_irel->r_info = ELF32_R_INFO (ELF32_R_SYM (cond_irel->r_info), reloc);
  irel->r_info = ELF32_R_INFO (ELF32_R_SYM (irel->r_info), R_NDS32_NONE);
  for (i = 0; i < ARRAY_SIZE (checked_types); i++)
    {
      cond_irel = find_relocs_at_address_addr (irel, internal_relocs, irelend,
            checked_types[i], laddr);
      if (cond_irel != irelend)
 {
   if (*seq_len == 0
       && (ELF32_R_TYPE (cond_irel->r_info) == R_NDS32_INSN16))
     {
       insn16 = NDS32_NOP16;
       bfd_putb16 (insn16, contents + laddr);
       cond_irel->r_addend = R_NDS32_INSN16_CONVERT_FLAG;
     }
   else
     cond_irel->r_info = ELF32_R_INFO (ELF32_R_SYM (cond_irel->r_info),
           R_NDS32_NONE);
 }
    }
  *insn_len = 0;
  return TRUE;
}
static bfd_boolean
nds32_elf_relax_longjump6 (bfd *abfd, asection *sec, Elf_Internal_Rela *irel,
      Elf_Internal_Rela *internal_relocs, int *insn_len,
      int *seq_len, bfd_byte *contents,
      Elf_Internal_Sym *isymbuf,
      Elf_Internal_Shdr *symtab_hdr)
{
  enum elf_nds32_reloc_type checked_types[] =
    { R_NDS32_17_PCREL_RELA, R_NDS32_15_PCREL_RELA,
      R_NDS32_9_PCREL_RELA, R_NDS32_INSN16 };
  int reloc_off = 0, cond_removed = 0;
  bfd_vma laddr;
  Elf_Internal_Rela *cond_irel, *em_irel, *irelend, *insn_irel;
  unsigned int i;
  bfd_signed_vma foff;
  uint32_t insn, re_insn = 0;
  uint16_t insn16, re_insn16 = 0;
  unsigned long reloc;
  irelend = internal_relocs + sec->reloc_count;
  laddr = irel->r_offset;
  em_irel = find_relocs_at_address_addr (irel, internal_relocs, irelend,
      R_NDS32_EMPTY, irel->r_addend);
  if (em_irel == irelend)
    {
      (*_bfd_error_handler)
 ("%B: warning: R_NDS32_LONGJUMP6 points to unrecognized "
  "reloc at 0x%lx.", abfd, (long) irel->r_offset);
      return FALSE;
    }
  foff = calculate_offset (abfd, sec, em_irel, isymbuf, symtab_hdr);
  if (foff == 0 || foff < -CONSERVATIVE_24BIT_S1
      || foff >= CONSERVATIVE_24BIT_S1)
    return FALSE;
  insn = bfd_getb32 (contents + laddr);
  if (insn & 0x80000000)
    {
      *seq_len = 0;
      insn16 = insn >> 16;
      nds32_elf_convert_branch (insn16, 0, &re_insn16, &re_insn);
    }
  else
    nds32_elf_convert_branch (0, insn, &re_insn16, &re_insn);
  if (N32_OP6 (re_insn) == N32_OP6_BR1
      && (foff >= -CONSERVATIVE_14BIT_S1 && foff < CONSERVATIVE_14BIT_S1))
    {
      bfd_putb32 (re_insn, contents + em_irel->r_offset);
      reloc = R_NDS32_15_PCREL_RELA;
      cond_removed = 1;
    }
  else if (N32_OP6 (re_insn) == N32_OP6_BR2
    && foff >= -CONSERVATIVE_16BIT_S1 && foff < CONSERVATIVE_16BIT_S1)
    {
      bfd_putb32 (re_insn, contents + em_irel->r_offset);
      reloc = R_NDS32_17_PCREL_RELA;
      cond_removed = 1;
    }
  else if (foff >= -CONSERVATIVE_24BIT_S1 - reloc_off
    && foff < CONSERVATIVE_24BIT_S1 - reloc_off)
    {
      insn = INSN_J;
      reloc = R_NDS32_25_PCREL_RELA;
      bfd_putb32 (insn, contents + em_irel->r_offset);
    }
  else
    return FALSE;
  em_irel->r_info = ELF32_R_INFO (ELF32_R_SYM (em_irel->r_info), reloc);
  cond_irel =
    find_relocs_at_address_addr (irel, internal_relocs, irelend,
     R_NDS32_PTR_RESOLVED, em_irel->r_offset);
  cond_irel->r_addend = 1;
  insn_irel = find_relocs_at_address_addr (irel, internal_relocs, irelend,
        R_NDS32_INSN16, irel->r_offset);
  if (insn_irel == irelend)
    {
      insn_irel =
 find_relocs_at_address_addr (irel, internal_relocs, irelend,
         R_NDS32_INSN16, em_irel->r_offset);
      insn_irel->r_info = ELF32_R_INFO (ELF32_R_SYM (cond_irel->r_info),
     R_NDS32_NONE);
    }
  if (cond_removed == 1)
    {
      *insn_len = 0;
      irel->r_info = ELF32_R_INFO (ELF32_R_SYM (irel->r_info), R_NDS32_NONE);
      for (i = 0; i < ARRAY_SIZE (checked_types); i++)
 {
   cond_irel =
     find_relocs_at_address_addr (irel, internal_relocs, irelend,
      checked_types[i], laddr);
   if (cond_irel != irelend)
     {
       if (*seq_len == 0
    && (ELF32_R_TYPE (cond_irel->r_info) == R_NDS32_INSN16))
  {
    insn16 = NDS32_NOP16;
    bfd_putb16 (insn16, contents + laddr);
    cond_irel->r_addend = R_NDS32_INSN16_CONVERT_FLAG;
  }
       else
  cond_irel->r_info =
    ELF32_R_INFO (ELF32_R_SYM (cond_irel->r_info), R_NDS32_NONE);
     }
 }
    }
  else
    {
      irel->r_info = ELF32_R_INFO (ELF32_R_SYM (irel->r_info),
       R_NDS32_LONGJUMP5);
    }
  return TRUE;
}
static bfd_boolean
nds32_elf_relax_longjump7 (bfd *abfd, asection *sec, Elf_Internal_Rela *irel,
      Elf_Internal_Rela *internal_relocs, int *insn_len,
      int *seq_len, bfd_byte *contents,
      Elf_Internal_Sym *isymbuf,
      Elf_Internal_Shdr *symtab_hdr)
{
  bfd_vma laddr;
  Elf_Internal_Rela *cond_irel, *irelend, *insn_irel;
  bfd_signed_vma foff;
  uint32_t insn, re_insn = 0;
  uint16_t insn16;
  uint32_t imm11;
  irelend = internal_relocs + sec->reloc_count;
  laddr = irel->r_offset;
  cond_irel =
    find_relocs_at_address_addr (irel, internal_relocs, irelend,
     R_NDS32_15_PCREL_RELA, irel->r_addend);
  if (cond_irel == irelend)
    {
      (*_bfd_error_handler)
 ("%B: warning: R_NDS32_LONGJUMP7 points to unrecognized "
  "reloc at 0x%lx.", abfd, (long) irel->r_offset);
      return FALSE;
    }
  foff = calculate_offset (abfd, sec, cond_irel, isymbuf, symtab_hdr);
  if (foff == 0 || foff < -CONSERVATIVE_8BIT_S1
      || foff >= CONSERVATIVE_8BIT_S1)
    return FALSE;
  insn = bfd_getb32 (contents + laddr);
  if (insn & 0x80000000)
    {
      *seq_len = 0;
      imm11 = N16_IMM5S (insn >> 16);
    }
  else
    {
      imm11 = N32_IMM20S (insn);
    }
  insn = bfd_getb32 (contents + irel->r_addend);
  if ((insn >> 14) & 0x1)
    re_insn = N32_BR3 (BNEC, N32_RT5 (insn), imm11, 0);
  else
    re_insn = N32_BR3 (BEQC, N32_RT5 (insn), imm11, 0);
  bfd_putb32 (re_insn, contents + cond_irel->r_offset);
  cond_irel->r_info = ELF32_R_INFO (ELF32_R_SYM (cond_irel->r_info),
        R_NDS32_WORD_9_PCREL_RELA);
  irel->r_info = ELF32_R_INFO (ELF32_R_SYM (irel->r_info), R_NDS32_NONE);
  insn_irel = find_relocs_at_address_addr (irel, internal_relocs, irelend,
        R_NDS32_INSN16, irel->r_offset);
  if (insn_irel != irelend)
    {
      if (*seq_len == 0)
 {
   insn16 = NDS32_NOP16;
   bfd_putb16 (insn16, contents + laddr);
   insn_irel->r_addend = R_NDS32_INSN16_CONVERT_FLAG;
 }
      else
 cond_irel->r_info = ELF32_R_INFO (ELF32_R_SYM (cond_irel->r_info),
       R_NDS32_NONE);
    }
  *insn_len = 0;
  return TRUE;
}
static bfd_boolean
nds32_elf_relax_guard (bfd_vma *access_addr, bfd_vma local_sda, asection *sec,
         Elf_Internal_Rela *irel, bfd_boolean *again,
         bfd_boolean init,
         struct elf_nds32_link_hash_table *table,
         Elf_Internal_Sym *isymbuf, Elf_Internal_Shdr *symtab_hdr)
{
  int offset_to_gp;
  static bfd_boolean sec_pass = FALSE;
  static asection *first_sec = NULL, *sym_sec;
  static int count = 0, record_count;
  Elf_Internal_Sym *isym;
  struct elf_link_hash_entry *h = NULL;
  int indx;
  unsigned long r_symndx;
  bfd *abfd = sec->owner;
  static bfd_vma record_sda = 0;
  int sda_offset = 0;
  if (table->hyper_relax == 2)
    return TRUE;
  if (init)
    {
      if (!first_sec)
 first_sec = sec;
      else if (first_sec == sec)
 {
   record_count = count;
   count = 0;
   sec_pass = TRUE;
 }
      if (!sec_pass)
 *again = TRUE;
      return TRUE;
    }
  if (record_sda == 0)
    record_sda = local_sda;
  else if (local_sda > record_sda)
    sda_offset = local_sda - record_sda;
  count++;
  r_symndx = ELF32_R_SYM (irel->r_info);
  if (r_symndx >= symtab_hdr->sh_info)
    {
      indx = ELF32_R_SYM (irel->r_info) - symtab_hdr->sh_info;
      h = elf_sym_hashes (abfd)[indx];
      sym_sec = h->root.u.def.section;
      if (NDS32_GUARD_SEC_P (sym_sec->flags)
   || bfd_is_abs_section (sym_sec))
 {
   if (table->hyper_relax == 0)
     return FALSE;
   offset_to_gp = *access_addr - local_sda;
   if (elf32_nds32_hash_entry (h)->offset_to_gp == 0)
     elf32_nds32_hash_entry (h)->offset_to_gp = offset_to_gp;
   else if (abs (elf32_nds32_hash_entry (h)->offset_to_gp)
     < abs (offset_to_gp) - sda_offset)
     {
       if (*access_addr >= local_sda)
  *access_addr += (record_count * 4);
       else
  *access_addr -= (record_count * 4);
     }
   return sec_pass;
 }
    }
  else
    {
      if (!elf32_nds32_allocate_local_sym_info (abfd))
 return FALSE;
      isym = isymbuf + r_symndx;
      sym_sec = bfd_section_from_elf_index (abfd, isym->st_shndx);
      if (NDS32_GUARD_SEC_P (sym_sec->flags))
 {
   if (table->hyper_relax == 0)
     return FALSE;
   offset_to_gp = *access_addr - local_sda;
   if (elf32_nds32_local_gp_offset (abfd)[r_symndx] == 0)
     elf32_nds32_local_gp_offset (abfd)[r_symndx] = offset_to_gp;
   else if (abs (elf32_nds32_local_gp_offset (abfd)[r_symndx])
     < abs (offset_to_gp) - sda_offset)
     {
       if (*access_addr >= local_sda)
  *access_addr += (record_count * 4);
       else
  *access_addr -= (record_count * 4);
     }
   return sec_pass;
 }
    }
  return TRUE;
}
#define GET_LOADSTORE_RANGE(addend) (((addend) >> 8) & 0x3f)
static bfd_boolean
nds32_elf_relax_loadstore (struct bfd_link_info *link_info, bfd *abfd,
      asection *sec, Elf_Internal_Rela *irel,
      Elf_Internal_Rela *internal_relocs, int *insn_len,
      bfd_byte *contents, Elf_Internal_Sym *isymbuf,
      Elf_Internal_Shdr *symtab_hdr, int load_store_relax,
      struct elf_nds32_link_hash_table *table)
{
  int eliminate_sethi = 0, range_type, i;
  bfd_vma local_sda, laddr;
  int seq_len;
  uint32_t insn;
  Elf_Internal_Rela *hi_irelfn = NULL, *irelend;
  bfd_vma access_addr = 0;
  bfd_vma range_l = 0, range_h = 0;
  struct elf_link_hash_entry *h = NULL;
  int indx;
  enum elf_nds32_reloc_type checked_types[] =
    { R_NDS32_HI20_RELA, R_NDS32_GOT_HI20,
      R_NDS32_GOTPC_HI20, R_NDS32_GOTOFF_HI20,
      R_NDS32_PLTREL_HI20, R_NDS32_PLT_GOTREL_HI20,
      R_NDS32_TLS_LE_HI20, R_NDS32_TLS_IE_HI20,
      R_NDS32_TLS_IEGP_HI20, R_NDS32_TLS_DESC_HI20
    };
  irelend = internal_relocs + sec->reloc_count;
  seq_len = GET_SEQ_LEN (irel->r_addend);
  laddr = irel->r_offset;
  *insn_len = seq_len;
  for (i = 0; (unsigned) i < ARRAY_SIZE (checked_types); i++)
    {
      hi_irelfn = find_relocs_at_address_addr (irel, internal_relocs, irelend,
            checked_types[i], laddr);
      if (hi_irelfn != irelend)
 break;
    }
  if (hi_irelfn == irelend)
    {
      if (i != 0)
        (*_bfd_error_handler)
   ("%B: warning: R_NDS32_LOADSTORE points to unrecognized "
    "reloc at 0x%lx.", abfd, (long) irel->r_offset);
   return FALSE;
    }
  range_type = GET_LOADSTORE_RANGE (irel->r_addend);
  nds32_elf_final_sda_base (sec->output_section->owner,
       link_info, &local_sda, FALSE);
  switch (ELF32_R_TYPE (hi_irelfn->r_info))
    {
    case R_NDS32_HI20_RELA:
      insn = bfd_getb32 (contents + laddr);
      access_addr =
 calculate_memory_address (abfd, hi_irelfn, isymbuf, symtab_hdr);
      if (ELF32_R_SYM (hi_irelfn->r_info) >= symtab_hdr->sh_info)
 {
   indx = ELF32_R_SYM (hi_irelfn->r_info) - symtab_hdr->sh_info;
   h = elf_sym_hashes (abfd)[indx];
 }
      if (range_type == NDS32_LOADSTORE_IMM)
 {
   if ((access_addr < CONSERVATIVE_20BIT)
       && (!h || (h && strcmp (h->root.root.string, FP_BASE_NAME) != 0)))
     {
       eliminate_sethi = 1;
       break;
     }
 }
      if (h && strcmp (h->root.root.string, FP_BASE_NAME) == 0)
 {
   eliminate_sethi = 1;
   break;
 }
      else if (!nds32_elf_relax_guard (&access_addr, local_sda, sec, hi_irelfn,
      NULL, FALSE, table, isymbuf, symtab_hdr))
 return FALSE;
      if (!load_store_relax)
 return FALSE;
      if (N32_RT5 (insn) == REG_GP)
 return FALSE;
      if (range_type == NDS32_LOADSTORE_FLOAT_S
   || range_type == NDS32_LOADSTORE_FLOAT_S)
 {
   range_l = sdata_range[0][0];
   range_h = sdata_range[0][1];
 }
      else
 {
   range_l = sdata_range[1][0];
   range_h = sdata_range[1][1];
 }
      break;
    default:
      return FALSE;
    }
  if (eliminate_sethi == 1
      || (local_sda <= access_addr && (access_addr - local_sda) < range_h)
      || (local_sda > access_addr && (local_sda - access_addr) <= range_l))
    {
      hi_irelfn->r_info =
 ELF32_R_INFO (ELF32_R_SYM (hi_irelfn->r_info), R_NDS32_NONE);
      irel->r_info =
 ELF32_R_INFO (ELF32_R_SYM (irel->r_info), R_NDS32_NONE);
      *insn_len = 0;
      return TRUE;
    }
  return FALSE;
}
static void
nds32_elf_relax_lo12 (struct bfd_link_info *link_info, bfd *abfd,
        asection *sec, Elf_Internal_Rela *irel,
        Elf_Internal_Rela *internal_relocs, bfd_byte *contents,
        Elf_Internal_Sym *isymbuf, Elf_Internal_Shdr *symtab_hdr,
        struct elf_nds32_link_hash_table *table)
{
  uint32_t insn;
  bfd_vma local_sda, laddr;
  unsigned long reloc;
  bfd_vma access_addr;
  bfd_vma range_l = 0, range_h = 0;
  Elf_Internal_Rela *irelfn = NULL, *irelend;
  struct elf_link_hash_entry *h = NULL;
  int indx;
  nds32_elf_final_sda_base (sec->output_section->owner, link_info,
       &local_sda, FALSE);
  irelend = internal_relocs + sec->reloc_count;
  laddr = irel->r_offset;
  insn = bfd_getb32 (contents + laddr);
  if (!is_sda_access_insn (insn) && N32_OP6 (insn) != N32_OP6_ORI)
    return;
  access_addr = calculate_memory_address (abfd, irel, isymbuf, symtab_hdr);
  if (ELF32_R_SYM (irel->r_info) >= symtab_hdr->sh_info)
    {
      indx = ELF32_R_SYM (irel->r_info) - symtab_hdr->sh_info;
      h = elf_sym_hashes (abfd)[indx];
    }
  if (N32_OP6 (insn) == N32_OP6_ORI && access_addr < CONSERVATIVE_20BIT
      && (!h || (h && strcmp (h->root.root.string, FP_BASE_NAME) != 0)))
    {
      reloc = R_NDS32_20_RELA;
      irel->r_info = ELF32_R_INFO (ELF32_R_SYM (irel->r_info), reloc);
      insn = N32_TYPE1 (MOVI, N32_RT5 (insn), 0);
      bfd_putb32 (insn, contents + laddr);
    }
  else
    {
      if (h && strcmp (h->root.root.string, FP_BASE_NAME) == 0)
 { }
      else if (!nds32_elf_relax_guard (&access_addr, local_sda, sec, irel, NULL,
           FALSE, table, isymbuf, symtab_hdr))
 return;
      range_l = sdata_range[1][0];
      range_h = sdata_range[1][1];
      switch (ELF32_R_TYPE (irel->r_info))
 {
 case R_NDS32_LO12S0_RELA:
   reloc = R_NDS32_SDA19S0_RELA;
   break;
 case R_NDS32_LO12S1_RELA:
   reloc = R_NDS32_SDA18S1_RELA;
   break;
 case R_NDS32_LO12S2_RELA:
   reloc = R_NDS32_SDA17S2_RELA;
   break;
 case R_NDS32_LO12S2_DP_RELA:
   range_l = sdata_range[0][0];
   range_h = sdata_range[0][1];
   reloc = R_NDS32_SDA12S2_DP_RELA;
   break;
 case R_NDS32_LO12S2_SP_RELA:
   range_l = sdata_range[0][0];
   range_h = sdata_range[0][1];
   reloc = R_NDS32_SDA12S2_SP_RELA;
   break;
 default:
   return;
 }
      if ((local_sda <= access_addr && (access_addr - local_sda) < range_h)
   || (local_sda > access_addr && (local_sda - access_addr) <= range_l)
   || (h && strcmp (h->root.root.string, FP_BASE_NAME) == 0))
 {
   if (N32_OP6 (insn) == N32_OP6_ORI && N32_RT5 (insn) == REG_GP)
     {
       return;
     }
   if (!turn_insn_to_sda_access (insn, ELF32_R_TYPE (irel->r_info),
     &insn))
     return;
   irel->r_info = ELF32_R_INFO (ELF32_R_SYM (irel->r_info), reloc);
   bfd_putb32 (insn, contents + laddr);
   irelfn = find_relocs_at_address (irel, internal_relocs, irelend,
        R_NDS32_INSN16);
   if (irelfn != irelend && reloc != R_NDS32_SDA17S2_RELA)
     irelfn->r_info =
       ELF32_R_INFO (ELF32_R_SYM (irelfn->r_info), R_NDS32_NONE);
 }
    }
  return;
}
ATTRIBUTE_UNUSED static void
nds32_elf_relax_piclo12 (struct bfd_link_info *link_info, bfd *abfd,
    asection *sec, Elf_Internal_Rela *irel,
    bfd_byte *contents, Elf_Internal_Sym *isymbuf,
    Elf_Internal_Shdr *symtab_hdr)
{
  uint32_t insn;
  bfd_vma local_sda, laddr;
  bfd_signed_vma foff;
  unsigned long reloc;
  nds32_elf_final_sda_base (sec->output_section->owner, link_info,
       &local_sda, FALSE);
  laddr = irel->r_offset;
  insn = bfd_getb32 (contents + laddr);
  if (N32_OP6 (insn) != N32_OP6_ORI)
    return;
  if (ELF32_R_TYPE (irel->r_info) == R_NDS32_GOT_LO12)
    {
      foff = calculate_got_memory_address (abfd, link_info, irel,
        symtab_hdr) - local_sda;
      reloc = R_NDS32_GOT20;
    }
  else if (ELF32_R_TYPE (irel->r_info) == R_NDS32_PLT_GOTREL_LO12)
    {
      foff = calculate_plt_memory_address (abfd, link_info, isymbuf, irel,
        symtab_hdr) - local_sda;
      reloc = R_NDS32_PLT_GOTREL_LO20;
    }
  else if (ELF32_R_TYPE (irel->r_info) == R_NDS32_GOTOFF_LO12)
    {
      foff = calculate_memory_address (abfd, irel, isymbuf,
           symtab_hdr) - local_sda;
      reloc = R_NDS32_GOTOFF;
    }
  else if (ELF32_R_TYPE (irel->r_info) == R_NDS32_GOTPC_LO12)
    {
      foff = local_sda - sec->output_section->vma + sec->output_offset
 + irel->r_offset + irel->r_addend;
      reloc = R_NDS32_GOTPC20;
    }
  else
    return;
  if ((foff < CONSERVATIVE_20BIT) && (foff >= -CONSERVATIVE_20BIT))
    {
      irel->r_info = ELF32_R_INFO (ELF32_R_SYM (irel->r_info), reloc);
      insn = N32_TYPE1 (MOVI, N32_RT5 (insn), 0);
      bfd_putb32 (insn, contents + laddr);
    }
}
ATTRIBUTE_UNUSED static void
nds32_elf_relax_letlslo12 (struct bfd_link_info *link_info, bfd *abfd,
      Elf_Internal_Rela *irel,
      bfd_byte *contents, Elf_Internal_Sym *isymbuf,
      Elf_Internal_Shdr *symtab_hdr)
{
  uint32_t insn;
  bfd_vma laddr;
  bfd_signed_vma foff;
  unsigned long reloc;
  laddr = irel->r_offset;
  foff = calculate_memory_address (abfd, irel, isymbuf, symtab_hdr);
  BFD_ASSERT (elf_hash_table (link_info)->tls_sec != NULL);
  foff -= (elf_hash_table (link_info)->tls_sec->vma + TP_OFFSET);
  insn = bfd_getb32 (contents + laddr);
  if ( (bfd_signed_vma) (foff) < CONSERVATIVE_20BIT
      && (bfd_signed_vma) (foff) >= -CONSERVATIVE_20BIT)
    {
      reloc = R_NDS32_TLS_LE_20;
      irel->r_info = ELF32_R_INFO (ELF32_R_SYM (irel->r_info), reloc);
      insn = N32_TYPE1 (MOVI, N32_RT5 (insn), 0);
      bfd_putb32 (insn, contents + laddr);
    }
}
ATTRIBUTE_UNUSED static void
nds32_elf_relax_letlsadd (struct bfd_link_info *link_info, bfd *abfd,
     asection *sec, Elf_Internal_Rela *irel,
     Elf_Internal_Rela *internal_relocs,
     bfd_byte *contents, Elf_Internal_Sym *isymbuf,
     Elf_Internal_Shdr *symtab_hdr, bfd_boolean *again)
{
  uint32_t insn;
  bfd_vma laddr;
  bfd_signed_vma foff;
  Elf_Internal_Rela *i1_irelfn, *irelend;
  irelend = internal_relocs + sec->reloc_count;
  laddr = irel->r_offset;
  insn = bfd_getb32 (contents + laddr);
  i1_irelfn = find_relocs_at_address (irel, internal_relocs, irelend,
          R_NDS32_PTR_RESOLVED);
  foff = calculate_memory_address (abfd, irel, isymbuf, symtab_hdr);
  BFD_ASSERT (elf_hash_table (link_info)->tls_sec != NULL);
  foff -= (elf_hash_table (link_info)->tls_sec->vma + TP_OFFSET);
  if ((bfd_signed_vma) (foff) < CONSERVATIVE_15BIT
      && (bfd_signed_vma) (foff) >= -CONSERVATIVE_15BIT)
    {
      insn = N32_TYPE2 (ADDI, N32_RT5 (insn), N32_RB5 (insn), 0);
      irel->r_info =
 ELF32_R_INFO (ELF32_R_SYM (irel->r_info), R_NDS32_TLS_LE_15S0);
      bfd_putb32 (insn, contents + laddr);
      if (i1_irelfn != irelend)
 {
   i1_irelfn->r_addend |= 1;
   *again = TRUE;
 }
    }
}
ATTRIBUTE_UNUSED static void
nds32_elf_relax_letlsls (struct bfd_link_info *link_info, bfd *abfd,
    asection *sec, Elf_Internal_Rela *irel,
    Elf_Internal_Rela *internal_relocs,
    bfd_byte *contents, Elf_Internal_Sym *isymbuf,
    Elf_Internal_Shdr *symtab_hdr, bfd_boolean *again)
{
  uint32_t insn;
  bfd_vma laddr;
  bfd_signed_vma foff;
  Elf_Internal_Rela *i1_irelfn, *irelend;
  int success = 0;
  irelend = internal_relocs + sec->reloc_count;
  laddr = irel->r_offset;
  insn = bfd_getb32 (contents + laddr);
  i1_irelfn = find_relocs_at_address (irel, internal_relocs, irelend,
          R_NDS32_PTR_RESOLVED);
  foff = calculate_memory_address (abfd, irel, isymbuf, symtab_hdr);
  BFD_ASSERT (elf_hash_table (link_info)->tls_sec != NULL);
  foff -= (elf_hash_table (link_info)->tls_sec->vma + TP_OFFSET);
  switch ((N32_OP6 (insn) << 8) | (insn & 0xff))
    {
    case (N32_OP6_MEM << 8) | N32_MEM_LB:
    case (N32_OP6_MEM << 8) | N32_MEM_SB:
    case (N32_OP6_MEM << 8) | N32_MEM_LBS:
      if ((bfd_signed_vma) (foff) < CONSERVATIVE_15BIT
   && (bfd_signed_vma) (foff) >= -CONSERVATIVE_15BIT)
 {
   insn =
     ((insn & 0xff) << 25) | (insn & 0x1f00000) | ((insn & 0x7c00) << 5);
   irel->r_info =
     ELF32_R_INFO (ELF32_R_SYM (irel->r_info), R_NDS32_TLS_LE_15S0);
   success = 1;
   break;
 }
    case (N32_OP6_MEM << 8) | N32_MEM_LH:
    case (N32_OP6_MEM << 8) | N32_MEM_SH:
    case (N32_OP6_MEM << 8) | N32_MEM_LHS:
      if ((bfd_signed_vma) (foff) < CONSERVATIVE_15BIT_S1
   && (bfd_signed_vma) (foff) >= -CONSERVATIVE_15BIT_S1)
 {
   insn =
     ((insn & 0xff) << 25) | (insn & 0x1f00000) | ((insn & 0x7c00) << 5);
   irel->r_info =
     ELF32_R_INFO (ELF32_R_SYM (irel->r_info), R_NDS32_TLS_LE_15S1);
   success = 1;
   break;
 }
    case (N32_OP6_MEM << 8) | N32_MEM_LW:
    case (N32_OP6_MEM << 8) | N32_MEM_SW:
      if ((bfd_signed_vma) (foff) < CONSERVATIVE_15BIT_S2
   && (bfd_signed_vma) (foff) >= -CONSERVATIVE_15BIT_S2)
 {
   insn =
     ((insn & 0xff) << 25) | (insn & 0x1f00000) | ((insn & 0x7c00) << 5);
   irel->r_info =
     ELF32_R_INFO (ELF32_R_SYM (irel->r_info), R_NDS32_TLS_LE_15S2);
   success = 1;
   break;
 }
    default:
      break;
    }
  if (success)
    {
      bfd_putb32 (insn, contents + laddr);
      if (i1_irelfn != irelend)
 {
   i1_irelfn->r_addend |= 1;
   *again = TRUE;
 }
    }
}
static bfd_boolean
nds32_elf_relax_ptr (bfd *abfd, asection *sec, Elf_Internal_Rela *irel,
       Elf_Internal_Rela *internal_relocs, int *insn_len,
       int *seq_len, bfd_byte *contents)
{
  Elf_Internal_Rela *ptr_irel, *irelend, *count_irel, *re_irel;
  irelend = internal_relocs + sec->reloc_count;
  re_irel =
    find_relocs_at_address_addr (irel, internal_relocs, irelend,
     R_NDS32_PTR_RESOLVED, irel->r_addend);
  if (re_irel == irelend)
    {
      (*_bfd_error_handler)
 ("%B: warning: R_NDS32_PTR points to unrecognized reloc at 0x%lx.",
  abfd, (long) irel->r_offset);
      return FALSE;
    }
  if (re_irel->r_addend != 1)
    return FALSE;
  irel->r_info = ELF32_R_INFO (ELF32_R_SYM (irel->r_info), R_NDS32_NONE);
  count_irel = find_relocs_at_address (irel, internal_relocs, irelend,
           R_NDS32_PTR_COUNT);
  ptr_irel = find_relocs_at_address (irel, internal_relocs, irelend,
         R_NDS32_PTR);
  if (count_irel != irelend)
    {
      if (--count_irel->r_addend > 0)
 return FALSE;
    }
  if (ptr_irel != irelend)
    return FALSE;
  *seq_len = nds32_elf_insn_size (abfd, contents, irel->r_offset);
  *insn_len = 0;
  return TRUE;
}
ATTRIBUTE_UNUSED static void
nds32_elf_relax_pltgot_suff (struct bfd_link_info *link_info, bfd *abfd,
        asection *sec, Elf_Internal_Rela *irel,
        Elf_Internal_Rela *internal_relocs,
        bfd_byte *contents, Elf_Internal_Sym *isymbuf,
        Elf_Internal_Shdr *symtab_hdr, bfd_boolean *again)
{
  uint32_t insn;
  bfd_signed_vma foff;
  Elf_Internal_Rela *i1_irelfn, *irelend;
  bfd_vma local_sda, laddr;
  irelend = internal_relocs + sec->reloc_count;
  laddr = irel->r_offset;
  insn = bfd_getb32 (contents + laddr);
  if (insn & 0x80000000)
    return;
  if (nds32_elf_check_dup_relocs
      (irel, internal_relocs, irelend, R_NDS32_PLT_GOT_SUFF))
    return;
  i1_irelfn =
    find_relocs_at_address (irel, internal_relocs, irelend,
       R_NDS32_PTR_RESOLVED);
  if (N32_OP6 (insn) == N32_OP6_ALU1
      && N32_SUB5 (insn) == N32_ALU1_ADD)
    {
      nds32_elf_final_sda_base (sec->output_section->owner, link_info,
    &local_sda, FALSE);
      foff = (bfd_signed_vma) (calculate_plt_memory_address
          (abfd, link_info, isymbuf, irel,
    symtab_hdr) - local_sda);
      if (foff == 0)
 return;
      if (foff < -CONSERVATIVE_19BIT || foff >= CONSERVATIVE_19BIT)
 return;
      irel->r_info = ELF32_R_INFO (ELF32_R_SYM (irel->r_info),
       R_NDS32_PLT_GOTREL_LO19);
      insn = N32_TYPE1 (SBGP, N32_RT5 (insn), __BIT (19));
    }
  else if (N32_OP6 (insn) == N32_OP6_JREG
    && N32_SUB5 (insn) == N32_JREG_JRAL)
    {
      foff =
 calculate_plt_offset (abfd, sec, link_info, isymbuf, irel, symtab_hdr);
      if (foff == 0)
 return;
      if (foff < -CONSERVATIVE_24BIT_S1 || foff >= CONSERVATIVE_24BIT_S1)
 return;
      irel->r_info = ELF32_R_INFO (ELF32_R_SYM (irel->r_info), R_NDS32_25_PLTREL);
      insn = INSN_JAL;
    }
  else
    return;
  bfd_putb32 (insn, contents + laddr);
  if (i1_irelfn != irelend)
    {
      i1_irelfn->r_addend |= 1;
      *again = TRUE;
    }
}
ATTRIBUTE_UNUSED static void
nds32_elf_relax_got_suff (struct bfd_link_info *link_info, bfd *abfd,
     asection *sec, Elf_Internal_Rela *irel,
     Elf_Internal_Rela *internal_relocs,
     bfd_byte *contents, Elf_Internal_Shdr *symtab_hdr,
     bfd_boolean *again)
{
  uint32_t insn;
  bfd_signed_vma foff;
  Elf_Internal_Rela *i1_irelfn, *irelend;
  bfd_vma local_sda, laddr;
  irelend = internal_relocs + sec->reloc_count;
  laddr = irel->r_offset;
  insn = bfd_getb32 (contents + laddr);
  if (insn & 0x80000000)
    return;
  if (nds32_elf_check_dup_relocs
      (irel, internal_relocs, irelend, R_NDS32_GOT_SUFF))
    return;
  i1_irelfn = find_relocs_at_address (irel, internal_relocs, irelend,
          R_NDS32_PTR_RESOLVED);
  nds32_elf_final_sda_base (sec->output_section->owner, link_info,
       &local_sda, FALSE);
  foff = calculate_got_memory_address (abfd, link_info, irel,
           symtab_hdr) - local_sda;
  if (foff < CONSERVATIVE_19BIT && foff >= -CONSERVATIVE_19BIT)
    {
      insn = N32_TYPE1 (HWGP, N32_RT5 (insn), __MF (6, 17, 3));
      irel->r_info =
 ELF32_R_INFO (ELF32_R_SYM (irel->r_info), R_NDS32_GOT17S2_RELA);
      bfd_putb32 (insn, contents + laddr);
      if (i1_irelfn != irelend)
 {
   i1_irelfn->r_addend |= 1;
   *again = TRUE;
 }
    }
}
ATTRIBUTE_UNUSED static void
nds32_elf_relax_gotoff_suff (struct bfd_link_info *link_info, bfd *abfd,
        asection *sec, Elf_Internal_Rela *irel,
        Elf_Internal_Rela *internal_relocs,
        bfd_byte *contents, Elf_Internal_Sym *isymbuf,
        Elf_Internal_Shdr *symtab_hdr, bfd_boolean *again)
{
  int opc_insn_gotoff;
  uint32_t insn;
  bfd_signed_vma foff;
  Elf_Internal_Rela *i1_irelfn, *i2_irelfn, *irelend;
  bfd_vma local_sda, laddr;
  irelend = internal_relocs + sec->reloc_count;
  laddr = irel->r_offset;
  insn = bfd_getb32 (contents + laddr);
  if (insn & 0x80000000)
    return;
  if (nds32_elf_check_dup_relocs
      (irel, internal_relocs, irelend, R_NDS32_GOTOFF_SUFF))
    return;
  i1_irelfn = find_relocs_at_address (irel, internal_relocs, irelend,
          R_NDS32_PTR_RESOLVED);
  nds32_elf_final_sda_base (sec->output_section->owner, link_info,
       &local_sda, FALSE);
  foff = calculate_memory_address (abfd, irel, isymbuf, symtab_hdr);
  foff = foff - local_sda;
  if (foff >= CONSERVATIVE_19BIT || foff < -CONSERVATIVE_19BIT)
    return;
  opc_insn_gotoff = (N32_OP6 (insn) << 8) | (insn & 0xff);
  switch (opc_insn_gotoff)
    {
    case (N32_OP6_MEM << 8) | N32_MEM_LW:
      insn = N32_TYPE1 (HWGP, N32_RT5 (insn), __MF (6, 17, 3));
      irel->r_info =
 ELF32_R_INFO (ELF32_R_SYM (irel->r_info), R_NDS32_SDA17S2_RELA);
      break;
    case (N32_OP6_MEM << 8) | N32_MEM_SW:
      insn = N32_TYPE1 (HWGP, N32_RT5 (insn), __MF (7, 17, 3));
      irel->r_info =
 ELF32_R_INFO (ELF32_R_SYM (irel->r_info), R_NDS32_SDA17S2_RELA);
      break;
    case (N32_OP6_MEM << 8) | N32_MEM_LH:
      insn = N32_TYPE1 (HWGP, N32_RT5 (insn), 0);
      irel->r_info =
 ELF32_R_INFO (ELF32_R_SYM (irel->r_info), R_NDS32_SDA18S1_RELA);
      break;
    case (N32_OP6_MEM << 8) | N32_MEM_LHS:
      insn = N32_TYPE1 (HWGP, N32_RT5 (insn), __BIT (18));
      irel->r_info =
 ELF32_R_INFO (ELF32_R_SYM (irel->r_info), R_NDS32_SDA18S1_RELA);
      break;
    case (N32_OP6_MEM << 8) | N32_MEM_SH:
      insn = N32_TYPE1 (HWGP, N32_RT5 (insn), __BIT (19));
      irel->r_info =
 ELF32_R_INFO (ELF32_R_SYM (irel->r_info), R_NDS32_SDA18S1_RELA);
      break;
    case (N32_OP6_MEM << 8) | N32_MEM_LB:
      insn = N32_TYPE1 (LBGP, N32_RT5 (insn), 0);
      irel->r_info =
 ELF32_R_INFO (ELF32_R_SYM (irel->r_info), R_NDS32_SDA19S0_RELA);
      break;
    case (N32_OP6_MEM << 8) | N32_MEM_LBS:
      insn = N32_TYPE1 (LBGP, N32_RT5 (insn), __BIT (19));
      irel->r_info =
 ELF32_R_INFO (ELF32_R_SYM (irel->r_info), R_NDS32_SDA19S0_RELA);
      break;
    case (N32_OP6_MEM << 8) | N32_MEM_SB:
      insn = N32_TYPE1 (SBGP, N32_RT5 (insn), 0);
      irel->r_info =
 ELF32_R_INFO (ELF32_R_SYM (irel->r_info), R_NDS32_SDA19S0_RELA);
      break;
    case (N32_OP6_ALU1 << 8) | N32_ALU1_ADD:
      insn = N32_TYPE1 (SBGP, N32_RT5 (insn), __BIT (19));
      irel->r_info =
 ELF32_R_INFO (ELF32_R_SYM (irel->r_info), R_NDS32_SDA19S0_RELA);
      break;
    default:
      return;
    }
  bfd_putb32 (insn, contents + laddr);
  if (i1_irelfn != irelend)
    {
      i1_irelfn->r_addend |= 1;
      *again = TRUE;
    }
  if ((i2_irelfn = find_relocs_at_address (irel, internal_relocs, irelend,
        R_NDS32_INSN16)) != irelend)
    i2_irelfn->r_info = ELF32_R_INFO (ELF32_R_SYM (irel->r_info), R_NDS32_NONE);
}
static void
nds32_elf_relax_flsi (struct bfd_link_info *link_info, bfd *abfd,
        asection *sec, Elf_Internal_Rela *irel,
        Elf_Internal_Rela *internal_relocs,
        bfd_byte *contents, Elf_Internal_Sym *isymbuf,
        Elf_Internal_Shdr *symtab_hdr, bfd_boolean *again)
{
  uint32_t insn;
  bfd_vma local_sda, laddr;
  unsigned long reloc;
  bfd_vma access_addr, flsi_offset;
  bfd_vma range_l = 0, range_h = 0;
  Elf_Internal_Rela *irelend, *re_irel;
  unsigned int opcode;
  irelend = internal_relocs + sec->reloc_count;
  laddr = irel->r_offset;
  insn = bfd_getb32 (contents + laddr);
  if ((insn & 0x80000000) || !is_sda_access_insn (insn))
    return;
  if ((insn & 0x1000))
    return;
  opcode = N32_OP6 (insn);
  if ((opcode == N32_OP6_LWC) || (opcode == N32_OP6_SWC))
    reloc = R_NDS32_SDA12S2_SP_RELA;
  else if ((opcode == N32_OP6_LDC) || (opcode == N32_OP6_SDC))
    reloc = R_NDS32_SDA12S2_DP_RELA;
  else
    return;
  re_irel = find_relocs_at_address (irel, internal_relocs, irelend,
        R_NDS32_PTR_RESOLVED);
  if (re_irel == irelend)
    {
      (*_bfd_error_handler)
 ("%B: warning: R_NDS32_LSI has no R_NDS32_PTR_RESOLVED at 0x%lx.",
 abfd, (long) irel->r_offset);
      return;
    }
  nds32_elf_final_sda_base (sec->output_section->owner, link_info,
       &local_sda, FALSE);
  access_addr = calculate_memory_address (abfd, irel, isymbuf, symtab_hdr);
  flsi_offset = (insn & 0xfff) << 2;
  access_addr += flsi_offset;
  range_l = sdata_range[0][0];
  range_h = sdata_range[0][1];
  if ((local_sda <= access_addr && (access_addr - local_sda) < range_h)
      || (local_sda > access_addr && (local_sda - access_addr) <= range_l))
    {
      insn = (insn & 0x7ff07000) | (REG_GP << 15);
      irel->r_info = ELF32_R_INFO (ELF32_R_SYM (irel->r_info), reloc);
      irel->r_addend += flsi_offset;
      bfd_putb32 (insn, contents + re_irel->r_offset);
      re_irel->r_addend |= 1;
      *again = TRUE;
    }
}
static bfd_boolean
nds32_relax_adjust_label (bfd *abfd, asection *sec,
     Elf_Internal_Rela *internal_relocs,
     bfd_byte *contents,
     nds32_elf_blank_t **relax_blank_list,
     int optimize, int opt_size)
{
  Elf_Internal_Rela *insn_rel = NULL, *label_rel = NULL, *irel;
  Elf_Internal_Rela *tmp_rel, *tmp2_rel = NULL;
  Elf_Internal_Rela rel_temp;
  Elf_Internal_Rela *irelend;
  bfd_vma address;
  uint16_t insn16;
  nds32_insertion_sort (internal_relocs, sec->reloc_count,
   sizeof (Elf_Internal_Rela), compar_reloc);
  irelend = internal_relocs + sec->reloc_count;
  for (label_rel = internal_relocs, insn_rel = internal_relocs;
       label_rel < irelend; label_rel++)
    {
      if (ELF32_R_TYPE (label_rel->r_info) != R_NDS32_LABEL)
 continue;
      while (insn_rel < irelend && insn_rel->r_offset < label_rel->r_offset)
 insn_rel++;
      for (;insn_rel < irelend && insn_rel->r_offset == label_rel->r_offset;
    insn_rel++)
 if (ELF32_R_TYPE (insn_rel->r_info) == R_NDS32_INSN16)
   break;
      if (insn_rel < irelend && insn_rel->r_offset == label_rel->r_offset
   && insn_rel < label_rel)
 {
   memcpy (&rel_temp, insn_rel, sizeof (Elf_Internal_Rela));
   memcpy (insn_rel, label_rel, sizeof (Elf_Internal_Rela));
   memcpy (label_rel, &rel_temp, sizeof (Elf_Internal_Rela));
 }
    }
  label_rel = NULL;
  insn_rel = NULL;
  for (tmp_rel = internal_relocs; tmp_rel < irelend; tmp_rel++)
    {
      if (ELF32_R_TYPE (tmp_rel->r_info) == R_NDS32_LABEL)
 {
   if (label_rel == NULL)
     {
       if (tmp_rel->r_addend < 2)
  label_rel = tmp_rel;
       continue;
     }
   else if (tmp_rel->r_addend > 1)
     {
       for (tmp2_rel = label_rel; tmp2_rel < tmp_rel; tmp2_rel++)
  {
    if (tmp2_rel->r_offset == tmp_rel->r_offset)
      break;
    if (ELF32_R_TYPE (tmp2_rel->r_info) == R_NDS32_LABEL
        && tmp2_rel->r_addend < 2)
      tmp2_rel->r_info =
        ELF32_R_INFO (ELF32_R_SYM (tmp2_rel->r_info),
        R_NDS32_NONE);
  }
       label_rel = NULL;
     }
 }
      else if (ELF32_R_TYPE (tmp_rel->r_info) == R_NDS32_INSN16 && label_rel)
 {
   if (is_convert_32_to_16 (abfd, sec, tmp_rel, internal_relocs,
       irelend, &insn16)
       || is_16bit_NOP (abfd, sec, tmp_rel))
     label_rel = NULL;
 }
    }
  label_rel = NULL;
  insn_rel = NULL;
  for (irel = internal_relocs;
       irel < irelend && irel->r_offset < sec->size; irel++)
    {
      if (ELF32_R_TYPE (irel->r_info) != R_NDS32_INSN16
   && ELF32_R_TYPE (irel->r_info) != R_NDS32_LABEL)
 continue;
      if (ELF32_R_TYPE (irel->r_info) == R_NDS32_INSN16)
 {
   if (is_convert_32_to_16
       (abfd, sec, irel, internal_relocs, irelend, &insn16)
       || is_16bit_NOP (abfd, sec, irel))
     {
       if (insn_rel)
  {
    if (is_convert_32_to_16 (abfd, sec, insn_rel, internal_relocs,
        irelend, &insn16))
      {
        nds32_elf_write_16 (abfd, contents, insn_rel,
       internal_relocs, irelend, insn16);
        if (!insert_nds32_elf_blank_recalc_total
     (relax_blank_list, insn_rel->r_offset + 2, 2))
   return FALSE;
      }
    else if (is_16bit_NOP (abfd, sec, insn_rel))
      {
        if (!insert_nds32_elf_blank_recalc_total
     (relax_blank_list, insn_rel->r_offset, 2))
   return FALSE;
      }
    insn_rel->r_info =
      ELF32_R_INFO (ELF32_R_SYM (insn_rel->r_info), R_NDS32_NONE);
  }
       insn_rel = irel;
     }
   else
     irel->r_info = ELF32_R_INFO (ELF32_R_SYM (irel->r_info),
      R_NDS32_NONE);
 }
      else if (ELF32_R_TYPE (irel->r_info) == R_NDS32_LABEL)
 {
   int force_relax = 0;
   insn16 = bfd_getb16 (contents + irel->r_offset);
   if ((irel->r_addend & 0x1f) < 2 && (!optimize || (insn16 & 0x8000)))
     {
       irel->r_info =
  ELF32_R_INFO (ELF32_R_SYM (irel->r_info), R_NDS32_NONE);
       continue;
     }
   address =
     irel->r_offset - get_nds32_elf_blank_total (relax_blank_list,
       irel->r_offset, 1);
   if (!insn_rel)
     {
       if (irel->r_addend == 2 && address & 0x2)
  return FALSE;
       continue;
     }
   if ((irel->r_addend & 0x1f) < 2)
     {
       for (tmp_rel = irel;
     tmp_rel < irelend && tmp_rel->r_offset == irel->r_offset;
     tmp_rel++)
  {
    if (ELF32_R_TYPE (tmp_rel->r_info) == R_NDS32_INSN16
        && (is_convert_32_to_16
     (abfd, sec, tmp_rel, internal_relocs,
      irelend, &insn16)
     || is_16bit_NOP (abfd, sec, tmp_rel)))
      {
        force_relax = 1;
        break;
      }
  }
     }
   if (force_relax || irel->r_addend == 1 || address & 0x2)
     {
       if (is_convert_32_to_16 (abfd, sec, insn_rel,
           internal_relocs, irelend, &insn16))
  {
    nds32_elf_write_16 (abfd, contents, insn_rel,
          internal_relocs, irelend, insn16);
    if (!insert_nds32_elf_blank_recalc_total
        (relax_blank_list, insn_rel->r_offset + 2, 2))
      return FALSE;
  }
       else if (is_16bit_NOP (abfd, sec, insn_rel))
  {
    if (!insert_nds32_elf_blank_recalc_total
        (relax_blank_list, insn_rel->r_offset, 2))
      return FALSE;
  }
     }
   insn_rel = NULL;
 }
    }
  address =
    sec->size - get_nds32_elf_blank_total (relax_blank_list, sec->size, 0);
  if (insn_rel && (address & 0x2 || opt_size))
    {
      if (is_convert_32_to_16 (abfd, sec, insn_rel, internal_relocs,
          irelend, &insn16))
 {
   nds32_elf_write_16 (abfd, contents, insn_rel, internal_relocs,
         irelend, insn16);
   if (!insert_nds32_elf_blank_recalc_total
       (relax_blank_list, insn_rel->r_offset + 2, 2))
     return FALSE;
   insn_rel->r_info = ELF32_R_INFO (ELF32_R_SYM (insn_rel->r_info),
        R_NDS32_NONE);
 }
      else if (is_16bit_NOP (abfd, sec, insn_rel))
 {
   if (!insert_nds32_elf_blank_recalc_total
       (relax_blank_list, insn_rel->r_offset, 2))
     return FALSE;
   insn_rel->r_info = ELF32_R_INFO (ELF32_R_SYM (insn_rel->r_info),
        R_NDS32_NONE);
 }
    }
  insn_rel = NULL;
  return TRUE;
}
static bfd_boolean
nds32_elf_relax_section (bfd *abfd, asection *sec,
    struct bfd_link_info *link_info, bfd_boolean *again)
{
  nds32_elf_blank_t *relax_blank_list = NULL;
  Elf_Internal_Shdr *symtab_hdr;
  Elf_Internal_Rela *internal_relocs;
  Elf_Internal_Rela *irel;
  Elf_Internal_Rela *irelend;
  Elf_Internal_Sym *isymbuf = NULL;
  bfd_byte *contents = NULL;
  bfd_boolean result = TRUE;
  int optimize = 0;
  int opt_size = 0;
  uint32_t insn;
  uint16_t insn16;
  struct elf_nds32_link_hash_table *table;
  int load_store_relax;
  int relax_round ATTRIBUTE_UNUSED;
  relax_blank_list = NULL;
  *again = FALSE;
  if (link_info->relocatable
      || (sec->flags & SEC_RELOC) == 0
      || (sec->flags & SEC_EXCLUDE) == 1
      || (sec->flags & SEC_CODE) == 0
      || sec->size == 0
      || sec->reloc_count == 0)
    return TRUE;
  if (sec->alignment_power > 2)
    return TRUE;
#ifdef NDS32_LINUX_TOOLCHAIN
  nds32_elf_unify_tls_model (abfd, sec, contents, link_info);
#endif
  table = nds32_elf_hash_table (link_info);
  if (is_SDA_BASE_set == 0)
    {
      bfd_vma gp;
      is_SDA_BASE_set = 1;
      nds32_elf_final_sda_base (sec->output_section->owner, link_info,
    &gp, FALSE);
      relax_range_measurement (abfd);
    }
  symtab_hdr = &elf_tdata (abfd)->symtab_hdr;
  internal_relocs = _bfd_elf_link_read_relocs (abfd, sec, NULL, NULL,
            TRUE );
  if (internal_relocs == NULL)
    goto error_return;
  irelend = internal_relocs + sec->reloc_count;
  irel = find_relocs_at_address (internal_relocs, internal_relocs,
     irelend, R_NDS32_RELAX_ENTRY);
  if (irel == irelend)
    return TRUE;
  if (ELF32_R_TYPE (irel->r_info) == R_NDS32_RELAX_ENTRY)
    {
      if (irel->r_addend & R_NDS32_RELAX_ENTRY_DISABLE_RELAX_FLAG)
 return TRUE;
      if (irel->r_addend & R_NDS32_RELAX_ENTRY_OPTIMIZE_FLAG)
 optimize = 1;
      if (irel->r_addend & R_NDS32_RELAX_ENTRY_OPTIMIZE_FOR_SPACE_FLAG)
 opt_size = 1;
    }
  load_store_relax = table->load_store_relax;
  if (!nds32_get_section_contents (abfd, sec, &contents, TRUE)
      || !nds32_get_local_syms (abfd, sec, &isymbuf))
    goto error_return;
  for (irel = internal_relocs; irel < irelend; irel++)
    {
      int seq_len;
      int insn_len = 0;
      bfd_boolean removed;
      insn = 0;
      if (ELF32_R_TYPE (irel->r_info) == R_NDS32_LABEL
   && (irel->r_addend & 0x1f) >= 2)
 optimize = 1;
      if (ELF32_R_TYPE (irel->r_info) >= R_NDS32_LONGCALL1
   && ELF32_R_TYPE (irel->r_info) <= R_NDS32_LOADSTORE)
 seq_len = GET_SEQ_LEN (irel->r_addend);
      else if (ELF32_R_TYPE (irel->r_info) >= R_NDS32_LONGCALL4
        && ELF32_R_TYPE (irel->r_info) <= R_NDS32_LONGJUMP7)
 seq_len = 4;
      else if ((ELF32_R_TYPE (irel->r_info) <= R_NDS32_LO12S0_RELA
  && ELF32_R_TYPE (irel->r_info) >= R_NDS32_LO12S2_RELA)
        || ELF32_R_TYPE (irel->r_info) == R_NDS32_LO12S2_SP_RELA
        || ELF32_R_TYPE (irel->r_info) == R_NDS32_LO12S2_DP_RELA
        || ELF32_R_TYPE (irel->r_info) == R_NDS32_GOT_LO12
        || ELF32_R_TYPE (irel->r_info) == R_NDS32_GOTOFF_LO12
        || ELF32_R_TYPE (irel->r_info) == R_NDS32_GOTPC_LO12
        || ELF32_R_TYPE (irel->r_info) == R_NDS32_PLTREL_LO12
        || ELF32_R_TYPE (irel->r_info) == R_NDS32_PLT_GOTREL_LO12
        || (ELF32_R_TYPE (irel->r_info) >= R_NDS32_GOT_SUFF
     && ELF32_R_TYPE (irel->r_info) <= R_NDS32_PTR)
        || ELF32_R_TYPE (irel->r_info) == R_NDS32_17IFC_PCREL_RELA
        || ELF32_R_TYPE (irel->r_info) == R_NDS32_TLS_LE_LO12
        || ELF32_R_TYPE (irel->r_info) == R_NDS32_TLS_LE_ADD
        || ELF32_R_TYPE (irel->r_info) == R_NDS32_TLS_LE_LS
        || ELF32_R_TYPE (irel->r_info) == R_NDS32_LSI)
 seq_len = 0;
      else
 continue;
      insn_len = seq_len;
      removed = FALSE;
      switch (ELF32_R_TYPE (irel->r_info))
 {
 case R_NDS32_LONGCALL1:
   removed = nds32_elf_relax_longcall1 (abfd, sec, irel, internal_relocs,
            &insn_len, contents, isymbuf,
            symtab_hdr);
   break;
 case R_NDS32_LONGCALL2:
   removed = nds32_elf_relax_longcall2 (abfd, sec, irel, internal_relocs,
            &insn_len, contents, isymbuf,
            symtab_hdr);
   break;
 case R_NDS32_LONGCALL3:
   removed = nds32_elf_relax_longcall3 (abfd, sec, irel, internal_relocs,
            &insn_len, contents, isymbuf,
            symtab_hdr);
   break;
 case R_NDS32_LONGJUMP1:
   removed = nds32_elf_relax_longjump1 (abfd, sec, irel, internal_relocs,
            &insn_len, contents, isymbuf,
            symtab_hdr);
   break;
 case R_NDS32_LONGJUMP2:
   removed = nds32_elf_relax_longjump2 (abfd, sec, irel, internal_relocs,
            &insn_len, contents, isymbuf,
            symtab_hdr);
   break;
 case R_NDS32_LONGJUMP3:
   removed = nds32_elf_relax_longjump3 (abfd, sec, irel, internal_relocs,
            &insn_len, contents, isymbuf,
            symtab_hdr);
   break;
 case R_NDS32_LONGCALL4:
   removed = nds32_elf_relax_longcall4 (abfd, sec, irel, internal_relocs,
            &insn_len, contents, isymbuf,
            symtab_hdr);
   break;
 case R_NDS32_LONGCALL5:
   removed = nds32_elf_relax_longcall5 (abfd, sec, irel, internal_relocs,
            &insn_len, contents, isymbuf,
            symtab_hdr);
   break;
 case R_NDS32_LONGCALL6:
   removed = nds32_elf_relax_longcall6 (abfd, sec, irel, internal_relocs,
            &insn_len, contents, isymbuf,
            symtab_hdr);
   break;
 case R_NDS32_LONGJUMP4:
   removed = nds32_elf_relax_longjump4 (abfd, sec, irel, internal_relocs,
            &insn_len, contents, isymbuf,
            symtab_hdr);
   break;
 case R_NDS32_LONGJUMP5:
   removed = nds32_elf_relax_longjump5 (abfd, sec, irel, internal_relocs,
            &insn_len, &seq_len, contents,
            isymbuf, symtab_hdr);
   break;
 case R_NDS32_LONGJUMP6:
   removed = nds32_elf_relax_longjump6 (abfd, sec, irel, internal_relocs,
            &insn_len, &seq_len, contents,
            isymbuf, symtab_hdr);
   break;
 case R_NDS32_LONGJUMP7:
   removed = nds32_elf_relax_longjump7 (abfd, sec, irel, internal_relocs,
            &insn_len, &seq_len, contents,
            isymbuf, symtab_hdr);
   break;
 case R_NDS32_LOADSTORE:
   removed = nds32_elf_relax_loadstore (link_info, abfd, sec, irel,
            internal_relocs, &insn_len,
            contents, isymbuf, symtab_hdr,
            load_store_relax, table);
   break;
 case R_NDS32_LO12S0_RELA:
 case R_NDS32_LO12S1_RELA:
 case R_NDS32_LO12S2_RELA:
 case R_NDS32_LO12S2_DP_RELA:
 case R_NDS32_LO12S2_SP_RELA:
   nds32_elf_relax_lo12 (link_info, abfd, sec, irel, internal_relocs,
    contents, isymbuf, symtab_hdr, table);
   continue;
 case R_NDS32_PTR:
   removed = nds32_elf_relax_ptr (abfd, sec, irel, internal_relocs,
      &insn_len, &seq_len, contents);
   break;
 case R_NDS32_LSI:
   nds32_elf_relax_flsi (link_info, abfd, sec, irel, internal_relocs,
    contents, isymbuf, symtab_hdr, again);
   continue;
 case R_NDS32_GOT_LO12:
 case R_NDS32_GOTOFF_LO12:
 case R_NDS32_PLTREL_LO12:
 case R_NDS32_PLT_GOTREL_LO12:
 case R_NDS32_GOTPC_LO12:
 case R_NDS32_TLS_LE_LO12:
 case R_NDS32_TLS_LE_ADD:
 case R_NDS32_TLS_LE_LS:
 case R_NDS32_PLT_GOT_SUFF:
 case R_NDS32_GOT_SUFF:
 case R_NDS32_GOTOFF_SUFF:
   continue;
 default:
   continue;
 }
      if (removed && seq_len - insn_len > 0)
 {
   if (!insert_nds32_elf_blank
       (&relax_blank_list, irel->r_offset + insn_len,
        seq_len - insn_len))
     goto error_return;
   *again = TRUE;
 }
    }
  calc_nds32_blank_total (relax_blank_list);
  if (table->relax_fp_as_gp)
    {
      if (!nds32_relax_fp_as_gp (link_info, abfd, sec, internal_relocs,
     irelend, isymbuf))
 goto error_return;
      if (*again == FALSE)
 {
   if (!nds32_fag_remove_unused_fpbase (abfd, sec, internal_relocs,
            irelend))
     goto error_return;
 }
    }
  if (*again == FALSE)
    {
      if (!nds32_relax_adjust_label (abfd, sec, internal_relocs, contents,
         &relax_blank_list, optimize, opt_size))
 goto error_return;
    }
  if (relax_blank_list)
    {
      nds32_elf_relax_delete_blanks (abfd, sec, relax_blank_list);
      relax_blank_list = NULL;
    }
  if (*again == FALSE)
    {
      bfd_vma sec_size_align;
      Elf_Internal_Rela *tmp_rel;
      sec_size_align = (sec->size + (~((bfd_vma)(-1) << sec->alignment_power)))
         & ((bfd_vma)(-1) << sec->alignment_power);
      if ((sec_size_align - sec->size) & 0x2)
 {
   insn16 = NDS32_NOP16;
   bfd_putb16 (insn16, contents + sec->size);
   sec->size += 2;
 }
      while (sec_size_align != sec->size)
 {
   insn = NDS32_NOP32;
   bfd_putb32 (insn, contents + sec->size);
   sec->size += 4;
 }
      tmp_rel = find_relocs_at_address (internal_relocs, internal_relocs,
     irelend, R_NDS32_RELAX_ENTRY);
      if (tmp_rel != irelend)
 tmp_rel->r_addend |= R_NDS32_RELAX_ENTRY_DISABLE_RELAX_FLAG;
      clean_nds32_elf_blank ();
    }
finish:
  if (internal_relocs != NULL
      && elf_section_data (sec)->relocs != internal_relocs)
    free (internal_relocs);
  if (contents != NULL
      && elf_section_data (sec)->this_hdr.contents != contents)
    free (contents);
  if (isymbuf != NULL && symtab_hdr->contents != (bfd_byte *) isymbuf)
    free (isymbuf);
  return result;
error_return:
  result = FALSE;
  goto finish;
}
static struct bfd_elf_special_section const nds32_elf_special_sections[] = {
  {".sdata", 6, -2, SHT_PROGBITS, SHF_ALLOC + SHF_WRITE},
  {".sbss", 5, -2, SHT_NOBITS, SHF_ALLOC + SHF_WRITE},
  {NULL, 0, 0, 0, 0}
};
static bfd_boolean
nds32_elf_output_arch_syms (bfd *output_bfd ATTRIBUTE_UNUSED,
       struct bfd_link_info *info,
       void *finfo ATTRIBUTE_UNUSED,
       bfd_boolean (*func) (void *, const char *,
       Elf_Internal_Sym *,
       asection *,
       struct elf_link_hash_entry *)
       ATTRIBUTE_UNUSED)
{
  FILE *sym_ld_script = NULL;
  struct elf_nds32_link_hash_table *table;
  table = nds32_elf_hash_table (info);
  sym_ld_script = table->sym_ld_script;
  if (check_start_export_sym)
    fprintf (sym_ld_script, "}\n");
  return TRUE;
}
static enum elf_reloc_type_class
nds32_elf_reloc_type_class (const struct bfd_link_info *info ATTRIBUTE_UNUSED,
       const asection *rel_sec ATTRIBUTE_UNUSED,
       const Elf_Internal_Rela *rela)
{
  switch ((int) ELF32_R_TYPE (rela->r_info))
    {
    case R_NDS32_RELATIVE:
      return reloc_class_relative;
    case R_NDS32_JMP_SLOT:
      return reloc_class_plt;
    case R_NDS32_COPY:
      return reloc_class_copy;
    default:
      return reloc_class_normal;
    }
}
void
bfd_elf32_nds32_set_target_option (struct bfd_link_info *link_info,
       int relax_fp_as_gp,
       int eliminate_gc_relocs,
       FILE * sym_ld_script, int load_store_relax,
       int hyper_relax, int tls_desc_trampoline,
       char *abi)
{
  struct elf_nds32_link_hash_table *table;
  nds32_elf_ict_hash_init ();
  table = nds32_elf_hash_table (link_info);
  if (table == NULL)
    return;
  table->relax_fp_as_gp = relax_fp_as_gp;
  table->eliminate_gc_relocs = eliminate_gc_relocs;
  table->sym_ld_script = sym_ld_script;
  table ->load_store_relax = load_store_relax;
  table->hyper_relax = hyper_relax;
  table->tls_desc_trampoline = tls_desc_trampoline;
  output_abi = abi;
}
void
bfd_elf32_nds32_append_section (struct bfd_link_info *link_info,
    bfd *abfd, int target_optimize ATTRIBUTE_UNUSED)
{
  asection *itable;
  struct bfd_link_hash_entry *h;
  unsigned int i, count = 0;
  indirect_call_table.frozen = 1;
  for (i = 0; i < indirect_call_table.size; i++)
    {
      struct bfd_hash_entry *p;
      struct elf_nds32_ict_hash_entry *entry;
      for (p = indirect_call_table.table[i]; p != NULL; p = p->next)
 {
   entry = (struct elf_nds32_ict_hash_entry *) p;
   entry->order = count;
   count++;
 }
    }
  indirect_call_table.frozen = 0;
  if (count)
    {
      h = bfd_link_hash_lookup (link_info->hash, "_INDIRECT_CALL_TABLE_BASE_",
    FALSE, FALSE, FALSE);
      if (h && (h->type == bfd_link_hash_defined
  || h->type == bfd_link_hash_defweak
  || h->type == bfd_link_hash_common))
 {
   (*_bfd_error_handler) (_("Warning: _INDIRECT_CALL_TABLE_BASE_ has already"
       "be defined. All ICT suffix is ignored."));
   ignore_indirect_call = TRUE;
   return;
 }
      if (ict_model == R_NDS32_RELAX_ENTRY_ICT_LARGE)
 itable = bfd_make_section_with_flags (abfd, NDS32_ICT_SECTION,
           SEC_DATA | SEC_ALLOC | SEC_LOAD
           | SEC_HAS_CONTENTS | SEC_READONLY
           | SEC_IN_MEMORY | SEC_KEEP
           | SEC_RELOC);
      else
 itable = bfd_make_section_with_flags (abfd, NDS32_ICT_SECTION,
           SEC_CODE | SEC_ALLOC | SEC_LOAD
           | SEC_HAS_CONTENTS | SEC_READONLY
           | SEC_IN_MEMORY | SEC_KEEP
           | SEC_RELOC);
      if (itable)
 {
   itable->gc_mark = 1;
   itable->alignment_power = 2;
   itable->size = count * 4;
   itable->contents = bfd_zalloc (abfd, itable->size);
   h = bfd_link_hash_lookup (link_info->hash,
        "_INDIRECT_CALL_TABLE_BASE_",
        FALSE, FALSE, FALSE);
   _bfd_generic_link_add_one_symbol
     (link_info, link_info->output_bfd, "_INDIRECT_CALL_TABLE_BASE_",
      BSF_GLOBAL | BSF_WEAK, itable, 0, (const char *) NULL, FALSE,
      get_elf_backend_data (link_info->output_bfd)->collect, &h);
 }
      ict_file = fopen ("nds32_ict.s", FOPEN_WT);
      if(ict_file == NULL)
 (*_bfd_error_handler) (_("Warning: Fail to build nds32_ict.s."));
    }
}
#define FAG_THRESHOLD 3
#define FAG_WINDOW (508 - 32)
struct nds32_fag
{
  struct nds32_fag *next;
  bfd_vma addr;
  Elf_Internal_Rela **relas;
  int count;
  int relas_capcity;
};
static void
nds32_fag_init (struct nds32_fag *head)
{
  memset (head, 0, sizeof (struct nds32_fag));
}
static void
nds32_fag_verify (struct nds32_fag *head)
{
  struct nds32_fag *iter;
  struct nds32_fag *prev;
  prev = NULL;
  iter = head->next;
  while (iter)
    {
      if (prev && prev->addr >= iter->addr)
 puts ("Bug in fp-as-gp insertion.");
      prev = iter;
      iter = iter->next;
    }
}
static void
nds32_fag_insert (struct nds32_fag *head, bfd_vma addr,
    Elf_Internal_Rela * rel)
{
  struct nds32_fag *iter;
  struct nds32_fag *new_fag;
  const int INIT_RELAS_CAP = 4;
  for (iter = head;
       iter->next && iter->next->addr <= addr;
       iter = iter->next)
                                     ;
  if (iter != head && iter->addr == addr)
    {
      if (iter->count >= iter->relas_capcity)
 {
   iter->relas_capcity *= 2;
   iter->relas = bfd_realloc
     (iter->relas, iter->relas_capcity * sizeof (void *));
 }
      iter->relas[iter->count++] = rel;
      return;
    }
  new_fag = bfd_malloc (sizeof (struct nds32_fag));
  memset (new_fag, 0, sizeof (*new_fag));
  new_fag->addr = addr;
  new_fag->count = 1;
  new_fag->next = iter->next;
  new_fag->relas_capcity = INIT_RELAS_CAP;
  new_fag->relas = (Elf_Internal_Rela **)
    bfd_malloc (new_fag->relas_capcity * sizeof (void *));
  new_fag->relas[0] = rel;
  iter->next = new_fag;
  nds32_fag_verify (head);
}
static void
nds32_fag_free_list (struct nds32_fag *head)
{
  struct nds32_fag *iter;
  iter = head->next;
  while (iter)
    {
      struct nds32_fag *tmp = iter;
      iter = iter->next;
      free (tmp->relas);
      tmp->relas = NULL;
      free (tmp);
    }
}
static int
nds32_fag_find_base (struct nds32_fag *head, struct nds32_fag **bestpp)
{
  struct nds32_fag *base;
  struct nds32_fag *last;
  int accu = 0;
  struct nds32_fag *best;
  int baccu = 0;
  if (head->next == NULL)
    {
      *bestpp = NULL;
      return 0;
    }
  base = head->next;
  best = base;
  for (last = base;
       last && last->addr < base->addr + FAG_WINDOW;
       last = last->next)
    accu += last->count;
  baccu = accu;
  while (base->next)
    {
      accu -= base->count;
      base = base->next;
      for ( ;
    last && last->addr < base->addr + FAG_WINDOW;
    last = last->next)
 accu += last->count;
      if (accu > baccu)
 {
   best = base;
   baccu = accu;
 }
    }
  if (bestpp)
    *bestpp = best;
  return baccu;
}
static bfd_boolean
nds32_fag_mark_relax (struct bfd_link_info *link_info,
        asection *sec, struct nds32_fag *best_fag,
        Elf_Internal_Rela *internal_relocs,
        Elf_Internal_Rela *irelend)
{
  struct nds32_fag *ifag;
  bfd_vma best_fpbase, gp;
  bfd *output_bfd;
  output_bfd = sec->output_section->owner;
  nds32_elf_final_sda_base (output_bfd, link_info, &gp, FALSE);
  best_fpbase = best_fag->addr;
  if (best_fpbase > gp + sdata_range[1][1]
      || best_fpbase < gp - sdata_range[1][0])
    return FALSE;
  for (ifag = best_fag;
       ifag && ifag->addr < best_fpbase + FAG_WINDOW; ifag = ifag->next)
    {
      int i;
      for (i = 0; i < ifag->count; i++)
 {
   Elf_Internal_Rela *insn16_rel;
   Elf_Internal_Rela *fag_rel;
   fag_rel = ifag->relas[i];
   insn16_rel = find_relocs_at_address
     (fag_rel, internal_relocs, irelend, R_NDS32_INSN16);
   if (insn16_rel != irelend)
     insn16_rel->r_addend = R_NDS32_INSN16_FP7U2_FLAG;
 }
    }
  return TRUE;
}
static void
nds32_fag_unmark_relax (struct nds32_fag *fag,
   Elf_Internal_Rela *internal_relocs,
   Elf_Internal_Rela *irelend)
{
  struct nds32_fag *ifag;
  int i;
  Elf_Internal_Rela *insn16_rel;
  Elf_Internal_Rela *fag_rel;
  for (ifag = fag; ifag; ifag = ifag->next)
    {
      for (i = 0; i < ifag->count; i++)
 {
   fag_rel = ifag->relas[i];
   insn16_rel = find_relocs_at_address
     (fag_rel, internal_relocs, irelend, R_NDS32_INSN16);
   if (insn16_rel != irelend)
     insn16_rel->r_addend &= ~R_NDS32_INSN16_FP7U2_FLAG;
 }
    }
}
static bfd_boolean
nds32_relax_fp_as_gp (struct bfd_link_info *link_info,
        bfd *abfd, asection *sec,
        Elf_Internal_Rela *internal_relocs,
        Elf_Internal_Rela *irelend,
        Elf_Internal_Sym *isymbuf)
{
  Elf_Internal_Rela *begin_rel = NULL;
  Elf_Internal_Rela *irel;
  struct nds32_fag fag_head;
  Elf_Internal_Shdr *symtab_hdr;
  bfd_byte *contents;
  bfd_boolean ifc_inside = FALSE;
  symtab_hdr = &elf_tdata (abfd)->symtab_hdr;
  if (!nds32_get_section_contents (abfd, sec, &contents, TRUE)
      || !nds32_get_local_syms (abfd, sec, &isymbuf))
    return FALSE;
  for (irel = internal_relocs; irel < irelend; irel++)
    {
      if (ELF32_R_TYPE (irel->r_info) == R_NDS32_RELAX_REGION_BEGIN
   && (irel->r_addend & R_NDS32_RELAX_REGION_OMIT_FP_FLAG))
 {
   if (begin_rel)
     (*_bfd_error_handler) (_("%B: Nested OMIT_FP in %A."), abfd, sec);
   begin_rel = irel;
   nds32_fag_init (&fag_head);
   ifc_inside = FALSE;
 }
      else if (ELF32_R_TYPE (irel->r_info) == R_NDS32_RELAX_REGION_END
        && (irel->r_addend & R_NDS32_RELAX_REGION_OMIT_FP_FLAG))
 {
   int accu;
   struct nds32_fag *best_fag, *tmp_fag;
   int dist;
   if (begin_rel == NULL)
     {
       (*_bfd_error_handler) (_("%B: Unmatched OMIT_FP in %A."), abfd, sec);
       continue;
     }
   accu = nds32_fag_find_base (&fag_head, &best_fag);
   tmp_fag = fag_head.next;
   nds32_fag_unmark_relax (tmp_fag, internal_relocs, irelend);
   if (accu < FAG_THRESHOLD
       || !nds32_fag_mark_relax (link_info, sec, best_fag,
     internal_relocs, irelend))
     {
       begin_rel->r_addend |= R_NDS32_RELAX_REGION_NOT_OMIT_FP_FLAG;
       begin_rel->r_addend &= ~R_NDS32_RELAX_REGION_OMIT_FP_FLAG;
       irel->r_addend |= R_NDS32_RELAX_REGION_NOT_OMIT_FP_FLAG;
       irel->r_addend &= ~R_NDS32_RELAX_REGION_OMIT_FP_FLAG;
       nds32_fag_free_list (&fag_head);
       begin_rel = NULL;
       continue;
     }
   dist = best_fag->relas[0] - begin_rel;
   BFD_ASSERT (dist > 0 && dist < 0xffffff);
   begin_rel->r_addend &= (0x1 << 16) - 1;
   begin_rel->r_addend |= dist << 16;
   nds32_fag_free_list (&fag_head);
   begin_rel = NULL;
 }
      if (begin_rel == NULL || ifc_inside)
 continue;
      if (ELF32_R_TYPE (irel->r_info) == R_NDS32_SDA15S2_RELA
   || ELF32_R_TYPE (irel->r_info) == R_NDS32_SDA17S2_RELA)
 {
   bfd_vma addr;
   uint32_t insn;
   insn = bfd_getb32 (contents + irel->r_offset);
   if (!N32_IS_RT3 (insn))
     continue;
   addr = calculate_memory_address (abfd, irel, isymbuf, symtab_hdr);
   nds32_fag_insert (&fag_head, addr, irel);
 }
      else if (ELF32_R_TYPE (irel->r_info) == R_NDS32_SDA_FP7U2_RELA)
 {
   begin_rel = NULL;
 }
      else if (ELF32_R_TYPE (irel->r_info) == R_NDS32_17IFC_PCREL_RELA
        || ELF32_R_TYPE (irel->r_info) == R_NDS32_10IFCU_PCREL_RELA)
 {
   ifc_inside = TRUE;
 }
    }
  return TRUE;
}
static bfd_boolean
nds32_fag_remove_unused_fpbase (bfd *abfd, asection *sec,
    Elf_Internal_Rela *internal_relocs,
    Elf_Internal_Rela *irelend)
{
  Elf_Internal_Rela *irel;
  Elf_Internal_Shdr *symtab_hdr;
  bfd_byte *contents = NULL;
  nds32_elf_blank_t *relax_blank_list = NULL;
  bfd_boolean result = TRUE;
  bfd_boolean unused_region = FALSE;
  symtab_hdr = &elf_tdata (abfd)->symtab_hdr;
  nds32_get_section_contents (abfd, sec, &contents, TRUE);
  for (irel = internal_relocs; irel < irelend; irel++)
    {
      const char *syname;
      int syndx;
      uint32_t insn;
      if (ELF32_R_TYPE (irel->r_info) == R_NDS32_RELAX_REGION_BEGIN
   && (irel->r_addend & R_NDS32_RELAX_REGION_NOT_OMIT_FP_FLAG))
 unused_region = TRUE;
      else if (ELF32_R_TYPE (irel->r_info) == R_NDS32_RELAX_REGION_END
        && (irel->r_addend & R_NDS32_RELAX_REGION_NOT_OMIT_FP_FLAG))
 unused_region = FALSE;
      if (!unused_region)
 continue;
      syndx = ELF32_R_SYM (irel->r_info) - symtab_hdr->sh_info;
      if (ELF32_R_SYM (irel->r_info) < symtab_hdr->sh_info)
 continue;
      syname = elf_sym_hashes (abfd)[syndx]->root.root.string;
      if (strcmp (syname, FP_BASE_NAME) != 0)
 continue;
      if (ELF32_R_TYPE (irel->r_info) == R_NDS32_SDA19S0_RELA)
 {
   insn = bfd_getb32 (contents + irel->r_offset);
   if (insn != INSN_ADDIGP_TO_FP)
     continue;
 }
      else if (ELF32_R_TYPE (irel->r_info) == R_NDS32_SDA15S0_RELA)
 {
   insn = bfd_getb32 (contents + irel->r_offset);
   if (insn != INSN_ADDI_GP_TO_FP)
     continue;
 }
      else if (ELF32_R_TYPE (irel->r_info) == R_NDS32_20_RELA)
 {
   insn = bfd_getb32 (contents + irel->r_offset);
   if (insn != INSN_MOVI_TO_FP)
     continue;
 }
      else
 continue;
      if (!insert_nds32_elf_blank_recalc_total
   (&relax_blank_list, irel->r_offset, 4))
 goto error_return;
    }
finish:
  if (relax_blank_list)
    {
      nds32_elf_relax_delete_blanks (abfd, sec, relax_blank_list);
      relax_blank_list = NULL;
    }
  return result;
error_return:
  result = FALSE;
  goto finish;
}
static bfd_byte *
nds32_elf_get_relocated_section_contents (bfd *abfd,
       struct bfd_link_info *link_info,
       struct bfd_link_order *link_order,
       bfd_byte *data,
       bfd_boolean relocatable,
       asymbol **symbols)
{
  bfd *input_bfd = link_order->u.indirect.section->owner;
  asection *input_section = link_order->u.indirect.section;
  long reloc_size;
  arelent **reloc_vector;
  long reloc_count;
  reloc_size = bfd_get_reloc_upper_bound (input_bfd, input_section);
  if (reloc_size < 0)
    return NULL;
  if (!nds32_get_section_contents (input_bfd, input_section, &data, FALSE))
    return NULL;
  if (reloc_size == 0)
    return data;
  reloc_vector = (arelent **) bfd_malloc (reloc_size);
  if (reloc_vector == NULL)
    return NULL;
  reloc_count = bfd_canonicalize_reloc (input_bfd, input_section,
     reloc_vector, symbols);
  if (reloc_count < 0)
    goto error_return;
  if (reloc_count > 0)
    {
      arelent **parent;
      for (parent = reloc_vector; *parent != NULL; parent++)
 {
   char *error_message = NULL;
   asymbol *symbol;
   bfd_reloc_status_type r;
   symbol = *(*parent)->sym_ptr_ptr;
   if (symbol->section && discarded_section (symbol->section))
     {
       bfd_byte *p;
       static reloc_howto_type none_howto
  = HOWTO (0, 0, 0, 0, FALSE, 0, complain_overflow_dont, NULL,
    "unused", FALSE, 0, 0, FALSE);
       p = data + (*parent)->address * bfd_octets_per_byte (input_bfd);
       _bfd_clear_contents ((*parent)->howto, input_bfd, input_section,
       p);
       (*parent)->sym_ptr_ptr = bfd_abs_section_ptr->symbol_ptr_ptr;
       (*parent)->addend = 0;
       (*parent)->howto = &none_howto;
       r = bfd_reloc_ok;
     }
   else
     r = bfd_perform_relocation (input_bfd, *parent, data,
     input_section,
     relocatable ? abfd : NULL,
     &error_message);
   if (relocatable)
     {
       asection *os = input_section->output_section;
       os->orelocation[os->reloc_count] = *parent;
       os->reloc_count++;
     }
   if (r != bfd_reloc_ok)
     {
       switch (r)
  {
  case bfd_reloc_undefined:
    if (!((*link_info->callbacks->undefined_symbol)
   (link_info, bfd_asymbol_name (*(*parent)->sym_ptr_ptr),
    input_bfd, input_section, (*parent)->address, TRUE)))
      goto error_return;
    break;
  case bfd_reloc_dangerous:
    BFD_ASSERT (error_message != NULL);
    if (!((*link_info->callbacks->reloc_dangerous)
   (link_info, error_message, input_bfd, input_section,
    (*parent)->address)))
      goto error_return;
    break;
  case bfd_reloc_overflow:
    if (!((*link_info->callbacks->reloc_overflow)
   (link_info, NULL,
    bfd_asymbol_name (*(*parent)->sym_ptr_ptr),
    (*parent)->howto->name, (*parent)->addend,
    input_bfd, input_section, (*parent)->address)))
      goto error_return;
    break;
  case bfd_reloc_outofrange:
    link_info->callbacks->einfo
      (_("%X%P: %B(%A): relocation \"%R\" goes out of range\n"),
       abfd, input_section, * parent);
    goto error_return;
  default:
    abort ();
    break;
  }
     }
 }
    }
  free (reloc_vector);
  return data;
error_return:
  free (reloc_vector);
  return NULL;
}
static bfd_boolean
nds32_elf_is_target_special_symbol (bfd *abfd ATTRIBUTE_UNUSED, asymbol *sym)
{
  if (!sym || !sym->name || sym->name[0] != '$')
    return FALSE;
  return TRUE;
}
static bfd_size_type
nds32_elf_maybe_function_sym (const asymbol *sym, asection *sec,
         bfd_vma *code_off)
{
  if (nds32_elf_is_target_special_symbol (NULL, (asymbol *) sym))
    return 0;
  return _bfd_elf_maybe_function_sym (sym, sec, code_off);
}
typedef struct relax_group_list_t
{
  Elf_Internal_Rela *relo;
  struct relax_group_list_t *next;
  struct relax_group_list_t *next_sibling;
  int id;
} relax_group_list_t;
int
list_insert (relax_group_list_t *pHead, Elf_Internal_Rela *pElem);
int
list_insert_sibling (relax_group_list_t *pNode, Elf_Internal_Rela *pElem);
void
dump_chain (relax_group_list_t *pHead);
int
list_insert (relax_group_list_t *pHead, Elf_Internal_Rela *pElem)
{
  relax_group_list_t *pNext = pHead;
  while (pNext->next)
    {
      if (pNext->next->id > (int) pElem->r_addend)
 break;
      pNext = pNext->next;
    }
  relax_group_list_t *pNew = bfd_malloc (sizeof (relax_group_list_t));
  if (!pNew)
    return FALSE;
  relax_group_list_t *tmp = pNext->next;
  pNext->next = pNew;
  pNew->id = pElem->r_addend;
  pNew->relo = pElem;
  pNew->next = tmp;
  pNew->next_sibling = NULL;
  return TRUE;
}
int
list_insert_sibling (relax_group_list_t *pNode, Elf_Internal_Rela *pElem)
{
  relax_group_list_t *pNext = pNode;
  while (pNext->next_sibling)
    {
      pNext = pNext->next_sibling;
    }
  relax_group_list_t *pNew = bfd_malloc (sizeof (relax_group_list_t));
  if (!pNew)
    return FALSE;
  relax_group_list_t *tmp = pNext->next_sibling;
  pNext->next_sibling = pNew;
  pNew->id = -1;
  pNew->relo = pElem;
  pNew->next = NULL;
  pNew->next_sibling = tmp;
  return TRUE;
}
void
dump_chain (relax_group_list_t *pHead)
{
  relax_group_list_t *pNext = pHead->next;
  while (pNext)
    {
      printf("group %d @ 0x%08x", pNext->id, (unsigned)pNext->relo->r_offset);
      relax_group_list_t *pNextSib = pNext->next_sibling;
      while (pNextSib)
 {
   printf(", %d", (unsigned) ELF32_R_TYPE (pNextSib->relo->r_info));
   pNextSib = pNextSib->next_sibling;
 }
      pNext = pNext->next;
      printf("\n");
    }
}
int
elf32_nds32_check_relax_group (bfd *abfd, asection *asec)
{
  elf32_nds32_relax_group_t *relax_group_ptr =
      elf32_nds32_relax_group_ptr (abfd);
  int min_id = relax_group_ptr->min_id;
  int max_id = relax_group_ptr->max_id;
  Elf_Internal_Rela *rel;
  Elf_Internal_Rela *relend;
  Elf_Internal_Rela *relocs;
  enum elf_nds32_reloc_type rtype;
  do
    {
      relocs = _bfd_elf_link_read_relocs (abfd, asec, NULL, NULL,
       TRUE );
      if (relocs == NULL)
 break;
      relend = relocs + asec->reloc_count;
      for (rel = relocs; rel < relend; rel++)
 {
   int id;
   rtype = ELF32_R_TYPE (rel->r_info);
   if (rtype != R_NDS32_RELAX_GROUP)
     continue;
   id = rel->r_addend;
   if (id < min_id)
     min_id = id;
   else if (id > max_id)
     max_id = id;
 }
    }
  while (FALSE);
  if ((relocs != NULL) && (elf_section_data (asec)->relocs != relocs))
    free (relocs);
  if ((min_id != relax_group_ptr->min_id)
      || (max_id != relax_group_ptr->max_id))
    {
      relax_group_ptr->count = max_id - min_id + 1;
      BFD_ASSERT(min_id <= relax_group_ptr->min_id);
      relax_group_ptr->min_id = min_id;
      BFD_ASSERT(max_id >= relax_group_ptr->max_id);
      relax_group_ptr->max_id = max_id;
    }
  return relax_group_ptr->count;
}
struct section_id_list_t *relax_group_section_id_list = NULL;
struct section_id_list_t *
elf32_nds32_lookup_section_id (int id, struct section_id_list_t **lst_ptr)
{
  struct section_id_list_t *result = NULL;
  struct section_id_list_t *lst = *lst_ptr;
  if (NULL == lst)
    {
      result = (struct section_id_list_t *) calloc (
   1, sizeof (struct section_id_list_t));
      BFD_ASSERT (result);
      result->id = id;
      *lst_ptr = result;
    }
  else
    {
      struct section_id_list_t *cur = lst;
      struct section_id_list_t *prv = NULL;
      struct section_id_list_t *sec = NULL;
      while (cur)
 {
   if (cur->id < id)
     {
       prv = cur;
       cur = cur->next;
       continue;
     }
   if (cur->id > id)
     {
       cur = NULL;
       sec = cur;
     }
   break;
 }
      if (NULL == cur)
 {
   result = (struct section_id_list_t *) calloc (
       1, sizeof (struct section_id_list_t));
   BFD_ASSERT (result);
   result->id = id;
   if (NULL != prv)
     {
       result->next = prv->next;
       prv->next = result;
     }
   else
     {
       *lst_ptr = result;
       result->next = sec;
     }
 }
    }
  return result;
}
int
elf32_nds32_unify_relax_group (bfd *abfd, asection *asec)
{
  static int next_relax_group_bias = 0;
  elf32_nds32_relax_group_t *relax_group_ptr =
      elf32_nds32_relax_group_ptr (abfd);
  bfd_boolean result = TRUE;
  Elf_Internal_Rela *rel;
  Elf_Internal_Rela *relend;
  Elf_Internal_Rela *relocs = NULL;
  enum elf_nds32_reloc_type rtype;
  struct section_id_list_t *node = NULL;
  int count = 0;
  do
    {
      if (0 == relax_group_ptr->count)
        break;
      node = elf32_nds32_lookup_section_id (asec->id, &relax_group_section_id_list);
      if (NULL == node)
 break;
      relocs = _bfd_elf_link_read_relocs (abfd, asec, NULL, NULL,
       TRUE );
      if (relocs == NULL)
 {
   BFD_ASSERT (0);
   break;
 }
      if (0 == relax_group_ptr->init)
 {
   relax_group_ptr->bias = next_relax_group_bias;
   next_relax_group_bias += relax_group_ptr->count;
   relax_group_ptr->init = 1;
 }
      relend = relocs + asec->reloc_count;
      for (rel = relocs; rel < relend; rel++)
 {
   rtype = ELF32_R_TYPE(rel->r_info);
   if (rtype != R_NDS32_RELAX_GROUP)
     continue;
   rel->r_addend += relax_group_ptr->bias;
   count++;
 }
    }
  while (FALSE);
  if (relocs != NULL && elf_section_data (asec)->relocs != relocs)
    free (relocs);
  return result;
}
int
nds32_elf_unify_tls_model (bfd *inbfd, asection *insec, bfd_byte *incontents,
      struct bfd_link_info *lnkinfo)
{
  bfd_boolean result = TRUE;
  Elf_Internal_Rela *irel;
  Elf_Internal_Rela *irelend;
  Elf_Internal_Rela *internal_relocs;
  unsigned long r_symndx;
  enum elf_nds32_reloc_type r_type;
  Elf_Internal_Sym *local_syms = NULL;
  bfd_byte *contents = NULL;
  relax_group_list_t chain = { .id = -1, .next = NULL, .next_sibling = NULL };
  Elf_Internal_Shdr *symtab_hdr = &elf_tdata (inbfd)->symtab_hdr;
  struct elf_link_hash_entry **sym_hashes, **sym_hashes_end;
  sym_hashes = elf_sym_hashes (inbfd);
  sym_hashes_end =
    sym_hashes + symtab_hdr->sh_size / sizeof (Elf32_External_Sym);
  if (!elf_bad_symtab (inbfd))
    sym_hashes_end -= symtab_hdr->sh_info;
  if (lnkinfo->relocatable)
    {
      elf32_nds32_unify_relax_group (inbfd, insec);
      return result;
    }
  internal_relocs = _bfd_elf_link_read_relocs (inbfd, insec, NULL, NULL,
            TRUE );
  if (internal_relocs == NULL)
    goto error_return;
  irelend = internal_relocs + insec->reloc_count;
  irel = find_relocs_at_address (internal_relocs, internal_relocs,
     irelend, R_NDS32_RELAX_ENTRY);
  if (irel == irelend)
    goto finish;
  for (irel = internal_relocs; irel < irelend; irel++)
    {
      r_symndx = ELF32_R_SYM (irel->r_info);
      r_type = ELF32_R_TYPE (irel->r_info);
      if (r_type != R_NDS32_RELAX_GROUP)
 continue;
      irel->r_info = ELF32_R_INFO (r_symndx, R_NDS32_NONE);
      if (!list_insert (&chain, irel))
 goto error_return;
    }
  relax_group_list_t *pNext = chain.next;
  while (pNext)
    {
      for (irel = internal_relocs; irel < irelend; irel++)
 {
   if (irel->r_offset == pNext->relo->r_offset)
     {
       r_type = ELF32_R_TYPE (irel->r_info);
       if ((R_NDS32_TLS_LE_HI20 > r_type)
    || (R_NDS32_RELAX_ENTRY == r_type))
  continue;
       if (!list_insert_sibling (pNext, irel))
  goto error_return;
     }
   else if (irel->r_offset > pNext->relo->r_offset)
     {
       pNext = pNext->next;
       if (!pNext)
  break;
       bfd_vma current_offset = pNext->relo->r_offset;
       if (irel->r_offset > current_offset)
  irel = internal_relocs;
       else
  --irel;
       continue;
     }
   else
     {
     }
 }
      if (pNext)
 pNext = pNext->next;
    }
#ifdef DUBUG_VERBOSE
  dump_chain(&chain);
#endif
  if (incontents)
      contents = incontents;
  else if (!nds32_get_section_contents (inbfd, insec, &contents, TRUE)
      || !nds32_get_local_syms (inbfd, insec, &local_syms))
    goto error_return;
  char *local_got_tls_type = elf32_nds32_local_got_tls_type (inbfd);
  pNext = chain.next;
  int cur_grp_id = -1;
  int sethi_rt = -1;
  int add_rt = -1;
  enum elf_nds32_tls_type tls_type, org_tls_type, eff_tls_type;
  tls_type = org_tls_type = eff_tls_type = 0;
  while (pNext)
    {
      relax_group_list_t *pNextSig = pNext->next_sibling;
      while (pNextSig)
 {
   struct elf_link_hash_entry *h = NULL;
   irel = pNextSig->relo;
   r_symndx = ELF32_R_SYM(irel->r_info);
   r_type = ELF32_R_TYPE(irel->r_info);
   if (pNext->id != cur_grp_id)
     {
       cur_grp_id = pNext->id;
       org_tls_type = get_tls_type (r_type, NULL);
       if (r_symndx >= symtab_hdr->sh_info)
  {
    h = sym_hashes[r_symndx - symtab_hdr->sh_info];
    while (h->root.type == bfd_link_hash_indirect
        || h->root.type == bfd_link_hash_warning)
      h = (struct elf_link_hash_entry *) h->root.u.i.link;
    tls_type = ((struct elf_nds32_link_hash_entry *) h)->tls_type;
  }
       else
  {
    tls_type = local_got_tls_type ? local_got_tls_type[r_symndx] : GOT_NORMAL;
  }
       eff_tls_type = 1 << (fls (tls_type) - 1);
       sethi_rt = N32_RT5(bfd_getb32 (contents + irel->r_offset));
     }
   if (eff_tls_type != org_tls_type)
     {
       switch (org_tls_type)
  {
  case GOT_TLS_DESC:
    switch (eff_tls_type)
      {
      case GOT_TLS_IE:
        switch (r_type)
   {
   case R_NDS32_TLS_DESC_HI20:
     irel->r_info = ELF32_R_INFO(r_symndx,
            R_NDS32_TLS_IE_HI20);
     break;
   case R_NDS32_TLS_DESC_LO12:
     irel->r_info = ELF32_R_INFO(r_symndx,
            R_NDS32_TLS_IE_LO12);
     break;
   case R_NDS32_TLS_DESC_ADD:
     {
       uint32_t insn = bfd_getb32 (
    contents + irel->r_offset);
       add_rt = N32_RT5 (insn);
       insn = N32_TYPE2 (LWI, add_rt, sethi_rt, 0);
       bfd_putb32 (insn, contents + irel->r_offset);
       irel->r_info = ELF32_R_INFO(r_symndx, R_NDS32_NONE);
     }
     break;
   case R_NDS32_TLS_DESC_FUNC:
     bfd_putb32 (INSN_NOP, contents + irel->r_offset);
     irel->r_info = ELF32_R_INFO(r_symndx,
            R_NDS32_RELAX_REMOVE);
     break;
   case R_NDS32_TLS_DESC_CALL:
     {
       uint32_t insn = N32_ALU1(ADD, REG_R0, add_rt,
           REG_TP);
       bfd_putb32 (insn, contents + irel->r_offset);
       irel->r_info = ELF32_R_INFO(r_symndx, R_NDS32_NONE);
     }
     break;
   case R_NDS32_LOADSTORE:
   case R_NDS32_PTR:
   case R_NDS32_PTR_RESOLVED:
   case R_NDS32_NONE:
   case R_NDS32_LABEL:
     break;
   default:
     BFD_ASSERT(0);
     break;
   }
        break;
      case GOT_TLS_IEGP:
        switch (r_type)
   {
   case R_NDS32_TLS_DESC_HI20:
     irel->r_info = ELF32_R_INFO(r_symndx,
            R_NDS32_TLS_IEGP_HI20);
     break;
   case R_NDS32_TLS_DESC_LO12:
     irel->r_info = ELF32_R_INFO(r_symndx,
            R_NDS32_TLS_IEGP_LO12);
     break;
   case R_NDS32_TLS_DESC_ADD:
     {
       uint32_t insn = bfd_getb32 (
    contents + irel->r_offset);
       add_rt = N32_RT5 (insn);
       insn = N32_MEM(LW, add_rt, sethi_rt, REG_GP, 0);
       bfd_putb32 (insn, contents + irel->r_offset);
       irel->r_info = ELF32_R_INFO(r_symndx, R_NDS32_NONE);
     }
     break;
   case R_NDS32_TLS_DESC_FUNC:
     bfd_putb32 (INSN_NOP, contents + irel->r_offset);
     irel->r_info = ELF32_R_INFO(r_symndx,
            R_NDS32_RELAX_REMOVE);
     break;
   case R_NDS32_TLS_DESC_CALL:
     {
       uint32_t insn = N32_ALU1(ADD, REG_R0, add_rt,
           REG_TP);
       bfd_putb32 (insn, contents + irel->r_offset);
       irel->r_info = ELF32_R_INFO(r_symndx, R_NDS32_NONE);
     }
     break;
   case R_NDS32_LOADSTORE:
   case R_NDS32_PTR:
   case R_NDS32_PTR_RESOLVED:
   case R_NDS32_NONE:
   case R_NDS32_LABEL:
     break;
   default:
     BFD_ASSERT(0);
     break;
   }
        break;
      case GOT_TLS_LE:
        switch (r_type)
   {
   case R_NDS32_TLS_DESC_HI20:
     irel->r_info = ELF32_R_INFO (r_symndx, R_NDS32_TLS_LE_HI20);
     break;
   case R_NDS32_TLS_DESC_LO12:
     irel->r_info = ELF32_R_INFO (r_symndx, R_NDS32_TLS_LE_LO12);
     break;
   case R_NDS32_TLS_DESC_ADD:
     {
       uint32_t insn = bfd_getb32 (contents + irel->r_offset);
       add_rt = N32_RT5 (insn);
       insn = N32_ALU1 (ADD, REG_R0, sethi_rt, REG_TP);
       bfd_putb32 (insn, contents + irel->r_offset);
       irel->r_info = ELF32_R_INFO (r_symndx, R_NDS32_TLS_LE_ADD);
     }
     break;
   case R_NDS32_TLS_DESC_FUNC:
     bfd_putb32 (INSN_NOP, contents + irel->r_offset);
     irel->r_info = ELF32_R_INFO (r_symndx, R_NDS32_RELAX_REMOVE);
     break;
   case R_NDS32_TLS_DESC_CALL:
     bfd_putb32 (INSN_NOP, contents + irel->r_offset);
     irel->r_info = ELF32_R_INFO (r_symndx, R_NDS32_RELAX_REMOVE);
     break;
   case R_NDS32_LOADSTORE:
   case R_NDS32_PTR:
   case R_NDS32_PTR_RESOLVED:
   case R_NDS32_NONE:
   case R_NDS32_LABEL:
     break;
   default:
     BFD_ASSERT(0);
     break;
   }
        break;
      default:
#ifdef DEBUG_VERBOSE
        printf (
     "SKIP: %s: %s @ 0x%08x tls_type = 0x%08x, eff_tls_type = 0x%08x, org_tls_type = 0x%08x\n",
     inbfd->filename, h ? h->root.root.string : "local",
     (unsigned) irel->r_offset, tls_type, eff_tls_type,
     org_tls_type);
#endif
        break;
      }
    break;
  case GOT_TLS_IEGP:
    switch (eff_tls_type)
      {
      case GOT_TLS_IE:
        switch (r_type)
   {
   case R_NDS32_TLS_IEGP_HI20:
     irel->r_info = ELF32_R_INFO(r_symndx,
            R_NDS32_TLS_IE_HI20);
     break;
   case R_NDS32_TLS_IEGP_LO12:
     irel->r_info = ELF32_R_INFO(r_symndx,
            R_NDS32_TLS_IE_LO12);
     break;
   case R_NDS32_PTR_RESOLVED:
     {
       uint32_t insn = bfd_getb32 (
    contents + irel->r_offset);
       add_rt = N32_RT5 (insn);
       insn = N32_TYPE2 (LWI, add_rt, sethi_rt, 0);
       bfd_putb32 (insn, contents + irel->r_offset);
     }
     break;
   case R_NDS32_TLS_IEGP_LW:
     break;
   case R_NDS32_LOADSTORE:
   case R_NDS32_PTR:
   case R_NDS32_NONE:
   case R_NDS32_LABEL:
     break;
   default:
     BFD_ASSERT(0);
     break;
   }
        break;
      case GOT_TLS_LE:
        switch (r_type)
   {
   case R_NDS32_TLS_IEGP_HI20:
     irel->r_info = ELF32_R_INFO (r_symndx, R_NDS32_TLS_LE_HI20);
     break;
   case R_NDS32_TLS_IEGP_LO12:
     irel->r_info = ELF32_R_INFO (r_symndx, R_NDS32_TLS_LE_LO12);
     break;
   case R_NDS32_TLS_IEGP_LW:
     bfd_putb32 (INSN_NOP, contents + irel->r_offset);
                          irel->r_info = ELF32_R_INFO (r_symndx, R_NDS32_RELAX_REMOVE);
                          break;
   case R_NDS32_LOADSTORE:
   case R_NDS32_PTR:
   case R_NDS32_NONE:
   case R_NDS32_LABEL:
   case R_NDS32_PTR_RESOLVED:
     break;
   default:
     BFD_ASSERT(0);
     break;
   }
        break;
      default:
#ifdef DEBUG_VERBOSE
        printf (
     "SKIP: %s: %s @ 0x%08x tls_type = 0x%08x, eff_tls_type = 0x%08x, org_tls_type = 0x%08x\n",
     inbfd->filename, h ? h->root.root.string : "local",
     (unsigned) irel->r_offset, tls_type, eff_tls_type,
     org_tls_type);
#endif
        break;
      }
    break;
  case GOT_TLS_IE:
                  switch (eff_tls_type)
                    {
      case GOT_TLS_LE:
        switch (r_type)
   {
   case R_NDS32_TLS_IE_HI20:
     irel->r_info = ELF32_R_INFO (r_symndx, R_NDS32_TLS_LE_HI20);
     break;
   case R_NDS32_TLS_IE_LO12S2:
                          {
       uint32_t insn = bfd_getb32 (contents + irel->r_offset);
       add_rt = N32_RT5 (insn);
       insn = N32_TYPE2 (ORI, add_rt, sethi_rt, 0);
       bfd_putb32 (insn, contents + irel->r_offset);
       irel->r_info = ELF32_R_INFO (r_symndx, R_NDS32_TLS_LE_LO12);
     }
                          break;
   case R_NDS32_LOADSTORE:
   case R_NDS32_PTR:
   case R_NDS32_NONE:
   case R_NDS32_LABEL:
     break;
   default:
     BFD_ASSERT(0);
     break;
   }
      break;
      default:
#ifdef DEBUG_VERBOSE
        printf (
     "SKIP: %s: %s @ 0x%08x tls_type = 0x%08x, eff_tls_type = 0x%08x, org_tls_type = 0x%08x\n",
     inbfd->filename, h ? h->root.root.string : "local",
     (unsigned) irel->r_offset, tls_type, eff_tls_type,
     org_tls_type);
#endif
        break;
      }
    break;
  default:
#ifdef DEBUG_VERBOSE
    printf (
        "SKIP: %s: %s @ 0x%08x tls_type = 0x%08x, eff_tls_type = 0x%08x, org_tls_type = 0x%08x\n",
        inbfd->filename, h ? h->root.root.string : "local",
        (unsigned) irel->r_offset, tls_type, eff_tls_type,
        org_tls_type);
#endif
    break;
  }
     }
   pNextSig = pNextSig->next_sibling;
 }
#if 1
      pNext = pNext->next;
#else
      while (pNext)
 {
   if (pNext->id != cur_grp_id)
     break;
   pNext = pNext->next;
 }
#endif
    }
finish:
  if (incontents)
    contents = NULL;
  if (internal_relocs != NULL
      && elf_section_data (insec)->relocs != internal_relocs)
    free (internal_relocs);
  if (contents != NULL
      && elf_section_data (insec)->this_hdr.contents != contents)
    free (contents);
  if (local_syms != NULL && symtab_hdr->contents != (bfd_byte *) local_syms)
    free (local_syms);
  if (chain.next)
    {
      pNext = chain.next;
      relax_group_list_t *pDel;
      while (pNext)
 {
   pDel = pNext;
   pNext = pNext->next;
   free (pDel);
 }
    }
  return result;
error_return:
  result = FALSE;
  goto finish;
}
static struct bfd_hash_entry *
nds32_elf_ict_hash_newfunc (struct bfd_hash_entry *entry,
       struct bfd_hash_table *table,
       const char *string)
{
  struct elf_nds32_ict_hash_entry *ret;
  if (entry == NULL)
    {
      entry = (struct bfd_hash_entry *)
 bfd_hash_allocate (table, sizeof (*ret));
      if (entry == NULL)
 return entry;
    }
  entry = bfd_hash_newfunc (entry, table, string);
  if (entry == NULL)
    return entry;
  ret = (struct elf_nds32_ict_hash_entry*) entry;
  ret->order = 0;
  return &ret->root;
}
static void
nds32_elf_ict_hash_init (void)
{
  if (!bfd_hash_table_init_n (&indirect_call_table, nds32_elf_ict_hash_newfunc,
         sizeof (struct elf_nds32_ict_hash_entry),
         1023))
    (*_bfd_error_handler) (_("ld error: cannot init rom patch hash table\n"));
  return;
}
static void
nds32_elf_ict_relocate (bfd *output_bfd, struct bfd_link_info *info)
{
  static bfd_boolean done = FALSE;
  asection *sec;
  bfd_byte *contents = NULL;
  uint32_t insn;
  unsigned int i;
  struct elf_link_hash_entry *h;
  struct bfd_link_hash_entry *h2;
  bfd_vma relocation, base;
  if (done)
    return;
  done = TRUE;
  sec = nds32_elf_get_target_section (info, NDS32_ICT_SECTION);
  h2 = bfd_link_hash_lookup (info->hash, "_INDIRECT_CALL_TABLE_BASE_",
        FALSE, FALSE, FALSE);
  base = ((h2->u.def.value
    + h2->u.def.section->output_section->vma
    + h2->u.def.section->output_offset));
  if (!nds32_get_section_contents (sec->owner, sec, &contents, TRUE))
    return;
  indirect_call_table.frozen = 1;
  for (i = 0; i < indirect_call_table.size; i++)
    {
      struct bfd_hash_entry *p;
      struct elf_nds32_ict_hash_entry *entry;
      for (p = indirect_call_table.table[i]; p != NULL; p = p->next)
 {
   entry = (struct elf_nds32_ict_hash_entry *) p;
   insn = INSN_J;
   h = entry->h;
   if ((h->root.type == bfd_link_hash_defined
        || h->root.type == bfd_link_hash_defweak)
       && h->root.u.def.section != NULL
       && h->root.u.def.section->output_section != NULL)
     {
       if (ict_model == R_NDS32_RELAX_ENTRY_ICT_LARGE)
  {
    insn = h->root.u.def.value +
      h->root.u.def.section->output_section->vma +
      h->root.u.def.section->output_offset;
    bfd_put_32 (output_bfd, insn, contents + (entry->order) * 4);
  }
       else
  {
    relocation = h->root.u.def.value +
      h->root.u.def.section->output_section->vma +
      h->root.u.def.section->output_offset;
    insn |= ((relocation - base - entry->order * 4) >> 1)
     & 0xffffff;
    bfd_putb32 (insn, contents + (entry->order) * 4);
  }
     }
   else
     {
       if (ict_model == R_NDS32_RELAX_ENTRY_ICT_LARGE)
  {
    insn = 0;
    bfd_put_32 (output_bfd, insn, contents + (entry->order) * 4);
  }
       else
  bfd_putb32 (insn, contents + (entry->order) * 4);
     }
 }
    }
  indirect_call_table.frozen = 0;
}
static asection*
nds32_elf_get_target_section (struct bfd_link_info *info, char *name)
{
  asection *sec = NULL;
  bfd *abfd;
  for (abfd = info->input_bfds; abfd != NULL; abfd = abfd->link_next)
    {
      sec = bfd_get_section_by_name (abfd, name);
      if (sec != NULL)
 break;
    }
  return sec;
}
#define ELF_ARCH bfd_arch_nds32
#define ELF_MACHINE_CODE EM_NDS32
#define ELF_MAXPAGESIZE 0x1000
#define ELF_TARGET_ID NDS32_ELF_DATA
#define TARGET_BIG_SYM bfd_elf32_nds32be_vec
#define TARGET_BIG_NAME "elf32-nds32be"
#define TARGET_LITTLE_SYM bfd_elf32_nds32le_vec
#define TARGET_LITTLE_NAME "elf32-nds32le"
#define elf_info_to_howto nds32_info_to_howto
#define elf_info_to_howto_rel nds32_info_to_howto_rel
#define bfd_elf32_bfd_link_hash_table_create nds32_elf_link_hash_table_create
#define bfd_elf32_bfd_merge_private_bfd_data nds32_elf_merge_private_bfd_data
#define bfd_elf32_bfd_print_private_bfd_data nds32_elf_print_private_bfd_data
#define bfd_elf32_bfd_relax_section nds32_elf_relax_section
#define bfd_elf32_bfd_set_private_flags nds32_elf_set_private_flags
#define bfd_elf32_mkobject nds32_elf_mkobject
#define elf_backend_action_discarded nds32_elf_action_discarded
#define elf_backend_add_symbol_hook nds32_elf_add_symbol_hook
#define elf_backend_check_relocs nds32_elf_check_relocs
#define elf_backend_adjust_dynamic_symbol nds32_elf_adjust_dynamic_symbol
#define elf_backend_create_dynamic_sections nds32_elf_create_dynamic_sections
#define elf_backend_finish_dynamic_sections nds32_elf_finish_dynamic_sections
#define elf_backend_finish_dynamic_symbol nds32_elf_finish_dynamic_symbol
#define elf_backend_size_dynamic_sections nds32_elf_size_dynamic_sections
#define elf_backend_relocate_section nds32_elf_relocate_section
#define elf_backend_gc_mark_hook nds32_elf_gc_mark_hook
#define elf_backend_gc_sweep_hook nds32_elf_gc_sweep_hook
#define elf_backend_grok_prstatus nds32_elf_grok_prstatus
#define elf_backend_grok_psinfo nds32_elf_grok_psinfo
#define elf_backend_reloc_type_class nds32_elf_reloc_type_class
#define elf_backend_copy_indirect_symbol nds32_elf_copy_indirect_symbol
#define elf_backend_link_output_symbol_hook nds32_elf_output_symbol_hook
#define elf_backend_output_arch_syms nds32_elf_output_arch_syms
#define elf_backend_object_p nds32_elf_object_p
#define elf_backend_final_write_processing nds32_elf_final_write_processing
#define elf_backend_special_sections nds32_elf_special_sections
#define bfd_elf32_bfd_get_relocated_section_contents \
                                nds32_elf_get_relocated_section_contents
#define bfd_elf32_bfd_is_target_special_symbol nds32_elf_is_target_special_symbol
#define elf_backend_maybe_function_sym nds32_elf_maybe_function_sym
#define elf_backend_can_gc_sections 1
#define elf_backend_can_refcount 1
#define elf_backend_want_got_plt 1
#define elf_backend_plt_readonly 1
#define elf_backend_want_plt_sym 0
#define elf_backend_got_header_size 12
#define elf_backend_may_use_rel_p 1
#define elf_backend_default_use_rela_p 1
#define elf_backend_may_use_rela_p 1
#include "elf32-target.h"
#undef ELF_MAXPAGESIZE
#define ELF_MAXPAGESIZE 0x2000
#undef TARGET_BIG_SYM
#define TARGET_BIG_SYM bfd_elf32_nds32belin_vec
#undef TARGET_BIG_NAME
#define TARGET_BIG_NAME "elf32-nds32be-linux"
#undef TARGET_LITTLE_SYM
#define TARGET_LITTLE_SYM bfd_elf32_nds32lelin_vec
#undef TARGET_LITTLE_NAME
#define TARGET_LITTLE_NAME "elf32-nds32le-linux"
#undef elf32_bed
#define elf32_bed elf32_nds32_lin_bed
#include "elf32-target.h"
