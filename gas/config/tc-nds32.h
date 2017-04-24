#ifndef TC_NDS32
#define TC_NDS32 
#include "bfd_stdint.h"
enum mstate
{
  MAP_UNDEFINED = 0,
  MAP_DATA,
  MAP_CODE,
};
#define TC_SEGMENT_INFO_TYPE struct nds32_segment_info_type
struct nds32_segment_info_type
{
  enum mstate mapstate;
};
#define LISTING_HEADER \
  (target_big_endian ? "NDS32 GAS" : "NDS32 GAS Little Endian")
#define TARGET_ARCH bfd_arch_nds32
#define ISA_V1 bfd_mach_n1h
#define ISA_V2 bfd_mach_n1h_v2
#define ISA_V3 bfd_mach_n1h_v3
#define ISA_V3M bfd_mach_n1h_v3m
#ifndef TARGET_BYTES_BIG_ENDIAN
#define TARGET_BYTES_BIG_ENDIAN 1
#endif
extern int nds32_parse_option (int, char *);
extern void nds32_after_parse_args (void);
extern const char *nds32_target_format (void);
#define md_parse_option(optc,optarg) nds32_parse_option (optc, optarg)
#define md_after_parse_args() nds32_after_parse_args ()
#define TARGET_FORMAT nds32_target_format()
extern int nds32_parse_name (char const *, expressionS *, enum expr_mode, char *);
extern bfd_boolean nds32_allow_local_subtract (expressionS *, expressionS *, segT);
#define md_parse_name(name,exprP,mode,nextcharP) \
 nds32_parse_name (name, exprP, mode, nextcharP)
#define md_allow_local_subtract(lhs,rhs,sect) nds32_allow_local_subtract (lhs, rhs, sect)
#define DWARF2_USE_FIXED_ADVANCE_PC 1
extern long nds32_pcrel_from_section (struct fix *, segT);
extern bfd_boolean nds32_fix_adjustable (struct fix *);
extern void nds32_frob_file (void);
extern void nds32_post_relax_hook (void);
extern void nds32_frob_file_before_fix (void);
extern void elf_nds32_final_processing (void);
extern int nds32_validate_fix_sub (struct fix *, segT);
extern int nds32_force_relocation (struct fix *);
extern void nds32_set_section_relocs (asection *, arelent ** , unsigned int );
extern void nds32_handle_align (fragS *);
extern int nds32_relax_frag (segT, fragS *, long);
extern int tc_nds32_regname_to_dw2regnum (char *regname);
extern void tc_nds32_frame_initial_instructions (void);
#define MD_PCREL_FROM_SECTION(fix,sect) nds32_pcrel_from_section (fix, sect)
#define TC_FINALIZE_SYMS_BEFORE_SIZE_SEG 0
#define tc_fix_adjustable(FIX) nds32_fix_adjustable (FIX)
#define md_apply_fix(fixP,addn,seg) nds32_apply_fix (fixP, addn, seg)
#define md_post_relax_hook nds32_post_relax_hook ()
#define tc_frob_file_before_fix() nds32_frob_file_before_fix ()
#define elf_tc_final_processing() elf_nds32_final_processing ()
#define TC_FORCE_RELOCATION_SUB_SAME(FIX,SEC) \
  (! SEG_NORMAL (SEC) || TC_FORCE_RELOCATION (FIX))
#define TC_FORCE_RELOCATION(fix) nds32_force_relocation (fix)
#define TC_VALIDATE_FIX_SUB(FIX,SEG) nds32_validate_fix_sub (FIX,SEG)
#define SET_SECTION_RELOCS(sec,relocs,n) nds32_set_section_relocs (sec, relocs, n)
#define MD_APPLY_SYM_VALUE(FIX) 0
#define HANDLE_ALIGN(f) nds32_handle_align (f)
#undef DIFF_EXPR_OK
#define md_relax_frag(segment,fragP,stretch) nds32_relax_frag (segment, fragP, stretch)
#define WORKING_DOT_WORD 
#define TC_FIX_TYPE struct fix*
#define TC_INIT_FIX_DATA(fixP) do \
{ \
  fixP->tc_fix_data=NULL; \
} while (0)
extern void nds32_macro_start (void);
extern void nds32_macro_end (void);
extern void nds32_macro_info (void *macro);
extern void nds32_start_line_hook (void);
extern void nds32_elf_section_change_hook (void);
extern void md_begin (void);
extern void md_end (void);
extern int nds32_start_label (int, int);
extern void nds32_cleanup (void);
extern void nds32_flush_pending_output (void);
extern void nds32_cons_align (int n);
extern void nds32_check_label (symbolS *);
extern void nds32_frob_label (symbolS *);
void nds32_pre_do_align (int, char*, int, int);
void nds32_do_align (int);
#define md_macro_start() nds32_macro_start ()
#define md_macro_end() nds32_macro_end ()
#define md_macro_info(args) nds32_macro_info (args)
#define TC_START_LABEL(C,S,STR) (C == ':' && nds32_start_label (0, 0))
#define tc_check_label(label) nds32_check_label (label)
#define tc_frob_label(label) nds32_frob_label (label)
#define md_end md_end
#define md_start_line_hook() nds32_start_line_hook ()
#define md_cons_align(n) nds32_cons_align (n)
#define md_do_align(N,FILL,LEN,MAX,LABEL) \
  nds32_pre_do_align (N, FILL, LEN, MAX); \
  if ((N) > 1 && (subseg_text_p (now_seg) \
      || strncmp (now_seg->name, ".gcc_except_table", sizeof (".gcc_except_table") - 1) == 0)) \
    nds32_do_align (N); \
  goto LABEL;
#define md_elf_section_change_hook() nds32_elf_section_change_hook ()
#define md_flush_pending_output() nds32_flush_pending_output ()
#define md_cleanup() nds32_cleanup ()
#define LOCAL_LABELS_FB 1
enum FRAG_ATTR
{
  NDS32_FRAG_RELAXABLE = 0x1,
  NDS32_FRAG_RELAXED = 0x2,
  NDS32_FRAG_BRANCH = 0x4,
  NDS32_FRAG_LABEL = 0x8,
  NDS32_FRAG_FINAL = 0x10,
  NDS32_FRAG_RELAXABLE_BRANCH = 0x20,
  NDS32_FRAG_ALIGN = 0x40,
  NDS32_FRAG_ICT_BRANCH = 0x80
};
struct nds32_frag_type {
  relax_substateT flag;
  struct nds32_opcode *opcode;
  uint32_t insn;
  struct fix *fixup;
};
extern void nds32_frag_init (fragS*);
#define TC_FRAG_TYPE struct nds32_frag_type
#define TC_FRAG_INIT(fragP) nds32_frag_init (fragP)
extern void nds32_elf_frame_initial_instructions (void);
extern int tc_nds32_regname_to_dw2regnum (char *regname);
#define TARGET_USE_CFIPOP 1
#define DWARF2_DEFAULT_RETURN_COLUMN 30
#define DWARF2_CIE_DATA_ALIGNMENT -4
#define DWARF2_LINE_MIN_INSN_LENGTH 2
#define tc_regname_to_dw2regnum tc_nds32_regname_to_dw2regnum
#define tc_cfi_frame_initial_instructions tc_nds32_frame_initial_instructions
#if 1
#define TC_RELOC_RTSYM_LOC_FIXUP(FIX) \
   ((FIX)->fx_addsy == NULL \
    || (! S_IS_EXTERNAL ((FIX)->fx_addsy) \
 && ! S_IS_WEAK ((FIX)->fx_addsy) \
 && S_IS_DEFINED ((FIX)->fx_addsy) \
 && ! S_IS_COMMON ((FIX)->fx_addsy)))
#define TC_HANDLES_FX_DONE 
#define TC_FIX_ADJUSTABLE(fixP) obj_fix_adjustable (fixP)
#endif
#define md_allow_eh_opt 0
enum nds32_br_range
{
  BR_RANGE_S256 = 0,
  BR_RANGE_S16K,
  BR_RANGE_S64K,
  BR_RANGE_S16M,
  BR_RANGE_U4G,
  BR_RANGE_NUM,
};
enum nds32_ramp
{
  NDS32_CREATE_LABEL = 1,
  NDS32_RELAX = (1 << 1),
  NDS32_ORIGIN = (1 << 2),
  NDS32_INSN16 = (1 << 3),
  NDS32_PTR = (1 << 4),
  NDS32_ABS = (1 << 5),
  NDS32_HINT = (1 << 6),
  NDS32_FIX = (1 << 7),
  NDS32_ADDEND = (1 << 8),
  NDS32_SYM = (1 << 9),
  NDS32_PCREL = (1 << 10),
  NDS32_PTR_PATTERN = (1 << 11),
  NDS32_PTR_MULTIPLE = (1 << 12),
  NDS32_GROUP = (1 << 13),
  NDS32_SYM_DESC_MEM = (1 << 14),
};
typedef struct nds32_relax_fixup_info
{
  int offset;
  int size;
  int ramp;
  enum bfd_reloc_code_real r_type;
} nds32_relax_fixup_info_t;
typedef struct nds32_cond_field
{
  int offset;
  int bitpos;
  int bitmask;
  bfd_boolean signed_extend;
} nds32_cond_field_t;
#define NDS32_MAXCHAR 20
#define MAX_RELAX_NUM 6
#define MAX_RELAX_FIX 12
typedef struct nds32_relax_info
{
  const char *opcode;
  enum nds32_br_range br_range;
  nds32_cond_field_t cond_field[MAX_RELAX_NUM];
  uint32_t relax_code_seq[BR_RANGE_NUM][MAX_RELAX_NUM];
  nds32_cond_field_t relax_code_condition[BR_RANGE_NUM][MAX_RELAX_NUM];
  unsigned int relax_code_size[BR_RANGE_NUM];
  int relax_branch_isize[BR_RANGE_NUM];
  nds32_relax_fixup_info_t relax_fixup[BR_RANGE_NUM][MAX_RELAX_FIX];
} relax_info_t;
enum nds32_relax_hint_type
{
  NDS32_RELAX_HINT_NONE = 0,
  NDS32_RELAX_HINT_LA_FLSI,
  NDS32_RELAX_HINT_LALS,
  NDS32_RELAX_HINT_LA_PLT,
  NDS32_RELAX_HINT_LA_GOT,
  NDS32_RELAX_HINT_LA_GOTOFF,
  NDS32_RELAX_HINT_TLS_START = 0x100,
  NDS32_RELAX_HINT_TLS_LE_LS,
  NDS32_RELAX_HINT_TLS_IE_LS,
  NDS32_RELAX_HINT_TLS_IE_LA,
  NDS32_RELAX_HINT_TLS_IEGP_LA,
  NDS32_RELAX_HINT_TLS_DESC_LS,
  NDS32_RELAX_HINT_ICT_LA,
};
struct nds32_relax_hint_table
{
  enum nds32_relax_hint_type main_type;
  unsigned int relax_code_size;
  uint32_t relax_code_seq[MAX_RELAX_NUM];
  nds32_relax_fixup_info_t relax_fixup[MAX_RELAX_FIX];
};
#endif
