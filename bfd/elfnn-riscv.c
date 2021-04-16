/* RISC-V-specific support for NN-bit ELF.
   Copyright (C) 2011-2019 Free Software Foundation, Inc.

   Contributed by Andrew Waterman (andrew@sifive.com).
   Based on TILE-Gx and MIPS targets.

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

/* This file handles RISC-V ELF targets.  */

#include "sysdep.h"
#include "bfd.h"
#include "libbfd.h"
#include "bfdlink.h"
#include "genlink.h"
#include "elf-bfd.h"
#include "elfxx-riscv.h"
#include "elf/riscv.h"
#include "opcode/riscv.h"

#define ARCH_SIZE NN

#define MINUS_ONE ((bfd_vma)0 - 1)

#define RISCV_ELF_LOG_WORD_BYTES (ARCH_SIZE == 32 ? 2 : 3)

#define RISCV_ELF_WORD_BYTES (1 << RISCV_ELF_LOG_WORD_BYTES)

/* The name of the dynamic interpreter.  This is put in the .interp
   section.  */

#define ELF64_DYNAMIC_INTERPRETER "/lib/ld.so.1"
#define ELF32_DYNAMIC_INTERPRETER "/lib32/ld.so.1"

#define ELF_ARCH			bfd_arch_riscv
#define ELF_TARGET_ID			RISCV_ELF_DATA
#define ELF_MACHINE_CODE		EM_RISCV
#define ELF_MAXPAGESIZE			0x1000
#define ELF_COMMONPAGESIZE		0x1000

/* Helper functions.  */
static void riscv_insertion_sort (void *, size_t, size_t,
				  int (*) (const void *, const void *));
static int compar_reloc (const void *, const void *);
static int riscv_get_local_syms (bfd *, asection *ATTRIBUTE_UNUSED,
				 Elf_Internal_Sym **);
static int riscv_get_section_contents (bfd *, asection *,
				       bfd_byte **, bfd_boolean);
static void riscv_elf_get_insn_with_reg (bfd *, Elf_Internal_Rela *,
					 uint32_t, uint32_t *);
static bfd_vma riscv_elf_encode_relocation (bfd *, Elf_Internal_Rela *irel,
					    bfd_vma);
static Elf_Internal_Rela *find_relocs_at_address
(Elf_Internal_Rela *, Elf_Internal_Rela *,
 Elf_Internal_Rela *, enum elf_riscv_reloc_type);
static int riscv_relocation_check (struct bfd_link_info *, Elf_Internal_Rela **,
				   Elf_Internal_Rela *, asection *, bfd_vma *,
				   bfd_byte *, int);
static bfd_boolean riscv_init_global_pointer (bfd *, struct bfd_link_info *);

/* Helper functions for EXECIT.  */
static int riscv_elf_execit_init (void);
static bfd_boolean riscv_elf_execit_build_hash_table (bfd *, asection *,
						      struct bfd_link_info *);
static bfd_boolean riscv_elf_execit_itb_base (struct bfd_link_info *);
static void riscv_elf_execit_import_table (bfd *abfd, struct bfd_link_info *);
static void riscv_elf_execit_build_itable (bfd *abfd, struct bfd_link_info *link_info);
static void riscv_elf_execit_finish (bfd *, struct bfd_link_info *);
static void riscv_elf_relocate_execit_table (struct bfd_link_info *, bfd *);
static bfd_boolean riscv_elf_execit_replace_instruction (struct bfd_link_info *,
							 bfd *, asection *);
static void riscv_elf_execit_save_local_symbol_value (void);

static int is_ITB_BASE_set = 0;
static int check_start_export_sym = 0;
static int nds_backward_compatible = 0;

/* Used for riscv_relocation_check.  */
enum
{
  DATA_EXIST = 1,
  /* For checking EXECIT with alignment.  */
  ALIGN_CLEAN_PRE = 1 << 1,
  ALIGN_PUSH_PRE = 1 << 2
};

/* Helper functions for Rom Patch and ICT.  */
static void riscv_elf_ict_init (void);
static void riscv_elf_relocate_ict_table (struct bfd_link_info *, bfd *);
static void riscv_elf_ict_hash_to_exported_table (void);

/* The entry of the ict hash table.  */
struct elf_riscv_ict_hash_entry
{
  struct bfd_hash_entry root;
  struct elf_link_hash_entry *h;
  unsigned int order;
};

/* The entry of the exported ict table.  */
struct riscv_elf_ict_table_entry
{
  struct elf_link_hash_entry *h;
  unsigned int order;
  struct riscv_elf_ict_table_entry *next;
};

/* The exported indirect call table.  */
static FILE *ict_table_file = NULL;
/* Indirect call hash table.  */
static struct bfd_hash_table indirect_call_table;
/* The exported indirect call table.  */
static struct riscv_elf_ict_table_entry *exported_ict_table_head = NULL;

#define ARCH_SIZE NN

#define MINUS_ONE ((bfd_vma)0 - 1)

#define RISCV_ELF_LOG_WORD_BYTES (ARCH_SIZE == 32 ? 2 : 3)

#define RISCV_ELF_WORD_BYTES (1 << RISCV_ELF_LOG_WORD_BYTES)

/* The name of the dynamic interpreter.  This is put in the .interp
   section.  */

#define ELF64_DYNAMIC_INTERPRETER "/lib/ld.so.1"
#define ELF32_DYNAMIC_INTERPRETER "/lib32/ld.so.1"

#define ELF_ARCH			bfd_arch_riscv
#define ELF_TARGET_ID			RISCV_ELF_DATA
#define ELF_MACHINE_CODE		EM_RISCV
#define ELF_MAXPAGESIZE			0x1000
#define ELF_COMMONPAGESIZE		0x1000

/* RISC-V ELF linker hash entry.  */

struct riscv_elf_link_hash_entry
{
  struct elf_link_hash_entry elf;

  /* Track dynamic relocs copied for this symbol.  */
  struct elf_dyn_relocs *dyn_relocs;

#define GOT_UNKNOWN     0
#define GOT_NORMAL      1
#define GOT_TLS_GD      2
#define GOT_TLS_IE      4
#define GOT_TLS_LE      8
  char tls_type;

  bfd_boolean indirect_call;
};

#define riscv_elf_hash_entry(ent) \
  ((struct riscv_elf_link_hash_entry *)(ent))

struct _bfd_riscv_elf_obj_tdata
{
  struct elf_obj_tdata root;

  /* tls_type for each local got entry.  */
  char *local_got_tls_type;
};

#define _bfd_riscv_elf_tdata(abfd) \
  ((struct _bfd_riscv_elf_obj_tdata *) (abfd)->tdata.any)

#define _bfd_riscv_elf_local_got_tls_type(abfd) \
  (_bfd_riscv_elf_tdata (abfd)->local_got_tls_type)

#define _bfd_riscv_elf_tls_type(abfd, h, symndx)		\
  (*((h) != NULL ? &riscv_elf_hash_entry (h)->tls_type		\
     : &_bfd_riscv_elf_local_got_tls_type (abfd) [symndx]))

#define is_riscv_elf(bfd)				\
  (bfd_get_flavour (bfd) == bfd_target_elf_flavour	\
   && elf_tdata (bfd) != NULL				\
   && elf_object_id (bfd) == RISCV_ELF_DATA)

#include "elf/common.h"
#include "elf/internal.h"

static bfd_boolean
riscv_info_to_howto_rela (bfd *abfd,
			  arelent *cache_ptr,
			  Elf_Internal_Rela *dst)
{
  cache_ptr->howto = riscv_elf_rtype_to_howto (abfd, ELFNN_R_TYPE (dst->r_info));
  return cache_ptr->howto != NULL;
}

static void
riscv_elf_append_rela (bfd *abfd, asection *s, Elf_Internal_Rela *rel)
{
  const struct elf_backend_data *bed;
  bfd_byte *loc;

  bed = get_elf_backend_data (abfd);
  loc = s->contents + (s->reloc_count++ * bed->s->sizeof_rela);
  bed->s->swap_reloca_out (abfd, rel, loc);
}

/* PLT/GOT stuff.  */

#define PLT_HEADER_INSNS 8
#define PLT_ENTRY_INSNS 4
#define PLT_HEADER_SIZE (PLT_HEADER_INSNS * 4)
#define PLT_ENTRY_SIZE (PLT_ENTRY_INSNS * 4)

#define GOT_ENTRY_SIZE RISCV_ELF_WORD_BYTES

#define GOTPLT_HEADER_SIZE (2 * GOT_ENTRY_SIZE)

#define sec_addr(sec) ((sec)->output_section->vma + (sec)->output_offset)

static bfd_vma
riscv_elf_got_plt_val (bfd_vma plt_index, struct bfd_link_info *info)
{
  return sec_addr (riscv_elf_hash_table (info)->elf.sgotplt)
	 + GOTPLT_HEADER_SIZE + (plt_index * GOT_ENTRY_SIZE);
}

#if ARCH_SIZE == 32
# define MATCH_LREG MATCH_LW
#else
# define MATCH_LREG MATCH_LD
#endif

/* Generate a PLT header.  */

static bfd_boolean
riscv_make_plt_header (bfd *output_bfd, bfd_vma gotplt_addr, bfd_vma addr,
		       uint32_t *entry)
{
  bfd_vma gotplt_offset_high = RISCV_PCREL_HIGH_PART (gotplt_addr, addr);
  bfd_vma gotplt_offset_low = RISCV_PCREL_LOW_PART (gotplt_addr, addr);

  /* RVE has no t3 register, so this won't work, and is not supported.  */
  if (elf_elfheader (output_bfd)->e_flags & EF_RISCV_RVE)
    {
      _bfd_error_handler (_("%pB: warning: RVE PLT generation not supported"),
			  output_bfd);
      return FALSE;
    }

  /* auipc  t2, %hi(.got.plt)
     sub    t1, t1, t3		     # shifted .got.plt offset + hdr size + 12
     l[w|d] t3, %lo(.got.plt)(t2)    # _dl_runtime_resolve
     addi   t1, t1, -(hdr size + 12) # shifted .got.plt offset
     addi   t0, t2, %lo(.got.plt)    # &.got.plt
     srli   t1, t1, log2(16/PTRSIZE) # .got.plt offset
     l[w|d] t0, PTRSIZE(t0)	     # link map
     jr	    t3 */

  entry[0] = RISCV_UTYPE (AUIPC, X_T2, gotplt_offset_high);
  entry[1] = RISCV_RTYPE (SUB, X_T1, X_T1, X_T3);
  entry[2] = RISCV_ITYPE (LREG, X_T3, X_T2, gotplt_offset_low);
  entry[3] = RISCV_ITYPE (ADDI, X_T1, X_T1, -(PLT_HEADER_SIZE + 12));
  entry[4] = RISCV_ITYPE (ADDI, X_T0, X_T2, gotplt_offset_low);
  entry[5] = RISCV_ITYPE (SRLI, X_T1, X_T1, 4 - RISCV_ELF_LOG_WORD_BYTES);
  entry[6] = RISCV_ITYPE (LREG, X_T0, X_T0, RISCV_ELF_WORD_BYTES);
  entry[7] = RISCV_ITYPE (JALR, 0, X_T3, 0);

  return TRUE;
}

/* Generate a PLT entry.  */

static bfd_boolean
riscv_make_plt_entry (bfd *output_bfd, bfd_vma got, bfd_vma addr,
		      uint32_t *entry)
{
  /* RVE has no t3 register, so this won't work, and is not supported.  */
  if (elf_elfheader (output_bfd)->e_flags & EF_RISCV_RVE)
    {
      _bfd_error_handler (_("%pB: warning: RVE PLT generation not supported"),
			  output_bfd);
      return FALSE;
    }

  /* auipc  t3, %hi(.got.plt entry)
     l[w|d] t3, %lo(.got.plt entry)(t3)
     jalr   t1, t3
     nop */

  entry[0] = RISCV_UTYPE (AUIPC, X_T3, RISCV_PCREL_HIGH_PART (got, addr));
  entry[1] = RISCV_ITYPE (LREG,  X_T3, X_T3, RISCV_PCREL_LOW_PART (got, addr));
  entry[2] = RISCV_ITYPE (JALR, X_T1, X_T3, 0);
  entry[3] = RISCV_NOP;

  return TRUE;
}

/* Create an entry in an RISC-V ELF linker hash table.  */

static struct bfd_hash_entry *
link_hash_newfunc (struct bfd_hash_entry *entry,
		   struct bfd_hash_table *table, const char *string)
{
  /* Allocate the structure if it has not already been allocated by a
     subclass.  */
  if (entry == NULL)
    {
      entry =
	bfd_hash_allocate (table,
			   sizeof (struct riscv_elf_link_hash_entry));
      if (entry == NULL)
	return entry;
    }

  /* Call the allocation method of the superclass.  */
  entry = _bfd_elf_link_hash_newfunc (entry, table, string);
  if (entry != NULL)
    {
      struct riscv_elf_link_hash_entry *eh;

      eh = (struct riscv_elf_link_hash_entry *) entry;
      eh->dyn_relocs = NULL;
      eh->tls_type = GOT_UNKNOWN;
      eh->indirect_call = FALSE;
    }

  return entry;
}

/* Create a RISC-V ELF linker hash table.  */

static struct bfd_link_hash_table *
riscv_elf_link_hash_table_create (bfd *abfd)
{
  struct riscv_elf_link_hash_table *ret;
  bfd_size_type amt = sizeof (struct riscv_elf_link_hash_table);

  ret = (struct riscv_elf_link_hash_table *) bfd_zmalloc (amt);
  if (ret == NULL)
    return NULL;

  if (!_bfd_elf_link_hash_table_init (&ret->elf, abfd, link_hash_newfunc,
				      sizeof (struct riscv_elf_link_hash_entry),
				      RISCV_ELF_DATA))
    {
      free (ret);
      return NULL;
    }

  ret->max_alignment = (bfd_vma) -1;
  return &ret->elf.root;
}

/* Create the .got section.  */

static bfd_boolean
riscv_elf_create_got_section (bfd *abfd, struct bfd_link_info *info)
{
  flagword flags;
  asection *s, *s_got;
  struct elf_link_hash_entry *h;
  const struct elf_backend_data *bed = get_elf_backend_data (abfd);
  struct elf_link_hash_table *htab = elf_hash_table (info);

  /* This function may be called more than once.  */
  if (htab->sgot != NULL)
    return TRUE;

  flags = bed->dynamic_sec_flags;

  s = bfd_make_section_anyway_with_flags (abfd,
					  (bed->rela_plts_and_copies_p
					   ? ".rela.got" : ".rel.got"),
					  (bed->dynamic_sec_flags
					   | SEC_READONLY));
  if (s == NULL
      || ! bfd_set_section_alignment (abfd, s, bed->s->log_file_align))
    return FALSE;
  htab->srelgot = s;

  s = s_got = bfd_make_section_anyway_with_flags (abfd, ".got", flags);
  if (s == NULL
      || !bfd_set_section_alignment (abfd, s, bed->s->log_file_align))
    return FALSE;
  htab->sgot = s;

  /* The first bit of the global offset table is the header.  */
  s->size += bed->got_header_size;

  if (bed->want_got_plt)
    {
      s = bfd_make_section_anyway_with_flags (abfd, ".got.plt", flags);
      if (s == NULL
	  || !bfd_set_section_alignment (abfd, s,
					 bed->s->log_file_align))
	return FALSE;
      htab->sgotplt = s;

      /* Reserve room for the header.  */
      s->size += GOTPLT_HEADER_SIZE;
    }

  if (bed->want_got_sym)
    {
      /* Define the symbol _GLOBAL_OFFSET_TABLE_ at the start of the .got
	 section.  We don't do this in the linker script because we don't want
	 to define the symbol if we are not creating a global offset
	 table.  */
      h = _bfd_elf_define_linkage_sym (abfd, info, s_got,
				       "_GLOBAL_OFFSET_TABLE_");
      elf_hash_table (info)->hgot = h;
      if (h == NULL)
	return FALSE;
    }

  return TRUE;
}

/* Create .plt, .rela.plt, .got, .got.plt, .rela.got, .dynbss, and
   .rela.bss sections in DYNOBJ, and set up shortcuts to them in our
   hash table.  */

static bfd_boolean
riscv_elf_create_dynamic_sections (bfd *dynobj,
				   struct bfd_link_info *info)
{
  struct riscv_elf_link_hash_table *htab;

  htab = riscv_elf_hash_table (info);
  BFD_ASSERT (htab != NULL);

  if (!riscv_elf_create_got_section (dynobj, info))
    return FALSE;

  if (!_bfd_elf_create_dynamic_sections (dynobj, info))
    return FALSE;

  if (!bfd_link_pic (info))
    {
      htab->sdyntdata =
	bfd_make_section_anyway_with_flags (dynobj, ".tdata.dyn",
					    (SEC_ALLOC | SEC_THREAD_LOCAL
					     | SEC_LINKER_CREATED));
    }

  if (!htab->elf.splt || !htab->elf.srelplt || !htab->elf.sdynbss
      || (!bfd_link_pic (info) && (!htab->elf.srelbss || !htab->sdyntdata)))
    abort ();

  return TRUE;
}

/* Copy the extra info we tack onto an elf_link_hash_entry.  */

static void
riscv_elf_copy_indirect_symbol (struct bfd_link_info *info,
				struct elf_link_hash_entry *dir,
				struct elf_link_hash_entry *ind)
{
  struct riscv_elf_link_hash_entry *edir, *eind;

  edir = (struct riscv_elf_link_hash_entry *) dir;
  eind = (struct riscv_elf_link_hash_entry *) ind;

  if (eind->dyn_relocs != NULL)
    {
      if (edir->dyn_relocs != NULL)
	{
	  struct elf_dyn_relocs **pp;
	  struct elf_dyn_relocs *p;

	  /* Add reloc counts against the indirect sym to the direct sym
	     list.  Merge any entries against the same section.  */
	  for (pp = &eind->dyn_relocs; (p = *pp) != NULL; )
	    {
	      struct elf_dyn_relocs *q;

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

  if (ind->root.type == bfd_link_hash_indirect
      && dir->got.refcount <= 0)
    {
      edir->tls_type = eind->tls_type;
      eind->tls_type = GOT_UNKNOWN;
    }
  _bfd_elf_link_hash_copy_indirect (info, dir, ind);
}

static bfd_boolean
riscv_elf_record_tls_type (bfd *abfd, struct elf_link_hash_entry *h,
			   unsigned long symndx, char tls_type)
{
  char *new_tls_type = &_bfd_riscv_elf_tls_type (abfd, h, symndx);

  *new_tls_type |= tls_type;
  if ((*new_tls_type & GOT_NORMAL) && (*new_tls_type & ~GOT_NORMAL))
    {
      (*_bfd_error_handler)
	(_("%pB: `%s' accessed both as normal and thread local symbol"),
	 abfd, h ? h->root.root.string : "<local>");
      return FALSE;
    }
  return TRUE;
}

static bfd_boolean
riscv_elf_record_got_reference (bfd *abfd, struct bfd_link_info *info,
				struct elf_link_hash_entry *h, long symndx)
{
  struct riscv_elf_link_hash_table *htab = riscv_elf_hash_table (info);
  Elf_Internal_Shdr *symtab_hdr = &elf_tdata (abfd)->symtab_hdr;

  if (htab->elf.sgot == NULL)
    {
      if (!riscv_elf_create_got_section (htab->elf.dynobj, info))
	return FALSE;
    }

  if (h != NULL)
    {
      h->got.refcount += 1;
      return TRUE;
    }

  /* This is a global offset table entry for a local symbol.  */
  if (elf_local_got_refcounts (abfd) == NULL)
    {
      bfd_size_type size = symtab_hdr->sh_info * (sizeof (bfd_vma) + 1);
      if (!(elf_local_got_refcounts (abfd) = bfd_zalloc (abfd, size)))
	return FALSE;
      _bfd_riscv_elf_local_got_tls_type (abfd)
	= (char *) (elf_local_got_refcounts (abfd) + symtab_hdr->sh_info);
    }
  elf_local_got_refcounts (abfd) [symndx] += 1;

  return TRUE;
}

static bfd_boolean
bad_static_reloc (bfd *abfd, unsigned r_type, struct elf_link_hash_entry *h)
{
  reloc_howto_type * r = riscv_elf_rtype_to_howto (abfd, r_type);

  (*_bfd_error_handler)
    (_("%pB: relocation %s against `%s' can not be used when making a shared "
       "object; recompile with -fPIC"),
     abfd, r ? r->name : _("<unknown>"),
     h != NULL ? h->root.root.string : "a local symbol");
  bfd_set_error (bfd_error_bad_value);
  return FALSE;
}

static bfd_boolean
riscv_elf_update_ict_hash_table (bfd *abfd, asection *sec,
				 struct elf_link_hash_entry *h,
				 const Elf_Internal_Rela *rel)
{
  /* I am not sure why the addend isn't allowed.  */
  if (rel->r_addend != 0)
    {
      (*_bfd_error_handler)
	(_("%pB %s: Error: Rom-patch relocation offset: 0x%lx "
	   "with addend 0x%lx\n"),
	 abfd, sec->name, rel->r_offset, rel->r_addend);
      return FALSE;
    }

  if (h)
    {
      struct elf_riscv_ict_hash_entry *entry;
      /* First, just check whether the ICT symbol is the hash table.  */
      entry = (struct elf_riscv_ict_hash_entry *)
	bfd_hash_lookup (&indirect_call_table, h->root.root.string,
			 FALSE, FALSE);
      if (entry == NULL)
	{
	  /* Create new hash entry.  */
	  entry = (struct elf_riscv_ict_hash_entry *)
	    bfd_hash_lookup (&indirect_call_table, h->root.root.string,
			     TRUE, TRUE);
	  if (entry == NULL)
	    {
	      (*_bfd_error_handler)
		(_("%pB: failed to create indirect call %s hash table\n"),
		 abfd, h->root.root.string);
	      return FALSE;
	    }

	  riscv_elf_hash_entry (h)->indirect_call = TRUE;
	  entry->h = h;
	  entry->order = ict_table_entries;
	  ict_table_entries++;
	}
    }
  else
    {
      /* Rom-patch functions cannot be local.  */
      (*_bfd_error_handler)
	(_("%pB: indirect call relocation with local symbol.\n"), abfd);
      return FALSE;
    }

  return TRUE;
}

/* Look through the relocs for a section during the first phase, and
   allocate space in the global offset table or procedure linkage
   table.  */

static bfd_boolean
riscv_elf_check_relocs (bfd *abfd, struct bfd_link_info *info,
			asection *sec, const Elf_Internal_Rela *relocs)
{
  struct riscv_elf_link_hash_table *htab;
  Elf_Internal_Shdr *symtab_hdr;
  struct elf_link_hash_entry **sym_hashes;
  const Elf_Internal_Rela *rel;
  asection *sreloc = NULL;
  bfd_boolean update_ict_hash_first = FALSE;
  bfd_boolean update_ict_hash_second = FALSE;

  if (bfd_link_relocatable (info))
    return TRUE;

  htab = riscv_elf_hash_table (info);
  symtab_hdr = &elf_tdata (abfd)->symtab_hdr;
  sym_hashes = elf_sym_hashes (abfd);

  if (htab->elf.dynobj == NULL)
    htab->elf.dynobj = abfd;

  /* We update the ict hash table when we encountering the
     R_RISCV_XXX_ICT_XXX relocations at the first link-time.
     Then we also need to update the ict hash table when we
     compiling the patch code at the second link-time, but
     the relocations in the imported ict table are not belonged
     to the ICT.  Therefore, we handle the following relocations
     specially at the second link-time: R_RISCV_JAL, R_RISCV_CALL,
     and R_RISCV_64.  */
  if (!find_imported_ict_table)
    update_ict_hash_first = TRUE;
  else if (find_imported_ict_table
	   && sec == bfd_get_section_by_name (abfd, ".nds.ict"))
    update_ict_hash_second = TRUE;

  for (rel = relocs; rel < relocs + sec->reloc_count; rel++)
    {
      unsigned int r_type;
      unsigned int r_symndx;
      struct elf_link_hash_entry *h;

      r_symndx = ELFNN_R_SYM (rel->r_info);
      r_type = ELFNN_R_TYPE (rel->r_info);

      if (r_symndx >= NUM_SHDR_ENTRIES (symtab_hdr))
	{
	  (*_bfd_error_handler) (_("%pB: bad symbol index: %d"),
				 abfd, r_symndx);
	  return FALSE;
	}

      if (r_symndx < symtab_hdr->sh_info)
	h = NULL;
      else
	{
	  h = sym_hashes[r_symndx - symtab_hdr->sh_info];
	  while (h->root.type == bfd_link_hash_indirect
		 || h->root.type == bfd_link_hash_warning)
	    h = (struct elf_link_hash_entry *) h->root.u.i.link;
	}

      switch (r_type)
	{
	case R_RISCV_TLS_GD_HI20:
	  if (!riscv_elf_record_got_reference (abfd, info, h, r_symndx)
	      || !riscv_elf_record_tls_type (abfd, h, r_symndx, GOT_TLS_GD))
	    return FALSE;
	  break;

	case R_RISCV_TLS_GOT_HI20:
	  if (bfd_link_pic (info))
	    info->flags |= DF_STATIC_TLS;
	  if (!riscv_elf_record_got_reference (abfd, info, h, r_symndx)
	      || !riscv_elf_record_tls_type (abfd, h, r_symndx, GOT_TLS_IE))
	    return FALSE;
	  break;

	case R_RISCV_GOT_HI20:
	  if (!riscv_elf_record_got_reference (abfd, info, h, r_symndx)
	      || !riscv_elf_record_tls_type (abfd, h, r_symndx, GOT_NORMAL))
	    return FALSE;
	  break;

	case R_RISCV_CALL_PLT:
	  /* This symbol requires a procedure linkage table entry.  We
	     actually build the entry in adjust_dynamic_symbol,
	     because this might be a case of linking PIC code without
	     linking in any dynamic objects, in which case we don't
	     need to generate a procedure linkage table after all.  */

	  if (h != NULL)
	    {
	      h->needs_plt = 1;
	      h->plt.refcount += 1;
	    }
	  break;

	case R_RISCV_CALL:
	case R_RISCV_JAL:
	  if (update_ict_hash_second
	      && !riscv_elf_update_ict_hash_table (abfd, sec, h, rel))
	    return FALSE;
	  /* Fall through.  */

	case R_RISCV_BRANCH:
	case R_RISCV_RVC_BRANCH:
	case R_RISCV_RVC_JUMP:
	case R_RISCV_PCREL_HI20:
	  /* In shared libraries, these relocs are known to bind locally.  */
	  if (bfd_link_pic (info))
	    break;
	  goto static_reloc;

	case R_RISCV_TPREL_HI20:
	  if (!bfd_link_executable (info))
	    return bad_static_reloc (abfd, r_type, h);
	  if (h != NULL)
	    riscv_elf_record_tls_type (abfd, h, r_symndx, GOT_TLS_LE);
	  goto static_reloc;

	case R_RISCV_64:
	  if (update_ict_hash_second
	      && !riscv_elf_update_ict_hash_table (abfd, sec, h, rel))
	    return FALSE;
	  goto static_reloc;

	case R_RISCV_HI20:
	  if (bfd_link_pic (info))
	    return bad_static_reloc (abfd, r_type, h);
	  /* Fall through.  */

	case R_RISCV_COPY:
	case R_RISCV_JUMP_SLOT:
	case R_RISCV_RELATIVE:
	case R_RISCV_32:
	  /* Fall through.  */

	static_reloc:
	  /* This reloc might not bind locally.  */
	  if (h != NULL)
	    h->non_got_ref = 1;

	  if (h != NULL && !bfd_link_pic (info))
	    {
	      /* We may need a .plt entry if the function this reloc
		 refers to is in a shared lib.  */
	      h->plt.refcount += 1;
	    }

	  /* If we are creating a shared library, and this is a reloc
	     against a global symbol, or a non PC relative reloc
	     against a local symbol, then we need to copy the reloc
	     into the shared library.  However, if we are linking with
	     -Bsymbolic, we do not need to copy a reloc against a
	     global symbol which is defined in an object we are
	     including in the link (i.e., DEF_REGULAR is set).  At
	     this point we have not seen all the input files, so it is
	     possible that DEF_REGULAR is not set now but will be set
	     later (it is never cleared).  In case of a weak definition,
	     DEF_REGULAR may be cleared later by a strong definition in
	     a shared library.  We account for that possibility below by
	     storing information in the relocs_copied field of the hash
	     table entry.  A similar situation occurs when creating
	     shared libraries and symbol visibility changes render the
	     symbol local.

	     If on the other hand, we are creating an executable, we
	     may need to keep relocations for symbols satisfied by a
	     dynamic library if we manage to avoid copy relocs for the
	     symbol.  */
	  reloc_howto_type * r = riscv_elf_rtype_to_howto (abfd, r_type);

	  if ((bfd_link_pic (info)
	       && (sec->flags & SEC_ALLOC) != 0
	       && ((r != NULL && ! r->pc_relative)
		   || (h != NULL
		       && (! info->symbolic
			   || h->root.type == bfd_link_hash_defweak
			   || !h->def_regular))))
	      || (!bfd_link_pic (info)
		  && (sec->flags & SEC_ALLOC) != 0
		  && h != NULL
		  && (h->root.type == bfd_link_hash_defweak
		      || !h->def_regular)))
	    {
	      struct elf_dyn_relocs *p;
	      struct elf_dyn_relocs **head;

	      /* When creating a shared object, we must copy these
		 relocs into the output file.  We create a reloc
		 section in dynobj and make room for the reloc.  */
	      if (sreloc == NULL)
		{
		  sreloc = _bfd_elf_make_dynamic_reloc_section
		    (sec, htab->elf.dynobj, RISCV_ELF_LOG_WORD_BYTES,
		    abfd, /*rela?*/ TRUE);

		  if (sreloc == NULL)
		    return FALSE;
		}

	      /* If this is a global symbol, we count the number of
		 relocations we need for this symbol.  */
	      if (h != NULL)
		head = &((struct riscv_elf_link_hash_entry *) h)->dyn_relocs;
	      else
		{
		  /* Track dynamic relocs needed for local syms too.
		     We really need local syms available to do this
		     easily.  Oh well.  */

		  asection *s;
		  void *vpp;
		  Elf_Internal_Sym *isym;

		  isym = bfd_sym_from_r_symndx (&htab->sym_cache,
						abfd, r_symndx);
		  if (isym == NULL)
		    return FALSE;

		  s = bfd_section_from_elf_index (abfd, isym->st_shndx);
		  if (s == NULL)
		    s = sec;

		  vpp = &elf_section_data (s)->local_dynrel;
		  head = (struct elf_dyn_relocs **) vpp;
		}

	      p = *head;
	      if (p == NULL || p->sec != sec)
		{
		  bfd_size_type amt = sizeof *p;
		  p = ((struct elf_dyn_relocs *)
		       bfd_alloc (htab->elf.dynobj, amt));
		  if (p == NULL)
		    return FALSE;
		  p->next = *head;
		  *head = p;
		  p->sec = sec;
		  p->count = 0;
		  p->pc_count = 0;
		}

	      p->count += 1;
	      p->pc_count += r == NULL ? 0 : r->pc_relative;
	    }

	  break;

	case R_RISCV_GNU_VTINHERIT:
	  if (!bfd_elf_gc_record_vtinherit (abfd, sec, h, rel->r_offset))
	    return FALSE;
	  break;

	case R_RISCV_GNU_VTENTRY:
	  if (!bfd_elf_gc_record_vtentry (abfd, sec, h, rel->r_addend))
	    return FALSE;
	  break;

	case R_RISCV_ICT_HI20:
	case R_RISCV_ICT_LO12_I:
	case R_RISCV_PCREL_ICT_HI20:
	case R_RISCV_CALL_ICT:
	case R_RISCV_ICT_64:
	  if (update_ict_hash_first
	      && !riscv_elf_update_ict_hash_table (abfd, sec, h, rel))
	    return FALSE;
	  break;

	default:
	  break;
	}
    }

  return TRUE;
}

static asection *
riscv_elf_gc_mark_hook (asection *sec,
			struct bfd_link_info *info,
			Elf_Internal_Rela *rel,
			struct elf_link_hash_entry *h,
			Elf_Internal_Sym *sym)
{
  if (h != NULL)
    switch (ELFNN_R_TYPE (rel->r_info))
      {
      case R_RISCV_GNU_VTINHERIT:
      case R_RISCV_GNU_VTENTRY:
	return NULL;
      }

  return _bfd_elf_gc_mark_hook (sec, info, rel, h, sym);
}

/* Find dynamic relocs for H that apply to read-only sections.  */

static asection *
readonly_dynrelocs (struct elf_link_hash_entry *h)
{
  struct elf_dyn_relocs *p;

  for (p = riscv_elf_hash_entry (h)->dyn_relocs; p != NULL; p = p->next)
    {
      asection *s = p->sec->output_section;

      if (s != NULL && (s->flags & SEC_READONLY) != 0)
	return p->sec;
    }
  return NULL;
}

/* Adjust a symbol defined by a dynamic object and referenced by a
   regular object.  The current definition is in some section of the
   dynamic object, but we're not including those sections.  We have to
   change the definition to something the rest of the link can
   understand.  */

static bfd_boolean
riscv_elf_adjust_dynamic_symbol (struct bfd_link_info *info,
				 struct elf_link_hash_entry *h)
{
  struct riscv_elf_link_hash_table *htab;
  struct riscv_elf_link_hash_entry * eh;
  bfd *dynobj;
  asection *s, *srel;

  htab = riscv_elf_hash_table (info);
  BFD_ASSERT (htab != NULL);

  dynobj = htab->elf.dynobj;

  /* Make sure we know what is going on here.  */
  BFD_ASSERT (dynobj != NULL
	      && (h->needs_plt
		  || h->type == STT_GNU_IFUNC
		  || h->is_weakalias
		  || (h->def_dynamic
		      && h->ref_regular
		      && !h->def_regular)));

  /* If this is a function, put it in the procedure linkage table.  We
     will fill in the contents of the procedure linkage table later
     (although we could actually do it here).  */
  if (h->type == STT_FUNC || h->type == STT_GNU_IFUNC || h->needs_plt)
    {
      if (h->plt.refcount <= 0
	  || SYMBOL_CALLS_LOCAL (info, h)
	  || (ELF_ST_VISIBILITY (h->other) != STV_DEFAULT
	      && h->root.type == bfd_link_hash_undefweak))
	{
	  /* This case can occur if we saw a R_RISCV_CALL_PLT reloc in an
	     input file, but the symbol was never referred to by a dynamic
	     object, or if all references were garbage collected.  In such
	     a case, we don't actually need to build a PLT entry.  */
	  h->plt.offset = (bfd_vma) -1;
	  h->needs_plt = 0;
	}

      return TRUE;
    }
  else
    h->plt.offset = (bfd_vma) -1;

  /* If this is a weak symbol, and there is a real definition, the
     processor independent code will have arranged for us to see the
     real definition first, and we can just use the same value.  */
  if (h->is_weakalias)
    {
      struct elf_link_hash_entry *def = weakdef (h);
      BFD_ASSERT (def->root.type == bfd_link_hash_defined);
      h->root.u.def.section = def->root.u.def.section;
      h->root.u.def.value = def->root.u.def.value;
      return TRUE;
    }

  /* This is a reference to a symbol defined by a dynamic object which
     is not a function.  */

  /* If we are creating a shared library, we must presume that the
     only references to the symbol are via the global offset table.
     For such cases we need not do anything here; the relocations will
     be handled correctly by relocate_section.  */
  if (bfd_link_pic (info))
    return TRUE;

  /* If there are no references to this symbol that do not use the
     GOT, we don't need to generate a copy reloc.  */
  if (!h->non_got_ref)
    return TRUE;

  /* If -z nocopyreloc was given, we won't generate them either.  */
  if (info->nocopyreloc)
    {
      h->non_got_ref = 0;
      return TRUE;
    }

  /* If we don't find any dynamic relocs in read-only sections, then
     we'll be keeping the dynamic relocs and avoiding the copy reloc.  */
  if (!readonly_dynrelocs (h))
    {
      h->non_got_ref = 0;
      return TRUE;
    }

  /* We must allocate the symbol in our .dynbss section, which will
     become part of the .bss section of the executable.  There will be
     an entry for this symbol in the .dynsym section.  The dynamic
     object will contain position independent code, so all references
     from the dynamic object to this symbol will go through the global
     offset table.  The dynamic linker will use the .dynsym entry to
     determine the address it must put in the global offset table, so
     both the dynamic object and the regular object will refer to the
     same memory location for the variable.  */

  /* We must generate a R_RISCV_COPY reloc to tell the dynamic linker
     to copy the initial value out of the dynamic object and into the
     runtime process image.  We need to remember the offset into the
     .rel.bss section we are going to use.  */
  eh = (struct riscv_elf_link_hash_entry *) h;
  if (eh->tls_type & ~GOT_NORMAL)
    {
      s = htab->sdyntdata;
      srel = htab->elf.srelbss;
    }
  else if ((h->root.u.def.section->flags & SEC_READONLY) != 0)
    {
      s = htab->elf.sdynrelro;
      srel = htab->elf.sreldynrelro;
    }
  else
    {
      s = htab->elf.sdynbss;
      srel = htab->elf.srelbss;
    }
  if ((h->root.u.def.section->flags & SEC_ALLOC) != 0 && h->size != 0)
    {
      srel->size += sizeof (ElfNN_External_Rela);
      h->needs_copy = 1;
    }

  return _bfd_elf_adjust_dynamic_copy (info, h, s);
}

/* Allocate space in .plt, .got and associated reloc sections for
   dynamic relocs.  */

static bfd_boolean
allocate_dynrelocs (struct elf_link_hash_entry *h, void *inf)
{
  struct bfd_link_info *info;
  struct riscv_elf_link_hash_table *htab;
  struct riscv_elf_link_hash_entry *eh;
  struct elf_dyn_relocs *p;

  if (h->root.type == bfd_link_hash_indirect)
    return TRUE;

  info = (struct bfd_link_info *) inf;
  htab = riscv_elf_hash_table (info);
  BFD_ASSERT (htab != NULL);

  if (htab->elf.dynamic_sections_created
      && h->plt.refcount > 0)
    {
      /* Make sure this symbol is output as a dynamic symbol.
	 Undefined weak syms won't yet be marked as dynamic.  */
      if (h->dynindx == -1
	  && !h->forced_local)
	{
	  if (! bfd_elf_link_record_dynamic_symbol (info, h))
	    return FALSE;
	}

      if (WILL_CALL_FINISH_DYNAMIC_SYMBOL (1, bfd_link_pic (info), h))
	{
	  asection *s = htab->elf.splt;

	  if (s->size == 0)
	    s->size = PLT_HEADER_SIZE;

	  h->plt.offset = s->size;

	  /* Make room for this entry.  */
	  s->size += PLT_ENTRY_SIZE;

	  /* We also need to make an entry in the .got.plt section.  */
	  htab->elf.sgotplt->size += GOT_ENTRY_SIZE;

	  /* We also need to make an entry in the .rela.plt section.  */
	  htab->elf.srelplt->size += sizeof (ElfNN_External_Rela);

	  /* If this symbol is not defined in a regular file, and we are
	     not generating a shared library, then set the symbol to this
	     location in the .plt.  This is required to make function
	     pointers compare as equal between the normal executable and
	     the shared library.  */
	  if (! bfd_link_pic (info)
	      && !h->def_regular)
	    {
	      h->root.u.def.section = s;
	      h->root.u.def.value = h->plt.offset;
	    }
	}
      else
	{
	  h->plt.offset = (bfd_vma) -1;
	  h->needs_plt = 0;
	}
    }
  else
    {
      h->plt.offset = (bfd_vma) -1;
      h->needs_plt = 0;
    }

  if (h->got.refcount > 0)
    {
      asection *s;
      bfd_boolean dyn;
      int tls_type = riscv_elf_hash_entry (h)->tls_type;

      /* Make sure this symbol is output as a dynamic symbol.
	 Undefined weak syms won't yet be marked as dynamic.  */
      if (h->dynindx == -1
	  && !h->forced_local)
	{
	  if (! bfd_elf_link_record_dynamic_symbol (info, h))
	    return FALSE;
	}

      s = htab->elf.sgot;
      h->got.offset = s->size;
      dyn = htab->elf.dynamic_sections_created;
      if (tls_type & (GOT_TLS_GD | GOT_TLS_IE))
	{
	  /* TLS_GD needs two dynamic relocs and two GOT slots.  */
	  if (tls_type & GOT_TLS_GD)
	    {
	      s->size += 2 * RISCV_ELF_WORD_BYTES;
	      htab->elf.srelgot->size += 2 * sizeof (ElfNN_External_Rela);
	    }

	  /* TLS_IE needs one dynamic reloc and one GOT slot.  */
	  if (tls_type & GOT_TLS_IE)
	    {
	      s->size += RISCV_ELF_WORD_BYTES;
	      htab->elf.srelgot->size += sizeof (ElfNN_External_Rela);
	    }
	}
      else
	{
	  s->size += RISCV_ELF_WORD_BYTES;
	  if (WILL_CALL_FINISH_DYNAMIC_SYMBOL (dyn, bfd_link_pic (info), h)
	      && ! UNDEFWEAK_NO_DYNAMIC_RELOC (info, h))
	    htab->elf.srelgot->size += sizeof (ElfNN_External_Rela);
	}
    }
  else
    h->got.offset = (bfd_vma) -1;

  eh = (struct riscv_elf_link_hash_entry *) h;
  if (eh->dyn_relocs == NULL)
    return TRUE;

  /* In the shared -Bsymbolic case, discard space allocated for
     dynamic pc-relative relocs against symbols which turn out to be
     defined in regular objects.  For the normal shared case, discard
     space for pc-relative relocs that have become local due to symbol
     visibility changes.  */

  if (bfd_link_pic (info))
    {
      if (SYMBOL_CALLS_LOCAL (info, h))
	{
	  struct elf_dyn_relocs **pp;

	  for (pp = &eh->dyn_relocs; (p = *pp) != NULL; )
	    {
	      p->count -= p->pc_count;
	      p->pc_count = 0;
	      if (p->count == 0)
		*pp = p->next;
	      else
		pp = &p->next;
	    }
	}

      /* Also discard relocs on undefined weak syms with non-default
	 visibility.  */
      if (eh->dyn_relocs != NULL
	  && h->root.type == bfd_link_hash_undefweak)
	{
	  if (ELF_ST_VISIBILITY (h->other) != STV_DEFAULT
	      || UNDEFWEAK_NO_DYNAMIC_RELOC (info, h))
	    eh->dyn_relocs = NULL;

	  /* Make sure undefined weak symbols are output as a dynamic
	     symbol in PIEs.  */
	  else if (h->dynindx == -1
		   && !h->forced_local)
	    {
	      if (! bfd_elf_link_record_dynamic_symbol (info, h))
		return FALSE;
	    }
	}
    }
  else
    {
      /* For the non-shared case, discard space for relocs against
	 symbols which turn out to need copy relocs or are not
	 dynamic.  */

      if (!h->non_got_ref
	  && ((h->def_dynamic
	       && !h->def_regular)
	      || (htab->elf.dynamic_sections_created
		  && (h->root.type == bfd_link_hash_undefweak
		      || h->root.type == bfd_link_hash_undefined))))
	{
	  /* Make sure this symbol is output as a dynamic symbol.
	     Undefined weak syms won't yet be marked as dynamic.  */
	  if (h->dynindx == -1
	      && !h->forced_local)
	    {
	      if (! bfd_elf_link_record_dynamic_symbol (info, h))
		return FALSE;
	    }

	  /* If that succeeded, we know we'll be keeping all the
	     relocs.  */
	  if (h->dynindx != -1)
	    goto keep;
	}

      eh->dyn_relocs = NULL;

    keep: ;
    }

  /* Finally, allocate space.  */
  for (p = eh->dyn_relocs; p != NULL; p = p->next)
    {
      asection *sreloc = elf_section_data (p->sec)->sreloc;
      sreloc->size += p->count * sizeof (ElfNN_External_Rela);
    }

  return TRUE;
}

/* Set DF_TEXTREL if we find any dynamic relocs that apply to
   read-only sections.  */

static bfd_boolean
maybe_set_textrel (struct elf_link_hash_entry *h, void *info_p)
{
  asection *sec;

  if (h->root.type == bfd_link_hash_indirect)
    return TRUE;

  sec = readonly_dynrelocs (h);
  if (sec != NULL)
    {
      struct bfd_link_info *info = (struct bfd_link_info *) info_p;

      info->flags |= DF_TEXTREL;
      info->callbacks->minfo
	(_("%pB: dynamic relocation against `%pT' in read-only section `%pA'\n"),
	 sec->owner, h->root.root.string, sec);

      /* Not an error, just cut short the traversal.  */
      return FALSE;
    }
  return TRUE;
}

static bfd_boolean
riscv_elf_size_dynamic_sections (bfd *output_bfd, struct bfd_link_info *info)
{
  struct riscv_elf_link_hash_table *htab;
  bfd *dynobj;
  asection *s;
  bfd *ibfd;

  htab = riscv_elf_hash_table (info);
  BFD_ASSERT (htab != NULL);
  dynobj = htab->elf.dynobj;
  BFD_ASSERT (dynobj != NULL);

  if (elf_hash_table (info)->dynamic_sections_created)
    {
      /* Set the contents of the .interp section to the interpreter.  */
      if (bfd_link_executable (info) && !info->nointerp)
	{
	  s = bfd_get_linker_section (dynobj, ".interp");
	  BFD_ASSERT (s != NULL);
	  s->size = strlen (ELFNN_DYNAMIC_INTERPRETER) + 1;
	  s->contents = (unsigned char *) ELFNN_DYNAMIC_INTERPRETER;
	}
    }

  /* Set up .got offsets for local syms, and space for local dynamic
     relocs.  */
  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    {
      bfd_signed_vma *local_got;
      bfd_signed_vma *end_local_got;
      char *local_tls_type;
      bfd_size_type locsymcount;
      Elf_Internal_Shdr *symtab_hdr;
      asection *srel;

      if (! is_riscv_elf (ibfd))
	continue;

      for (s = ibfd->sections; s != NULL; s = s->next)
	{
	  struct elf_dyn_relocs *p;

	  for (p = elf_section_data (s)->local_dynrel; p != NULL; p = p->next)
	    {
	      if (!bfd_is_abs_section (p->sec)
		  && bfd_is_abs_section (p->sec->output_section))
		{
		  /* Input section has been discarded, either because
		     it is a copy of a linkonce section or due to
		     linker script /DISCARD/, so we'll be discarding
		     the relocs too.  */
		}
	      else if (p->count != 0)
		{
		  srel = elf_section_data (p->sec)->sreloc;
		  srel->size += p->count * sizeof (ElfNN_External_Rela);
		  if ((p->sec->output_section->flags & SEC_READONLY) != 0)
		    info->flags |= DF_TEXTREL;
		}
	    }
	}

      local_got = elf_local_got_refcounts (ibfd);
      if (!local_got)
	continue;

      symtab_hdr = &elf_symtab_hdr (ibfd);
      locsymcount = symtab_hdr->sh_info;
      end_local_got = local_got + locsymcount;
      local_tls_type = _bfd_riscv_elf_local_got_tls_type (ibfd);
      s = htab->elf.sgot;
      srel = htab->elf.srelgot;
      for (; local_got < end_local_got; ++local_got, ++local_tls_type)
	{
	  if (*local_got > 0)
	    {
	      *local_got = s->size;
	      s->size += RISCV_ELF_WORD_BYTES;
	      if (*local_tls_type & GOT_TLS_GD)
		s->size += RISCV_ELF_WORD_BYTES;
	      if (bfd_link_pic (info)
		  || (*local_tls_type & (GOT_TLS_GD | GOT_TLS_IE)))
		srel->size += sizeof (ElfNN_External_Rela);
	    }
	  else
	    *local_got = (bfd_vma) -1;
	}
    }

  /* Allocate global sym .plt and .got entries, and space for global
     sym dynamic relocs.  */
  elf_link_hash_traverse (&htab->elf, allocate_dynrelocs, info);

  if (htab->elf.sgotplt)
    {
      struct elf_link_hash_entry *got;
      got = elf_link_hash_lookup (elf_hash_table (info),
				  "_GLOBAL_OFFSET_TABLE_",
				  FALSE, FALSE, FALSE);

      /* Don't allocate .got.plt section if there are no GOT nor PLT
	 entries and there is no refeence to _GLOBAL_OFFSET_TABLE_.  */
      if ((got == NULL
	   || !got->ref_regular_nonweak)
	  && (htab->elf.sgotplt->size == GOTPLT_HEADER_SIZE)
	  && (htab->elf.splt == NULL
	      || htab->elf.splt->size == 0)
	  && (htab->elf.sgot == NULL
	      || (htab->elf.sgot->size
		  == get_elf_backend_data (output_bfd)->got_header_size)))
	htab->elf.sgotplt->size = 0;
    }

  /* The check_relocs and adjust_dynamic_symbol entry points have
     determined the sizes of the various dynamic sections.  Allocate
     memory for them.  */
  for (s = dynobj->sections; s != NULL; s = s->next)
    {
      if ((s->flags & SEC_LINKER_CREATED) == 0)
	continue;

      if (s == htab->elf.splt
	  || s == htab->elf.sgot
	  || s == htab->elf.sgotplt
	  || s == htab->elf.sdynbss
	  || s == htab->elf.sdynrelro
	  || s == htab->sdyntdata)
	{
	  /* Strip this section if we don't need it; see the
	     comment below.  */
	}
      else if (strncmp (s->name, ".rela", 5) == 0)
	{
	  if (s->size != 0)
	    {
	      /* We use the reloc_count field as a counter if we need
		 to copy relocs into the output file.  */
	      s->reloc_count = 0;
	    }
	}
      else
	{
	  /* It's not one of our sections.  */
	  continue;
	}

      if (s->size == 0)
	{
	  /* If we don't need this section, strip it from the
	     output file.  This is mostly to handle .rela.bss and
	     .rela.plt.  We must create both sections in
	     create_dynamic_sections, because they must be created
	     before the linker maps input sections to output
	     sections.  The linker does that before
	     adjust_dynamic_symbol is called, and it is that
	     function which decides whether anything needs to go
	     into these sections.  */
	  s->flags |= SEC_EXCLUDE;
	  continue;
	}

      if ((s->flags & SEC_HAS_CONTENTS) == 0)
	continue;

      /* Allocate memory for the section contents.  Zero the memory
	 for the benefit of .rela.plt, which has 4 unused entries
	 at the beginning, and we don't want garbage.  */
      s->contents = (bfd_byte *) bfd_zalloc (dynobj, s->size);
      if (s->contents == NULL)
	return FALSE;
    }

  if (elf_hash_table (info)->dynamic_sections_created)
    {
      /* Add some entries to the .dynamic section.  We fill in the
	 values later, in riscv_elf_finish_dynamic_sections, but we
	 must add the entries now so that we get the correct size for
	 the .dynamic section.  The DT_DEBUG entry is filled in by the
	 dynamic linker and used by the debugger.  */
#define add_dynamic_entry(TAG, VAL) \
  _bfd_elf_add_dynamic_entry (info, TAG, VAL)

      if (bfd_link_executable (info))
	{
	  if (!add_dynamic_entry (DT_DEBUG, 0))
	    return FALSE;
	}

      if (htab->elf.srelplt->size != 0)
	{
	  if (!add_dynamic_entry (DT_PLTGOT, 0)
	      || !add_dynamic_entry (DT_PLTRELSZ, 0)
	      || !add_dynamic_entry (DT_PLTREL, DT_RELA)
	      || !add_dynamic_entry (DT_JMPREL, 0))
	    return FALSE;
	}

      if (!add_dynamic_entry (DT_RELA, 0)
	  || !add_dynamic_entry (DT_RELASZ, 0)
	  || !add_dynamic_entry (DT_RELAENT, sizeof (ElfNN_External_Rela)))
	return FALSE;

      /* If any dynamic relocs apply to a read-only section,
	 then we need a DT_TEXTREL entry.  */
      if ((info->flags & DF_TEXTREL) == 0)
	elf_link_hash_traverse (&htab->elf, maybe_set_textrel, info);

      if (info->flags & DF_TEXTREL)
	{
	  if (!add_dynamic_entry (DT_TEXTREL, 0))
	    return FALSE;
	}
    }
#undef add_dynamic_entry

  return TRUE;
}

#define TP_OFFSET 0
#define DTP_OFFSET 0x800

/* Return the relocation value for a TLS dtp-relative reloc.  */

static bfd_vma
dtpoff (struct bfd_link_info *info, bfd_vma address)
{
  /* If tls_sec is NULL, we should have signalled an error already.  */
  if (elf_hash_table (info)->tls_sec == NULL)
    return 0;
  return address - elf_hash_table (info)->tls_sec->vma - DTP_OFFSET;
}

/* Return the relocation value for a static TLS tp-relative relocation.  */

static bfd_vma
tpoff (struct bfd_link_info *info, bfd_vma address)
{
  /* If tls_sec is NULL, we should have signalled an error already.  */
  if (elf_hash_table (info)->tls_sec == NULL)
    return 0;
  return address - elf_hash_table (info)->tls_sec->vma - TP_OFFSET;
}

/* Return the global pointer's value, or 0 if it is not in use.  */

static bfd_vma
riscv_global_pointer_value (struct bfd_link_info *info)
{
  struct bfd_link_hash_entry *h;

  h = bfd_link_hash_lookup (info->hash, RISCV_GP_SYMBOL, FALSE, FALSE, TRUE);
  if (h == NULL || h->type != bfd_link_hash_defined)
    return 0;

  return h->u.def.value + sec_addr (h->u.def.section);
}

/* Return the symbol DATA_START_SYMBOLS value, or 0 if it is not in use.  */

static bfd_vma
riscv_data_start_value (struct bfd_link_info *info)
{
  struct bfd_link_hash_entry *h;

  h = bfd_link_hash_lookup (info->hash, "__DATA_BEGIN__", FALSE, FALSE, TRUE);
  if (h == NULL || h->type != bfd_link_hash_defined)
    return 0;

  return h->u.def.value + sec_addr (h->u.def.section);
}

/* Emplace a static relocation.  */

static bfd_reloc_status_type
perform_relocation (const reloc_howto_type *howto,
		    const Elf_Internal_Rela *rel,
		    bfd_vma value,
		    asection *input_section,
		    bfd *input_bfd,
		    bfd_byte *contents)
{
  if (howto->pc_relative)
    value -= sec_addr (input_section) + rel->r_offset;
  value += rel->r_addend;

  switch (ELFNN_R_TYPE (rel->r_info))
    {
    case R_RISCV_HI20:
    case R_RISCV_TPREL_HI20:
    case R_RISCV_PCREL_HI20:
    case R_RISCV_GOT_HI20:
    case R_RISCV_TLS_GOT_HI20:
    case R_RISCV_TLS_GD_HI20:
    case R_RISCV_LALO_HI20:
    case R_RISCV_ICT_HI20:
    case R_RISCV_PCREL_ICT_HI20:
      if (ARCH_SIZE > 32 && !VALID_UTYPE_IMM (RISCV_CONST_HIGH_PART (value)))
	return bfd_reloc_overflow;
      value = ENCODE_UTYPE_IMM (RISCV_CONST_HIGH_PART (value));
      break;

    case R_RISCV_LO12_I:
    case R_RISCV_GPREL_I:
    case R_RISCV_TPREL_LO12_I:
    case R_RISCV_TPREL_I:
    case R_RISCV_PCREL_LO12_I:
    case R_RISCV_LALO_LO12_I:
    case R_RISCV_ICT_LO12_I:
      value = ENCODE_ITYPE_IMM (value);
      break;

    case R_RISCV_LO12_S:
    case R_RISCV_GPREL_S:
    case R_RISCV_TPREL_LO12_S:
    case R_RISCV_TPREL_S:
    case R_RISCV_PCREL_LO12_S:
      value = ENCODE_STYPE_IMM (value);
      break;

    case R_RISCV_CALL:
    case R_RISCV_CALL_PLT:
    case R_RISCV_CALL_ICT:
      if (ARCH_SIZE > 32 && !VALID_UTYPE_IMM (RISCV_CONST_HIGH_PART (value)))
	return bfd_reloc_overflow;
      value = ENCODE_UTYPE_IMM (RISCV_CONST_HIGH_PART (value))
	      | (ENCODE_ITYPE_IMM (value) << 32);
      break;

    case R_RISCV_JAL:
      if (!VALID_UJTYPE_IMM (value))
	return bfd_reloc_overflow;
      value = ENCODE_UJTYPE_IMM (value);
      break;

    case R_RISCV_BRANCH:
      if (!VALID_SBTYPE_IMM (value))
	return bfd_reloc_overflow;
      value = ENCODE_SBTYPE_IMM (value);
      break;

    case R_RISCV_RVC_BRANCH:
      if (!VALID_RVC_B_IMM (value))
	return bfd_reloc_overflow;
      value = ENCODE_RVC_B_IMM (value);
      break;

    case R_RISCV_RVC_JUMP:
      if (!VALID_RVC_J_IMM (value))
	return bfd_reloc_overflow;
      value = ENCODE_RVC_J_IMM (value);
      break;

    case R_RISCV_RVC_LUI:
      if (!VALID_RVC_LUI_IMM (RISCV_CONST_HIGH_PART (value)))
	return bfd_reloc_overflow;
      value = ENCODE_RVC_LUI_IMM (RISCV_CONST_HIGH_PART (value));
      /* If value is zero, convert it to c.li.  */
      if (value == 0)
	{
	  bfd_vma insn = bfd_get_16 (input_bfd, contents + rel->r_offset);
	  int rd = (insn >> 7) & 0x1f;
	  bfd_vma word = MATCH_C_LI | (rd << 7);
	  bfd_put (16, input_bfd, word, contents + rel->r_offset);
	  return bfd_reloc_ok;
	}
      break;

    case R_RISCV_10_PCREL:
      if (!VALID_SBTYPE_IMM (value))
	return bfd_reloc_overflow;
      value = ENCODE_STYPE_IMM10 (value);
      break;

    case R_RISCV_LGP18S0:
      if (!VALID_GPTYPE_LB_IMM (value))
	return bfd_reloc_overflow;
      value = ENCODE_GPTYPE_LB_IMM (value);
      break;

    case R_RISCV_LGP17S1:
      if (!VALID_GPTYPE_LH_IMM (value))
	return bfd_reloc_overflow;
      value = ENCODE_GPTYPE_LH_IMM (value);
      break;

    case R_RISCV_LGP17S2:
      if (!VALID_GPTYPE_LW_IMM (value))
	return bfd_reloc_overflow;
      value = ENCODE_GPTYPE_LW_IMM (value);
      break;

    case R_RISCV_LGP17S3:
      if (!VALID_GPTYPE_LD_IMM (value))
	return bfd_reloc_overflow;
      value = ENCODE_GPTYPE_LD_IMM (value);
      break;

    case R_RISCV_SGP18S0:
      if (!VALID_GPTYPE_SB_IMM (value))
	return bfd_reloc_overflow;
      value = ENCODE_GPTYPE_SB_IMM (value);
      break;

    case R_RISCV_SGP17S1:
      if (!VALID_GPTYPE_SH_IMM (value))
	return bfd_reloc_overflow;
      value = ENCODE_GPTYPE_SH_IMM (value);
      break;

    case R_RISCV_SGP17S2:
      if (!VALID_GPTYPE_SW_IMM (value))
	return bfd_reloc_overflow;
      value = ENCODE_GPTYPE_SW_IMM (value);
      break;

    case R_RISCV_SGP17S3:
      if (!VALID_GPTYPE_SD_IMM (value))
	return bfd_reloc_overflow;
      value = ENCODE_GPTYPE_SD_IMM (value);
      break;

    case R_RISCV_32:
    case R_RISCV_64:
    case R_RISCV_ADD8:
    case R_RISCV_ADD16:
    case R_RISCV_ADD32:
    case R_RISCV_ADD64:
    case R_RISCV_SUB6:
    case R_RISCV_SUB8:
    case R_RISCV_SUB16:
    case R_RISCV_SUB32:
    case R_RISCV_SUB64:
    case R_RISCV_SET6:
    case R_RISCV_SET8:
    case R_RISCV_SET16:
    case R_RISCV_SET32:
    case R_RISCV_32_PCREL:
    case R_RISCV_TLS_DTPREL32:
    case R_RISCV_TLS_DTPREL64:
    case R_RISCV_ICT_64:
      break;

    case R_RISCV_DELETE:
      return bfd_reloc_ok;

    default:
      return bfd_reloc_notsupported;
    }

  bfd_vma word = bfd_get (howto->bitsize, input_bfd, contents + rel->r_offset);
  word = (word & ~howto->dst_mask) | (value & howto->dst_mask);
  bfd_put (howto->bitsize, input_bfd, word, contents + rel->r_offset);

  return bfd_reloc_ok;
}

/* Remember all PC-relative high-part relocs we've encountered to help us
   later resolve the corresponding low-part relocs.  */

typedef struct
{
  bfd_vma address;
  bfd_vma value;
} riscv_pcrel_hi_reloc;

typedef struct riscv_pcrel_lo_reloc
{
  asection *			 input_section;
  struct bfd_link_info *	 info;
  reloc_howto_type *		 howto;
  const Elf_Internal_Rela *	 reloc;
  bfd_vma			 addr;
  const char *			 name;
  bfd_byte *			 contents;
  struct riscv_pcrel_lo_reloc *	 next;
} riscv_pcrel_lo_reloc;

typedef struct
{
  htab_t hi_relocs;
  riscv_pcrel_lo_reloc *lo_relocs;
} riscv_pcrel_relocs;

static hashval_t
riscv_pcrel_reloc_hash (const void *entry)
{
  const riscv_pcrel_hi_reloc *e = entry;
  return (hashval_t)(e->address >> 2);
}

static bfd_boolean
riscv_pcrel_reloc_eq (const void *entry1, const void *entry2)
{
  const riscv_pcrel_hi_reloc *e1 = entry1, *e2 = entry2;
  return e1->address == e2->address;
}

static bfd_boolean
riscv_init_pcrel_relocs (riscv_pcrel_relocs *p)
{

  p->lo_relocs = NULL;
  p->hi_relocs = htab_create (1024, riscv_pcrel_reloc_hash,
			      riscv_pcrel_reloc_eq, free);
  return p->hi_relocs != NULL;
}

static void
riscv_free_pcrel_relocs (riscv_pcrel_relocs *p)
{
  riscv_pcrel_lo_reloc *cur = p->lo_relocs;

  while (cur != NULL)
    {
      riscv_pcrel_lo_reloc *next = cur->next;
      free (cur);
      cur = next;
    }

  htab_delete (p->hi_relocs);
}

static bfd_boolean
riscv_zero_pcrel_hi_reloc (Elf_Internal_Rela *rel,
			   struct bfd_link_info *info,
			   bfd_vma pc,
			   bfd_vma addr,
			   bfd_byte *contents,
			   const reloc_howto_type *howto,
			   bfd *input_bfd)
{
  /* We may need to reference low addreses in PC-relative modes even when the
   * PC is far away from these addresses.  For example, undefweak references
   * need to produce the address 0 when linked.  As 0 is far from the arbitrary
   * addresses that we can link PC-relative programs at, the linker can't
   * actually relocate references to those symbols.  In order to allow these
   * programs to work we simply convert the PC-relative auipc sequences to
   * 0-relative lui sequences.  */
  if (bfd_link_pic (info))
    return FALSE;

  /* If it's possible to reference the symbol using auipc we do so, as that's
   * more in the spirit of the PC-relative relocations we're processing.  */
  bfd_vma offset = addr - pc;
  if (ARCH_SIZE == 32 || VALID_UTYPE_IMM (RISCV_CONST_HIGH_PART (offset)))
    return FALSE;

  /* If it's impossible to reference this with a LUI-based offset then don't
   * bother to convert it at all so users still see the PC-relative relocation
   * in the truncation message.  */
  if (ARCH_SIZE > 32 && !VALID_UTYPE_IMM (RISCV_CONST_HIGH_PART (addr)))
    return FALSE;

  rel->r_info = ELFNN_R_INFO(addr, R_RISCV_HI20);

  bfd_vma insn = bfd_get(howto->bitsize, input_bfd, contents + rel->r_offset);
  insn = (insn & ~MASK_AUIPC) | MATCH_LUI;
  bfd_put(howto->bitsize, input_bfd, insn, contents + rel->r_offset);
  return TRUE;
}

static bfd_boolean
riscv_record_pcrel_hi_reloc (riscv_pcrel_relocs *p, bfd_vma addr,
			     bfd_vma value, bfd_boolean absolute)
{
  bfd_vma offset = absolute ? value : value - addr;
  riscv_pcrel_hi_reloc entry = {addr, offset};
  riscv_pcrel_hi_reloc **slot =
    (riscv_pcrel_hi_reloc **) htab_find_slot (p->hi_relocs, &entry, INSERT);

  BFD_ASSERT (*slot == NULL);
  *slot = (riscv_pcrel_hi_reloc *) bfd_malloc (sizeof (riscv_pcrel_hi_reloc));
  if (*slot == NULL)
    return FALSE;
  **slot = entry;
  return TRUE;
}

static bfd_boolean
riscv_record_pcrel_lo_reloc (riscv_pcrel_relocs *p,
			     asection *input_section,
			     struct bfd_link_info *info,
			     reloc_howto_type *howto,
			     const Elf_Internal_Rela *reloc,
			     bfd_vma addr,
			     const char *name,
			     bfd_byte *contents)
{
  riscv_pcrel_lo_reloc *entry;
  entry = (riscv_pcrel_lo_reloc *) bfd_malloc (sizeof (riscv_pcrel_lo_reloc));
  if (entry == NULL)
    return FALSE;
  *entry = (riscv_pcrel_lo_reloc) {input_section, info, howto, reloc, addr,
				   name, contents, p->lo_relocs};
  p->lo_relocs = entry;
  return TRUE;
}

static bfd_boolean
riscv_resolve_pcrel_lo_relocs (riscv_pcrel_relocs *p)
{
  riscv_pcrel_lo_reloc *r;

  for (r = p->lo_relocs; r != NULL; r = r->next)
    {
      bfd *input_bfd = r->input_section->owner;

      riscv_pcrel_hi_reloc search = {r->addr, 0};
      riscv_pcrel_hi_reloc *entry = htab_find (p->hi_relocs, &search);
      if (entry == NULL
	  /* Check for overflow into bit 11 when adding reloc addend.  */
	  || (! (entry->value & 0x800)
	      && ((entry->value + r->reloc->r_addend) & 0x800)))
	{
	  char *string = (entry == NULL
			  ? "%pcrel_lo missing matching %pcrel_hi"
			  : "%pcrel_lo overflow with an addend");
	  (*r->info->callbacks->reloc_dangerous)
	    (r->info, string, input_bfd, r->input_section, r->reloc->r_offset);
	  return TRUE;
	}

      perform_relocation (r->howto, r->reloc, entry->value, r->input_section,
			  input_bfd, r->contents);
    }

  return TRUE;
}

/* Relocate a RISC-V ELF section.

   The RELOCATE_SECTION function is called by the new ELF backend linker
   to handle the relocations for a section.

   The relocs are always passed as Rela structures.

   This function is responsible for adjusting the section contents as
   necessary, and (if generating a relocatable output file) adjusting
   the reloc addend as necessary.

   This function does not have to worry about setting the reloc
   address or the reloc symbol index.

   LOCAL_SYMS is a pointer to the swapped in local symbols.

   LOCAL_SECTIONS is an array giving the section in the input file
   corresponding to the st_shndx field of each local symbol.

   The global hash table entry for the global symbols can be found
   via elf_sym_hashes (input_bfd).

   When generating relocatable output, this function must handle
   STB_LOCAL/STT_SECTION symbols specially.  The output symbol is
   going to be the section symbol corresponding to the output
   section, which means that the addend must be adjusted
   accordingly.  */

static bfd_boolean
riscv_elf_relocate_section (bfd *output_bfd,
			    struct bfd_link_info *info,
			    bfd *input_bfd,
			    asection *input_section,
			    bfd_byte *contents,
			    Elf_Internal_Rela *relocs,
			    Elf_Internal_Sym *local_syms,
			    asection **local_sections)
{
  Elf_Internal_Rela *rel;
  Elf_Internal_Rela *relend;
  riscv_pcrel_relocs pcrel_relocs;
  bfd_boolean ret = FALSE;
  asection *sreloc = elf_section_data (input_section)->sreloc;
  struct riscv_elf_link_hash_table *htab = riscv_elf_hash_table (info);
  Elf_Internal_Shdr *symtab_hdr = &elf_symtab_hdr (input_bfd);
  struct elf_link_hash_entry **sym_hashes = elf_sym_hashes (input_bfd);
  bfd_vma *local_got_offsets = elf_local_got_offsets (input_bfd);
  bfd_boolean absolute;

  if (!riscv_init_pcrel_relocs (&pcrel_relocs))
    return FALSE;

  if (is_ITB_BASE_set == 0)
    {
      /* Set the _ITB_BASE_.  */
      if (!riscv_elf_execit_itb_base (info))
	{
	  (*_bfd_error_handler) (_("%pB: error: Cannot set _ITB_BASE_"),
				 output_bfd);
	  bfd_set_error (bfd_error_bad_value);
	}
    }

  /* Relocation for .exec.itable.  */
  if (htab->target_optimize & RISCV_RELAX_EXECIT_ON)
    riscv_elf_relocate_execit_table (info, input_bfd);

  /* Before relocating the ict table, we should order the
     ict hash entries according to the `entry->order'.  */
  riscv_elf_ict_hash_to_exported_table ();
  /* Relocation for .nds.ict table.  */
  /* When compiling the patch code, we don't need to relocate
     the imported ict table in the riscv_elf_relocate_ict_table
     since the imported ict table already have it's relocations.  */
  if (!find_imported_ict_table
      && exported_ict_table_head)
    riscv_elf_relocate_ict_table (info, output_bfd);

  relend = relocs + input_section->reloc_count;
  for (rel = relocs; rel < relend; rel++)
    {
      unsigned long r_symndx;
      struct elf_link_hash_entry *h;
      Elf_Internal_Sym *sym;
      asection *sec;
      bfd_vma relocation;
      bfd_reloc_status_type r = bfd_reloc_ok;
      const char *name;
      bfd_vma off, ie_off;
      bfd_boolean unresolved_reloc, is_ie = FALSE;
      bfd_vma pc = sec_addr (input_section) + rel->r_offset;
      int r_type = ELFNN_R_TYPE (rel->r_info), tls_type;
      reloc_howto_type *howto = riscv_elf_rtype_to_howto (input_bfd, r_type);
      const char *msg = NULL;
      bfd_boolean resolved_to_zero;

      if (howto == NULL
	  || r_type == R_RISCV_GNU_VTINHERIT
	  || r_type == R_RISCV_GNU_VTENTRY
	  || r_type == R_RISCV_DATA
	  || r_type == R_RISCV_RELAX_ENTRY
	  || r_type == R_RISCV_ALIGN
	  || r_type == R_RISCV_RELAX_REGION_BEGIN
	  || r_type == R_RISCV_RELAX_REGION_END
	  || r_type == R_RISCV_NO_RVC_REGION_BEGIN
	  || r_type == R_RISCV_NO_RVC_REGION_END)
	continue;

      /* This is a final link.  */
      r_symndx = ELFNN_R_SYM (rel->r_info);
      h = NULL;
      sym = NULL;
      sec = NULL;
      unresolved_reloc = FALSE;
      if (r_symndx < symtab_hdr->sh_info)
	{
	  sym = local_syms + r_symndx;
	  sec = local_sections[r_symndx];
	  relocation = _bfd_elf_rela_local_sym (output_bfd, sym, &sec, rel);
	}
      else
	{
	  bfd_boolean warned, ignored;

	  RELOC_FOR_GLOBAL_SYMBOL (info, input_bfd, input_section, rel,
				   r_symndx, symtab_hdr, sym_hashes,
				   h, sec, relocation,
				   unresolved_reloc, warned, ignored);
	  if (warned)
	    {
	      /* To avoid generating warning messages about truncated
		 relocations, set the relocation's address to be the same as
		 the start of this section.  */
	      if (input_section->output_section != NULL)
		relocation = input_section->output_section->vma;
	      else
		relocation = 0;
	    }
	}

      if (sec != NULL && discarded_section (sec))
	RELOC_AGAINST_DISCARDED_SECTION (info, input_bfd, input_section,
					 rel, 1, relend, howto, 0, contents);

      if (bfd_link_relocatable (info))
	continue;

      if (h != NULL)
	name = h->root.root.string;
      else
	{
	  name = (bfd_elf_string_from_elf_section
		  (input_bfd, symtab_hdr->sh_link, sym->st_name));
	  if (name == NULL || *name == '\0')
	    name = bfd_section_name (input_bfd, sec);
	}

      resolved_to_zero = (h != NULL
			  && UNDEFWEAK_NO_DYNAMIC_RELOC (info, h));

      /* We don't allow any mixed indirect call function.  */
      if (find_imported_ict_table
	  && input_section == bfd_get_section_by_name (input_bfd, ".nds.ict"))
	{
	  /* Don't need to check the mixed ict cases for the
	     imported ict table at the second link-time.  */
	}
      else if (h && riscv_elf_hash_entry (h)->indirect_call
	       && r_type != R_RISCV_ICT_HI20
	       && r_type != R_RISCV_ICT_LO12_I
	       && r_type != R_RISCV_PCREL_ICT_HI20
	       && r_type != R_RISCV_CALL_ICT
	       && r_type != R_RISCV_ICT_64)
	{
	  (*_bfd_error_handler)
	    (_("%pB: Error: there are mixed indirect call function \'%s\' "
	       "in the ICT model\n"),
	     input_bfd, h->root.root.string);
	  return FALSE;
	}

      switch (r_type)
	{
	case R_RISCV_NONE:
	case R_RISCV_RELAX:
	case R_RISCV_TPREL_ADD:
	case R_RISCV_COPY:
	case R_RISCV_JUMP_SLOT:
	case R_RISCV_RELATIVE:
	  /* These require nothing of us at all.  */
	  continue;

	case R_RISCV_HI20:
	case R_RISCV_BRANCH:
	case R_RISCV_RVC_BRANCH:
	case R_RISCV_RVC_LUI:
	case R_RISCV_LO12_I:
	case R_RISCV_LO12_S:
	case R_RISCV_SET6:
	case R_RISCV_SET8:
	case R_RISCV_SET16:
	case R_RISCV_SET32:
	case R_RISCV_32_PCREL:
	case R_RISCV_10_PCREL:
	case R_RISCV_DELETE:
	  /* These require no special handling beyond perform_relocation.  */
	  break;

	case R_RISCV_LALO_HI20:
	case R_RISCV_LALO_LO12_I:
	  relocation &= 0xffffffff;
	  break;

	case R_RISCV_LGP18S0:
	case R_RISCV_LGP17S1:
	case R_RISCV_LGP17S2:
	case R_RISCV_LGP17S3:
	case R_RISCV_SGP18S0:
	case R_RISCV_SGP17S1:
	case R_RISCV_SGP17S2:
	case R_RISCV_SGP17S3:
	  {
	    bfd_vma gp = riscv_global_pointer_value (info);
	    relocation -= gp;
	    unresolved_reloc = FALSE;
	    break;
	  }

	case R_RISCV_GOT_HI20:
	  if (h != NULL)
	    {
	      bfd_boolean dyn, pic;

	      off = h->got.offset;
	      BFD_ASSERT (off != (bfd_vma) -1);
	      dyn = elf_hash_table (info)->dynamic_sections_created;
	      pic = bfd_link_pic (info);

	      if (! WILL_CALL_FINISH_DYNAMIC_SYMBOL (dyn, pic, h)
		  || (pic && SYMBOL_REFERENCES_LOCAL (info, h)))
		{
		  /* This is actually a static link, or it is a
		     -Bsymbolic link and the symbol is defined
		     locally, or the symbol was forced to be local
		     because of a version file.  We must initialize
		     this entry in the global offset table.  Since the
		     offset must always be a multiple of the word size,
		     we use the least significant bit to record whether
		     we have initialized it already.

		     When doing a dynamic link, we create a .rela.got
		     relocation entry to initialize the value.  This
		     is done in the finish_dynamic_symbol routine.  */
		  if ((off & 1) != 0)
		    off &= ~1;
		  else
		    {
		      bfd_put_NN (output_bfd, relocation,
				  htab->elf.sgot->contents + off);
		      h->got.offset |= 1;
		    }
		}
	      else
		unresolved_reloc = FALSE;
	    }
	  else
	    {
	      BFD_ASSERT (local_got_offsets != NULL
			  && local_got_offsets[r_symndx] != (bfd_vma) -1);

	      off = local_got_offsets[r_symndx];

	      /* The offset must always be a multiple of the word size.
		 So, we can use the least significant bit to record
		 whether we have already processed this entry.  */
	      if ((off & 1) != 0)
		off &= ~1;
	      else
		{
		  if (bfd_link_pic (info))
		    {
		      asection *s;
		      Elf_Internal_Rela outrel;

		      /* We need to generate a R_RISCV_RELATIVE reloc
			 for the dynamic linker.  */
		      s = htab->elf.srelgot;
		      BFD_ASSERT (s != NULL);

		      outrel.r_offset = sec_addr (htab->elf.sgot) + off;
		      outrel.r_info =
			ELFNN_R_INFO (0, R_RISCV_RELATIVE);
		      outrel.r_addend = relocation;
		      relocation = 0;
		      riscv_elf_append_rela (output_bfd, s, &outrel);
		    }

		  bfd_put_NN (output_bfd, relocation,
			      htab->elf.sgot->contents + off);
		  local_got_offsets[r_symndx] |= 1;
		}
	    }
	  relocation = sec_addr (htab->elf.sgot) + off;
	  absolute = riscv_zero_pcrel_hi_reloc (rel,
						info,
						pc,
						relocation,
						contents,
						howto,
						input_bfd);
	  r_type = ELFNN_R_TYPE (rel->r_info);
	  howto = riscv_elf_rtype_to_howto (input_bfd, r_type);
	  if (howto == NULL)
	    r = bfd_reloc_notsupported;
	  else if (!riscv_record_pcrel_hi_reloc (&pcrel_relocs, pc,
						 relocation, absolute))
	    r = bfd_reloc_overflow;
	  break;

	case R_RISCV_ADD8:
	case R_RISCV_ADD16:
	case R_RISCV_ADD32:
	case R_RISCV_ADD64:
	  {
	    bfd_vma old_value = bfd_get (howto->bitsize, input_bfd,
					 contents + rel->r_offset);
	    relocation = old_value + relocation;
	  }
	  break;

	case R_RISCV_SUB6:
	case R_RISCV_SUB8:
	case R_RISCV_SUB16:
	case R_RISCV_SUB32:
	case R_RISCV_SUB64:
	  {
	    bfd_vma old_value = bfd_get (howto->bitsize, input_bfd,
					 contents + rel->r_offset);
	    relocation = old_value - relocation;
	  }
	  break;

	case R_RISCV_CALL:
	  /* Handle a call to an undefined weak function.  This won't be
	     relaxed, so we have to handle it here.  */
	  if (h != NULL && h->root.type == bfd_link_hash_undefweak
	      && h->plt.offset == MINUS_ONE)
	    {
	      /* We can use x0 as the base register.  */
	      bfd_vma insn = bfd_get_32 (input_bfd,
					 contents + rel->r_offset + 4);
	      insn &= ~(OP_MASK_RS1 << OP_SH_RS1);
	      bfd_put_32 (input_bfd, insn, contents + rel->r_offset + 4);
	      /* Set the relocation value so that we get 0 after the pc
		 relative adjustment.  */
	      relocation = sec_addr (input_section) + rel->r_offset;
	    }
	  /* Fall through.  */

	case R_RISCV_CALL_PLT:
	case R_RISCV_JAL:
	case R_RISCV_RVC_JUMP:
	  if (bfd_link_pic (info) && h != NULL && h->plt.offset != MINUS_ONE)
	    {
	      /* Refer to the PLT entry.  */
	      relocation = sec_addr (htab->elf.splt) + h->plt.offset;
	      unresolved_reloc = FALSE;
	    }
	  break;

	case R_RISCV_TPREL_HI20:
	  relocation = tpoff (info, relocation);
	  break;

	case R_RISCV_TPREL_LO12_I:
	case R_RISCV_TPREL_LO12_S:
	  relocation = tpoff (info, relocation);
	  break;

	case R_RISCV_TPREL_I:
	case R_RISCV_TPREL_S:
	  relocation = tpoff (info, relocation);
	  if (VALID_ITYPE_IMM (relocation + rel->r_addend))
	    {
	      /* We can use tp as the base register.  */
	      bfd_vma insn = bfd_get_32 (input_bfd, contents + rel->r_offset);
	      insn &= ~(OP_MASK_RS1 << OP_SH_RS1);
	      insn |= X_TP << OP_SH_RS1;
	      bfd_put_32 (input_bfd, insn, contents + rel->r_offset);
	    }
	  else
	    r = bfd_reloc_overflow;
	  break;

	case R_RISCV_GPREL_I:
	case R_RISCV_GPREL_S:
	  {
	    bfd_vma gp = riscv_global_pointer_value (info);
	    bfd_boolean x0_base = VALID_ITYPE_IMM (relocation + rel->r_addend);
	    if (x0_base || VALID_ITYPE_IMM (relocation + rel->r_addend - gp))
	      {
		/* We can use x0 or gp as the base register.  */
		bfd_vma insn = bfd_get_32 (input_bfd, contents + rel->r_offset);
		insn &= ~(OP_MASK_RS1 << OP_SH_RS1);
		if (!x0_base)
		  {
		    rel->r_addend -= gp;
		    insn |= X_GP << OP_SH_RS1;
		  }
		bfd_put_32 (input_bfd, insn, contents + rel->r_offset);
	      }
	    else
	      r = bfd_reloc_overflow;
	    break;
	  }

	case R_RISCV_PCREL_HI20:
	  absolute = riscv_zero_pcrel_hi_reloc (rel,
						info,
						pc,
						relocation,
						contents,
						howto,
						input_bfd);
	  r_type = ELFNN_R_TYPE (rel->r_info);
	  howto = riscv_elf_rtype_to_howto (input_bfd, r_type);
	  if (howto == NULL)
	    r = bfd_reloc_notsupported;
	  else if (!riscv_record_pcrel_hi_reloc (&pcrel_relocs, pc,
						 relocation + rel->r_addend,
						 absolute))
	    r = bfd_reloc_overflow;
	  break;

	case R_RISCV_PCREL_LO12_I:
	case R_RISCV_PCREL_LO12_S:
	  /* We don't allow section symbols plus addends as the auipc address,
	     because then riscv_relax_delete_bytes would have to search through
	     all relocs to update these addends.  This is also ambiguous, as
	     we do allow offsets to be added to the target address, which are
	     not to be used to find the auipc address.  */
	  if ((ELF_ST_TYPE (sym->st_info) == STT_SECTION) && rel->r_addend)
	    {
	      r = bfd_reloc_dangerous;
	      break;
	    }

	  if (riscv_record_pcrel_lo_reloc (&pcrel_relocs, input_section, info,
					   howto, rel, relocation, name,
					   contents))
	    continue;
	  r = bfd_reloc_overflow;
	  break;

	case R_RISCV_TLS_DTPREL32:
	case R_RISCV_TLS_DTPREL64:
	  relocation = dtpoff (info, relocation);
	  break;

	case R_RISCV_32:
	case R_RISCV_64:
	  if ((input_section->flags & SEC_ALLOC) == 0)
	    break;

	  if ((bfd_link_pic (info)
	       && (h == NULL
		   || (ELF_ST_VISIBILITY (h->other) == STV_DEFAULT
		       && !resolved_to_zero)
		   || h->root.type != bfd_link_hash_undefweak)
	       && (! howto->pc_relative
		   || !SYMBOL_CALLS_LOCAL (info, h)))
	      || (!bfd_link_pic (info)
		  && h != NULL
		  && h->dynindx != -1
		  && !h->non_got_ref
		  && ((h->def_dynamic
		       && !h->def_regular)
		      || h->root.type == bfd_link_hash_undefweak
		      || h->root.type == bfd_link_hash_undefined)))
	    {
	      Elf_Internal_Rela outrel;
	      bfd_boolean skip_static_relocation, skip_dynamic_relocation;
	      bfd_boolean dyn;

	      /* When generating a shared object, these relocations
		 are copied into the output file to be resolved at run
		 time.  */

	      outrel.r_offset =
		_bfd_elf_section_offset (output_bfd, info, input_section,
					 rel->r_offset);
	      skip_static_relocation = outrel.r_offset != (bfd_vma) -2;
	      skip_dynamic_relocation = outrel.r_offset >= (bfd_vma) -2;
	      outrel.r_offset += sec_addr (input_section);

	      dyn = elf_hash_table (info)->dynamic_sections_created;
	      if (sreloc == NULL && dyn)
		{
		  sreloc = _bfd_elf_get_dynamic_reloc_section
		    (input_bfd, input_section,
		     TRUE);

		  if (sreloc == NULL)
		    return bfd_reloc_notsupported;
		}

	      if (skip_dynamic_relocation)
		memset (&outrel, 0, sizeof outrel);
	      else if (h != NULL && h->dynindx != -1
		       && !(bfd_link_pic (info)
			    && SYMBOLIC_BIND (info, h)
			    && h->def_regular))
		{
		  outrel.r_info = ELFNN_R_INFO (h->dynindx, r_type);
		  outrel.r_addend = rel->r_addend;
		}
	      else
		{
		  outrel.r_info = ELFNN_R_INFO (0, R_RISCV_RELATIVE);
		  outrel.r_addend = relocation + rel->r_addend;
		}

	      riscv_elf_append_rela (output_bfd, sreloc, &outrel);
	      if (skip_static_relocation)
		continue;
	    }
	  break;

	case R_RISCV_TLS_GOT_HI20:
	  is_ie = TRUE;
	  /* Fall through.  */

	case R_RISCV_TLS_GD_HI20:
	  if (h != NULL)
	    {
	      off = h->got.offset;
	      h->got.offset |= 1;
	    }
	  else
	    {
	      off = local_got_offsets[r_symndx];
	      local_got_offsets[r_symndx] |= 1;
	    }

	  tls_type = _bfd_riscv_elf_tls_type (input_bfd, h, r_symndx);
	  BFD_ASSERT (tls_type & (GOT_TLS_IE | GOT_TLS_GD));
	  /* If this symbol is referenced by both GD and IE TLS, the IE
	     reference's GOT slot follows the GD reference's slots.  */
	  ie_off = 0;
	  if ((tls_type & GOT_TLS_GD) && (tls_type & GOT_TLS_IE))
	    ie_off = 2 * GOT_ENTRY_SIZE;

	  if ((off & 1) != 0)
	    off &= ~1;
	  else
	    {
	      Elf_Internal_Rela outrel;
	      int indx = 0;
	      bfd_boolean need_relocs = FALSE;

	      if (htab->elf.srelgot == NULL)
		abort ();

	      if (h != NULL)
		{
		  bfd_boolean dyn, pic;
		  dyn = htab->elf.dynamic_sections_created;
		  pic = bfd_link_pic (info);

		  if (WILL_CALL_FINISH_DYNAMIC_SYMBOL (dyn, pic, h)
		      && (!pic || !SYMBOL_REFERENCES_LOCAL (info, h)))
		    indx = h->dynindx;
		}

	      /* The GOT entries have not been initialized yet.  Do it
		 now, and emit any relocations.  */
	      if ((bfd_link_pic (info) || indx != 0)
		  && (h == NULL
		      || ELF_ST_VISIBILITY (h->other) == STV_DEFAULT
		      || h->root.type != bfd_link_hash_undefweak))
		    need_relocs = TRUE;

	      if (tls_type & GOT_TLS_GD)
		{
		  if (need_relocs)
		    {
		      outrel.r_offset = sec_addr (htab->elf.sgot) + off;
		      outrel.r_addend = 0;
		      outrel.r_info = ELFNN_R_INFO (indx, R_RISCV_TLS_DTPMODNN);
		      bfd_put_NN (output_bfd, 0,
				  htab->elf.sgot->contents + off);
		      riscv_elf_append_rela (output_bfd, htab->elf.srelgot, &outrel);
		      if (indx == 0)
			{
			  BFD_ASSERT (! unresolved_reloc);
			  bfd_put_NN (output_bfd,
				      dtpoff (info, relocation),
				      (htab->elf.sgot->contents + off +
				       RISCV_ELF_WORD_BYTES));
			}
		      else
			{
			  bfd_put_NN (output_bfd, 0,
				      (htab->elf.sgot->contents + off +
				       RISCV_ELF_WORD_BYTES));
			  outrel.r_info = ELFNN_R_INFO (indx, R_RISCV_TLS_DTPRELNN);
			  outrel.r_offset += RISCV_ELF_WORD_BYTES;
			  riscv_elf_append_rela (output_bfd, htab->elf.srelgot, &outrel);
			}
		    }
		  else
		    {
		      /* If we are not emitting relocations for a
			 general dynamic reference, then we must be in a
			 static link or an executable link with the
			 symbol binding locally.  Mark it as belonging
			 to module 1, the executable.  */
		      bfd_put_NN (output_bfd, 1,
				  htab->elf.sgot->contents + off);
		      bfd_put_NN (output_bfd,
				  dtpoff (info, relocation),
				  (htab->elf.sgot->contents + off +
				   RISCV_ELF_WORD_BYTES));
		   }
		}

	      if (tls_type & GOT_TLS_IE)
		{
		  if (need_relocs)
		    {
		      bfd_put_NN (output_bfd, 0,
				  htab->elf.sgot->contents + off + ie_off);
		      outrel.r_offset = sec_addr (htab->elf.sgot)
				       + off + ie_off;
		      outrel.r_addend = 0;
		      if (indx == 0)
			outrel.r_addend = tpoff (info, relocation);
		      outrel.r_info = ELFNN_R_INFO (indx, R_RISCV_TLS_TPRELNN);
		      riscv_elf_append_rela (output_bfd, htab->elf.srelgot, &outrel);
		    }
		  else
		    {
		      bfd_put_NN (output_bfd, tpoff (info, relocation),
				  htab->elf.sgot->contents + off + ie_off);
		    }
		}
	    }

	  BFD_ASSERT (off < (bfd_vma) -2);
	  relocation = sec_addr (htab->elf.sgot) + off + (is_ie ? ie_off : 0);
	  if (!riscv_record_pcrel_hi_reloc (&pcrel_relocs, pc,
					    relocation, FALSE))
	    r = bfd_reloc_overflow;
	  unresolved_reloc = FALSE;
	  break;

	case R_RISCV_ICT_HI20:
	case R_RISCV_ICT_LO12_I:
	case R_RISCV_PCREL_ICT_HI20:
	case R_RISCV_CALL_ICT:
	case R_RISCV_ICT_64:
	  {
	    struct elf_riscv_ict_hash_entry *entry;
	    struct bfd_link_hash_entry *ict_base;
	    int ict_entry_size;

	    entry = (struct elf_riscv_ict_hash_entry*)
	      bfd_hash_lookup (&indirect_call_table, h->root.root.string,
			       FALSE, FALSE);
	    if (entry == NULL)
	      {
		(*_bfd_error_handler)
		  (_("%pB %pA: internal error indirect call relocation "
		     "0x%lx without hash.\n"),
		     input_bfd, sec, rel->r_offset);
		bfd_set_error (bfd_error_bad_value);
		return FALSE;
	      }

	    ict_base = bfd_link_hash_lookup (info->hash,
					     "_INDIRECT_CALL_TABLE_BASE_",
					     FALSE, FALSE, FALSE);

	    if (ict_model == 1 || ict_model == 2)
	      /* Small model, use `call' in the ict table.  */
	      /* Large model, use `.dword' in the ict table.  */
	      ict_entry_size = 8;
	    else
	      /* Tiny model, use `jal' in the ict table.  */
	      ict_entry_size = 4;

	    relocation = ((ict_base->u.def.value
			   + ict_base->u.def.section->output_section->vma
			   + ict_base->u.def.section->output_offset)
			  + (entry->order * ict_entry_size));
	    break;
	  }

	default:
	  r = bfd_reloc_notsupported;
	}

      /* Dynamic relocs are not propagated for SEC_DEBUGGING sections
	 because such sections are not SEC_ALLOC and thus ld.so will
	 not process them.  */
      if (unresolved_reloc
	  && !((input_section->flags & SEC_DEBUGGING) != 0
	       && h->def_dynamic)
	  && _bfd_elf_section_offset (output_bfd, info, input_section,
				      rel->r_offset) != (bfd_vma) -1)
	{
	  (*_bfd_error_handler)
	    (_("%pB(%pA+%#" PRIx64 "): "
	       "unresolvable %s relocation against symbol `%s'"),
	     input_bfd,
	     input_section,
	     (uint64_t) rel->r_offset,
	     howto->name,
	     h->root.root.string);
	  continue;
	}

      if (r == bfd_reloc_ok)
	r = perform_relocation (howto, rel, relocation, input_section,
				input_bfd, contents);

      switch (r)
	{
	case bfd_reloc_ok:
	  continue;

	case bfd_reloc_overflow:
	  info->callbacks->reloc_overflow
	    (info, (h ? &h->root : NULL), name, howto->name,
	     (bfd_vma) 0, input_bfd, input_section, rel->r_offset);
	  break;

	case bfd_reloc_undefined:
	  info->callbacks->undefined_symbol
	    (info, name, input_bfd, input_section, rel->r_offset,
	     TRUE);
	  break;

	case bfd_reloc_outofrange:
	  msg = _("%X%P: internal error: out of range error\n");
	  break;

	case bfd_reloc_notsupported:
	  msg = _("%X%P: internal error: unsupported relocation error\n");
	  break;

	case bfd_reloc_dangerous:
	  info->callbacks->reloc_dangerous
	    (info, "%pcrel_lo section symbol with an addend", input_bfd,
	     input_section, rel->r_offset);
	  break;

	default:
	  msg = _("%X%P: internal error: unknown error\n");
	  break;
	}

      if (msg)
	info->callbacks->einfo (msg);

      /* We already reported the error via a callback, so don't try to report
	 it again by returning false.  That leads to spurious errors.  */
      ret = TRUE;
      goto out;
    }

  ret = riscv_resolve_pcrel_lo_relocs (&pcrel_relocs);
out:
  riscv_free_pcrel_relocs (&pcrel_relocs);
  return ret;
}

/* Finish up dynamic symbol handling.  We set the contents of various
   dynamic sections here.  */

static bfd_boolean
riscv_elf_finish_dynamic_symbol (bfd *output_bfd,
				 struct bfd_link_info *info,
				 struct elf_link_hash_entry *h,
				 Elf_Internal_Sym *sym)
{
  struct riscv_elf_link_hash_table *htab = riscv_elf_hash_table (info);
  const struct elf_backend_data *bed = get_elf_backend_data (output_bfd);

  if (h->plt.offset != (bfd_vma) -1)
    {
      /* We've decided to create a PLT entry for this symbol.  */
      bfd_byte *loc;
      bfd_vma i, header_address, plt_idx, got_address;
      uint32_t plt_entry[PLT_ENTRY_INSNS];
      Elf_Internal_Rela rela;

      BFD_ASSERT (h->dynindx != -1);

      /* Calculate the address of the PLT header.  */
      header_address = sec_addr (htab->elf.splt);

      /* Calculate the index of the entry.  */
      plt_idx = (h->plt.offset - PLT_HEADER_SIZE) / PLT_ENTRY_SIZE;

      /* Calculate the address of the .got.plt entry.  */
      got_address = riscv_elf_got_plt_val (plt_idx, info);

      /* Find out where the .plt entry should go.  */
      loc = htab->elf.splt->contents + h->plt.offset;

      /* Fill in the PLT entry itself.  */
      if (! riscv_make_plt_entry (output_bfd, got_address,
				  header_address + h->plt.offset,
				  plt_entry))
	return FALSE;

      for (i = 0; i < PLT_ENTRY_INSNS; i++)
	bfd_put_32 (output_bfd, plt_entry[i], loc + 4*i);

      /* Fill in the initial value of the .got.plt entry.  */
      loc = htab->elf.sgotplt->contents
	    + (got_address - sec_addr (htab->elf.sgotplt));
      bfd_put_NN (output_bfd, sec_addr (htab->elf.splt), loc);

      /* Fill in the entry in the .rela.plt section.  */
      rela.r_offset = got_address;
      rela.r_addend = 0;
      rela.r_info = ELFNN_R_INFO (h->dynindx, R_RISCV_JUMP_SLOT);

      loc = htab->elf.srelplt->contents + plt_idx * sizeof (ElfNN_External_Rela);
      bed->s->swap_reloca_out (output_bfd, &rela, loc);

      if (!h->def_regular)
	{
	  /* Mark the symbol as undefined, rather than as defined in
	     the .plt section.  Leave the value alone.  */
	  sym->st_shndx = SHN_UNDEF;
	  /* If the symbol is weak, we do need to clear the value.
	     Otherwise, the PLT entry would provide a definition for
	     the symbol even if the symbol wasn't defined anywhere,
	     and so the symbol would never be NULL.  */
	  if (!h->ref_regular_nonweak)
	    sym->st_value = 0;
	}
    }

  if (h->got.offset != (bfd_vma) -1
      && !(riscv_elf_hash_entry (h)->tls_type & (GOT_TLS_GD | GOT_TLS_IE))
      && !UNDEFWEAK_NO_DYNAMIC_RELOC (info, h))
    {
      asection *sgot;
      asection *srela;
      Elf_Internal_Rela rela;

      /* This symbol has an entry in the GOT.  Set it up.  */

      sgot = htab->elf.sgot;
      srela = htab->elf.srelgot;
      BFD_ASSERT (sgot != NULL && srela != NULL);

      rela.r_offset = sec_addr (sgot) + (h->got.offset &~ (bfd_vma) 1);

      /* If this is a local symbol reference, we just want to emit a RELATIVE
	 reloc.  This can happen if it is a -Bsymbolic link, or a pie link, or
	 the symbol was forced to be local because of a version file.
	 The entry in the global offset table will already have been
	 initialized in the relocate_section function.  */
      if (bfd_link_pic (info)
	  && SYMBOL_REFERENCES_LOCAL (info, h))
	{
	  BFD_ASSERT((h->got.offset & 1) != 0);
	  asection *sec = h->root.u.def.section;
	  rela.r_info = ELFNN_R_INFO (0, R_RISCV_RELATIVE);
	  rela.r_addend = (h->root.u.def.value
			   + sec->output_section->vma
			   + sec->output_offset);
	}
      else
	{
	  BFD_ASSERT((h->got.offset & 1) == 0);
	  BFD_ASSERT (h->dynindx != -1);
	  rela.r_info = ELFNN_R_INFO (h->dynindx, R_RISCV_NN);
	  rela.r_addend = 0;
	}

      bfd_put_NN (output_bfd, 0,
		  sgot->contents + (h->got.offset & ~(bfd_vma) 1));
      riscv_elf_append_rela (output_bfd, srela, &rela);
    }

  if (h->needs_copy)
    {
      Elf_Internal_Rela rela;
      asection *s;

      /* This symbols needs a copy reloc.  Set it up.  */
      BFD_ASSERT (h->dynindx != -1);

      rela.r_offset = sec_addr (h->root.u.def.section) + h->root.u.def.value;
      rela.r_info = ELFNN_R_INFO (h->dynindx, R_RISCV_COPY);
      rela.r_addend = 0;
      if (h->root.u.def.section == htab->elf.sdynrelro)
	s = htab->elf.sreldynrelro;
      else
	s = htab->elf.srelbss;
      riscv_elf_append_rela (output_bfd, s, &rela);
    }

  /* Mark some specially defined symbols as absolute.  */
  if (h == htab->elf.hdynamic
      || (h == htab->elf.hgot || h == htab->elf.hplt))
    sym->st_shndx = SHN_ABS;

  return TRUE;
}

/* Finish up the dynamic sections.  */

static bfd_boolean
riscv_finish_dyn (bfd *output_bfd, struct bfd_link_info *info,
		  bfd *dynobj, asection *sdyn)
{
  struct riscv_elf_link_hash_table *htab = riscv_elf_hash_table (info);
  const struct elf_backend_data *bed = get_elf_backend_data (output_bfd);
  size_t dynsize = bed->s->sizeof_dyn;
  bfd_byte *dyncon, *dynconend;

  dynconend = sdyn->contents + sdyn->size;
  for (dyncon = sdyn->contents; dyncon < dynconend; dyncon += dynsize)
    {
      Elf_Internal_Dyn dyn;
      asection *s;

      bed->s->swap_dyn_in (dynobj, dyncon, &dyn);

      switch (dyn.d_tag)
	{
	case DT_PLTGOT:
	  s = htab->elf.sgotplt;
	  dyn.d_un.d_ptr = s->output_section->vma + s->output_offset;
	  break;
	case DT_JMPREL:
	  s = htab->elf.srelplt;
	  dyn.d_un.d_ptr = s->output_section->vma + s->output_offset;
	  break;
	case DT_PLTRELSZ:
	  s = htab->elf.srelplt;
	  dyn.d_un.d_val = s->size;
	  break;
	default:
	  continue;
	}

      bed->s->swap_dyn_out (output_bfd, &dyn, dyncon);
    }
  return TRUE;
}

static bfd_boolean
riscv_elf_finish_dynamic_sections (bfd *output_bfd,
				   struct bfd_link_info *info)
{
  bfd *dynobj;
  asection *sdyn;
  struct riscv_elf_link_hash_table *htab;

  htab = riscv_elf_hash_table (info);
  BFD_ASSERT (htab != NULL);
  dynobj = htab->elf.dynobj;

  sdyn = bfd_get_linker_section (dynobj, ".dynamic");

  if (elf_hash_table (info)->dynamic_sections_created)
    {
      asection *splt;
      bfd_boolean ret;

      splt = htab->elf.splt;
      BFD_ASSERT (splt != NULL && sdyn != NULL);

      ret = riscv_finish_dyn (output_bfd, info, dynobj, sdyn);

      if (!ret)
	return ret;

      /* Fill in the head and tail entries in the procedure linkage table.  */
      if (splt->size > 0)
	{
	  int i;
	  uint32_t plt_header[PLT_HEADER_INSNS];
	  ret = riscv_make_plt_header (output_bfd,
				       sec_addr (htab->elf.sgotplt),
				       sec_addr (splt), plt_header);
	  if (!ret)
	    return ret;

	  for (i = 0; i < PLT_HEADER_INSNS; i++)
	    bfd_put_32 (output_bfd, plt_header[i], splt->contents + 4*i);

	  elf_section_data (splt->output_section)->this_hdr.sh_entsize
	    = PLT_ENTRY_SIZE;
	}
    }

  if (htab->elf.sgotplt)
    {
      asection *output_section = htab->elf.sgotplt->output_section;

      if (bfd_is_abs_section (output_section))
	{
	  (*_bfd_error_handler)
	    (_("discarded output section: `%pA'"), htab->elf.sgotplt);
	  return FALSE;
	}

      if (htab->elf.sgotplt->size > 0)
	{
	  /* Write the first two entries in .got.plt, needed for the dynamic
	     linker.  */
	  bfd_put_NN (output_bfd, (bfd_vma) -1, htab->elf.sgotplt->contents);
	  bfd_put_NN (output_bfd, (bfd_vma) 0,
		      htab->elf.sgotplt->contents + GOT_ENTRY_SIZE);
	}

      elf_section_data (output_section)->this_hdr.sh_entsize = GOT_ENTRY_SIZE;
    }

  if (htab->elf.sgot)
    {
      asection *output_section = htab->elf.sgot->output_section;

      if (htab->elf.sgot->size > 0)
	{
	  /* Set the first entry in the global offset table to the address of
	     the dynamic section.  */
	  bfd_vma val = sdyn ? sec_addr (sdyn) : 0;
	  bfd_put_NN (output_bfd, val, htab->elf.sgot->contents);
	}

      elf_section_data (output_section)->this_hdr.sh_entsize = GOT_ENTRY_SIZE;
    }

  return TRUE;
}

/* Return address for Ith PLT stub in section PLT, for relocation REL
   or (bfd_vma) -1 if it should not be included.  */

static bfd_vma
riscv_elf_plt_sym_val (bfd_vma i, const asection *plt,
		       const arelent *rel ATTRIBUTE_UNUSED)
{
  return plt->vma + PLT_HEADER_SIZE + i * PLT_ENTRY_SIZE;
}

static enum elf_reloc_type_class
riscv_reloc_type_class (const struct bfd_link_info *info ATTRIBUTE_UNUSED,
			const asection *rel_sec ATTRIBUTE_UNUSED,
			const Elf_Internal_Rela *rela)
{
  switch (ELFNN_R_TYPE (rela->r_info))
    {
    case R_RISCV_RELATIVE:
      return reloc_class_relative;
    case R_RISCV_JUMP_SLOT:
      return reloc_class_plt;
    case R_RISCV_COPY:
      return reloc_class_copy;
    default:
      return reloc_class_normal;
    }
}

/* Given the ELF header flags in FLAGS, it returns a string that describes the
   float ABI.  */

static const char *
riscv_float_abi_string (flagword flags)
{
  switch (flags & EF_RISCV_FLOAT_ABI)
    {
    case EF_RISCV_FLOAT_ABI_SOFT:
      return "soft-float";
      break;
    case EF_RISCV_FLOAT_ABI_SINGLE:
      return "single-float";
      break;
    case EF_RISCV_FLOAT_ABI_DOUBLE:
      return "double-float";
      break;
    case EF_RISCV_FLOAT_ABI_QUAD:
      return "quad-float";
      break;
    default:
      abort ();
    }
}

/* The information of architecture attribute.  */
static riscv_subset_list_t in_subsets;
static riscv_subset_list_t out_subsets;
static riscv_subset_list_t merged_subsets;

/* Predicator for standard extension.  */

static bfd_boolean
riscv_std_ext_p (const char *name)
{
  return (strlen (name) == 1) && (name[0] != 'x') && (name[0] != 's');
}

static bfd_boolean
riscv_std_ext_long_p (const char *name)
{
  return (strlen (name) >= 2) && strchr("Zz", name[0]);
}

/* Predicator for non-standard extension.  */

static bfd_boolean
riscv_non_std_ext_p (const char *name)
{
  return (strlen (name) >= 2) && (name[0] == 'x');
}

/* Predicator for standard supervisor extension.  */

static bfd_boolean
riscv_std_sv_ext_p (const char *name)
{
  return (strlen (name) >= 2) && (name[0] == 's') && (name[1] != 'x');
}

/* Predicator for non-standard supervisor extension.  */

static bfd_boolean
riscv_non_std_sv_ext_p (const char *name)
{
  return (strlen (name) >= 3) && (name[0] == 's') && (name[1] == 'x');
}

/* Error handler when version mis-match.  */

static void
riscv_version_mismatch (bfd *ibfd,
			struct riscv_subset_t *in,
			struct riscv_subset_t *out)
{
  _bfd_error_handler
    (_("error: %pB: Mis-matched ISA version for '%s' exetension. "
       "%d.%d vs %d.%d"),
       ibfd, in->name,
       in->major_version, in->minor_version,
       out->major_version, out->minor_version);
}

/* Return true if subset is 'i' or 'e'.  */

static bfd_boolean
riscv_i_or_e_p (bfd *ibfd,
		const char *arch,
		struct riscv_subset_t *subset)
{
  if ((strcasecmp (subset->name, "e") != 0)
      && (strcasecmp (subset->name, "i") != 0))
    {
      _bfd_error_handler
	(_("error: %pB: corrupted ISA string '%s'."
	   "first letter should be 'i' or 'e' but got '%s'."),
	   ibfd, arch, subset->name);
      return FALSE;
    }
  return TRUE;
}

/* Merge standard extensions.

   Return Value:
     Return FALSE if failed to merge.

   Arguments:
     `bfd`: bfd handler.
     `in_arch`: Raw arch string for input object.
     `out_arch`: Raw arch string for output object.
     `pin`: subset list for input object, and it'll skip all merged subset after
            merge.
     `pout`: Like `pin`, but for output object.  */

static bfd_boolean
riscv_merge_std_ext (bfd *ibfd,
		     const char *in_arch,
		     const char *out_arch,
		     struct riscv_subset_t **pin,
		     struct riscv_subset_t **pout)
{
  const char *standard_exts = riscv_supported_std_ext ();
  const char *p;
  struct riscv_subset_t *in = *pin;
  struct riscv_subset_t *out = *pout;

  /*   fix 'e' comes with 'i' issue: skip 'i'
   *   refert to 'riscv_parse_std_ext', case 'e'
   */
  struct riscv_subset_t *next;
  next = in->next;
  if (next && !strcasecmp (next->name, "e") && !strcasecmp (in->name, "i"))
    in = in->next;
  next = out->next;
  if (next && !strcasecmp (next->name, "e") && !strcasecmp (out->name, "i"))
    out = out->next;

  /* First letter should be 'i' or 'e'.  */
  if (!riscv_i_or_e_p (ibfd, in_arch, in))
    return FALSE;

  if (!riscv_i_or_e_p (ibfd, out_arch, out))
    return FALSE;

  if (in->name[0] != out->name[0])
    {
      /* TODO: We might allow merge 'i' with 'e'.  */
      _bfd_error_handler
	(_("error: %pB: Mis-matched ISA string to merge '%s' and '%s'."),
	 ibfd, in->name, out->name);
      return FALSE;
    }
  else if ((in->major_version != out->major_version) ||
	   (in->minor_version != out->minor_version))
    {
      /* TODO: Allow different merge policy.  */
      riscv_version_mismatch (ibfd, in, out);
      return FALSE;
    }
  else
    riscv_add_subset (&merged_subsets,
		      in->name, in->major_version, in->minor_version);

  in = in->next;
  out = out->next;

  /* Handle standard extension first.  */
  for (p = standard_exts; *p; ++p)
    {
      char find_ext[2] = {*p, '\0'};
      struct riscv_subset_t *find_in =
	riscv_lookup_subset (&in_subsets, find_ext);
      struct riscv_subset_t *find_out =
	riscv_lookup_subset (&out_subsets, find_ext);

      if (find_in == NULL && find_out == NULL)
	continue;

      /* Check version is same or not.  */
      /* TODO: Allow different merge policy.  */
      if ((find_in != NULL && find_out != NULL)
	  && ((find_in->major_version != find_out->major_version)
	      || (find_in->minor_version != find_out->minor_version)))
	{
	  riscv_version_mismatch (ibfd, in, out);
	  return FALSE;
	}

      struct riscv_subset_t *merged = find_in ? find_in : find_out;
      riscv_add_subset (&merged_subsets, merged->name,
			merged->major_version, merged->minor_version);
    }

  /* Skip all standard extensions.  */
  while ((in != NULL) && riscv_std_ext_p (in->name)) in = in->next;
  while ((out != NULL) && riscv_std_ext_p (out->name)) out = out->next;

  *pin = in;
  *pout = out;

  return TRUE;
}

/* Merge non-standard and supervisor extensions.
   Return Value:
     Return FALSE if failed to merge.

   Arguments:
     `bfd`: bfd handler.
     `in_arch`: Raw arch string for input object.
     `out_arch`: Raw arch string for output object.
     `pin`: subset list for input object, and it'll skip all merged subset after
            merge.
     `pout`: Like `pin`, but for output object. */

static bfd_boolean
riscv_merge_non_std_and_sv_ext (bfd *ibfd,
				riscv_subset_t **pin,
				riscv_subset_t **pout,
				bfd_boolean (*predicate_func) (const char *))
{
  riscv_subset_t *in = *pin;
  riscv_subset_t *out = *pout;

  for (in = *pin; in != NULL && predicate_func (in->name); in = in->next)
    riscv_add_subset (&merged_subsets, in->name, in->major_version,
		      in->minor_version);

  for (out = *pout; out != NULL && predicate_func (out->name); out = out->next)
    {
      riscv_subset_t *find_ext =
	riscv_lookup_subset (&merged_subsets, out->name);
      if (find_ext != NULL)
	{
	  /* Check version is same or not. */
	  /* TODO: Allow different merge policy.  */
	  if ((find_ext->major_version != out->major_version)
	      || (find_ext->minor_version != out->minor_version))
	    {
	      riscv_version_mismatch (ibfd, find_ext, out);
	      return FALSE;
	    }
	}
      else
	riscv_add_subset (&merged_subsets, out->name,
			  out->major_version, out->minor_version);
    }

  *pin = in;
  *pout = out;
  return TRUE;
}

/* Merge Tag_RISCV_arch attribute.  */

static char *
riscv_merge_arch_attr_info (bfd *ibfd, char *in_arch, char *out_arch)
{
  riscv_subset_t *in, *out;
  char *merged_arch_str;

  unsigned xlen_in, xlen_out;
  merged_subsets.head = NULL;
  merged_subsets.tail = NULL;

  riscv_parse_subset_t rpe_in;
  riscv_parse_subset_t rpe_out;

  rpe_in.subset_list = &in_subsets;
  rpe_in.error_handler = _bfd_error_handler;
  rpe_in.xlen = &xlen_in;

  rpe_out.subset_list = &out_subsets;
  rpe_out.error_handler = _bfd_error_handler;
  rpe_out.xlen = &xlen_out;

  if (in_arch == NULL && out_arch == NULL)
    return NULL;

  if (in_arch == NULL && out_arch != NULL)
    return out_arch;

  if (in_arch != NULL && out_arch == NULL)
    return in_arch;

  /* Parse subset from arch string.  */
  if (!riscv_parse_subset (&rpe_in, in_arch))
    return NULL;

  if (!riscv_parse_subset (&rpe_out, out_arch))
    return NULL;

  /* Checking XLEN.  */
  if (xlen_out != xlen_in)
    {
      _bfd_error_handler
	(_("error: %pB: ISA string of input (%s) doesn't match "
	   "output (%s)."), ibfd, in_arch, out_arch);
      return NULL;
    }

  /* Merge subset list.  */
  in = in_subsets.head;
  out = out_subsets.head;

  /* Merge standard extension.  */
  if (!riscv_merge_std_ext (ibfd, in_arch, out_arch, &in, &out))
    return NULL;
  if (!riscv_merge_non_std_and_sv_ext (ibfd, &in, &out, riscv_std_ext_long_p))
    return NULL;
  /* Merge non-standard extension.  */
  if (!riscv_merge_non_std_and_sv_ext (ibfd, &in, &out, riscv_non_std_ext_p))
    return NULL;
  /* Merge standard supervisor extension.  */
  if (!riscv_merge_non_std_and_sv_ext (ibfd, &in, &out, riscv_std_sv_ext_p))
    return NULL;
  /* Merge non-standard supervisor extension.  */
  if (!riscv_merge_non_std_and_sv_ext (ibfd, &in, &out, riscv_non_std_sv_ext_p))
    return NULL;

  if (xlen_in != xlen_out)
    {
      _bfd_error_handler
	(_("error: %pB: XLEN of input (%u) doesn't match "
	   "output (%u)."), ibfd, xlen_in, xlen_out);
      return NULL;
    }

  if (xlen_in != ARCH_SIZE)
    {
      _bfd_error_handler
	(_("error: %pB: Unspported XLEN (%u), you might"
	   "using wrong emulation."), ibfd, xlen_in);
      return NULL;
    }

  /*  V and X_efhw are incompatible */
  if (riscv_lookup_subset (&merged_subsets, "xefhw")
      && riscv_lookup_subset (&merged_subsets, "v"))
    {
      _bfd_error_handler
        (_("error: output arch \"%s\" is not compatible with \"%s\"."),
	 out_arch, in_arch);
      return NULL;
    }

  merged_arch_str = riscv_arch_str (ARCH_SIZE, &merged_subsets);

  /* Release the subset lists.  */
  riscv_release_subset_list (&in_subsets);
  riscv_release_subset_list (&out_subsets);
  riscv_release_subset_list (&merged_subsets);

  return merged_arch_str;
}

/* The information of architecture attribute.  */
struct arch_info
{
  char *name;
  int version;
  struct arch_info *next;
  /* Used to record input and output objects
     have the same arch.  */
  int valid;
};

static struct arch_info *non_standard_arch_info_head = NULL;
/* Buffer size enough?  */
static char output_arch_name[100] = {'\0'};
static char output_arch_buffer[100] = {'\0'};

static int
riscv_parse_arch_version (char **in_ver)
{
  int version, num;
  char *string = *in_ver;

  version = 0;
  num = 0;
  /* Major version.  */
  while (string[0] != '\0'
	 && string[0] != 'p'
	 && (string[0] - 48) >= 0
	 && (string[0] - 48) <= 9)
    {
      num = num * 10 + (string[0] - 48);
      string++;
    }
  version = num * 10000;
  /* Minor verison.  */
  if (string[0] == 'p')
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
	    {
	      _bfd_error_handler
		(_("error: minor version can not be larger than 9999"));
	    }
	}
      version += num;
    }
  *in_ver = string;

  return version;
}

static void
riscv_parse_arch_name (char **in_arch, int strlen, char **name)
{
  char *string;
  int i;

  /* Parse the non-standard version name.  */
  string = *in_arch;
  if (!strlen)
    {
      i = 0;
      if (strncasecmp (string, "xv5-", 4) == 0)
	i += 4;
      else
	while (string[i] != '\0'
	       && string[i] != '_'
	       && ((string[i] - 48) < 0
		   || (string[i] - 48) > 9))
	  i++;

      /* The first char 'x' is a keyword.  */
      if (i == 1)
	_bfd_error_handler
	  (_("error: empty non standard ISA extension? %s"),
	   string);
      else
	strlen = i;
    }

  *name = (char *) malloc ((strlen + 1) * sizeof (char));
  memcpy (*name, *in_arch, strlen);
  memcpy (*name + strlen, "\0", 1);
  *in_arch = string + strlen;
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
riscv_insert_non_standard_arch_info (char *name, int version)
{
  struct arch_info *arch = non_standard_arch_info_head;

  while (arch)
    {
      if (strcasecmp (arch->name, name) == 0)
	return;
      arch = arch->next;
    }

  arch = malloc (sizeof (struct arch_info));
  arch->name = xstrdup (name);
  arch->version = version;
  arch->valid = 0;
  arch->next = non_standard_arch_info_head;
  non_standard_arch_info_head = arch;
}

static bfd_boolean
riscv_parse_arch_attr_info (bfd *ibfd, char *in_arch, char *out_arch)
{
  const char *standard_arch = "imafdqcvpx";
  char *name;
  char ver[32];
  struct arch_info *non_standard_arch = NULL;
  int version_i, version_o, find_arch_i, find_arch_o, first_X_arch;

  if (!in_arch || !out_arch)
    return TRUE;

  memset(output_arch_buffer, 0, 100);

  /* Skip rv32/rv64.  */
  if (strncasecmp (in_arch, out_arch, 4) == 0
      && (strncasecmp (in_arch, "rv32", 4) == 0
	  || strncasecmp (in_arch, "rv64", 4) == 0))
    {
      strncat(output_arch_buffer, out_arch, 4);
      in_arch += 4;
      out_arch += 4;
    }
  else
    {
      _bfd_error_handler
	(_("error: %pB: ISA string of input (%s) is unmatched with "
	   "output (%s)."), ibfd, in_arch, out_arch);
      return FALSE;
    }

  for ( ; *standard_arch != 'x'; standard_arch++)
    {
      version_i = 0;
      version_o = 0;
      find_arch_i = 0;
      find_arch_o = 0;

      if (*in_arch == *standard_arch)
	{
	  in_arch++;
	  version_i = riscv_parse_arch_version (&in_arch);
	  find_arch_i = 1;
	}
      if (*out_arch == *standard_arch)
	{
	  out_arch++;
	  version_o = riscv_parse_arch_version (&out_arch);
	  find_arch_o = 1;
	}

      /* Objects with i extension can not be linked with objects
	 wihtout i extension.  */
      if (*standard_arch == 'i'
	  && ((find_arch_o && !find_arch_i)
	      || (!find_arch_o && find_arch_i)))
	return FALSE;

      /* Must compare the versions of input and output objects.  */
      if (version_i != 0
	  && version_o != 0
	  && version_i != version_o)
	{
	  _bfd_error_handler
	    (_("error: %pB: cannot mix the objects that have "
	       "different versions of ISA '%c'."),
	     ibfd, *standard_arch);
	  return FALSE;
	}
      else if (version_o != 0)
	version_i = version_o;

      if (find_arch_i || find_arch_o)
	{
	  strncat(output_arch_buffer, standard_arch, 1);
	  riscv_arch_version_int2str (version_i, ver, 0);
	  strncat(output_arch_buffer, ver, strlen (ver));
	  strncat(output_arch_buffer, "p", 1);
	  riscv_arch_version_int2str (version_i, ver, 1);
	  strncat(output_arch_buffer, ver, strlen (ver));
	}
    }

  /* Check non-standard arch attrs.  */
  /* TODO: This need to be rewrited, so I just choose the union
     of all non-standard architectures.  */
  while (*out_arch == 'x')
    {
      name = NULL;
      riscv_parse_arch_name (&out_arch, 0, &name);
      version_o = riscv_parse_arch_version (&out_arch);
      riscv_insert_non_standard_arch_info (name, version_o);
      if (*out_arch == '_')
	out_arch++;
      free ((char *) name);
    }
  while (*in_arch == 'x')
    {
      name = NULL;
      riscv_parse_arch_name (&in_arch, 0, &name);
      version_i = riscv_parse_arch_version (&in_arch);
      riscv_insert_non_standard_arch_info (name, version_i);

      if (*in_arch == '_')
        in_arch++;
      free ((char *) name);
    }

  first_X_arch = 1;
  while (non_standard_arch_info_head)
    {
      non_standard_arch = non_standard_arch_info_head;

      if (first_X_arch)
	first_X_arch = 0;
      else
	strncat(output_arch_buffer, "_", 1);

      strncat(output_arch_buffer, non_standard_arch->name,
	      strlen (non_standard_arch->name));
      riscv_arch_version_int2str (non_standard_arch->version, ver, 0);
      strncat(output_arch_buffer, ver, strlen (ver));
      strncat(output_arch_buffer, "p", 1);
      riscv_arch_version_int2str (non_standard_arch->version, ver, 1);
      strncat(output_arch_buffer, ver, strlen (ver));

      non_standard_arch_info_head = non_standard_arch_info_head->next;
      free (non_standard_arch);
    }

  return TRUE;
}

/* Merge object attributes from IBFD into output_bfd of INFO.
   Raise an error if there are conflicting attributes.  */

struct priv_spec_version {
  int major;
  int minor;
  int revision;
};

static bfd_boolean
riscv_merge_attributes (bfd *ibfd, struct bfd_link_info *info)
{
  bfd *obfd = info->output_bfd;
  obj_attribute *in_attr;
  obj_attribute *out_attr;
  obj_attribute_list *in_attr_list;
  obj_attribute_list *out_attr_list;
  bfd_boolean result = TRUE;
  const char *sec_name = get_elf_backend_data (ibfd)->obj_attrs_section;
  unsigned int i;
  struct priv_spec_version in_priv, out_priv;
  memset (&in_priv, 0, sizeof (in_priv));
  memset (&out_priv, 0, sizeof (out_priv));

  /* Skip linker created files.  */
  if (ibfd->flags & BFD_LINKER_CREATED)
    return TRUE;

  /* Skip any input that doesn't have an attribute section.
     This enables to link object files without attribute section with
     any others.  */
  if (bfd_get_section_by_name (ibfd, sec_name) == NULL)
    return TRUE;

  if (!elf_known_obj_attributes_proc (obfd)[0].i)
    {
      /* This is the first object.  Copy the attributes.  */
      _bfd_elf_copy_obj_attributes (ibfd, obfd);

      out_attr = elf_known_obj_attributes_proc (obfd);

      /* Use the Tag_null value to indicate the attributes have been
	 initialized.  */
      out_attr[0].i = 1;

      /* The function _bfd_elf_copy_obj_attributes only copy the attrs
	 from input bfd to output bfd. If we only have an input bfd,
	 we need to store the information of ict_model here.  */
      for (out_attr_list = elf_other_obj_attributes (obfd)[OBJ_ATTR_PROC];
	   out_attr_list;
	   out_attr_list = out_attr_list->next)
	{
	  if (out_attr_list->tag == Tag_ict_model)
	    {
	      if (strcmp (out_attr_list->attr.s, "tiny") == 0)
		ict_model = 0;
	      else if (strcmp (out_attr_list->attr.s, "small") == 0)
		ict_model = 1;
	      else if (strcmp (out_attr_list->attr.s, "large") == 0)
		ict_model = 2;
	    }
	}
      return TRUE;
    }

  in_attr = elf_known_obj_attributes_proc (ibfd);
  out_attr = elf_known_obj_attributes_proc (obfd);

  for (i = LEAST_KNOWN_OBJ_ATTRIBUTE; i < NUM_KNOWN_OBJ_ATTRIBUTES; i++)
    {
    switch (i)
      {
      case Tag_RISCV_arch:
	if (!out_attr[Tag_RISCV_arch].s)
	  out_attr[Tag_RISCV_arch].s = in_attr[Tag_RISCV_arch].s;
	else if (in_attr[Tag_RISCV_arch].s
		 && out_attr[Tag_RISCV_arch].s)
	  {
	    /* Check arch compatible.  */
	    char *merged_arch =
		riscv_merge_arch_attr_info (ibfd,
					    in_attr[Tag_RISCV_arch].s,
					    out_attr[Tag_RISCV_arch].s);
	    if (merged_arch == NULL)
	      {
		result = FALSE;
		out_attr[Tag_RISCV_arch].s = "";
	      }
	    else
	      out_attr[Tag_RISCV_arch].s = merged_arch;
	  }
	break;
      case Tag_RISCV_priv_spec:
      case Tag_RISCV_priv_spec_minor:
      case Tag_RISCV_priv_spec_revision:
	if (!in_attr[i].i) /* merge none  */
	  /* pass */;
	else if (!out_attr[i].i) /* promote input one  */
	  out_attr[i] = in_attr[i];
	else if (out_attr[i].i != in_attr[i].i)
	  {
	    _bfd_error_handler
	      (_("error: %pB: conflicting priv spec version "
		 "(major/minor/revision)."), ibfd);
	    result = FALSE;
	  }
	break;
      case Tag_RISCV_unaligned_access:
	out_attr[i].i |= in_attr[i].i;
	break;
      case Tag_RISCV_stack_align:
	if (out_attr[i].i == 0)
	  out_attr[i].i = in_attr[i].i;
	else if (in_attr[i].i != 0
		 && out_attr[i].i != 0
		 && out_attr[i].i != in_attr[i].i)
	  {
	    _bfd_error_handler
	      (_("error: %pB use %u-byte stack aligned but the output "
		 "use %u-byte stack aligned."),
	       ibfd, in_attr[i].i, out_attr[i].i);
	    result = FALSE;
	  }
	break;
      case Tag_arch + Tag_shfit:
	if (!out_attr[Tag_arch].s)
	  out_attr[Tag_arch].s = in_attr[Tag_arch].s;
	else if (in_attr[Tag_arch].s
		 && out_attr[Tag_arch].s)
	  {
	    /* Check arch compatible.  */
	    if (!riscv_parse_arch_attr_info (ibfd,
					     in_attr[Tag_arch].s,
					     out_attr[Tag_arch].s))
	      result = FALSE;
	    else
	      {
		memset (output_arch_name, 0, 100);
		memcpy (output_arch_name, output_arch_buffer, 100);
		out_attr[Tag_arch].s = output_arch_name;
	      }
	  }
	break;
      case Tag_priv_spec + Tag_shfit:
	in_priv.major = in_attr[i].i;
	out_priv.major = out_attr[i].i;
	break;
      case Tag_priv_spec_minor + Tag_shfit:
	in_priv.minor = in_attr[i].i;
	out_priv.minor = out_attr[i].i;
	break;
      case Tag_priv_spec_revision + Tag_shfit:
	in_priv.revision = in_attr[i].i;
	out_priv.revision = out_attr[i].i;
	break;
      case Tag_strict_align + Tag_shfit:
	out_attr[i].i |= in_attr[i].i;
	break;
      case Tag_stack_align + Tag_shfit:
	if (out_attr[i].i == 0)
	  out_attr[i].i = in_attr[i].i;
	else if (in_attr[i].i != 0
		 && out_attr[i].i != 0
		 && out_attr[i].i != in_attr[i].i)
	  {
	    _bfd_error_handler
	      (_("error: %pB use %u-byte stack aligned but the output "
		 "use %u-byte stack aligned."),
	       ibfd, in_attr[i].i, out_attr[i].i);
	    result = FALSE;
	  }
	break;
      default:
	result &= _bfd_elf_merge_unknown_attribute_low (ibfd, obfd, i);
      }

      /* If out_attr was copied from in_attr then it won't have a type yet.  */
      if (i >= LEAST_KNOWN_OBJ_ATTRIBUTE
	  && i < NUM_KNOWN_OBJ_ATTRIBUTES
	  && in_attr[i].type
	  && !out_attr[i].type)
	out_attr[i].type = in_attr[i].type;
    }

    if ((out_priv.major == 0)
	&& (out_priv.minor == 0)
	&& (out_priv.revision == 0))
      {
	out_attr[Tag_priv_spec].i = in_priv.major;
	out_attr[Tag_priv_spec_minor].i = in_priv.minor;
	out_attr[Tag_priv_spec_revision].i = in_priv.revision;
      }
    else
      {
	if ((!((in_priv.major == 0)
	       && (in_priv.minor == 0)
	       && (in_priv.revision == 0)))
	    && ((in_priv.major != out_priv.major)
		|| (in_priv.minor != out_priv.minor)
		|| (in_priv.revision != out_priv.revision)))
	  {
	    _bfd_error_handler
	      (_("error: %pB: conflicting priv spec version "
		 "(major/minor/revision)."), ibfd);
	    result = FALSE;
	  }
      }

  /* Handle our v5 attributes (unknown attributes).  */
  /* I recommend that don't use the riscv_elf_obj_attrs_handle_unknown
     for checking our v5 attributes, since the function only pass the
     information of input bfd.  */
  for (in_attr_list = elf_other_obj_attributes (ibfd)[OBJ_ATTR_PROC];
       in_attr_list;
       in_attr_list = in_attr_list->next)
    {
      for (out_attr_list = elf_other_obj_attributes (obfd)[OBJ_ATTR_PROC];
	   out_attr_list;
	   out_attr_list = out_attr_list->next)
	{
	  if (in_attr_list->tag == out_attr_list->tag)
	    {
	      /* Find the attr both in the input and output bfds.  */
	      switch (in_attr_list->tag)
		{
		case Tag_ict_version:
		  if (in_attr_list->attr.i
		      != out_attr_list->attr.i)
		    {
		      _bfd_error_handler
			(_("error: %pB: conflicting ict version %d, "
			   "the output ict version is %d."),
			 ibfd, in_attr_list->attr.i,
			 out_attr_list->attr.i);
		      result = FALSE;
		    }
		  break;
		case Tag_ict_model:
		  if (strcmp (in_attr_list->attr.s,
			      out_attr_list->attr.s) != 0)
		    {
		      _bfd_error_handler
			(_("error: %pB: conflicting ict model %s, "
			   "the output ict model is %s."),
			 ibfd, in_attr_list->attr.s,
			 out_attr_list->attr.s);
		      result = FALSE;
		    }
		  /* The information of ict_model is recorded when linking
		     the first input bfd.  */
		  break;
		default:
		  _bfd_error_handler
		    (_("Warning: %pB: Unknown RISC-V object attribute %d"),
		     ibfd, in_attr_list->tag);
		  result = FALSE;
		  break;
		}
	      break;
	    }
	}
      if (out_attr_list == NULL)
	{
	  /* Can not find the input attr in the output, so insert it
	     into the output bfd.  */
	  switch (in_attr_list->tag)
	    {
	    case Tag_ict_version:
	      bfd_elf_add_obj_attr_int (obfd, OBJ_ATTR_PROC,
					in_attr_list->tag,
					in_attr_list->attr.i);
	      break;
	    case Tag_ict_model:
	      bfd_elf_add_obj_attr_string (obfd, OBJ_ATTR_PROC,
					   in_attr_list->tag,
					   in_attr_list->attr.s);

	      /* Also store the information of ict_model here.  */
	      if (strcmp (in_attr_list->attr.s, "tiny") == 0)
		ict_model = 0;
	      else if (strcmp (in_attr_list->attr.s, "small") == 0)
		ict_model = 1;
	      else if (strcmp (in_attr_list->attr.s, "large") == 0)
		ict_model = 2;
	      break;
	    default:
	      _bfd_error_handler
		(_("Warning: %pB: Unknown RISC-V object attribute %d"),
		 ibfd, in_attr_list->tag);
	      result = FALSE;
	      break;
	    }
	}
    }

  /* Merge Tag_compatibility attributes and any common GNU ones.  */
  if (!_bfd_elf_merge_object_attributes (ibfd, info))
    return FALSE;

  return result;
}

/* Merge backend specific data from an object file to the output
   object file when linking.  */

static bfd_boolean
_bfd_riscv_elf_merge_private_bfd_data (bfd *ibfd, struct bfd_link_info *info)
{
  bfd *obfd = info->output_bfd;
  flagword new_flags = elf_elfheader (ibfd)->e_flags;
  flagword old_flags = elf_elfheader (obfd)->e_flags;

  if (!is_riscv_elf (ibfd) || !is_riscv_elf (obfd))
    return TRUE;

  if (strcmp (bfd_get_target (ibfd), bfd_get_target (obfd)) != 0)
    {
      (*_bfd_error_handler)
	(_("%pB: ABI is incompatible with that of the selected emulation:\n"
	   "  target emulation `%s' does not match `%s'"),
	 ibfd, bfd_get_target (ibfd), bfd_get_target (obfd));
      return FALSE;
    }

  if (!_bfd_elf_merge_object_attributes (ibfd, info))
    return FALSE;

  if (!riscv_merge_attributes (ibfd, info))
    return FALSE;

  if (!elf_flags_init (obfd))
    {
      elf_flags_init (obfd) = TRUE;
      elf_elfheader (obfd)->e_flags = new_flags;
      return TRUE;
    }

  /* Disallow linking different float ABIs.  */
  if ((old_flags ^ new_flags) & EF_RISCV_FLOAT_ABI)
    {
      (*_bfd_error_handler)
	(_("%pB: can't link %s modules with %s modules"), ibfd,
	 riscv_float_abi_string (new_flags),
	 riscv_float_abi_string (old_flags));
      goto fail;
    }

  /* Disallow linking RVE and non-RVE.  */
  if ((old_flags ^ new_flags) & EF_RISCV_RVE)
    {
      (*_bfd_error_handler)
       (_("%pB: can't link RVE with other target"), ibfd);
      goto fail;
    }

  /* Allow linking RVC and non-RVC, and keep the RVC flag.  */
  elf_elfheader (obfd)->e_flags |= new_flags & EF_RISCV_RVC;

  return TRUE;

fail:
  bfd_set_error (bfd_error_bad_value);
  return FALSE;
}

/* Delete some bytes from a section while relaxing.  */
/* TODO: For v3, we only need to do once memory move when relaxing.
   But we need to do many times of memory move here. It will increase
   the link time when doing relaxation.  */

static bfd_boolean
riscv_relax_delete_bytes (bfd *abfd, asection *sec, bfd_vma addr, size_t count,
			  struct bfd_link_info *link_info)
{
  unsigned int i, symcount;
  bfd_vma toaddr = sec->size;
  struct elf_link_hash_entry **sym_hashes = elf_sym_hashes (abfd);
  Elf_Internal_Shdr *symtab_hdr = &elf_tdata (abfd)->symtab_hdr;
  unsigned int sec_shndx = _bfd_elf_section_from_bfd_section (abfd, sec);
  struct bfd_elf_section_data *data = elf_section_data (sec);
  bfd_byte *contents = data->this_hdr.contents;

  /* Actually delete the bytes.  */
  sec->size -= count;
  memmove (contents + addr, contents + addr + count, toaddr - addr - count);

  /* Adjust the location of all of the relocs.  Note that we need not
     adjust the addends, since all PC-relative references must be against
     symbols, which we will adjust below.  */
  for (i = 0; i < sec->reloc_count; i++)
    if (data->relocs[i].r_offset > addr && data->relocs[i].r_offset < toaddr)
      data->relocs[i].r_offset -= count;

  /* Adjust the local symbols defined in this section.  */
  for (i = 0; i < symtab_hdr->sh_info; i++)
    {
      Elf_Internal_Sym *sym = (Elf_Internal_Sym *) symtab_hdr->contents + i;
      if (sym->st_shndx == sec_shndx)
	{
	  /* If the symbol is in the range of memory we just moved, we
	     have to adjust its value.  */
	  if (sym->st_value > addr && sym->st_value <= toaddr)
	    sym->st_value -= count;

	  /* If the symbol *spans* the bytes we just deleted (i.e. its
	     *end* is in the moved bytes but its *start* isn't), then we
	     must adjust its size.

	     This test needs to use the original value of st_value, otherwise
	     we might accidentally decrease size when deleting bytes right
	     before the symbol.  But since deleted relocs can't span across
	     symbols, we can't have both a st_value and a st_size decrease,
	     so it is simpler to just use an else.  */
	  else if (sym->st_value <= addr
		   && sym->st_value + sym->st_size > addr
		   && sym->st_value + sym->st_size <= toaddr)
	    sym->st_size -= count;
	}
    }

  /* Now adjust the global symbols defined in this section.  */
  symcount = ((symtab_hdr->sh_size / sizeof (ElfNN_External_Sym))
	      - symtab_hdr->sh_info);

  for (i = 0; i < symcount; i++)
    {
      struct elf_link_hash_entry *sym_hash = sym_hashes[i];

      /* The '--wrap SYMBOL' option is causing a pain when the object file,
	 containing the definition of __wrap_SYMBOL, includes a direct
	 call to SYMBOL as well. Since both __wrap_SYMBOL and SYMBOL reference
	 the same symbol (which is __wrap_SYMBOL), but still exist as two
	 different symbols in 'sym_hashes', we don't want to adjust
	 the global symbol __wrap_SYMBOL twice.  */
      /* The same problem occurs with symbols that are versioned_hidden, as
	 foo becomes an alias for foo@BAR, and hence they need the same
	 treatment.  */
      if (link_info->wrap_hash != NULL
	  || sym_hash->versioned == versioned_hidden)
	{
	  struct elf_link_hash_entry **cur_sym_hashes;

	  /* Loop only over the symbols which have already been checked.  */
	  for (cur_sym_hashes = sym_hashes; cur_sym_hashes < &sym_hashes[i];
	       cur_sym_hashes++)
	    {
	      /* If the current symbol is identical to 'sym_hash', that means
		 the symbol was already adjusted (or at least checked).  */
	      if (*cur_sym_hashes == sym_hash)
		break;
	    }
	  /* Don't adjust the symbol again.  */
	  if (cur_sym_hashes < &sym_hashes[i])
	    continue;
	}

      if ((sym_hash->root.type == bfd_link_hash_defined
	   || sym_hash->root.type == bfd_link_hash_defweak)
	  && sym_hash->root.u.def.section == sec)
	{
	  /* As above, adjust the value if needed.  */
	  if (sym_hash->root.u.def.value > addr
	      && sym_hash->root.u.def.value <= toaddr)
	    sym_hash->root.u.def.value -= count;

	  /* As above, adjust the size if needed.  */
	  else if (sym_hash->root.u.def.value <= addr
		   && sym_hash->root.u.def.value + sym_hash->size > addr
		   && sym_hash->root.u.def.value + sym_hash->size <= toaddr)
	    sym_hash->size -= count;
	}
    }

  return TRUE;
}

/* A second format for recording PC-relative hi relocations.  This stores the
   information required to relax them to GP-relative addresses.  */

typedef struct riscv_pcgp_hi_reloc riscv_pcgp_hi_reloc;
struct riscv_pcgp_hi_reloc
{
  bfd_vma hi_sec_off;
  bfd_vma hi_addend;
  bfd_vma hi_addr;
  unsigned hi_sym;
  asection *sym_sec;
  riscv_pcgp_hi_reloc *next;
};

typedef struct riscv_pcgp_lo_reloc riscv_pcgp_lo_reloc;
struct riscv_pcgp_lo_reloc
{
  bfd_vma hi_sec_off;
  riscv_pcgp_lo_reloc *next;
};

typedef struct
{
  riscv_pcgp_hi_reloc *hi;
  riscv_pcgp_lo_reloc *lo;
} riscv_pcgp_relocs;

/* Initialize the pcgp reloc info in P.  */

static bfd_boolean
riscv_init_pcgp_relocs (riscv_pcgp_relocs *p)
{
  p->hi = NULL;
  p->lo = NULL;
  return TRUE;
}

/* Free the pcgp reloc info in P.  */

static void
riscv_free_pcgp_relocs (riscv_pcgp_relocs *p,
			bfd *abfd ATTRIBUTE_UNUSED,
			asection *sec ATTRIBUTE_UNUSED)
{
  riscv_pcgp_hi_reloc *c;
  riscv_pcgp_lo_reloc *l;

  for (c = p->hi; c != NULL;)
    {
      riscv_pcgp_hi_reloc *next = c->next;
      free (c);
      c = next;
    }

  for (l = p->lo; l != NULL;)
    {
      riscv_pcgp_lo_reloc *next = l->next;
      free (l);
      l = next;
    }
}

/* Record pcgp hi part reloc info in P, using HI_SEC_OFF as the lookup index.
   The HI_ADDEND, HI_ADDR, HI_SYM, and SYM_SEC args contain info required to
   relax the corresponding lo part reloc.  */

static bfd_boolean
riscv_record_pcgp_hi_reloc (riscv_pcgp_relocs *p, bfd_vma hi_sec_off,
			    bfd_vma hi_addend, bfd_vma hi_addr,
			    unsigned hi_sym, asection *sym_sec)
{
  riscv_pcgp_hi_reloc *new = bfd_malloc (sizeof(*new));
  if (!new)
    return FALSE;
  new->hi_sec_off = hi_sec_off;
  new->hi_addend = hi_addend;
  new->hi_addr = hi_addr;
  new->hi_sym = hi_sym;
  new->sym_sec = sym_sec;
  new->next = p->hi;
  p->hi = new;
  return TRUE;
}

/* Look up hi part pcgp reloc info in P, using HI_SEC_OFF as the lookup index.
   This is used by a lo part reloc to find the corresponding hi part reloc.  */

static riscv_pcgp_hi_reloc *
riscv_find_pcgp_hi_reloc(riscv_pcgp_relocs *p, bfd_vma hi_sec_off)
{
  riscv_pcgp_hi_reloc *c;

  for (c = p->hi; c != NULL; c = c->next)
    if (c->hi_sec_off == hi_sec_off)
      return c;
  return NULL;
}

static bfd_boolean
riscv_delete_pcgp_hi_reloc(riscv_pcgp_relocs *p, bfd_vma hi_sec_off)
{
  bfd_boolean out = FALSE;
  riscv_pcgp_hi_reloc *c;

  for (c = p->hi; c != NULL; c = c->next)
      if (c->hi_sec_off == hi_sec_off)
	out = TRUE;

  return out;
}

static bfd_boolean
riscv_use_pcgp_hi_reloc(riscv_pcgp_relocs *p, bfd_vma hi_sec_off)
{
  bfd_boolean out = FALSE;
  riscv_pcgp_hi_reloc *c;

  for (c = p->hi; c != NULL; c = c->next)
    if (c->hi_sec_off == hi_sec_off)
      out = TRUE;

  return out;
}

/* Record pcgp lo part reloc info in P, using HI_SEC_OFF as the lookup info.
   This is used to record relocs that can't be relaxed.  */

static bfd_boolean
riscv_record_pcgp_lo_reloc (riscv_pcgp_relocs *p, bfd_vma hi_sec_off)
{
  riscv_pcgp_lo_reloc *new = bfd_malloc (sizeof(*new));
  if (!new)
    return FALSE;
  new->hi_sec_off = hi_sec_off;
  new->next = p->lo;
  p->lo = new;
  return TRUE;
}

/* Look up lo part pcgp reloc info in P, using HI_SEC_OFF as the lookup index.
   This is used by a hi part reloc to find the corresponding lo part reloc.  */

static bfd_boolean
riscv_find_pcgp_lo_reloc (riscv_pcgp_relocs *p, bfd_vma hi_sec_off)
{
  riscv_pcgp_lo_reloc *c;

  for (c = p->lo; c != NULL; c = c->next)
    if (c->hi_sec_off == hi_sec_off)
      return TRUE;
  return FALSE;
}

static bfd_boolean
riscv_delete_pcgp_lo_reloc (riscv_pcgp_relocs *p ATTRIBUTE_UNUSED,
			    bfd_vma lo_sec_off ATTRIBUTE_UNUSED,
			    size_t bytes ATTRIBUTE_UNUSED)
{
  return TRUE;
}

typedef bfd_boolean (*relax_func_t) (bfd *, asection *, asection *,
				     struct bfd_link_info *,
				     Elf_Internal_Rela *,
				     bfd_vma, bfd_vma, bfd_vma, bfd_boolean *,
				     riscv_pcgp_relocs *,
				     bfd_boolean);

/* Relax AUIPC + JALR into JAL.  */

static bfd_boolean
_bfd_riscv_relax_call (bfd *abfd, asection *sec, asection *sym_sec,
		       struct bfd_link_info *link_info,
		       Elf_Internal_Rela *rel,
		       bfd_vma symval,
		       bfd_vma max_alignment,
		       bfd_vma reserve_size ATTRIBUTE_UNUSED,
		       bfd_boolean *again,
		       riscv_pcgp_relocs *pcgp_relocs ATTRIBUTE_UNUSED,
		       bfd_boolean rvc)
{
  struct riscv_elf_link_hash_table *table;
  table = riscv_elf_hash_table (link_info);
  bfd_byte *contents = elf_section_data (sec)->this_hdr.contents;
  bfd_signed_vma foff = symval - (sec_addr (sec) + rel->r_offset);
  bfd_boolean near_zero = (symval + RISCV_IMM_REACH/2) < RISCV_IMM_REACH;
  bfd_vma auipc, jalr;
  int rd, r_type, len = 4;

  /* FIXME: If the call crosses section boundaries and some sections
     are fixed, ex9 and later relaxations may increase the PC-relative
     offset.  */
  if ((sym_sec->output_section != sec->output_section) &&
      (!table->set_relax_cross_section_call))
    return TRUE;

  /* If the call crosses section boundaries, an alignment directive could
     cause the PC-relative offset to later increase.  */
  if (VALID_UJTYPE_IMM (foff) && sym_sec->output_section != sec->output_section)
    foff += (foff < 0 ? -max_alignment : max_alignment);

  /* See if this function call can be shortened.  */
  if (!VALID_UJTYPE_IMM (foff) && !(!bfd_link_pic (link_info) && near_zero))
    return TRUE;

  /* Shorten the function call.  */
  BFD_ASSERT (rel->r_offset + 8 <= sec->size);

  auipc = bfd_get_32 (abfd, contents + rel->r_offset);
  jalr = bfd_get_32 (abfd, contents + rel->r_offset + 4);
  rd = (jalr >> OP_SH_RD) & OP_MASK_RD;
  rvc = rvc && VALID_RVC_J_IMM (foff) && ARCH_SIZE == 32;

  if (rvc && (rd == 0 || rd == X_RA))
    {
      /* Relax to C.J[AL] rd, addr.  */
      r_type = R_RISCV_RVC_JUMP;
      auipc = rd == 0 ? MATCH_C_J : MATCH_C_JAL;
      len = 2;
    }
  else if (VALID_UJTYPE_IMM (foff))
    {
      /* Relax to JAL rd, addr.  */
      r_type = R_RISCV_JAL;
      auipc = MATCH_JAL | (rd << OP_SH_RD);
    }
  else /* near_zero */
    {
      /* Relax to JALR rd, x0, addr.  */
      r_type = R_RISCV_LO12_I;
      auipc = MATCH_JALR | (rd << OP_SH_RD);
    }

  /* Replace the R_RISCV_CALL reloc.  */
  rel->r_info = ELFNN_R_INFO (ELFNN_R_SYM (rel->r_info), r_type);
  /* Replace the AUIPC.  */
  bfd_put (8 * len, abfd, auipc, contents + rel->r_offset);

  /* Delete unnecessary JALR.  */
  *again = TRUE;
  return riscv_relax_delete_bytes (abfd, sec, rel->r_offset + len, 8 - len,
				   link_info);
}

/* Traverse all output sections and return the max alignment.  */

static bfd_vma
_bfd_riscv_get_max_alignment (asection *sec)
{
  unsigned int max_alignment_power = 0;
  asection *o;

  for (o = sec->output_section->owner->sections; o != NULL; o = o->next)
    {
      if (o->alignment_power > max_alignment_power)
	max_alignment_power = o->alignment_power;
    }

  return (bfd_vma) 1 << max_alignment_power;
}

/* Record the symbol info for relaxing gp in relax_lui.  */
struct relax_gp_sym_info
{
  Elf_Internal_Sym *lsym;
  struct elf_link_hash_entry *h;
  asection *sec;
  struct relax_gp_sym_info *next;
};

static struct relax_gp_sym_info *relax_gp_sym_info_head = NULL;

static struct relax_gp_sym_info *
record_and_find_relax_gp_syms (asection *sec,
			       Elf_Internal_Sym *lsym,
			       struct elf_link_hash_entry *h,
			       int record)
{
  struct relax_gp_sym_info *ptr, *pre_ptr;
  ptr = relax_gp_sym_info_head;
  pre_ptr = ptr;

  /* Check whether the symbol is recorded.  */
  while (ptr)
    {
      if ((h && h == ptr->h && sec == ptr->sec)
	  || (lsym && lsym == ptr->lsym && sec == ptr->sec))
	return ptr;
      pre_ptr = ptr;
      ptr = ptr->next;
    }

  if (!ptr && record)
    {
      ptr = bfd_malloc (sizeof (struct relax_gp_sym_info));
      ptr->sec = sec;
      ptr->lsym = lsym;
      ptr->h = h;
      ptr->next = NULL;

      if (!relax_gp_sym_info_head)
	relax_gp_sym_info_head = ptr;
      else
	pre_ptr->next = ptr;
    }

  return NULL;
}

static bfd_boolean
riscv_relax_lui_to_rvc (bfd *abfd,
			asection *sec,
			Elf_Internal_Rela *rel,
			bfd_vma symval,
			bfd_boolean *again,
			bfd_boolean rvc,
			struct bfd_link_info *link_info)
{
  bfd_byte *contents = elf_section_data (sec)->this_hdr.contents;

  /* Can we relax LUI to C.LUI?  Alignment might move the section forward;
     account for this assuming page alignment at worst.  */
  /* The imm of lui may be changed to zero after relaxation. Even if we
     redefine the macro VALID_RVC_LUI_IMM(x) to limit the imm of c.lui
     can not be zero, linker may still convert the lui to illegal c.lui here.
     For sovling this problem, I remove the limitation of VALID_RVC_LUI_IMM,
     and then convert the illegal c.lui to c.li in the linker relocation
     (perform_relocation).  */
  if (rvc
      && ELFNN_R_TYPE (rel->r_info) == R_RISCV_HI20
      && VALID_RVC_LUI_IMM (RISCV_CONST_HIGH_PART (symval))
      && VALID_RVC_LUI_IMM (RISCV_CONST_HIGH_PART (symval + ELF_MAXPAGESIZE)))
    {
      /* Replace LUI with C.LUI if legal (i.e., rd != x0 and rd != x2/sp).  */
      bfd_vma lui = bfd_get_32 (abfd, contents + rel->r_offset);
      unsigned rd = ((unsigned)lui >> OP_SH_RD) & OP_MASK_RD;
      if (rd == 0 || rd == X_SP)
	return TRUE;

      lui = (lui & (OP_MASK_RD << OP_SH_RD)) | MATCH_C_LUI;
      bfd_put_32 (abfd, lui, contents + rel->r_offset);

      /* Replace the R_RISCV_HI20 reloc.  */
      rel->r_info = ELFNN_R_INFO (ELFNN_R_SYM (rel->r_info), R_RISCV_RVC_LUI);

      *again = TRUE;
      return riscv_relax_delete_bytes (abfd, sec, rel->r_offset + 2, 2, link_info);
    }

  return TRUE;
}

/* Relax non-PIC global variable references to gp relative instructions.  */
/* Relax pass 1: only low part insns
   Relax pass 2: only hi part isns.  */

static bfd_boolean
_bfd_riscv_relax_lui_gp_insn (bfd *abfd,
			      asection *sec,
			      asection *sym_sec,
			      struct bfd_link_info *link_info,
			      Elf_Internal_Rela *rel,
			      bfd_vma symval,
			      bfd_vma max_alignment,
			      bfd_vma reserve_size,
			      bfd_boolean *again ATTRIBUTE_UNUSED,
			      riscv_pcgp_relocs *pcgp_relocs ATTRIBUTE_UNUSED,
			      bfd_boolean rvc ATTRIBUTE_UNUSED)
{
  bfd_byte *contents = elf_section_data (sec)->this_hdr.contents;
  bfd_vma gp = riscv_global_pointer_value (link_info);
  bfd_vma data_start = riscv_data_start_value (link_info);
  struct riscv_elf_link_hash_table *table = riscv_elf_hash_table (link_info);
  int gp_relative_insn = table->gp_relative_insn;
  Elf_Internal_Shdr *symtab_hdr = &elf_symtab_hdr (abfd);
  Elf_Internal_Sym *isym = NULL;
  struct elf_link_hash_entry *h = NULL;

  /* Mergeable symbols and code might later move out of range.  */
  /* For bug-14274, symbols defined in the .rodata (the sections
     before .data, may also later move out of range.  */
  if (sym_sec->flags & (SEC_MERGE | SEC_CODE)
      || (data_start && sec_addr (sym_sec) < data_start))
    return TRUE;

  BFD_ASSERT (rel->r_offset + 4 <= sec->size);

  if (gp)
    {
      /* If gp and the symbol are in the same output section, then
	 consider only that section's alignment.  */
      struct bfd_link_hash_entry *gp_sym =
	bfd_link_hash_lookup (link_info->hash, RISCV_GP_SYMBOL, FALSE, FALSE,
			      TRUE);
      if (gp_sym->u.def.section->output_section == sym_sec->output_section)
	max_alignment = (bfd_vma) 1 << sym_sec->output_section->alignment_power;
    }

  /* For the gp relative insns, gp must be set to 4/8 bytes aligned
     address (Bug-14634).  */
  int gp_align;
  if ((ARCH_SIZE == 64))
    gp_align = 8;
  else
    gp_align = 4;
  if (gp_relative_insn
      && ((gp % gp_align) != 0))
    {
      (*_bfd_error_handler) (_("error: Please set gp to %x-byte aligned address "
			       "or turn off the gp relative instructions "
			       "(--mno-gp-insn).\n"), gp_align);
      return FALSE;
    }

  /* FIXME: Since we do not have grouping mechanism like v3, we may
     delete the high part insn that the corresponding low part insn
     isn't converted to gp relative one. Therefore, we record the
     symbols referenced by the non-relaxed low part insns in the
     relax Pass 1 round, and then do not delete the high part insns,
     which reference these symbols in the relax Pass 2 round.  */

  if (symtab_hdr->sh_info != 0
      && !symtab_hdr->contents
      && !(symtab_hdr->contents =
	   (unsigned char *) bfd_elf_get_elf_syms (abfd, symtab_hdr,
						   symtab_hdr->sh_info,
						   0, NULL, NULL, NULL)))
    return FALSE;

  if (ELFNN_R_SYM (rel->r_info) < symtab_hdr->sh_info)
    /* A local symbol.  */
    isym = ((Elf_Internal_Sym *) symtab_hdr->contents
	    + ELFNN_R_SYM (rel->r_info));
  else
    {
      /* A global symbol.  */
      unsigned long indx;
      indx = ELFNN_R_SYM (rel->r_info) - symtab_hdr->sh_info;
      h = elf_sym_hashes (abfd)[indx];

      while (h->root.type == bfd_link_hash_indirect
	     || h->root.type == bfd_link_hash_warning)
	h = (struct elf_link_hash_entry *) h->root.u.i.link;
    }

  /* Enable nds v5 gp relative insns.  */
  int do_replace = 0;
  uint32_t insn = bfd_get_32 (abfd, contents + rel->r_offset);
  /* For Bug-16488, check if gp-relative offset is in range.  */
  if ((symval >= gp
       && (symval - gp + max_alignment + reserve_size) < 0x20000)
      || (symval < gp
	  && (gp - symval + max_alignment + reserve_size) <= 0x20000))
    {
      do_replace = 1;
      unsigned sym = ELFNN_R_SYM (rel->r_info);
      if (ELFNN_R_TYPE (rel->r_info) == R_RISCV_HI20
	  && !record_and_find_relax_gp_syms (sym_sec, isym, h, 0))
	{
	  /* The HI20 can be deleted safely.  */
	  rel->r_info = ELFNN_R_INFO (0, R_RISCV_DELETE);
	  rel->r_addend = 4;
	  return TRUE;
	}
      else
	{
	  /* For Bug-16488, we don not need to consider max_alignment and
	     reserve_size here, since they may cause the alignment checking
	     fail.  */
	  if ((insn & MASK_ADDI) == MATCH_ADDI
	      && VALID_GPTYPE_LB_IMM (symval - gp))
	    {
	      rel->r_info = ELFNN_R_INFO (sym, R_RISCV_LGP18S0);
	      insn = (insn & (OP_MASK_RD << OP_SH_RD)) | MATCH_ADDIGP;
	    }
	  else if ((insn & MASK_LB) == MATCH_LB
		   && VALID_GPTYPE_LB_IMM (symval - gp))
	    {
	      rel->r_info = ELFNN_R_INFO (sym, R_RISCV_LGP18S0);
	      insn = (insn & (OP_MASK_RD << OP_SH_RD)) | MATCH_LBGP;
	    }
	  else if ((insn & MASK_LBU) == MATCH_LBU
		   && VALID_GPTYPE_LB_IMM (symval - gp))
	    {
	      rel->r_info = ELFNN_R_INFO (sym, R_RISCV_LGP18S0);
	      insn = (insn & (OP_MASK_RD << OP_SH_RD)) | MATCH_LBUGP;
	    }
	  else if ((insn & MASK_LH) == MATCH_LH
		   && VALID_GPTYPE_LH_IMM (symval - gp))
	    {
	      rel->r_info = ELFNN_R_INFO (sym, R_RISCV_LGP17S1);
	      insn = (insn & (OP_MASK_RD << OP_SH_RD)) | MATCH_LHGP;
	    }
	  else if ((insn & MASK_LHU) == MATCH_LHU
		   && VALID_GPTYPE_LH_IMM (symval - gp))
	    {
	      rel->r_info = ELFNN_R_INFO (sym, R_RISCV_LGP17S1);
	      insn = (insn & (OP_MASK_RD << OP_SH_RD)) | MATCH_LHUGP;
	    }
	  else if ((insn & MASK_LW) == MATCH_LW
		   && VALID_GPTYPE_LW_IMM (symval - gp))
	    {
	      rel->r_info = ELFNN_R_INFO (sym, R_RISCV_LGP17S2);
	      insn = (insn & (OP_MASK_RD << OP_SH_RD)) | MATCH_LWGP;
	    }
	  else if ((insn & MASK_LWU) == MATCH_LWU
		   && VALID_GPTYPE_LW_IMM (symval - gp))
	    {
	      rel->r_info = ELFNN_R_INFO (sym, R_RISCV_LGP17S2);
	      insn = (insn & (OP_MASK_RD << OP_SH_RD)) | MATCH_LWUGP;
	    }
	  else if ((insn & MASK_LD) == MATCH_LD
		   && VALID_GPTYPE_LD_IMM (symval - gp))
	    {
	      rel->r_info = ELFNN_R_INFO (sym, R_RISCV_LGP17S3);
	      insn = (insn & (OP_MASK_RD << OP_SH_RD)) | MATCH_LDGP;
	    }
	  else if ((insn & MASK_SB) == MATCH_SB
		   && VALID_GPTYPE_SB_IMM (symval - gp))
	    {
	      rel->r_info = ELFNN_R_INFO (sym, R_RISCV_SGP18S0);
	      insn = (insn & (OP_MASK_RS2 << OP_SH_RS2)) | MATCH_SBGP;
	    }
	  else if ((insn & MASK_SH) == MATCH_SH
		   && VALID_GPTYPE_SH_IMM (symval - gp))
	    {
	      rel->r_info = ELFNN_R_INFO (sym, R_RISCV_SGP17S1);
	      insn = (insn & (OP_MASK_RS2 << OP_SH_RS2)) | MATCH_SHGP;
	    }
	  else if ((insn & MASK_SW) == MATCH_SW
		   && VALID_GPTYPE_SW_IMM (symval - gp))
	    {
	      rel->r_info = ELFNN_R_INFO (sym, R_RISCV_SGP17S2);
	      insn = (insn & (OP_MASK_RS2 << OP_SH_RS2)) | MATCH_SWGP;
	    }
	  else if ((insn & MASK_SD) == MATCH_SD
		   && VALID_GPTYPE_SD_IMM (symval - gp))
	    {
	      rel->r_info = ELFNN_R_INFO (sym, R_RISCV_SGP17S3);
	      insn = (insn & (OP_MASK_RS2 << OP_SH_RS2)) | MATCH_SDGP;
	    }
	  else
	    do_replace = 0;
	}

      if (do_replace)
	bfd_put_32 (abfd, insn, contents + rel->r_offset);
      else
	/* The low insn can not be relaxed to v5 gp-relative insn.
	   Record the referenced symbol.  */
	record_and_find_relax_gp_syms (sym_sec, isym, h, 1);
    }

  /* Do not relax lui to c.lui here since the dangerous delete
     behavior.  */
  return TRUE;
}

/* Relax non-PIC global variable references without gp
   relative instructions.  */

static bfd_boolean
_bfd_riscv_relax_lui (bfd *abfd,
		      asection *sec,
		      asection *sym_sec,
		      struct bfd_link_info *link_info,
		      Elf_Internal_Rela *rel,
		      bfd_vma symval,
		      bfd_vma max_alignment,
		      bfd_vma reserve_size,
		      bfd_boolean *again,
		      riscv_pcgp_relocs *pcgp_relocs ATTRIBUTE_UNUSED,
		      bfd_boolean rvc)
{
  bfd_vma gp = riscv_global_pointer_value (link_info);
  bfd_vma data_start = riscv_data_start_value (link_info);

  /* Mergeable symbols and code might later move out of range.  */
  /* For bug-14274, symbols defined in the .rodata (the sections
     before .data, may also later move out of range.  */
  if (sym_sec->flags & (SEC_MERGE | SEC_CODE)
      || (data_start && sec_addr (sym_sec) < data_start))
    return TRUE;

  BFD_ASSERT (rel->r_offset + 4 <= sec->size);

  if (gp)
    {
      /* If gp and the symbol are in the same output section, then
	 consider only that section's alignment.  */
      struct bfd_link_hash_entry *h =
	bfd_link_hash_lookup (link_info->hash, RISCV_GP_SYMBOL, FALSE, FALSE,
			      TRUE);
      if (h->u.def.section->output_section == sym_sec->output_section)
	max_alignment = (bfd_vma) 1 << sym_sec->output_section->alignment_power;
    }

  /* Is the reference in range of x0 or gp?
     Valid gp range conservatively because of alignment issue.  */
  if (VALID_ITYPE_IMM (symval)
      || (symval >= gp
	  && VALID_ITYPE_IMM (symval - gp + max_alignment + reserve_size))
      || (symval < gp
	  && VALID_ITYPE_IMM (symval - gp - max_alignment - reserve_size)))
    {
      unsigned sym = ELFNN_R_SYM (rel->r_info);
      switch (ELFNN_R_TYPE (rel->r_info))
	{
	case R_RISCV_LO12_I:
	  rel->r_info = ELFNN_R_INFO (sym, R_RISCV_GPREL_I);
	  return TRUE;

	case R_RISCV_LO12_S:
	  rel->r_info = ELFNN_R_INFO (sym, R_RISCV_GPREL_S);
	  return TRUE;

	case R_RISCV_HI20:
	  /* We can delete the unnecessary LUI and reloc.  */
	  rel->r_info = ELFNN_R_INFO (0, R_RISCV_NONE);
	  *again = TRUE;
	  return riscv_relax_delete_bytes (abfd, sec, rel->r_offset, 4, link_info);

	default:
	  abort ();
	}
    }

  return riscv_relax_lui_to_rvc (abfd, sec, rel, symval, again, rvc, link_info);
}

/* Relax non-PIC TLS references.  */

static bfd_boolean
_bfd_riscv_relax_tls_le (bfd *abfd ATTRIBUTE_UNUSED,
			 asection *sec,
			 asection *sym_sec ATTRIBUTE_UNUSED,
			 struct bfd_link_info *link_info,
			 Elf_Internal_Rela *rel,
			 bfd_vma symval,
			 bfd_vma max_alignment ATTRIBUTE_UNUSED,
			 bfd_vma reserve_size ATTRIBUTE_UNUSED,
			 bfd_boolean *again,
			 riscv_pcgp_relocs *prcel_relocs ATTRIBUTE_UNUSED,
			 bfd_boolean rvc ATTRIBUTE_UNUSED)
{
  /* See if this symbol is in range of tp.  */
  if (RISCV_CONST_HIGH_PART (tpoff (link_info, symval)) != 0)
    return TRUE;

  BFD_ASSERT (rel->r_offset + 4 <= sec->size);
  switch (ELFNN_R_TYPE (rel->r_info))
    {
    case R_RISCV_TPREL_LO12_I:
      rel->r_info = ELFNN_R_INFO (ELFNN_R_SYM (rel->r_info), R_RISCV_TPREL_I);
      return TRUE;

    case R_RISCV_TPREL_LO12_S:
      rel->r_info = ELFNN_R_INFO (ELFNN_R_SYM (rel->r_info), R_RISCV_TPREL_S);
      return TRUE;

    case R_RISCV_TPREL_HI20:
    case R_RISCV_TPREL_ADD:
      /* We can delete the unnecessary instruction and reloc.  */
      rel->r_info = ELFNN_R_INFO (0, R_RISCV_NONE);
      *again = TRUE;
      return riscv_relax_delete_bytes (abfd, sec, rel->r_offset, 4, link_info);

    default:
      abort ();
    }
}

/* Convert a RVC instruction to RVI one.  Return 1 if done successfully,
   otherwise, return 0.  */
/* Just consider RV32C/RV64C. Skip RV128C instructions.  */

static int
riscv_convert_16_to_32 (uint16_t insn16, uint32_t *insn32)
{
  bfd_vma imm;
  /* Stack-Pointer-Based Loads and Stores.  */
  /* TODO: C.LQSP, C.FLWSP, C.FLDSP, C.SQSP, C.FSWSP, C.FSDSP.  */
  if ((insn16 & MASK_C_LWSP) == MATCH_C_LWSP)
    {
      /* CI format to I-TYPE.  */
      int rd = (insn16 >> 7) & 0x1f;
      if (rd == 0)
	return 0;
      imm = EXTRACT_RVC_LWSP_IMM (insn16);
      *insn32 = RISCV_ITYPE (LW, rd, X_SP, imm);  /* lw rd, imm(x2)  */
    }
  else if ((ARCH_SIZE == 64)
	   && (insn16 & MASK_C_LDSP) == MATCH_C_LDSP)
    {
      /* CI format to I-TYPE.  */
      int rd = (insn16 >> 7) & 0x1f;
      if (rd == 0)
	return 0;
      imm = EXTRACT_RVC_LDSP_IMM (insn16);
      *insn32 = RISCV_ITYPE (LD, rd, X_SP, imm); /* ld rd, imm(x2)  */
    }
  else if ((insn16 & MASK_C_SWSP) == MATCH_C_SWSP)
    {
      /* CSS format to S-TYPE.  */
      int rs2 = (insn16 >> OP_SH_CRS2) & OP_MASK_CRS2;
      imm = EXTRACT_RVC_SWSP_IMM (insn16);
      *insn32 = RISCV_STYPE (SW, X_SP, rs2, imm); /* sw rs2, imm(x2)  */
    }
  else if ((ARCH_SIZE == 64)
	   && (insn16 & MASK_C_SDSP) == MATCH_C_SDSP)
    {
      /* CSS format to S-TYPE.  */
      int rs2 = (insn16 >> OP_SH_CRS2) & OP_MASK_CRS2;
      imm = EXTRACT_RVC_SDSP_IMM (insn16);
      *insn32 = RISCV_STYPE (SD, X_SP, rs2, imm); /* sw rs2, imm(x2)  */
    }

  /* Register-Based Loads and Stores.  */
  /* TODO: C.LQ, C.FLW, C.FLD, C.SQ, C.FSW, C.FSD.  */
  else if ((insn16 & MASK_C_LW) == MATCH_C_LW)
    {
      /* CL format to I-TYPE.  */
      int rs1 = 8 + ((insn16 >> OP_SH_CRS1S) & OP_MASK_CRS1S);
      int rd = 8 + ((insn16 >> OP_SH_CRS2S) & OP_MASK_CRS2S);
      imm = EXTRACT_RVC_LW_IMM (insn16);
      *insn32 = RISCV_ITYPE (LW, rd, rs1, imm); /* lw rd, imm(rs1)  */
    }
  else if ((ARCH_SIZE == 64)
	   && (insn16 & MASK_C_LD) == MATCH_C_LD)
    {
      /* CL format to I-TYPE.  */
      int rs1 = 8 + ((insn16 >> OP_SH_CRS1S) & OP_MASK_CRS1S);
      int rd = 8 + ((insn16 >> OP_SH_CRS2S) & OP_MASK_CRS2S);
      imm = EXTRACT_RVC_LD_IMM (insn16);
      *insn32 = RISCV_ITYPE (LD, rd, rs1, imm); /* ld rd, imm(rs1)  */
    }
  else if ((insn16 & MASK_C_SW) == MATCH_C_SW)
    {
      /* CS format to S-TYPE.  */
      int rs1 = 8 + ((insn16 >> OP_SH_CRS1S) & OP_MASK_CRS1S);
      int rs2 = 8 + ((insn16 >> OP_SH_CRS2S) & OP_MASK_CRS2S);
      imm = EXTRACT_RVC_LW_IMM (insn16);
      *insn32 = RISCV_STYPE (SW, rs1, rs2, imm); /* sw rs2, imm(rs1)  */
    }
  else if ((ARCH_SIZE == 64)
	   && (insn16 & MASK_C_SD) == MATCH_C_SD)
    {
      /* CS format to S-TYPE.  */
      int rs1 = 8 + ((insn16 >> OP_SH_CRS1S) & OP_MASK_CRS1S);
      int rs2 = 8 + ((insn16 >> OP_SH_CRS2S) & OP_MASK_CRS2S);
      imm = EXTRACT_RVC_LD_IMM (insn16);
      *insn32 = RISCV_STYPE (SD, rs1, rs2, imm); /* sd rs2, imm(rs1)  */
    }

  /* Control Transfer Instructions.  */
  else if ((insn16 & MASK_C_J) == MATCH_C_J)
    {
      /* CJ format to UJ-TYPE.  */
      imm = EXTRACT_RVC_J_IMM (insn16);
      *insn32 = RISCV_UJTYPE (JAL, 0, imm);  /* jal x0, imm  */
    }
  else if ((ARCH_SIZE == 32)
	   && (insn16 & MASK_C_JAL) == MATCH_C_JAL)
    {
      /* CJ format to UJ-TYPE.  */
      imm = EXTRACT_RVC_J_IMM (insn16);
      *insn32 = RISCV_UJTYPE (JAL, X_RA, imm);  /* jal x0, imm  */
    }
  else if ((insn16 & MASK_C_JR) == MATCH_C_JR)
    {
      /* CR format to I-TYPE.  */
      int rs1 = (insn16 >> 7) & 0x1f;
      int rs2 = (insn16 >> OP_SH_CRS2) & OP_MASK_CRS2;
      if (rs1 == 0 || rs2 != 0)
	return 0;
      *insn32 = RISCV_ITYPE (JALR, 0, rs1, 0);  /* jalr x0, rs1, 0  */
    }
  else if ((insn16 & MASK_C_JALR) == MATCH_C_JALR)
    {
      /* CR format to I-TYPE.  */
      int rs1 = (insn16 >> 7) & 0x1f;
      int rs2 = (insn16 >> OP_SH_CRS2) & OP_MASK_CRS2;
      if (rs1 == 0 || rs2 != 0)
	return 0;
      *insn32 = RISCV_ITYPE (JALR, X_RA, rs1, 0); /* jalr x1, rs1, 0  */
    }
  else if ((insn16 & MASK_C_BEQZ) == MATCH_C_BEQZ)
    {
      /* CB format to SB-TYPE.  */
      int rs1 = 8 + ((insn16 >> OP_SH_CRS1S) & OP_MASK_CRS1S);
      imm = EXTRACT_RVC_B_IMM (insn16);
      *insn32 = RISCV_SBTYPE (BEQ, rs1, 0, imm);  /* beq rs1, x0, imm  */
    }
  else if ((insn16 & MASK_C_BNEZ) == MATCH_C_BNEZ)
    {
      /* CB format to SB-TYPE.  */
      int rs1 = 8 + ((insn16 >> OP_SH_CRS1S) & OP_MASK_CRS1S);
      imm = EXTRACT_RVC_B_IMM (insn16);
      *insn32 = RISCV_SBTYPE (BNE, rs1, 0, imm);  /* bne rs1, x0, imm  */
    }

  /* Integer Register-Immediate Operations.  */
  /* TODO: C.ADDIW.  */
  else if ((insn16 & MASK_C_ADDI) == MATCH_C_ADDI)
    {
      /* CI format to I-TYPE.  */
      int rd = (insn16 >> 7) & 0x1f;
      imm = EXTRACT_RVC_IMM (insn16);
      *insn32 = RISCV_ITYPE (ADDI, rd, rd, imm); /* addi rd, rd, nzimm  */
    }
  else if ((insn16 & MASK_C_ADDI16SP) == MATCH_C_ADDI16SP)
    {
      /* CI format to I-TYPE.  */
      /* c.addi16sp shares the opcode with c.lui.  */
      int rd = (insn16 >> 7) & 0x1f;
      if (rd != X_SP)
	return 0;

      imm = EXTRACT_RVC_ADDI16SP_IMM (insn16);
      *insn32 = RISCV_ITYPE (ADDI, X_SP, X_SP, imm); /* addi x2, x2, nzimm  */
    }
  else if ((insn16 & MASK_C_LUI) == MATCH_C_LUI)
    {
      /* CI format to I-TYPE.  */
      /* c.addi16sp shares the opcode with c.lui.  */
      int rd = (insn16 >> 7) & 0x1f;
      if (rd == 0 || rd == X_SP)
	return 0;

      imm = EXTRACT_RVC_LUI_IMM (insn16);
      *insn32 = RISCV_UTYPE (LUI, rd, imm); /* lui rd, nzimm  */
    }
  else if ((insn16 & MASK_C_ADDI4SPN) == MATCH_C_ADDI4SPN)
    {
      /* CIW format to I-TYPE.  */
      int rd = 8 + ((insn16 >> OP_SH_CRS2S) & OP_MASK_CRS2S);
      imm = EXTRACT_RVC_ADDI4SPN_IMM (insn16);
      *insn32 = RISCV_ITYPE (ADDI, rd, X_SP, imm); /* addi rd, x2, zimm  */
    }
  else if ((insn16 & MASK_C_SLLI) == MATCH_C_SLLI)
    {
      /* CI format to I-TYPE.  */
      int rd = (insn16 >> 7) & 0x1f;
      if (rd == 0)
	return 0;

      imm = RV_X(insn16, 2, 5) | (RV_X(insn16, 12, 1) << 5);
      *insn32 = RISCV_ITYPE (SLLI, rd, rd, imm); /* slli rd, rd, imm  */
    }
  else if ((insn16 & MASK_C_SRLI) == MATCH_C_SRLI)
    {
      /* CB format to I-TYPE.  */
      int rd = 8 + ((insn16 >> OP_SH_CRS1S) & OP_MASK_CRS1S);
      imm = RV_X(insn16, 2, 5) | (RV_X(insn16, 12, 1) << 5);
      *insn32 = RISCV_ITYPE (SRLI, rd, rd, imm); /* srli rd, rd, imm  */
    }
  else if ((insn16 & MASK_C_SRAI) == MATCH_C_SRAI)
    {
      /* CB format to I-TYPE.  */
      int rd = 8 + ((insn16 >> OP_SH_CRS1S) & OP_MASK_CRS1S);
      imm = RV_X(insn16, 2, 5) | (RV_X(insn16, 12, 1) << 5);
      *insn32 = RISCV_ITYPE (SRAI, rd, rd, imm); /* srai rd, rd, imm  */
    }
  else if ((insn16 & MASK_C_ANDI) == MATCH_C_ANDI)
    {
      /* CB format to I-TYPE.  */
      int rd = 8 + ((insn16 >> OP_SH_CRS1S) & OP_MASK_CRS1S);
      imm = EXTRACT_RVC_IMM (insn16);
      *insn32 = RISCV_ITYPE (ANDI, rd, rd, imm); /* andi rd, rd, imm  */
    }

  /* Integer Constant-Generation Instructions.  */
  else if ((insn16 & MASK_C_LI) == MATCH_C_LI)
    {
      /* CI format to I-TYPE.  */
      int rd = (insn16 >> 7) & 0x1f;
      if (rd == 0)
	return 0;
      imm = EXTRACT_RVC_IMM (insn16);
      *insn32 = RISCV_ITYPE (ADDI, rd, 0, imm); /* addi rd, x0, imm  */
    }

  /* Integer Register-Register Operations.  */
  /* TODO: C.ADDW, C.SUBW.  */
  else if ((insn16 & MASK_C_MV) == MATCH_C_MV)
    {
      /* CR format to R-TYPE.  */
      int rd = (insn16 >> 7) & 0x1f;
      int rs2 = (insn16 >> 2) & 0x1f;
      if (rd == 0 || rs2 == 0)
	return 0;
      *insn32 = RISCV_RTYPE (ADD, rd, 0, rs2); /* add rd, x0, rs2  */
    }
  else if ((insn16 & MASK_C_ADD) == MATCH_C_ADD)
    {
      /* CR format to R-TYPE.  */
      int rd = (insn16 >> 7) & 0x1f;
      int rs2 = (insn16 >> 2) & 0x1f;
      if (rd == 0 || rs2 == 0)
	return 0;
      *insn32 = RISCV_RTYPE (ADD, rd, rd, rs2); /* add rd, rd, rs2  */
    }
  else if ((insn16 & MASK_C_AND) == MATCH_C_AND)
    {
      /* CS format to R-TYPE.  */
      int rd = 8 + ((insn16 >> OP_SH_CRS1S) & OP_MASK_CRS1S);
      int rs2 = 8 + ((insn16 >> OP_SH_CRS2S) & OP_MASK_CRS2S);
      *insn32 = RISCV_RTYPE (AND, rd, rd, rs2); /* and rd, rd, rs2  */
    }
  else if ((insn16 & MASK_C_OR) == MATCH_C_OR)
    {
      /* CS format to R-TYPE.  */
      int rd = 8 + ((insn16 >> OP_SH_CRS1S) & OP_MASK_CRS1S);
      int rs2 = 8 + ((insn16 >> OP_SH_CRS2S) & OP_MASK_CRS2S);
      *insn32 = RISCV_RTYPE (OR, rd, rd, rs2); /* or rd, rd, rs2  */
    }
  else if ((insn16 & MASK_C_XOR) == MATCH_C_XOR)
    {
      /* CS format to R-TYPE.  */
      int rd = 8 + ((insn16 >> OP_SH_CRS1S) & OP_MASK_CRS1S);
      int rs2 = 8 + ((insn16 >> OP_SH_CRS2S) & OP_MASK_CRS2S);
      *insn32 = RISCV_RTYPE (XOR, rd, rd, rs2); /* xor rd, rd, rs2  */
    }
  else if ((insn16 & MASK_C_SUB) == MATCH_C_SUB)
    {
      /* CS format to R-TYPE.  */
      int rd = 8 + ((insn16 >> OP_SH_CRS1S) & OP_MASK_CRS1S);
      int rs2 = 8 + ((insn16 >> OP_SH_CRS2S) & OP_MASK_CRS2S);
      *insn32 = RISCV_RTYPE (SUB, rd, rd, rs2); /* sub rd, rd, rs2  */
    }
  else
    {
      /* This RVC can not be converted to RVI.  */
      return 0;
    }

  return 1;
}

static bfd_boolean
riscv_convert_16_to_32_reloc (Elf_Internal_Rela **irel)
{
  if (*irel)
    {
      unsigned sym = ELFNN_R_SYM ((*irel)->r_info);
      if (ELFNN_R_TYPE ((*irel)->r_info) == R_RISCV_RVC_BRANCH)
	(*irel)->r_info = ELFNN_R_INFO (sym, R_RISCV_BRANCH);
      else if (ELFNN_R_TYPE ((*irel)->r_info) == R_RISCV_RVC_JUMP)
	(*irel)->r_info = ELFNN_R_INFO (sym, R_RISCV_JAL);
      else if (ELFNN_R_TYPE ((*irel)->r_info) == R_RISCV_RVC_LUI)
	(*irel)->r_info = ELFNN_R_INFO (sym, R_RISCV_HI20);
      else
	/* Unsupported reloc converting.  */
	return FALSE;
    }
  return TRUE;
}

/* Check whether the ranges of 32-bit branch and jal is valid between
   the rvc candidate and alignment point after doing target aligned.  */

static bfd_boolean
target_align_check_branch_range (bfd *abfd, asection *sec, bfd_vma insn16_off,
				 bfd_vma nops_off, size_t count,
				 struct bfd_link_info *link_info)
{
  struct elf_link_hash_entry **sym_hashes = elf_sym_hashes (abfd);
  Elf_Internal_Shdr *symtab_hdr = &elf_tdata (abfd)->symtab_hdr;
  Elf_Internal_Sym *sym = (Elf_Internal_Sym *) symtab_hdr->contents;
  struct bfd_elf_section_data *data = elf_section_data (sec);
  bfd_byte *contents = data->this_hdr.contents;
  Elf_Internal_Rela *irel, *irelend;
  bfd_vma relocation = 0, pc = 0;
  bfd_vma where = insn16_off + 2;

  irel = data->relocs;
  irelend = data->relocs + sec->reloc_count;
  while (where < nops_off)
    {
      if ((*(contents + where) & 0x3) != 0x3)
	/* 16-bits insn, skip it.  */
	where += 2;
      else
	{
	  /* Find the relocation that it's r_offset is same as where.  */
	  while (irel != NULL && irel < irelend && irel->r_offset < where)
	    irel++;

	  /* Only check branch and jal range. If overflow, return 0.  */
	  riscv_relocation_check (link_info, &irel, irelend, sec, &where, contents, 0);

	  if (ELFNN_R_TYPE (irel->r_info) == R_RISCV_BRANCH
	      || ELFNN_R_TYPE (irel->r_info) == R_RISCV_JAL)
	    {
	      unsigned long r_symndx = ELFNN_R_SYM (irel->r_info);
	      if (r_symndx < symtab_hdr->sh_info)
		{
		  /* Local symbol.  */
		  int shndx = sym[r_symndx].st_shndx;
		  bfd_vma st_value = (sym + r_symndx)->st_value;
		  asection *sym_sec = elf_elfsections (abfd)[shndx]->bfd_section;
		  relocation = sym_sec->output_section->vma
		    + sym_sec->output_offset
		    + st_value;
		  if ((sym + r_symndx)->st_value > insn16_off
		      && (sym + r_symndx)->st_value <= nops_off)
		    relocation += count;
		}
	      else
		{
		  /* External symbol.  */
		  bfd_boolean warned ATTRIBUTE_UNUSED;
		  bfd_boolean ignored ATTRIBUTE_UNUSED;
		  bfd_boolean unresolved_reloc ATTRIBUTE_UNUSED;
		  struct elf_link_hash_entry *h;
		  asection *sym_sec;

		  RELOC_FOR_GLOBAL_SYMBOL (link_info, abfd, sec, irel,
					   r_symndx, symtab_hdr, sym_hashes,
					   h, sym_sec, relocation,
					   unresolved_reloc, warned, ignored);

		  if (h->root.u.def.value > insn16_off
		      && h->root.u.def.value <= nops_off)
		    relocation += count;
		}

	      pc = sec_addr (sec) + irel->r_offset;
	      if (irel->r_offset > insn16_off
		  && irel->r_offset < nops_off)
		pc += count;

	      reloc_howto_type *howto;
	      howto = riscv_elf_rtype_to_howto (abfd, ELFNN_R_TYPE (irel->r_info));
	      if (howto->pc_relative)
		relocation -= pc;
	      relocation += irel->r_addend;

	      if ((ELFNN_R_TYPE (irel->r_info) == R_RISCV_BRANCH
		   && !VALID_SBTYPE_IMM (relocation))
		  || (ELFNN_R_TYPE (irel->r_info) == R_RISCV_JAL
		      && !VALID_UJTYPE_IMM (relocation)))
		return FALSE;
	    }
	  where += 4;
	}
    }
  return TRUE;
}

/* Shift a field of section content while doing target aligned.
   Like riscv_relax_delete_bytes, we need to adjust relocations
   and symbols in the field.  */

static bfd_boolean
riscv_relax_shift_bytes (bfd *abfd, asection *sec, bfd_vma insn16_off,
			 bfd_vma nops_off, size_t count, uint32_t insn32)
{
  unsigned int i, symcount;
  struct elf_link_hash_entry **sym_hashes = elf_sym_hashes (abfd);
  Elf_Internal_Shdr *symtab_hdr = &elf_tdata (abfd)->symtab_hdr;
  unsigned int sec_shndx = _bfd_elf_section_from_bfd_section (abfd, sec);
  struct bfd_elf_section_data *data = elf_section_data (sec);
  bfd_byte *contents = data->this_hdr.contents;

  /* Shift the code, and then convert a 16-bit instruction into 32-bit.  */
  memmove (contents + insn16_off + 4, contents + insn16_off + 2, nops_off - insn16_off - 2);
  bfd_put_32 (abfd, insn32, contents + insn16_off);

  /* Adjust the location of all of the relocs.  */
  for (i = 0; i < sec->reloc_count; i++)
    if (data->relocs[i].r_offset > insn16_off
	&& data->relocs[i].r_offset <= nops_off)
      data->relocs[i].r_offset += count;

  /* Adjust the local symbols defined in this section.  */
  for (i = 0; i < symtab_hdr->sh_info; i++)
    {
      Elf_Internal_Sym *sym = (Elf_Internal_Sym *) symtab_hdr->contents + i;
      if (sym->st_shndx == sec_shndx)
	{
	  /* Adjust the symbol size if needed.  */
	  if (sym->st_value > insn16_off
	      && sym->st_value <= nops_off
	      && sym->st_value + sym->st_size > nops_off)
	    sym->st_size -= count;
	  else if (sym->st_value <= insn16_off
		   && sym->st_value + sym->st_size > insn16_off
		   && sym->st_value + sym->st_size <= nops_off)
	    sym->st_size += count;

	  /* If the symbol is in the range of memory we just shifted,
	     we have to adjust it's value.  */
	  if (sym->st_value > insn16_off && sym->st_value <= nops_off)
	    sym->st_value += count;
	}
    }

  /* Adjust the global symbols defined in this section.  */
  symcount = ((symtab_hdr->sh_size / sizeof (ElfNN_External_Sym))
	      - symtab_hdr->sh_info);

  for (i = 0; i < symcount; i++)
    {
      struct elf_link_hash_entry *sym_hash = sym_hashes[i];

      if ((sym_hash->root.type == bfd_link_hash_defined
	   || sym_hash->root.type == bfd_link_hash_defweak)
	  && sym_hash->root.u.def.section == sec)
	{
	  /* As above, adjust the size if needed.  */
	  if (sym_hash->root.u.def.value > insn16_off
	      && sym_hash->root.u.def.value <= nops_off
	      && sym_hash->root.u.def.value + sym_hash->size > nops_off)
	    sym_hash->size -= count;
	  else if (sym_hash->root.u.def.value <= insn16_off
		   && sym_hash->root.u.def.value + sym_hash->size > insn16_off
		   && sym_hash->root.u.def.value + sym_hash->size <= nops_off)
	    sym_hash->size += count;

	  /* As above, adjust the value if needed.  */
	  if (sym_hash->root.u.def.value > insn16_off
	      && sym_hash->root.u.def.value <= nops_off)
	    sym_hash->root.u.def.value += count;
	}
    }

  return TRUE;
}

/* For avioding BTB miss, we need to convert a 16-bit insn to
   32-bit one (this insn is located between JAL and branch), and
   then adjust symbols for the insn.  */

static bfd_boolean
riscv_relax_avoid_BTB_miss (bfd *abfd, asection *sec, bfd_vma align_off,
			    bfd_vma insn16_off, size_t count)
{
  unsigned int i, symcount;
  struct elf_link_hash_entry **sym_hashes = elf_sym_hashes (abfd);
  Elf_Internal_Shdr *symtab_hdr = &elf_tdata (abfd)->symtab_hdr;
  unsigned int sec_shndx = _bfd_elf_section_from_bfd_section (abfd, sec);
  struct bfd_elf_section_data *data = elf_section_data (sec);
  bfd_byte *contents = data->this_hdr.contents;

  if ((*(contents + align_off + insn16_off) & 0x3) != 0x3)
    {
      uint32_t insn;
      uint16_t insn16 = bfd_get_16 (abfd, contents + align_off + insn16_off);
      /* Convert a 16-bit branch to 32-bit one doesn't help
	 to solved BTB miss.  */
      if (!(((ARCH_SIZE == 32) && ((insn16 & MASK_C_JAL) == MATCH_C_JAL))
	    || (insn16 & MASK_C_J) == MATCH_C_J
	    || (insn16 & MASK_C_BNEZ) == MATCH_C_BNEZ
	    || (insn16 & MASK_C_BEQZ) == MATCH_C_BEQZ)
	  && riscv_convert_16_to_32 (insn16, &insn))
	{
	  bfd_put_32 (abfd, insn, contents + align_off + insn16_off - count);

	  /* Adjust the location of all of the relocs.  */
	  /* Maybe we should enhance the error msg here.  */
	  for (i = 0; i < sec->reloc_count; i++)
	    if (data->relocs[i].r_offset == align_off + insn16_off)
	      {
		Elf_Internal_Rela *reloc = &(data->relocs[i]);
		riscv_convert_16_to_32_reloc (&reloc);
		data->relocs[i].r_offset -= count;
	      }

	  for (i = 0; i < symtab_hdr->sh_info; i++)
	    {
	      Elf_Internal_Sym *sym = (Elf_Internal_Sym *) symtab_hdr->contents + i;
	      if (sym->st_shndx == sec_shndx)
		{
		  /* Adjust the symbol size if needed.  */
		  if (sym->st_value == align_off + insn16_off)
		    sym->st_value -= count;
		}
	    }

	  symcount = ((symtab_hdr->sh_size / sizeof (ElfNN_External_Sym))
		      - symtab_hdr->sh_info);
	  for (i = 0; i < symcount; i++)
	    {
	      struct elf_link_hash_entry *sym_hash = sym_hashes[i];

	      if ((sym_hash->root.type == bfd_link_hash_defined
		   || sym_hash->root.type == bfd_link_hash_defweak)
		  && sym_hash->root.u.def.section == sec)
		{
		  /* As above, adjust the value if needed.  */
		  if (sym_hash->root.u.def.value == align_off + insn16_off)
		    sym_hash->root.u.def.value -= count;
		}
	    }
	  return TRUE;
	}
    }

  /* Can not avoid BTB miss, return FALSE.  */
  return FALSE;
}

static bfd_boolean
btb_miss_occur (bfd_vma return_address, bfd_vma branch_end)
{
  if ((int)(return_address/4) == (int)(branch_end/4))
    return TRUE;
  else
    return FALSE;
}

static bfd_boolean
riscv_relax_check_BTB_miss (bfd *abfd, asection *sec, bfd_vma align_off,
			    bfd_vma addend, bfd_vma nop_bytes,
			    bfd_boolean target_align)
{
  struct bfd_elf_section_data *data = elf_section_data (sec);
  bfd_byte *contents = data->this_hdr.contents;
  bfd_vma return_address, check_begin, check_limit;
  unsigned int i;

  if (target_align)
    {
      return_address = sec_addr (sec) + align_off + addend;
      check_limit = 4;
    }
  else
    {
      return_address = sec_addr (sec) + align_off;
      check_limit = 4 - nop_bytes;
    }

  /* The case ALIGN_BTB + ALIGN is hard to check BTB miss, skip it.  */
  for (i = 0; i < sec->reloc_count; i++)
    if (data->relocs[i].r_offset == align_off + addend
	&& (ELFNN_R_TYPE (data->relocs[i].r_info) == R_RISCV_ALIGN
	    || ELFNN_R_TYPE (data->relocs[i].r_info) == R_RISCV_ALIGN_BTB))
      return FALSE;

  check_begin = 0;
  while (check_begin < check_limit)
    {
      if ((*(contents + align_off + addend + check_begin) & 0x3) != 0x3)
	{
	  /* 16-bits insn.  */
	  uint16_t insn16 = bfd_get_16 (abfd, contents + align_off + addend + check_begin);
	  bfd_vma branch_end = sec_addr (sec) + align_off + nop_bytes + check_begin;
	  if ((((ARCH_SIZE == 32) && (insn16 & MASK_C_JAL) == MATCH_C_JAL)
	       || (insn16 & MASK_C_JR) == MATCH_C_JR
	       || (insn16 & MASK_C_JALR) == MATCH_C_JALR
	       || (insn16 & MASK_C_J) == MATCH_C_J
	       || (insn16 & MASK_C_BEQZ) == MATCH_C_BEQZ
	       || (insn16 & MASK_C_BNEZ) == MATCH_C_BNEZ)
	      && btb_miss_occur (return_address, branch_end))
	    return TRUE;
	  check_begin += 2;
	}
      else
	{
	  /* 32-bits insn.  */
	  uint32_t insn = bfd_get_32 (abfd, contents + align_off + addend + check_begin);
	  bfd_vma branch_end = sec_addr (sec) + align_off + nop_bytes + check_begin + 2;
	  if (((insn & MASK_JAL) == MATCH_JAL
	       || (insn & MASK_JALR) == MATCH_JALR
	       || (insn & MASK_BEQ) == MATCH_BEQ
	       || (insn & MASK_BNE) == MATCH_BNE
	       || (insn & MASK_BLT) == MATCH_BLT
	       || (insn & MASK_BGE) == MATCH_BGE
	       || (insn & MASK_BLTU) == MATCH_BLTU
	       || (insn & MASK_BGEU) == MATCH_BGEU)
	      && btb_miss_occur (return_address, branch_end))
	    return TRUE;
	  check_begin += 4;
	}
    }
  return FALSE;
}

static bfd_vma pre_align_off;

/* Implement R_RISCV_ALIGN and R_RISCV_ALIGN_BTB by deleting excess alignment NOPs.  */

static bfd_boolean
_bfd_riscv_relax_align (bfd *abfd, asection *sec,
			asection *sym_sec,
			struct bfd_link_info *link_info,
			Elf_Internal_Rela *rel,
			bfd_vma symval,
			bfd_vma max_alignment ATTRIBUTE_UNUSED,
			bfd_vma reserve_size ATTRIBUTE_UNUSED,
			bfd_boolean *again ATTRIBUTE_UNUSED,
			riscv_pcgp_relocs *pcgp_relocs ATTRIBUTE_UNUSED,
			bfd_boolean rvc)
{
  if (rel->r_addend & (1 << 31))
    return TRUE;

  struct riscv_elf_link_hash_table *table = riscv_elf_hash_table (link_info);
  bfd_byte *contents = elf_section_data (sec)->this_hdr.contents;
  bfd_vma alignment = 1, pos;
  int align_btb = 0;
  while (alignment <= rel->r_addend)
    alignment *= 2;
  if (ELFNN_R_TYPE (rel->r_info) == R_RISCV_ALIGN_BTB)
    {
      alignment = 4;
      align_btb = 1;
    }

  symval -= rel->r_addend;
  bfd_vma aligned_addr = ((symval - 1) & ~(alignment - 1)) + alignment;
  bfd_vma nop_bytes = aligned_addr - symval;

  /* Once we've handled an R_RISCV_ALIGN, we can't relax anything else.  */
  /* Generally, we can't relax anything after we've handled an R_RISCV_ALIGN.
     Otherwise, we have to check alignment for each relaxation after
     _bfd_riscv_relax_align.  */
  if (!(table->target_optimize & RISCV_RELAX_EXECIT_ON))
    sec->sec_flg0 = TRUE;

  /* Make sure there are enough NOPs to actually achieve the alignment.  */
  if (rel->r_addend < nop_bytes)
    {
      _bfd_error_handler
	(_("%pB(%pA+%#" PRIx64 "): %" PRId64 " bytes required for alignment "
	   "to %" PRId64 "-byte boundary, but only %" PRId64 " present"),
	 abfd, sym_sec, (uint64_t) rel->r_offset,
	 (int64_t) nop_bytes, (int64_t) alignment, (int64_t) rel->r_addend);
      bfd_set_error (bfd_error_bad_value);
      return FALSE;
    }

  /* Since EXECIT needs the information about alignment later, we can not delete
     R_RISCV_ALIGN here. Unfortunately, we can only assure 4-byte aligned for
     EXECIT so far. Therefore, we reserve R_RISCV_ALIGN only for 4-byte aligned. */
  if (rel->r_addend != 2)
    rel->r_info = ELFNN_R_INFO (0, R_RISCV_NONE);

  /* TODO: Implement n-byte aligned.  */
  int data_flag;
  uint32_t insn = 0xffffffff;
  bfd_vma insn16_off = 0xffffffff;
  Elf_Internal_Rela *irel_save = NULL;
  bfd_vma where = pre_align_off;
  if (table->target_aligned && rvc
      && nop_bytes && alignment == 4)
    {
      Elf_Internal_Rela *relocs, *irelend, *irel;
      if (elf_section_data (sec)->relocs)
	relocs = elf_section_data (sec)->relocs;
      else
	relocs = _bfd_elf_link_read_relocs (abfd, sec, NULL, NULL,
					    TRUE /* keep_memory  */);
      irelend = relocs + sec->reloc_count;

      irel = relocs;
      while (where < rel->r_offset)
	{
	  /* Find the relocation that it's r_offset is same as where.  */
	  while (irel != NULL && irel < irelend && irel->r_offset < where)
	    irel++;

	  data_flag = riscv_relocation_check (link_info, &irel, irelend,
					      sec, &where, contents, 0);
	  if (data_flag & DATA_EXIST)
	    {
	      where += (data_flag >> 24);
	      continue;
	    }

	  if ((*(contents + where) & 0x3) != 0x3)
	    {
	      uint16_t insn16 = bfd_get_16 (abfd, contents + where);
	      if (riscv_convert_16_to_32 (insn16, &insn))
		{
		  insn16_off = where;
		  if (irel->r_offset == where)
		    irel_save = irel;
		  else
		    /* There is no relocation for the insn16.  */
		    irel_save = NULL;
		}
	      /* This RVC can not be converted to RVI.  */
	      where += 2;
	    }
	  else
	    where += 4;
	}
    }
  pre_align_off = rel->r_offset + nop_bytes;

  /* Convert it to RVI and then remove the nop16.  */
  /* We use the highest 1 byte of R_RISCV_ALIGN addend to record
     whether this relocation is relaxed by bfd_riscv_relax_align.  */
  if (insn != 0xffffffff
      && insn16_off != 0xffffffff
      && target_align_check_branch_range (abfd, sec, insn16_off, rel->r_offset,
					  2, link_info))
    {
	/* The rvc insn with relocs has been converted to 32-bit instruction
           above, therefore, we modify it's reloc, too.  */
      if (!riscv_convert_16_to_32_reloc (&irel_save))
	{
	  (*_bfd_error_handler)
	    (_("%pB(%pA+0x%lx): Unsupported reloc %ld when converting "
	       "insn from 16-bit to 32-bit for target aligned"),
	     abfd, sym_sec, irel_save->r_offset,
	     ELFNN_R_TYPE (irel_save->r_info));
	  bfd_set_error (bfd_error_bad_value);
	  return FALSE;
	}

      riscv_relax_shift_bytes (abfd, sec, insn16_off, rel->r_offset, 2, insn);

      /* Check BTB miss after target aligned.  */
      if (align_btb)
	{
	  bfd_put_16 (abfd, RVC_NOP, contents + rel->r_offset);
	  if (table->avoid_btb_miss
	      && riscv_relax_check_BTB_miss (abfd, sec, rel->r_offset,
					     rel->r_addend - 2, 0, 1)
	      && riscv_relax_avoid_BTB_miss (abfd, sec, rel->r_offset, 2, 2))
	    {
	      /* If BTB miss occurs, convert the rvc insn between jal and branch
		 to rvi insn in riscv_relax_avoid_BTB_miss.  */
	    }
	  else
	    /* Can not avoid BTB miss, we have to delete the redundant 2 bytes
	       for ALIGN_BTB.  */
	    riscv_relax_delete_bytes (abfd, sec, rel->r_offset,
				      rel->r_addend - nop_bytes, link_info);
	}

      rel->r_addend = (1 << 31);
      return TRUE;
    }
  else
    {
      /* BTB miss occurs without target aligned.  */
      if (align_btb && table->avoid_btb_miss
	  && riscv_relax_check_BTB_miss (abfd, sec, rel->r_offset,
					 rel->r_addend, nop_bytes, 0)
	  && riscv_relax_avoid_BTB_miss (abfd, sec, rel->r_offset, 4, 2))
	rel->r_addend -= 2;

      /* Write as many RISC-V NOPs as we need.  */
      for (pos = 0; pos < (nop_bytes & -4); pos += 4)
	bfd_put_32 (abfd, RISCV_NOP, contents + rel->r_offset + pos);

      /* Write a final RVC NOP if need be.  */
      if (nop_bytes % 4 != 0)
	bfd_put_16 (abfd, RVC_NOP, contents + rel->r_offset + pos);

      /* If the number of NOPs is already correct, there's nothing to do.  */
      if (nop_bytes == rel->r_addend)
	{
	  rel->r_addend = nop_bytes | (1 << 31);
	  return TRUE;
	}

      /* Delete the excess bytes.  */
      riscv_relax_delete_bytes (abfd, sec, rel->r_offset + nop_bytes,
				rel->r_addend - nop_bytes, link_info);
      rel->r_addend = nop_bytes | (1 << 31);
      return TRUE;
    }
}

/* Relax PC-relative references to GP-relative references.  */

static bfd_boolean
_bfd_riscv_relax_pc  (bfd *abfd,
		      asection *sec,
		      asection *sym_sec,
		      struct bfd_link_info *link_info,
		      Elf_Internal_Rela *rel,
		      bfd_vma symval,
		      bfd_vma max_alignment,
		      bfd_vma reserve_size,
		      bfd_boolean *again ATTRIBUTE_UNUSED,
		      riscv_pcgp_relocs *pcgp_relocs,
		      bfd_boolean rvc ATTRIBUTE_UNUSED)
{
  bfd_vma gp = riscv_global_pointer_value (link_info);

  BFD_ASSERT (rel->r_offset + 4 <= sec->size);

  /* Chain the _LO relocs to their cooresponding _HI reloc to compute the
   * actual target address.  */
  riscv_pcgp_hi_reloc hi_reloc;
  memset (&hi_reloc, 0, sizeof (hi_reloc));
  switch (ELFNN_R_TYPE (rel->r_info))
    {
    case R_RISCV_PCREL_LO12_I:
    case R_RISCV_PCREL_LO12_S:
      {
	/* If the %lo has an addend, it isn't for the label pointing at the
	   hi part instruction, but rather for the symbol pointed at by the
	   hi part instruction.  So we must subtract it here for the lookup.
	   It is still used below in the final symbol address.  */
	bfd_vma hi_sec_off = symval - sec_addr (sym_sec) - rel->r_addend;
	riscv_pcgp_hi_reloc *hi = riscv_find_pcgp_hi_reloc (pcgp_relocs,
							    hi_sec_off);
	if (hi == NULL)
	  {
	    riscv_record_pcgp_lo_reloc (pcgp_relocs, hi_sec_off);
	    return TRUE;
	  }

	hi_reloc = *hi;
	symval = hi_reloc.hi_addr;
	sym_sec = hi_reloc.sym_sec;
	if (!riscv_use_pcgp_hi_reloc(pcgp_relocs, hi->hi_sec_off))
	  (*_bfd_error_handler)
	   (_("%pB(%pA+0x%lx): Unable to clear RISCV_PCREL_HI20 reloc"
	      "for cooresponding RISCV_PCREL_LO12 reloc"),
	    abfd, sec, rel->r_offset);
      }
      break;

    case R_RISCV_PCREL_HI20:
      /* Mergeable symbols and code might later move out of range.  */
      if (sym_sec->flags & (SEC_MERGE | SEC_CODE))
	return TRUE;

      /* If the cooresponding lo relocation has already been seen then it's not
       * safe to relax this relocation.  */
      if (riscv_find_pcgp_lo_reloc (pcgp_relocs, rel->r_offset))
	return TRUE;

      break;

    default:
      abort ();
    }

  if (gp)
    {
      /* If gp and the symbol are in the same output section, then
	 consider only that section's alignment.  */
      struct bfd_link_hash_entry *h =
	bfd_link_hash_lookup (link_info->hash, RISCV_GP_SYMBOL, FALSE, FALSE, TRUE);
      if (h->u.def.section->output_section == sym_sec->output_section)
	max_alignment = (bfd_vma) 1 << sym_sec->output_section->alignment_power;
    }

  /* Is the reference in range of x0 or gp?
     Valid gp range conservatively because of alignment issue.  */
  if (VALID_ITYPE_IMM (symval)
      || (symval >= gp
	  && VALID_ITYPE_IMM (symval - gp + max_alignment + reserve_size))
      || (symval < gp
	  && VALID_ITYPE_IMM (symval - gp - max_alignment - reserve_size)))
    {
      unsigned sym = hi_reloc.hi_sym;
      switch (ELFNN_R_TYPE (rel->r_info))
	{
	case R_RISCV_PCREL_LO12_I:
	  rel->r_info = ELFNN_R_INFO (sym, R_RISCV_GPREL_I);
	  rel->r_addend += hi_reloc.hi_addend;
	  return riscv_delete_pcgp_lo_reloc (pcgp_relocs, rel->r_offset, 4);

	case R_RISCV_PCREL_LO12_S:
	  rel->r_info = ELFNN_R_INFO (sym, R_RISCV_GPREL_S);
	  rel->r_addend += hi_reloc.hi_addend;
	  return riscv_delete_pcgp_lo_reloc (pcgp_relocs, rel->r_offset, 4);

	case R_RISCV_PCREL_HI20:
	  riscv_record_pcgp_hi_reloc (pcgp_relocs,
				      rel->r_offset,
				      rel->r_addend,
				      symval,
				      ELFNN_R_SYM(rel->r_info),
				      sym_sec);
	  /* We can delete the unnecessary AUIPC and reloc.  */
	  rel->r_info = ELFNN_R_INFO (0, R_RISCV_DELETE);
	  rel->r_addend = 4;
	  return riscv_delete_pcgp_hi_reloc (pcgp_relocs, rel->r_offset);

	default:
	  abort ();
	}
    }

  return TRUE;
}

/* Relax PC-relative references to GP-relative references.  */

static bfd_boolean
_bfd_riscv_relax_delete (bfd *abfd,
			 asection *sec,
			 asection *sym_sec ATTRIBUTE_UNUSED,
			 struct bfd_link_info *link_info,
			 Elf_Internal_Rela *rel,
			 bfd_vma symval ATTRIBUTE_UNUSED,
			 bfd_vma max_alignment ATTRIBUTE_UNUSED,
			 bfd_vma reserve_size ATTRIBUTE_UNUSED,
			 bfd_boolean *again ATTRIBUTE_UNUSED,
			 riscv_pcgp_relocs *pcgp_relocs ATTRIBUTE_UNUSED,
			 bfd_boolean rvc ATTRIBUTE_UNUSED)
{
  if (!riscv_relax_delete_bytes(abfd, sec, rel->r_offset, rel->r_addend,
				link_info))
    return FALSE;

  /* Should we run relaxations again from Pass 1?  */
  rel->r_info = ELFNN_R_INFO(0, R_RISCV_NONE);
/*
  info->relax_pass = 1;
  *again = TRUE;
*/
  return TRUE;
}

/* Find the closest previous NO_RVC_REGION, and then check
   if the RVC is enabled.  */

static int
riscv_enable_rvc (Elf_Internal_Rela *rel, Elf_Internal_Rela *end)
{
  int type, result = -1;
  bfd_vma offset = rel->r_offset;

  while (rel != end && rel->r_offset == offset)
    {
      type = ELFNN_R_TYPE (rel->r_info);
      switch (type)
	{
	case R_RISCV_NO_RVC_REGION_BEGIN: result = 1; break;
	case R_RISCV_NO_RVC_REGION_END: result = 0; break;
	default: break;
	}
      rel = rel + 1;
    }

  return result;
}

/* Relax a section.
   Pass 1, 2 shortens code sequences unless disabled.
   Pass 3 deletes the bytes that pass 1 and 2 made obselete.
   Pass 4, which cannot be disabled, handles code alignment directives.
   Pass 0, 5, 6 which can only be done once, deal with EXECIT.  */

static bfd_boolean
_bfd_riscv_relax_section (bfd *abfd, asection *sec,
			  struct bfd_link_info *info,
			  bfd_boolean *again)
{
  Elf_Internal_Shdr *symtab_hdr = &elf_symtab_hdr (abfd);
  struct riscv_elf_link_hash_table *htab = riscv_elf_hash_table (info);
  struct bfd_elf_section_data *data = elf_section_data (sec);
  Elf_Internal_Rela *relocs;
  bfd_boolean ret = FALSE;
  unsigned int i;
  bfd_vma max_alignment, reserve_size = 0;
  riscv_pcgp_relocs pcgp_relocs;
  static int gp_init = 0;
  static asection *final_sec = NULL;
  /* Make sure that EXECIT can only be done once.  */
  static int execit_init = 0;
  static int execit_build_finish = 0;
  static int execit_replace_finish = 0;
  /* For EXECIT update.  */
  static int execit_replace_again = 0;
  bfd_boolean rvc = FALSE;
  Elf_Internal_Rela *relocs_end;

  /* Reset it for each input section.
     It used to record orevious alignment offset
     in _bfd_riscv_relax_align.  */
  pre_align_off = 0;

  *again = FALSE;

  /* Nothing to do for
     relocatable link or
     sec_flg0 section (the last relax) or
     non-relocatable section or
     excluded section or
     non-code section or
     empty content or
     no reloc entry or
     disable relaxation.  */
  if (bfd_link_relocatable (info)
      || sec->sec_flg0
      || (sec->flags & SEC_RELOC) == 0
      || (sec->flags & SEC_EXCLUDE) == 1
      || (sec->flags & SEC_CODE) == 0
      || sec->size == 0
      || sec->reloc_count == 0
      || (info->disable_target_specific_optimizations
	  && (info->relax_pass == 0
	      || info->relax_pass == 1
	      || info->relax_pass == 2
	      || info->relax_pass == 3
	      || info->relax_pass == 4
	      || info->relax_pass == 6
	      || info->relax_pass == 7)))
    return TRUE;

  riscv_init_pcgp_relocs (&pcgp_relocs);

  /* Check and init '__global_pointer$'.  */
  if (!gp_init && !bfd_link_pic (info))
    {
      if (!riscv_init_global_pointer (sec->output_section->owner, info))
	{
	  (*_bfd_error_handler)
	    (_("\nWarning: Init __global_pointer$ failed. "
	       "Can not find __global_pointer$ and .sdata section.\n"));
	}
      gp_init = 1;
    }

  /* Initialization for EXECIT.  */
  if (!execit_init)
    {
      if (htab->target_optimize & RISCV_RELAX_EXECIT_ON)
	{
	  /* No need to build EXECIT hash table when only EXECIT import is setting.  */
	  if (htab->execit_import_file == NULL
	      || htab->update_execit_table)
	    riscv_elf_execit_init ();
	  /* For EXECIT update, we replace execit candiadtes to exec.it
	     according to the imported table first. After that,
	     we build the EXECIT hash table for the remaining patterns
	     to do EXECIT replacement again.  */
	  if (htab->execit_import_file)
	    {
	      execit_build_finish = 1;
	      riscv_elf_execit_import_table (abfd, info);
	    }
	}
      else
	{
	  execit_build_finish = 1;
	  execit_replace_finish = 1;
	}

      execit_init = 1;
    }

  /* Read this BFD's relocs if we haven't done so already.  */
  if (data->relocs)
    relocs = data->relocs;
  else if (!(relocs = _bfd_elf_link_read_relocs (abfd, sec, NULL, NULL,
						 info->keep_memory)))
    goto fail;

  /* Sort relocation by r_offset.  */
  riscv_insertion_sort (relocs, sec->reloc_count,
			sizeof (Elf_Internal_Rela), compar_reloc);

  /* Check relax_pass and then do the corresponding relaxation.
     Only Pass 1 can be run many times.
     Pass 0: Empty round (find the last section)
     Pass 1: Normal relaxation round (relax_lui/call/pc/tls-le)
     Pass 2: relax_lui_gp_insn (low part)
     Pass 3: relax_lui_gp_insn (high part)
     Pass 4: Delete round for Pass 1-3 relaxations (lui_gp_insn/pc)
     Pass 5: Relax alignment round (alignment, target aligned,
	     avoid BTB miss)
     ------ Relaxations below must consider alignemnt issue -----
     Pass 6: Exec.it build round
     Pass 7: Exec.it replace round  */
  switch (info->relax_pass)
    {
    case 0:
      /* TODO: Can we remove the empty round?  */
      if (execit_build_finish && execit_replace_finish)
	return TRUE;
      final_sec = sec;
      return TRUE;
    case 1:
    case 2:
    case 3:
    case 4:
    case 5:
      break;
    case 6:
      if (execit_build_finish)
	return TRUE;
      /* Here is the entrance of EXECIT relaxation. There are two pass of
	 EXECIT relaxation. The one is to traverse all instructions and build
	 the hash table. The other one is to compare instructions and replace
	 it by exec.it.  */
      if (!riscv_elf_execit_build_hash_table (abfd, sec, info))
	return FALSE;
      if (final_sec == sec)
	{
	  riscv_elf_execit_finish (abfd, info);
	  execit_build_finish = 1;
	  if (htab->update_execit_table)
	    {
	      info->relax_pass = 7;
	      *again = TRUE;
	    }
	}
      return TRUE;
    case 7:
      if (execit_replace_finish)
	return TRUE;
      if (!riscv_elf_execit_replace_instruction (info, abfd, sec))
	return FALSE;
      if (final_sec == sec)
	{
	  /* Save the local symbol value before merging section.
	     It used to get the correct relocations in the
	     riscv_elf_execit_reloc_insn.  */
	  riscv_elf_execit_save_local_symbol_value ();
	  execit_replace_finish = 1;

	  if (htab->update_execit_table && !execit_replace_again)
	    {
	      execit_replace_again = 1;
	      execit_build_finish = 0;
	      execit_replace_finish = 0;
	      info->relax_pass = 6;
	      *again = TRUE;
	    }
	  else
	    {
	      /* Set it for the last relaxation.  */
	      sec->sec_flg0 = TRUE;
	    }
	}
      return TRUE;
    default:
      (*_bfd_error_handler) (_("error: Unknow relax pass."));
      break;
    }

  if (htab)
    {
      max_alignment = htab->max_alignment;
      if (max_alignment == (bfd_vma) -1)
	{
	  max_alignment = _bfd_riscv_get_max_alignment (sec);
	  htab->max_alignment = max_alignment;
	}
    }
  else
    max_alignment = _bfd_riscv_get_max_alignment (sec);

  rvc = elf_elfheader (abfd)->e_flags & EF_RISCV_RVC;
  /* Examine and consider relaxing each reloc.  */
  relocs_end = relocs + sec->reloc_count;
  for (i = 0; i < sec->reloc_count; i++)
    {
      asection *sym_sec;
      Elf_Internal_Rela *rel = relocs + i;
      relax_func_t relax_func;
      int type = ELFNN_R_TYPE (rel->r_info);
      bfd_vma symval;

      switch (riscv_enable_rvc (rel, relocs_end))
	{
	case 1: rvc = 0; break;
	case 0: rvc = 1; break;
	default: break;
	}

      relax_func = NULL;
      if (info->relax_pass == 1)
	{
	  if (htab->set_relax_call
	      && (type == R_RISCV_CALL
		  || type == R_RISCV_CALL_PLT))
	    relax_func = _bfd_riscv_relax_call;
	  else if (htab->set_relax_lui
		   && !htab->gp_relative_insn
		   && (type == R_RISCV_HI20
		       || type == R_RISCV_LO12_I
		       || type == R_RISCV_LO12_S))
	    relax_func = _bfd_riscv_relax_lui;
	  else if (htab->set_relax_pc
		   && !bfd_link_pic(info)
		   && (type == R_RISCV_PCREL_HI20
		       || type == R_RISCV_PCREL_LO12_I
		       || type == R_RISCV_PCREL_LO12_S))
	    relax_func = _bfd_riscv_relax_pc;
	  else if (htab->set_relax_tls_le
		   && (type == R_RISCV_TPREL_HI20
		       || type == R_RISCV_TPREL_ADD
		       || type == R_RISCV_TPREL_LO12_I
		       || type == R_RISCV_TPREL_LO12_S))
	    relax_func = _bfd_riscv_relax_tls_le;
	  else
	    continue;

	  /* Only relax this reloc if it is paired with R_RISCV_RELAX.  */
	  if (i == sec->reloc_count - 1
	      || ELFNN_R_TYPE ((rel + 1)->r_info) != R_RISCV_RELAX
	      || rel->r_offset != (rel + 1)->r_offset)
	    continue;

	  /* Skip over the R_RISCV_RELAX.  */
	  i++;
	}
      else if (((info->relax_pass == 2
		 && (type == R_RISCV_LO12_I
		     || type == R_RISCV_LO12_S))
		|| (info->relax_pass == 3
		    && type == R_RISCV_HI20))
	       && htab->set_relax_lui
	       && htab->gp_relative_insn)
	{
	  relax_func = _bfd_riscv_relax_lui_gp_insn;

	  /* Only relax this reloc if it is paired with R_RISCV_RELAX.  */
	  if (i == sec->reloc_count - 1
	      || ELFNN_R_TYPE ((rel + 1)->r_info) != R_RISCV_RELAX
	      || rel->r_offset != (rel + 1)->r_offset)
	    continue;

	  /* Skip over the R_RISCV_RELAX.  */
	  i++;
	}
      else if (info->relax_pass == 4
	       && type == R_RISCV_DELETE)
	relax_func = _bfd_riscv_relax_delete;
      else if (info->relax_pass == 5
	       && htab->set_relax_align
	       && (type == R_RISCV_ALIGN
		   || type == R_RISCV_ALIGN_BTB))
	relax_func = _bfd_riscv_relax_align;
      else
	continue;

      data->relocs = relocs;

      /* Read this BFD's contents if we haven't done so already.  */
      if (!data->this_hdr.contents
	  && !bfd_malloc_and_get_section (abfd, sec, &data->this_hdr.contents))
	goto fail;

      /* Read this BFD's symbols if we haven't done so already.  */
      if (symtab_hdr->sh_info != 0
	  && !symtab_hdr->contents
	  && !(symtab_hdr->contents =
	       (unsigned char *) bfd_elf_get_elf_syms (abfd, symtab_hdr,
						       symtab_hdr->sh_info,
						       0, NULL, NULL, NULL)))
	goto fail;

      /* Get the value of the symbol referred to by the reloc.  */
      if (ELFNN_R_SYM (rel->r_info) < symtab_hdr->sh_info)
	{
	  /* A local symbol.  */
	  Elf_Internal_Sym *isym = ((Elf_Internal_Sym *) symtab_hdr->contents
				    + ELFNN_R_SYM (rel->r_info));
	  reserve_size = (isym->st_size - rel->r_addend) > isym->st_size
	    ? 0 : isym->st_size - rel->r_addend;

	  if (isym->st_shndx == SHN_UNDEF)
	    sym_sec = sec, symval = sec_addr (sec) + rel->r_offset;
	  else
	    {
	      BFD_ASSERT (isym->st_shndx < elf_numsections (abfd));
	      sym_sec = elf_elfsections (abfd)[isym->st_shndx]->bfd_section;
#if 0
	      /* The purpose of this code is unknown.  It breaks linker scripts
		 for embedded development that place sections at address zero.
		 This code is believed to be unnecessary.  Disabling it but not
		 yet removing it, in case something breaks.  */
	      if (sec_addr (sym_sec) == 0)
		continue;
#endif
	      symval = sec_addr (sym_sec) + isym->st_value;
	    }
	}
      else
	{
	  unsigned long indx;
	  struct elf_link_hash_entry *h;

	  indx = ELFNN_R_SYM (rel->r_info) - symtab_hdr->sh_info;
	  h = elf_sym_hashes (abfd)[indx];

	  while (h->root.type == bfd_link_hash_indirect
		 || h->root.type == bfd_link_hash_warning)
	    h = (struct elf_link_hash_entry *) h->root.u.i.link;

	  if (h->plt.offset != MINUS_ONE)
	    symval = sec_addr (htab->elf.splt) + h->plt.offset;
	  else if (h->root.u.def.section->output_section == NULL
		   || (h->root.type != bfd_link_hash_defined
		       && h->root.type != bfd_link_hash_defweak))
	    continue;
	  else
	    symval = sec_addr (h->root.u.def.section) + h->root.u.def.value;

	  if (h->type != STT_FUNC)
	    reserve_size =
	      (h->size - rel->r_addend) > h->size ? 0 : h->size - rel->r_addend;
	  sym_sec = h->root.u.def.section;
	}

      symval += rel->r_addend;

      /* if symbol value exceeds output section end, it would break current
       * pcgp relaxation algorithm. skip it over by now.
       */
      if (relax_func == _bfd_riscv_relax_pc && sym_sec->output_section)
	{
	  bfd_vma secend = sec_addr (sym_sec) + sym_sec->output_section->rawsize;
	  if (symval >= secend)
	    continue;
	}

      if (!relax_func (abfd, sec, sym_sec, info, rel, symval,
		       max_alignment, reserve_size, again,
		       &pcgp_relocs, rvc))
	goto fail;
    }

  ret = TRUE;

fail:
  if (relocs != data->relocs)
    free (relocs);
  riscv_free_pcgp_relocs(&pcgp_relocs, abfd, sec);

  /* Free the unused info for relax_lui_gp_insn.  */
  struct relax_gp_sym_info *temp;
  if (info->relax_pass == 5)
    while (relax_gp_sym_info_head != NULL)
      {
	temp = relax_gp_sym_info_head;
	relax_gp_sym_info_head = relax_gp_sym_info_head->next;
	free (temp);
      }

  return ret;
}

static bfd_boolean
riscv_elf_output_symbol_hook (struct bfd_link_info *info,
			      const char *name,
			      Elf_Internal_Sym *elfsym ATTRIBUTE_UNUSED,
			      asection *input_sec,
			      struct elf_link_hash_entry *h ATTRIBUTE_UNUSED)
{
  const char *source;
  FILE *sym_ld_script = NULL;
  struct riscv_elf_link_hash_table *table;

  table = riscv_elf_hash_table (info);
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

      bfd_vma sym_value = h->root.u.def.value
	+ h->root.u.def.section->output_section->vma
	+ h->root.u.def.section->output_offset;

      if (riscv_elf_hash_entry (h)->indirect_call)
	fprintf (sym_ld_script, "\tPROVIDE (%s = 0x%08lx);\t /* %s  */\n",
		 h->root.root.string, sym_value, source);
      else
	fprintf (sym_ld_script, "\t%s = 0x%08lx;\t /* %s  */\n",
		 h->root.root.string, sym_value, source);
    }

  return TRUE;
}

static bfd_boolean
riscv_elf_output_arch_syms (bfd *output_bfd ATTRIBUTE_UNUSED,
			    struct bfd_link_info *info,
			    void *finfo ATTRIBUTE_UNUSED,
			    bfd_boolean (*func) (void *, const char *,
						 Elf_Internal_Sym *,
						 asection *,
						 struct elf_link_hash_entry *)
			    ATTRIBUTE_UNUSED)
{
  FILE *sym_ld_script = NULL;
  struct riscv_elf_link_hash_table *table;

  table = riscv_elf_hash_table (info);
  sym_ld_script = table->sym_ld_script;

  if (check_start_export_sym)
    fprintf (sym_ld_script, "}\n");

  return TRUE;
}

/* EXECIT Instruction Table Relaxation.  */

#define EXECIT_SECTION ".exec.itable"
#define INSN_EXECIT 0x8000

/* Global hash list.  */
struct elf_link_hash_entry_list
{
  struct elf_link_hash_entry *h;
  struct elf_link_hash_entry_list *next;
};

/* Relocation list.  */
struct elf_riscv_irel_entry
{
  Elf_Internal_Rela *irel;
  struct elf_riscv_irel_entry *next;
};

/* Save different destination but same insn.  */
struct elf_link_hash_entry_mul_list
{
  /* Global symbol times.  */
  int times;
  /* Save relocation for each global symbol.  */
  Elf_Internal_Rela *irel;
  /* For lui, two lui may have the same high-part
     but different low-parts.  */
  Elf_Internal_Rela rel_backup;
  struct elf_link_hash_entry_list *h_list;
  struct elf_link_hash_entry_mul_list *next;
};

/* Instruction hash table.  */
struct elf_riscv_code_hash_entry
{
  struct bfd_hash_entry root;
  int times;
  /* For insn that can use relocation or constant ex: lui.  */
  int const_insn;
  asection *sec;
  struct elf_link_hash_entry_mul_list *m_list;
  /* Using r_addend.  */
  Elf_Internal_Rela *irel;
  /* Using r_info.  */
  Elf_Internal_Rela rel_backup;
};

/* Instruction count list.  */
struct elf_riscv_insn_times_entry
{
  const char *string;
  int times;
  int order;
  int ex_reserve;
  asection *sec;
  bfd_vma local_sym_value;
  struct elf_link_hash_entry_mul_list *m_list;
  Elf_Internal_Rela *irel;
  Elf_Internal_Rela rel_backup;
  struct elf_riscv_insn_times_entry *next;
};

/* Fix exec.it for lui.  */
struct elf_riscv_execit_refix
{
  Elf_Internal_Rela *irel;
  asection *sec;
  struct elf_link_hash_entry *h;
  int order;
  struct elf_riscv_execit_refix *next;
  /* Do not fix the entries if disable is 1.  */
  int disable;
};

/* It used to record the blank information for EXECIT replacement.  */
struct elf_riscv_blank
{
  /* Where the blank begins.  */
  bfd_vma offset;
  /* The size of the blank.  */
  bfd_vma size;
  struct elf_riscv_blank *next;
  struct elf_riscv_blank *prev;
};

/* EXECIT hash table, used to store all patterns of code.  */
static struct bfd_hash_table execit_code_table;
/* EXECIT candiadtes, chosen from EXECIT hash table.  */
static struct elf_riscv_insn_times_entry *execit_insn_head = NULL;
/* After EXECIT relaxation, the high 20 bits of symbol may be
   changed, we may reserve more than one EXECIT entries at
   riscv_elf_execit_replace_instruction, and then fixed the
   id of exec.it insns at riscv_elf_relocate_execit_table.  */
static struct elf_riscv_execit_refix *execit_refix_head = NULL;
/* Used to record the spaces deleted by EXECIT.  */
static struct elf_riscv_blank *blank_list_head = NULL;
/* Used to record the recently used blank.  */
static struct elf_riscv_blank *blank_list_current = NULL;
/* Save EXECIT predicted reducing size.  */
static size_t execit_relax_size = 0;
static asection *execit_section = NULL;
/* Use to store the number of imported entries.  */
static int execit_import_number = 0;

/* riscv_create_elf_blank, riscv_search_elf_blank and riscv_insert_elf_blank
   are used to record the spaces deleted by EXECIT.  */

static struct elf_riscv_blank *
riscv_create_elf_blank (bfd_vma offset_p, bfd_vma size_p)
{
  struct elf_riscv_blank *blank_t;
  blank_t = bfd_malloc (sizeof (struct elf_riscv_blank));
  blank_t->offset = offset_p;
  blank_t->size = size_p;
  blank_t->next = NULL;
  blank_t->prev = NULL;
  return blank_t;
}

static struct elf_riscv_blank *
riscv_search_elf_blank (bfd_vma addr)
{
  /* Searching from the recently used blank. This can reduce
     the link time of EXECIT.  */
  struct elf_riscv_blank *blank_t = blank_list_current;

  while (blank_t && addr < blank_t->offset)
    blank_t = blank_t->prev;
  while (blank_t && blank_t->next && addr >= blank_t->next->offset)
    blank_t = blank_t->next;

  return blank_t;
}

static bfd_boolean
riscv_insert_elf_blank (bfd_vma addr, bfd_vma len)
{
  struct elf_riscv_blank *blank_t, *blank_t2;

  if (!blank_list_head)
    {
      blank_list_head = riscv_create_elf_blank (addr, len);
      blank_list_current = blank_list_head;
      return TRUE;
    }

  blank_t = riscv_search_elf_blank (addr);

  if (blank_t == NULL)
    {
      blank_t = riscv_create_elf_blank (addr, len);
      blank_list_head->prev = blank_t;
      blank_t->next = blank_list_head;
      blank_list_head = blank_t;
      blank_list_current = blank_t;
      return TRUE;
    }

  if (addr < blank_t->offset + blank_t->size)
    {
      /* Extend the origin blank.  */
      if (addr + len > blank_t->offset + blank_t->size)
	blank_t->size = addr + len - blank_t->offset;
      blank_list_current = blank_t;
    }
  else
    {
      blank_t2 = riscv_create_elf_blank (addr, len);
      if (blank_t->next)
	{
	  blank_t->next->prev = blank_t2;
	  blank_t2->next = blank_t->next;
	}
      blank_t2->prev = blank_t;
      blank_t->next = blank_t2;
      blank_list_current = blank_t2;
    }

  return TRUE;
}

/* Exec.it hash function.  */

static struct bfd_hash_entry *
riscv_elf_code_hash_newfunc (struct bfd_hash_entry *entry,
			     struct bfd_hash_table *table,
			     const char *string)
{
  struct elf_riscv_code_hash_entry *ret;

  /* Allocate the structure if it has not already been
     allocated by a subclass.  */
  if (entry == NULL)
    {
      entry = (struct bfd_hash_entry *)
	bfd_hash_allocate (table, sizeof (*ret));
      if (entry == NULL)
	return entry;
    }

  /* Call the allocation method of the superclass.  */
  entry = bfd_hash_newfunc (entry, table, string);
  if (entry == NULL)
    return entry;

  ret = (struct elf_riscv_code_hash_entry*) entry;
  ret->times = 0;
  ret->const_insn = 0;
  ret->m_list = NULL;
  ret->sec = NULL;
  ret->irel = NULL;
  return &ret->root;
}

/* Insert EXECIT entry. This insert must be stable sorted by times.  */

static void
riscv_elf_execit_insert_entry (struct elf_riscv_insn_times_entry *ptr)
{
  struct elf_riscv_insn_times_entry *temp;
  struct elf_riscv_insn_times_entry *temp2;

  if (execit_insn_head == NULL)
    {
      execit_insn_head = ptr;
      ptr->next = NULL;
    }
  else
    {
      temp = execit_insn_head;
      temp2 = execit_insn_head;
      while (temp->next &&
	     (temp->next->times >= ptr->times
	      || temp->times == -1))
	{
	  if (temp->times == -1)
	    temp2 = temp;
	  temp = temp->next;
	}
      if (ptr->times > temp->times && temp->times != -1)
	{
	  ptr->next = temp;
	  if (temp2->times == -1)
	    temp2->next = ptr;
	  else
	    execit_insn_head = ptr;
	}
      else if (temp->next == NULL)
	{
	  temp->next = ptr;
	  ptr->next = NULL;
	}
      else
	{
	  ptr->next = temp->next;
	  temp->next = ptr;
	}
    }
}

/* Examine each insn times in hash table.
   Handle multi-link hash entry.

   TODO: This function doesn't assign so much info since it is fake.  */

static int
riscv_elf_examine_insn_times (struct elf_riscv_code_hash_entry *h)
{
  struct elf_riscv_insn_times_entry *ptr;
  int times;

  if (h->m_list == NULL)
    {
      /* Local symbol insn or insn without relocation.  */
      if (h->times < 3)
	return TRUE;

      ptr = (struct elf_riscv_insn_times_entry *)
	bfd_malloc (sizeof (struct elf_riscv_insn_times_entry));
      ptr->times = h->times;
      ptr->string = h->root.string;
      ptr->m_list = NULL;
      ptr->ex_reserve = 0;
      ptr->sec = h->sec;
      ptr->local_sym_value = 0;
      ptr->irel = h->irel;
      ptr->rel_backup = h->rel_backup;
      riscv_elf_execit_insert_entry (ptr);
    }
  else
    {
      /* Global symbol insn.  */
      /* Only lui insn has multiple m_list.  */
      struct elf_link_hash_entry_mul_list *m_list = h->m_list;

      times = 0;
      while (m_list)
	{
	  times += m_list->times;
	  m_list = m_list->next;
	}
      if (times >= 3)
	{
	  m_list = h->m_list;
	  ptr = (struct elf_riscv_insn_times_entry *)
	    bfd_malloc (sizeof (struct elf_riscv_insn_times_entry));
	  ptr->times = times; /* Use the total times.  */
	  ptr->string = h->root.string;
	  ptr->m_list = m_list;
	  ptr->sec = h->sec;
	  ptr->local_sym_value = 0;
	  ptr->irel = m_list->irel;
	  ptr->ex_reserve = 0;
	  ptr->rel_backup = m_list->rel_backup;
	  riscv_elf_execit_insert_entry (ptr);
	}
      if (h->const_insn == 1)
	{
	  /* lui with constant value.  */
	  if (h->times < 3)
	    return TRUE;

	  ptr = (struct elf_riscv_insn_times_entry *)
	    bfd_malloc (sizeof (struct elf_riscv_insn_times_entry));
	  ptr->times = h->times;
	  ptr->string = h->root.string;
	  ptr->m_list = NULL;
	  ptr->sec = NULL;
	  ptr->local_sym_value = 0;
	  ptr->irel = NULL;
	  ptr->ex_reserve = 0;
	  ptr->rel_backup = h->rel_backup;
	  riscv_elf_execit_insert_entry (ptr);
	}
    }
  return TRUE;
}

/* Count each insn times in hash table. Handle multi-link hash entry.  */

static int
riscv_elf_count_insn_times (struct elf_riscv_code_hash_entry *h)
{
  int reservation, times;
  unsigned long relocation, min_relocation;
  struct elf_riscv_insn_times_entry *ptr;

  if (h->m_list == NULL)
    {
      /* Local symbol insn or insn without relocation.  */
      if (h->times < 3)
	return TRUE;
      ptr = (struct elf_riscv_insn_times_entry *)
	bfd_malloc (sizeof (struct elf_riscv_insn_times_entry));
      ptr->times = h->times;
      ptr->string = h->root.string;
      ptr->m_list = NULL;
      ptr->ex_reserve = 0;
      ptr->sec = h->sec;
      ptr->local_sym_value = 0;
      ptr->irel = h->irel;
      ptr->rel_backup = h->rel_backup;
      riscv_elf_execit_insert_entry (ptr);
    }
  else
    {
      /* Global symbol insn.  */
      /* Only lui/auipc insn has multiple m_list.  */
      struct elf_link_hash_entry_mul_list *m_list = h->m_list;

      if (ELFNN_R_TYPE (m_list->rel_backup.r_info) == R_RISCV_HI20
	  && m_list->next != NULL)
	{
	  /* lui insn has different symbol or addend but has same hi part.  */
	  times = 0;
	  reservation = 1;
	  relocation = 0;
	  min_relocation = 0xffffffff;
	  while (m_list)
	    {
	      /* Get the minimum lui address and calculate how many entry
		 the lui-list have to use.  */
	      if ((m_list->h_list->h->root.type == bfd_link_hash_defined
		   || m_list->h_list->h->root.type == bfd_link_hash_defweak)
		  && (m_list->h_list->h->root.u.def.section != NULL
		      && m_list->h_list->h->root.u.def.section->output_section != NULL))
		{
		  relocation = (m_list->h_list->h->root.u.def.value +
				m_list->h_list->h->root.u.def.section->output_section->vma +
				m_list->h_list->h->root.u.def.section->output_offset);
		  relocation += m_list->irel->r_addend;
		}
	      else
		relocation = 0;
	      if (relocation < min_relocation)
		min_relocation = relocation;
	      times += m_list->times;
	      m_list = m_list->next;
	    }
	  if (min_relocation < execit_relax_size)
	    reservation = (RISCV_CONST_HIGH_PART (min_relocation) >> 12) + 1;
	  else
	    reservation = (RISCV_CONST_HIGH_PART (min_relocation) >> 12)
	      - (RISCV_CONST_HIGH_PART(min_relocation - execit_relax_size) >> 12) + 1;
	  if ((reservation * 3) <= times)
	    {
	      /* Efficient enough to do EXECIT.  */
	      int i;
	      for (i = reservation ; i > 0; i--)
		{
		  /* Allocate numbers of reserved EXECIT entry.  */
		  ptr = (struct elf_riscv_insn_times_entry *)
		    bfd_malloc (sizeof (struct elf_riscv_insn_times_entry));
		  ptr->times = times / reservation;
		  ptr->string = h->root.string;
		  ptr->m_list = h->m_list;
		  ptr->sec = h->sec;
		  ptr->local_sym_value = 0;
		  ptr->ex_reserve = i - 1;;
		  ptr->irel = h->m_list->irel;
		  ptr->rel_backup = h->m_list->rel_backup;
		  riscv_elf_execit_insert_entry (ptr);
		}
	    }
	}
      else
	{
	  /* Normal global symbol that means no different address symbol
	     using same EXECIT entry.  */
	  if (m_list->times >= 3)
	    {
	      ptr = (struct elf_riscv_insn_times_entry *)
		bfd_malloc (sizeof (struct elf_riscv_insn_times_entry));
	      ptr->times = m_list->times;
	      ptr->string = h->root.string;
	      ptr->m_list = h->m_list;
	      ptr->sec = h->sec;
	      ptr->local_sym_value = 0;
	      ptr->ex_reserve = 0;
	      ptr->irel = h->m_list->irel;
	      ptr->rel_backup = h->m_list->rel_backup;
	      riscv_elf_execit_insert_entry (ptr);
	    }
	}

      if (h->const_insn == 1)
	{
	  /* lui with constant value.  */
	  if (h->times < 3)
	    return TRUE;

	  ptr = (struct elf_riscv_insn_times_entry *)
	    bfd_malloc (sizeof (struct elf_riscv_insn_times_entry));
	  ptr->times = h->times;
	  ptr->string = h->root.string;
	  ptr->m_list = NULL;
	  ptr->sec = NULL;
	  ptr->local_sym_value = 0;
	  ptr->irel = NULL;
	  ptr->ex_reserve = 0;
	  ptr->rel_backup = h->rel_backup;
	  riscv_elf_execit_insert_entry (ptr);
	}
    }

  return TRUE;
}

/* Hash table traverse function.  */

static void
riscv_elf_code_hash_traverse (int (*func) (struct elf_riscv_code_hash_entry*))
{
  unsigned int i;

  execit_code_table.frozen = 1;
  for (i = 0; i < execit_code_table.size; i++)
    {
      struct bfd_hash_entry *p;

      for (p = execit_code_table.table[i]; p != NULL; p = p->next)
	if (!func ((struct elf_riscv_code_hash_entry *) p))
	  goto out;
    }
out:
  execit_code_table.frozen = 0;
}

/* Give order number to insn list.  */

static void
riscv_elf_order_insn_times (struct bfd_link_info *info)
{
  struct elf_riscv_insn_times_entry *execit_insn;
  struct elf_riscv_insn_times_entry *temp = NULL;
  struct riscv_elf_link_hash_table *table;
  int total_execit_limit;
  int number = 0;

  if (execit_insn_head == NULL)
    return;

  /* Default maximum number of entries is 1024.  */
  table = riscv_elf_hash_table (info);
  if (table->execit_limit == -1)
    table->execit_limit = 1024;
  total_execit_limit = table->execit_limit + execit_import_number;
  if (total_execit_limit > 1024)
    total_execit_limit = 1024;

  execit_insn = execit_insn_head;

  while (execit_insn != NULL && number + execit_insn->ex_reserve < total_execit_limit)
    {
      execit_insn->order = number;
      number++;
      temp = execit_insn;
      execit_insn = execit_insn->next;
    }

  if (execit_insn && temp)
    temp->next = NULL;
  else if (temp == NULL)
    execit_insn_head = NULL; /* Discard all EXECIT candidates.  */

  /* TODO: Only free the pointer, which point to the structure
     elf_riscv_insn_times_entry, is not enough. This may cause
     memory leakage.  */
  while (execit_insn != NULL)
    {
      /* Free useless entries.  */
      temp = execit_insn;
      execit_insn = execit_insn->next;
      free (temp);
    }
}

/* Get section .exec.itable.  */

static asection*
riscv_elf_execit_get_section (bfd *input_bfds)
{
  asection *sec = NULL;
  bfd *abfd;

  if (execit_section != NULL)
    return execit_section;

  for (abfd = input_bfds; abfd != NULL; abfd = abfd->link.next)
    {
      sec = bfd_get_section_by_name (abfd, EXECIT_SECTION);
      if (sec != NULL)
	break;
    }

  execit_section = sec;
  return sec;
}

/* Build .exec.itable section.  */

static void
riscv_elf_execit_build_itable (bfd *abfd, struct bfd_link_info *link_info)
{
  asection *table_sec;
  struct elf_riscv_insn_times_entry *ptr;
  int number = 0;
  bfd_byte *contents = NULL;
  struct riscv_elf_link_hash_table *table;

  table = riscv_elf_hash_table (link_info);

  /* Find the section .exec.itable, and put all entries into it.  */
  table_sec = riscv_elf_execit_get_section (link_info->input_bfds);

  if (table_sec != NULL)
    {
      if (!riscv_get_section_contents (table_sec->owner, table_sec,
				       &contents, TRUE))
	return;

      for (ptr = execit_insn_head; ptr != NULL; ptr = ptr->next)
	number++;

      table_sec->size = number * 4;

      if (number == 0)
	return;

      /* Check ITB register if set.  */
      if (!table->execit_import_file
	  && !bfd_link_hash_lookup (link_info->hash, "_ITB_BASE_",
				    FALSE, FALSE, TRUE))
	{
	  (*_bfd_error_handler)
	    (_("\nError: Instruction Table(IT) is used, but Instruction "
	       "Table Base($ITB) isn't set.\nPlease add the following "
	       "instructions in _start of the startup code"
	       "(crt0.S or start.S):\n"
	       "\"la a0, _ITB_BASE_; csrrw x0, uitb, a0\""));
	  exit (1);
	}

      /* TODO: change the e_flag for EXECIT.  */

      number = 0;
      /* Write EXECIT candidates into .exec.itable. We will
	 relocate the patterns with relocations later
	 into the riscv_elf_relocate_execit_table.  */
      for (ptr = execit_insn_head; ptr != NULL ; ptr = ptr->next)
	{
	  long val;
	  val = strtoll (ptr->string, NULL, 16);
	  bfd_put_32 (abfd, (bfd_vma) val, (char *) contents + (number * 4));
	  number++;
	}
    }
}

static void
riscv_elf_insert_irel_entry (struct elf_riscv_irel_entry **irel_list,
			     struct elf_riscv_irel_entry *irel_ptr)
{
  if (*irel_list == NULL)
    {
      *irel_list = irel_ptr;
      irel_ptr->next = NULL;
    }
  else
    {
      irel_ptr->next = *irel_list;
      *irel_list = irel_ptr;
    }
}

static void
riscv_elf_execit_insert_fix (asection * sec, Elf_Internal_Rela * irel,
			     struct elf_link_hash_entry *h, int order)
{
  struct elf_riscv_execit_refix *ptr;

  ptr = bfd_malloc (sizeof (struct elf_riscv_execit_refix));
  ptr->sec = sec;
  ptr->irel = irel;
  ptr->h = h;
  ptr->order = order;
  ptr->next = NULL;
  ptr->disable = 0;

  if (execit_refix_head == NULL)
    execit_refix_head = ptr;
  else
    {
      struct elf_riscv_execit_refix *temp = execit_refix_head;

      while (temp->next != NULL)
	temp = temp->next;
      temp->next = ptr;
    }
}

/* Replace with exec.it instruction.  */

static bfd_boolean
riscv_elf_execit_push_insn (bfd *abfd, uint16_t insn16,
			    bfd_byte *contents, bfd_vma pre_off,
			    struct elf_riscv_irel_entry *pre_irel_ptr,
			    struct elf_riscv_irel_entry **irel_list,
			    struct bfd_link_info *link_info ATTRIBUTE_UNUSED)
{
  if (insn16 != 0)
    {
      /* Implement the EXECIT relaxation.  */
      bfd_put_16 (abfd, insn16, contents + pre_off);
      if (!riscv_insert_elf_blank (pre_off + 2, 2))
	return FALSE;
      if (pre_irel_ptr != NULL)
	riscv_elf_insert_irel_entry (irel_list, pre_irel_ptr);
    }
  return TRUE;
}

/* Check whether the high 11 bits of pc is different from
   the high 11 bits of relocation after EXECIT relaxation.
   Return True if the jal can be replaced with exec.it safely.  */

static bfd_boolean
execit_check_pchi_for_jal (bfd_vma relocation, bfd_vma insn_pc)
{
  bfd_vma min;

  /* Different high 11 bits.  */
  if ((relocation & 0xffe00000) != (insn_pc & 0xffe00000))
    return FALSE;
  /* High 11 bits are zero.  */
  else if (relocation < 0x200000)
    return TRUE;

  if (relocation < insn_pc)
    min = relocation;
  else
    min = insn_pc;

  if (min > execit_relax_size
      && ((min - execit_relax_size) & 0xffe00000) == (min & 0xffe00000))
    return TRUE;
  else
    return FALSE;
}

/* Replace input file instruction which is in the .exec.itable.  */

static bfd_boolean
riscv_elf_execit_replace_instruction (struct bfd_link_info *link_info,
				      bfd *abfd, asection *sec)
{
  struct elf_riscv_insn_times_entry *execit_insn = execit_insn_head;
  bfd_byte *contents = NULL;
  bfd_vma off;
  uint16_t insn16, insn_execit;
  /* "pre_*" are used to track previous instruction that can be
     converted to exec.it.  */
  bfd_vma pre_off = -1;
  uint16_t pre_insn16 = 0;
  struct elf_riscv_irel_entry *pre_irel_ptr = NULL;
  Elf_Internal_Rela *internal_relocs;
  Elf_Internal_Rela *irel;
  Elf_Internal_Rela *irelend;
  Elf_Internal_Shdr *symtab_hdr;
  Elf_Internal_Sym *isym = NULL;
  uint32_t insn = 0;
  uint32_t insn_with_reg = 0;
  uint32_t it_insn;
  uint32_t it_insn_with_reg;
  unsigned long r_symndx;
  asection *isec;
  struct elf_riscv_irel_entry *irel_list = NULL;
  struct elf_link_hash_entry **sym_hashes = elf_sym_hashes (abfd);
  int data_flag, do_replace, save_irel;
  struct elf_link_hash_entry_list *h_list;

  /* Load section instructions, relocations, and symbol table.  */
  if (!riscv_get_section_contents (abfd, sec, &contents, TRUE)
      || !riscv_get_local_syms (abfd, sec, &isym))
    return FALSE;
  internal_relocs =
    _bfd_elf_link_read_relocs (abfd, sec, NULL, NULL, TRUE /* keep_memory  */);
  irelend = internal_relocs + sec->reloc_count;
  symtab_hdr = &elf_tdata (abfd)->symtab_hdr;

  off = 0;

  /* Check the section enable EXECIT?  */
  irel = find_relocs_at_address (internal_relocs, internal_relocs, irelend,
				 R_RISCV_RELAX_ENTRY);

  /* Check this section trigger EXECIT relaxation.  */
  if (irel == NULL
      || irel >= irelend
      || ELFNN_R_TYPE (irel->r_info) != R_RISCV_RELAX_ENTRY
      || (ELFNN_R_TYPE (irel->r_info) == R_RISCV_RELAX_ENTRY
	  && !(irel->r_addend & R_RISCV_RELAX_ENTRY_EXECIT_FLAG)))
    return TRUE;

  irel = internal_relocs;
  /* Check alignment and fetch proper relocation.  */
  while (off < sec->size)
    {
      do_replace = 0;
      struct elf_link_hash_entry *h = NULL;
      struct elf_riscv_irel_entry *irel_ptr = NULL;

      /* Find the relocation that it's r_offset is same as off.  */
      while (irel != NULL && irel < irelend && irel->r_offset < off)
	irel++;

      data_flag = riscv_relocation_check (link_info, &irel, irelend,
					  sec, &off, contents, 1);

      if (data_flag & ALIGN_PUSH_PRE)
	if (!riscv_elf_execit_push_insn (abfd, pre_insn16, contents, pre_off,
					 pre_irel_ptr, &irel_list, link_info))
	  return FALSE;

      if (data_flag & ALIGN_CLEAN_PRE)
	{
	  pre_off = 0;
	  pre_insn16 = 0;

	  if (pre_irel_ptr != NULL
	      && !(data_flag & ALIGN_PUSH_PRE)
	      && ELFNN_R_TYPE (pre_irel_ptr->irel->r_info) == R_RISCV_HI20)
	    {
	      /* Disable the lui refix entry since this lui can not be
		 converted to exec.it (alignment issue).  */
	      struct elf_riscv_execit_refix *temp = execit_refix_head;
	      while (temp)
		{
		  if (temp->irel
		      && temp->sec == sec
		      && temp->irel == pre_irel_ptr->irel)
		    {
		      temp->disable = 1;
		      break;
		    }
		  temp = temp->next;
		}
	    }
	  pre_irel_ptr = NULL;
	}

      if (data_flag & DATA_EXIST)
	{
	  /* We save the move offset in the highest byte.  */
	  off += (data_flag >> 24);
	  continue;
	}

      if ((*(contents + off) & 0x3) != 0x3)
	{
	  /* 16-bit instruction.  */
	  off += 2;
	  continue;
	}

      /* Load the instruction and its opcode with register for comparing.  */
      execit_insn = execit_insn_head;
      insn = bfd_get_32 (abfd, contents + off);
      insn_with_reg = 0;
      int is_on_relocation = FALSE;

      if (irel != NULL && irel < irelend && irel->r_offset == off)
	is_on_relocation = TRUE;

      if (is_on_relocation == TRUE)
	riscv_elf_get_insn_with_reg (abfd, irel, insn, &insn_with_reg);

      while (execit_insn)
	{
	  it_insn = strtoll (execit_insn->string, NULL, 16);
	  it_insn_with_reg = 0;
	  do_replace = 0;
	  save_irel = 0;

      if (is_on_relocation == TRUE)
	    riscv_elf_get_insn_with_reg (abfd, execit_insn->irel, it_insn, &it_insn_with_reg);

	  if (is_on_relocation
	      && (ELFNN_R_TYPE (irel->r_info) ==
		  ELFNN_R_TYPE (execit_insn->rel_backup.r_info))
	      && (insn_with_reg == it_insn_with_reg))
	    {
	      /* Insn relocation and format is the same as table entry.  */
	      if (ELFNN_R_TYPE (irel->r_info) == R_RISCV_LO12_I
		  || ELFNN_R_TYPE (irel->r_info) == R_RISCV_LO12_S
		  || ELFNN_R_TYPE (irel->r_info) == R_RISCV_GPREL_I
		  || ELFNN_R_TYPE (irel->r_info) == R_RISCV_GPREL_S
		  || (ELFNN_R_TYPE (irel->r_info) >= R_RISCV_LGP18S0
		      && ELFNN_R_TYPE (irel->r_info) <= R_RISCV_SGP17S3))
		{
		  r_symndx = ELFNN_R_SYM (irel->r_info);
		  if (r_symndx < symtab_hdr->sh_info)
		    {
		      /* Local symbol.  */
		      int shndx = isym[r_symndx].st_shndx;

		      isec = elf_elfsections (abfd)[shndx]->bfd_section;
		      if (execit_insn->sec == isec
			  && execit_insn->irel->r_addend == irel->r_addend
			  && execit_insn->irel->r_info == irel->r_info)
			{
			  do_replace = 1;
			  save_irel = 1;
			}
		    }
		  else if (execit_insn->m_list)
		    {
		      /* External symbol.  */
		      h = sym_hashes[r_symndx - symtab_hdr->sh_info];
		      h_list = execit_insn->m_list->h_list;
		      while (h_list)
			{
			  if (execit_insn->m_list->irel->r_addend == irel->r_addend
			      && h == h_list->h)
			    {
			      do_replace = 1;
			      save_irel = 1;
			      break;
			    }
			  h_list = h_list->next;
			}
		    }
		}
	      if (ELFNN_R_TYPE (irel->r_info) == R_RISCV_JAL)
		{
		  bfd_vma insn_pc, relocation;
		  r_symndx = ELFNN_R_SYM (irel->r_info);
		  if (r_symndx < symtab_hdr->sh_info)
		    {
		      /* Local symbol.  */
		      int shndx = isym[r_symndx].st_shndx;
		      bfd_vma st_value = (isym + r_symndx)->st_value;

		      isec = elf_elfsections (abfd)[shndx]->bfd_section;
		      if (execit_insn->sec == isec
			  && execit_insn->irel->r_addend == irel->r_addend
			  && execit_insn->irel->r_info == irel->r_info)
			{
			  insn_pc = sec_addr (sec) + off;
			  relocation = isec->output_section->vma + isec->output_offset
			    + st_value + irel->r_addend;
			  if (execit_check_pchi_for_jal (relocation, insn_pc))
			    {
			      do_replace = 1;
			      save_irel = 1;
			    }
			}
		    }
		  else if (execit_insn->m_list)
		    {
		      /* External symbol.  */
		      h = sym_hashes[r_symndx - symtab_hdr->sh_info];
		      h_list = execit_insn->m_list->h_list;
		      while (h_list)
			{
			  if (execit_insn->m_list->irel->r_addend == irel->r_addend
			      && h == h_list->h)
			    {
			      /* We should skip bfd_link_hash_defined
				 and bfd_link_hash_defweak symbol
				 in riscv_elf_execit_build_hash_table.  */
			      insn_pc = sec_addr (sec) + off;
			      relocation = h->root.u.def.value +
				h->root.u.def.section->output_section->vma +
				h->root.u.def.section->output_offset
				+ irel->r_addend;
			      if (execit_check_pchi_for_jal (relocation, insn_pc))
				{
				  do_replace = 1;
				  save_irel = 1;
				}
			      break;
			    }
			  h_list = h_list->next;
			}
		    }
		}
	      else if (ELFNN_R_TYPE (irel->r_info) == R_RISCV_HI20)
		{
		  r_symndx = ELFNN_R_SYM (irel->r_info);
		  if (r_symndx < symtab_hdr->sh_info)
		    {
		      /* Local symbols.  Compare its base symbol
			 and offset.  */
		      int shndx = isym[r_symndx].st_shndx;

		      isec = elf_elfsections (abfd)[shndx]->bfd_section;
		      if (execit_insn->sec == isec
			  && execit_insn->irel->r_addend == irel->r_addend
			  && execit_insn->irel->r_info == irel->r_info)
			{
			  do_replace = 1;
			  save_irel = 1;
			}
		    }
		  else
		    {
		      /* External symbol.  */
		      struct elf_link_hash_entry_mul_list *m_list;

		      h = sym_hashes[r_symndx - symtab_hdr->sh_info];
		      m_list = execit_insn->m_list;

		      while (m_list && !do_replace)
			{
			  h_list = m_list->h_list;
			  while (h_list)
			    {
			      if (h == h_list->h
				  && m_list->irel->r_addend == irel->r_addend)
				{
				  do_replace = 1;
				  save_irel = 1;
				  /* lui multiple entry must be fixed.  */
				  if (execit_insn->next && execit_insn->m_list
				      && execit_insn->m_list == execit_insn->next->m_list)
				    {
				      riscv_elf_execit_insert_fix (sec, irel, h,
								   execit_insn->order);
				      break;
				    }
				}
			      h_list = h_list->next;
			    }
			  m_list = m_list->next;
			}
		    }
		}
	    }
	  else if (!is_on_relocation
		   && insn == it_insn && execit_insn->irel == NULL)
	    {
	      /* Instruction without relocation, we only
		 have to compare their byte code.  */
	      do_replace = 1;
	    }

	  /* Instruction match so replacing the code here.  */
	  if (do_replace == 1)
	    {
	      /* Insert exec.it instruction.  */
	      insn_execit = INSN_EXECIT;
	      insn16 = insn_execit | ENCODE_RVC_EXECIT_IMM (execit_insn->order << 2);
	      riscv_elf_execit_push_insn (abfd, pre_insn16, contents, pre_off,
					  pre_irel_ptr, &irel_list, link_info);
	      pre_off = off;
	      pre_insn16 = insn16;

	      if (save_irel)
		{
		  /* For instuction with relocation do relax.  */
		  irel_ptr = (struct elf_riscv_irel_entry *)
		    bfd_malloc (sizeof (struct elf_riscv_irel_entry));
		  irel_ptr->irel = irel;
		  irel_ptr->next = NULL;
		  pre_irel_ptr = irel_ptr;
		}
	      else
		pre_irel_ptr = NULL;
	      break;
	    }
	  execit_insn = execit_insn->next;
	}
      off += 4;
    }

  /* Insert exec.it instruction.  */
  riscv_elf_execit_push_insn (abfd, pre_insn16, contents, pre_off,
			      pre_irel_ptr, &irel_list, link_info);

  /* Delete blanks according to blank_list.  */
  struct elf_riscv_blank *blank_t;
  bfd_vma total_relax_size = 0;
  while (blank_list_head)
    {
      blank_t = blank_list_head;
      blank_t->offset = blank_t->offset - total_relax_size;
      riscv_relax_delete_bytes (abfd, sec, blank_t->offset,
				blank_t->size, link_info);
      total_relax_size += blank_t->size;
      /* Free the unused blank information.  */
      blank_list_head->prev = NULL;
      blank_list_head = blank_list_head->next;
      free (blank_t);
    }
  blank_list_current = NULL;

  /* Clear the relocations that are replaced by exec.it.  */
  while (irel_list)
    {
      struct elf_riscv_irel_entry *irel_ptr;

      irel_ptr = irel_list;
      irel_list = irel_ptr->next;
      irel_ptr->irel->r_info =
	ELFNN_R_INFO (ELFNN_R_SYM (irel_ptr->irel->r_info), R_RISCV_NONE);
      free (irel_ptr);
    }
  return TRUE;
}

/* Initialize EXECIT hash table.  */

static int
riscv_elf_execit_init (void)
{
  if (!bfd_hash_table_init_n (&execit_code_table, riscv_elf_code_hash_newfunc,
			      sizeof (struct elf_riscv_code_hash_entry),
			      1023))
    {
      (*_bfd_error_handler) (_("Linker: cannot init EXECIT hash table error \n"));
      return FALSE;
    }
  return TRUE;
}

/* Predict how many bytes will be relaxed for exec.it.  */

static void
riscv_elf_execit_total_relax (bfd *abfd ATTRIBUTE_UNUSED, struct bfd_link_info *info)
{
  struct elf_riscv_insn_times_entry *execit_insn;
  struct elf_riscv_insn_times_entry *last_imported_entry = NULL;
  int target_optimize ATTRIBUTE_UNUSED;
  struct riscv_elf_link_hash_table *table;
  int number = 0;

  if (execit_insn_head == NULL)
    return;

  table = riscv_elf_hash_table (info);
  target_optimize  = table->target_optimize;
  execit_insn = execit_insn_head;

  /* If EXECIT update option is set, we have to keep
     the EXECIT candidates, which are imported through
     the option "--mimport-execit", in the .exec.itable.  */
  if (table->update_execit_table)
    while (execit_insn && execit_insn->times == -1)
      {
	last_imported_entry = execit_insn;
	execit_insn = execit_insn->next;
      }
  if (last_imported_entry)
    last_imported_entry->next = NULL;

  struct elf_riscv_insn_times_entry *temp;
  /* TODO: Same as riscv_elf_order_insn_times, this may cause
     memory leakage.  */
  while (execit_insn)
    {
      number++;
      execit_relax_size = execit_insn->times * 2 + execit_relax_size;
      temp = execit_insn;
      execit_insn = execit_insn->next;
      /* Free the EXECIT candidates for this time.  */
      free (temp);
    }

  /* Keep the imported EXECIT candidates.  */
  if (!table->update_execit_table
      || last_imported_entry == NULL)
    execit_insn_head = NULL;

  execit_relax_size += (table->execit_limit - number) * 4;

  /* Consider the data segment alignment size defined in linker script.  */
  execit_relax_size += ELF_MAXPAGESIZE;

  /* TODO: consider other relax size after EXECIT.  */
}

void
riscv_elf_execit_finish (bfd *abfd, struct bfd_link_info *link_info)
{
  /* Choose EXECIT candidates, and then order them by times.  */
  riscv_elf_code_hash_traverse (riscv_elf_examine_insn_times);
  riscv_elf_order_insn_times (link_info);
  /* We may need to reserve more than one EXECIT entries for lui
     since their relocations may be differnet after relaxing code.
     Therefore, we have to predict the relaxed size of EXECIT,
     and then estimate how many entries we will need.  */
  riscv_elf_execit_total_relax (abfd, link_info);
  /* Choose EXECIT candidates again.  */
  riscv_elf_code_hash_traverse (riscv_elf_count_insn_times);
  riscv_elf_order_insn_times (link_info);
  /* Build .exec.itable section.  */
  riscv_elf_execit_build_itable (abfd, link_info);
}

/* Relocate the entries in .exec.itable.  */

static bfd_vma
riscv_elf_execit_reloc_insn (struct elf_riscv_insn_times_entry *ptr,
			     struct bfd_link_info *link_info)
{
  Elf_Internal_Sym *isym = NULL;
  bfd_vma relocation = -1;
  struct elf_link_hash_entry *h;

  if (ptr->m_list != NULL)
    {
      /* Global symbol.  */
      h = ptr->m_list->h_list->h;
      if ((h->root.type == bfd_link_hash_defined
	   || h->root.type == bfd_link_hash_defweak)
	  && h->root.u.def.section != NULL
	  && h->root.u.def.section->output_section != NULL)
	{

	  relocation = h->root.u.def.value +
	    h->root.u.def.section->output_section->vma +
	    h->root.u.def.section->output_offset;
	  relocation += ptr->m_list->irel->r_addend;
	}
      else
	relocation = 0;
    }
  else if (ptr->sec !=NULL)
    {
      /* Local symbol.  */
      bfd *abfd = ptr->sec->owner;
      Elf_Internal_Rela irel_backup = *(ptr->irel);
      asection *sec_backup = ptr->sec;

      if (!riscv_get_local_syms (abfd, ptr->sec, &isym))
	return FALSE;
      isym = isym + ELFNN_R_SYM (ptr->irel->r_info);
      bfd_vma value_backup = isym->st_value;

      /* According to elf_link_input_bfd, linker had called
	 _bfd_merged_section_offset to adjust the address of
	 symbols in the SEC_MERGE sections, and get the merged
	 sections. Since ptr->sec is the section before merging
	 (linker hasn't found the correct merge section in relax
	 time), we must call _bfd_merged_section_offset to find
	 the correct symbol address here, too.  */
      /* Note that we have to store the local symbol value for the
	 last relaxation before, since the symbol value here had
	 been modified in elf_link_input_bfd.  */
      if (ptr->sec->sec_info_type == SEC_INFO_TYPE_MERGE
	  && ELF_ST_TYPE (isym->st_info) != STT_SECTION)
	isym->st_value =
	  _bfd_merged_section_offset (link_info->output_bfd, &ptr->sec,
				      elf_section_data (ptr->sec)->sec_info,
				      ptr->local_sym_value);
      relocation = _bfd_elf_rela_local_sym (link_info->output_bfd, isym,
					    &ptr->sec,
					    ptr->irel);
      relocation += ptr->irel->r_addend;

      /* Restore origin value.  */
      *(ptr->irel) = irel_backup;
      ptr->sec = sec_backup;
      isym->st_value = value_backup;
    }

  return relocation;
}

/* Import .exec.itable and then build list.  */

static void
riscv_elf_execit_import_table (bfd *abfd, struct bfd_link_info *info)
{
  int num = 0;
  bfd_byte *contents;
  unsigned long insn;
  FILE *execit_import_file;
  struct riscv_elf_link_hash_table *table;

  table = riscv_elf_hash_table (info);
  execit_import_file = table->execit_import_file;
  rewind (table->execit_import_file);

  contents = bfd_malloc (sizeof (bfd_byte) * 4);

  /* Read instructions from the input file, and then build the list.  */
  while (!feof (execit_import_file))
    {
      char *code;
      struct elf_riscv_insn_times_entry *ptr;
      size_t nread;

      nread = fread (contents, sizeof (bfd_byte) * 4, 1, execit_import_file);
      /* Ignore the final byte 0x0a.  */
      if (nread < 1)
	break;
      insn = (*(contents + 3) << 24) | (*(contents + 2) << 16)
	| (*(contents + 1) << 8) | (*(contents));
      code = bfd_malloc (sizeof (char) * 9);
      snprintf (code, 9, "%08lx", insn);
      ptr = bfd_malloc (sizeof (struct elf_riscv_insn_times_entry));
      ptr->string = code;
      ptr->order = num;
      ptr->times = -1;
      ptr->sec = NULL;
      ptr->local_sym_value = 0;
      ptr->m_list = NULL;
      ptr->ex_reserve = 0;
      ptr->rel_backup.r_offset = 0;
      ptr->rel_backup.r_info = 0;
      ptr->rel_backup.r_addend = 0;
      ptr->irel = NULL;
      ptr->next = NULL;
      riscv_elf_execit_insert_entry (ptr);
      num++;
    }
  fclose (execit_import_file);

  /* Default set the maximun number of the EXECIT entries to 1024.
     There are still 1024 entries in .exec.itable even though the
     EXECIT limit setting exceeds the remaining entries.  */
  execit_import_number = num;
  if (table->update_execit_table
      && table->execit_limit != -1
      && (execit_import_number + table->execit_limit) > 1024)
    (*_bfd_error_handler)
      (_("Warning: There are only %d entries of .exec.itable left for this time."),
       (1024 - execit_import_number));

  /* We will run riscv_elf_execit_build_itable for EXECIT update
     in the riscv_elf_execit_finish.  */
  if (!table->update_execit_table && table->keep_import_execit)
    riscv_elf_execit_build_itable (abfd, info);
}

/* Adjust relocations in the .exec.itable, and then
   export it if needed.  */

static void
riscv_elf_relocate_execit_table (struct bfd_link_info *link_info, bfd *abfd)
{
  asection *table_sec = NULL;
  struct elf_riscv_insn_times_entry *execit_insn = execit_insn_head;
  struct elf_riscv_insn_times_entry *temp_ptr, *temp_ptr2;
  uint32_t insn, insn_with_reg, source_insn;
  bfd_byte *contents = NULL, *source_contents = NULL;
  int size = 0, offset = 0;
  Elf_Internal_Rela rel_backup;
  unsigned short insn_execit;
  struct riscv_elf_link_hash_table *table;
  static bfd_boolean done = FALSE;
  bfd_vma gp;

  /* Only need to be done once.  */
  if (done)
    return;
  done = TRUE;

  table = riscv_elf_hash_table (link_info);
  if (table)
    table->relax_status |= RISCV_RELAX_EXECIT_DONE;

  FILE *export_file = NULL;
  if (table->execit_export_file != NULL)
    {
      export_file = fopen (table->execit_export_file, "wb");
      if (export_file == NULL)
	{
	  (*_bfd_error_handler)
	    (_("Warning: cannot open the exported .exec.itable %s."),
	     table->execit_export_file);
	}
    }

  /* TODO: Maybe we should close the export file here, too.  */
  if (table->execit_import_file && !table->update_execit_table)
    return;

  table_sec = riscv_elf_execit_get_section (link_info->input_bfds);
  if (table_sec == NULL)
    {
      (*_bfd_error_handler) (_("ld: error cannot find .exec.itable section.\n"));
      return;
    }

  gp = riscv_global_pointer_value (link_info);
  if (table_sec->size == 0)
    return;
  if (!riscv_get_section_contents (table_sec->owner, table_sec,
				   &contents, TRUE))
    return;

  /* Relocate instruction.  */
  while (execit_insn)
    {
      bfd_vma relocation, min_relocation = 0xffffffff;

      insn = strtoll (execit_insn->string, NULL, 16);
      insn_with_reg = 0;
      /* (m_list != NULL): global symbol.
	 (execit_insn->sec != NULL): local sumbol.  */
      if (execit_insn->m_list != NULL || execit_insn->sec != NULL)
      {
	if (execit_insn->m_list)
	  rel_backup = execit_insn->m_list->rel_backup;
	else
	  rel_backup = execit_insn->rel_backup;

	riscv_elf_get_insn_with_reg (abfd, &rel_backup, insn, &insn_with_reg);
	if (ELFNN_R_TYPE (rel_backup.r_info) == R_RISCV_JAL
	    || ELFNN_R_TYPE (rel_backup.r_info) == R_RISCV_LO12_I
	    || ELFNN_R_TYPE (rel_backup.r_info) == R_RISCV_LO12_S)
	  {
	    relocation = riscv_elf_execit_reloc_insn (execit_insn, link_info);
	    insn = insn_with_reg
	      | riscv_elf_encode_relocation (abfd, &rel_backup, relocation);
	    bfd_put_32 (abfd, insn, contents + (execit_insn->order) * 4);
	  }
	else if (ELFNN_R_TYPE (rel_backup.r_info) == R_RISCV_GPREL_I
		 || ELFNN_R_TYPE (rel_backup.r_info) == R_RISCV_GPREL_S)
	  {
	    relocation = riscv_elf_execit_reloc_insn (execit_insn, link_info) - gp;
	    insn = insn_with_reg & ~(OP_MASK_RS1 << OP_SH_RS1);
	    insn |= X_GP << OP_SH_RS1;
	    insn |= riscv_elf_encode_relocation (abfd, &rel_backup, relocation);
	    bfd_put_32 (abfd, insn, contents + (execit_insn->order) * 4);
	  }
	else if (ELFNN_R_TYPE (rel_backup.r_info) >= R_RISCV_LGP18S0
		 && ELFNN_R_TYPE (rel_backup.r_info) <= R_RISCV_SGP17S3)
	  {
	    relocation = riscv_elf_execit_reloc_insn (execit_insn, link_info) - gp;
	    insn = insn_with_reg
	      | riscv_elf_encode_relocation (abfd, &rel_backup, relocation);
	    bfd_put_32 (abfd, insn, contents + (execit_insn->order) * 4);
	  }
	else if (ELFNN_R_TYPE (rel_backup.r_info) == R_RISCV_HI20)
	  {
	    /* lui may have multiple entries for one insn.  */
	    if (execit_insn->next && execit_insn->m_list
		&& execit_insn->m_list == execit_insn->next->m_list)
	      {
		struct elf_link_hash_entry_mul_list *m_list;
		struct elf_riscv_execit_refix *fix_ptr;
		struct elf_link_hash_entry *h;

		temp_ptr = execit_insn;
		temp_ptr2 = execit_insn;
		m_list = execit_insn->m_list;

		while (m_list)
		  {
		    h = m_list->h_list->h;
		    relocation = h->root.u.def.value +
		      h->root.u.def.section->output_section->vma +
		      h->root.u.def.section->output_offset;
		    relocation += m_list->irel->r_addend;

		    if (relocation < min_relocation)
		      min_relocation = relocation;
		    m_list = m_list->next;
		  }
		relocation = min_relocation;

		/* Put instruction into .exec.itable.  */
		insn = insn_with_reg
		  | riscv_elf_encode_relocation (abfd, &rel_backup, relocation);
		bfd_put_32 (abfd, insn, contents + (execit_insn->order) * 4);
		relocation = relocation + 0x1000;	/* hi20  */

		while (execit_insn->next && execit_insn->m_list
		       && execit_insn->m_list == execit_insn->next->m_list)
		  {
		    /* Multiple lui.  */
		    execit_insn = execit_insn->next;
		    size += 4;
		    insn = insn_with_reg
		      | riscv_elf_encode_relocation (abfd, &rel_backup, relocation);
		    bfd_put_32 (abfd, insn, contents + (execit_insn->order) * 4);
		    relocation = relocation + 0x1000;	/* hi20  */
		  }

		fix_ptr = execit_refix_head;
		/* Fix the exec.it insn for lui.  */
		while (fix_ptr)
		  {
		    /* temp_ptr2 points to the head of multiple lui.  */
		    temp_ptr = temp_ptr2;
		    while ((fix_ptr->order != temp_ptr->order
			    || fix_ptr->disable)
			   && fix_ptr->next)
		      fix_ptr = fix_ptr->next;

		    if (fix_ptr->order != temp_ptr->order
			|| fix_ptr->disable)
		      break;

		    /* Set source insn.  */
		    relocation =
		      fix_ptr->h->root.u.def.value +
		      fix_ptr->h->root.u.def.section->output_section->vma +
		      fix_ptr->h->root.u.def.section->output_offset;
		    relocation += fix_ptr->irel->r_addend;

		    /* lui imm is imm20s.  */
		    source_insn = insn_with_reg
		      | riscv_elf_encode_relocation (abfd, &rel_backup, relocation);

		    while (temp_ptr)
		      {
			/* Match entry and source code.  */
			insn = bfd_get_32 (abfd, contents + (temp_ptr->order) * 4 + offset);
			if (insn == source_insn)
			  {
			    /* Fix the exec.it insn.  */
			    if (temp_ptr->order != fix_ptr->order)
			      {
				if (!riscv_get_section_contents
				    (fix_ptr->sec->owner, fix_ptr->sec,
				     &source_contents, TRUE))
				  (*_bfd_error_handler)
				    (_("Linker: Can not get section contents when fixing "
				       "the exec.it for lui.\n"));
				insn_execit = INSN_EXECIT;
				insn_execit = insn_execit
				  | ENCODE_RVC_EXECIT_IMM (temp_ptr->order << 2);
				bfd_put_16 (abfd, insn_execit,
					    source_contents + fix_ptr->irel->r_offset);
			      }
			    break;
			  }
			else
			  {
			    if (!temp_ptr->next || temp_ptr->m_list != temp_ptr->next->m_list)
			      (*_bfd_error_handler)
				(_("Linker: Do not reserve enough EXECIT entries for lui\n"));
			    else
			      temp_ptr = temp_ptr->next;
			  }
		      }
		    fix_ptr = fix_ptr->next;
		  }
	      }
	    else
	      {
		/* lui with local symbol or single entry global symbol.  */
		relocation = riscv_elf_execit_reloc_insn (execit_insn, link_info);
		insn = insn_with_reg
		  | riscv_elf_encode_relocation (abfd, &rel_backup, relocation);
		bfd_put_32 (abfd, insn, contents + (execit_insn->order) * 4);
	      }
	  }
      }
      else
	{
	  /* No need to do relocation for insn without relocation.*/
	}
      execit_insn = execit_insn->next;
      size += 4;
    }
  if (!table->update_execit_table)
    size = table_sec->size;

  if (export_file != NULL)
    {
      fwrite (contents, sizeof (bfd_byte), size, export_file);
      fclose (export_file);
    }
}

#define MASK_IMM ENCODE_ITYPE_IMM (-1U)
#define MASK_RS1 (OP_MASK_RS1 << OP_SH_RS1)
#define MASK_RD (OP_MASK_RD << OP_SH_RD)
#define MASK_MAJOR_OP OP_MASK_OP
#define MATCH_OP_V (0x57)
#define MATCH_OP_AMO (0x2f)
#define MATCH_OP_LOAD_FP (0x07)
#define MATCH_OP_STORE_FP (0x27)

static bfd_boolean
riscv_elf_execit_check_insn_available (uint32_t insn)
{
  /* For bug-11621, system call should not be replaced by exec.it.  */
  /* According to spec, SCALL and SBREAK have been renamed to
     ECALL and EBREAK. Their encoding and functionality are unchanged.  */
  /* Invalid insns: ecall, ebreak, ACE, ret.  */
  if ((insn & MASK_ECALL) == MATCH_ECALL
      || (insn & MASK_EBREAK) == MATCH_EBREAK
      || (insn & 0x7f) == 0x7b
      || ((insn & (MASK_JALR | MASK_RD | MASK_RS1 | MASK_IMM))
	  == (MATCH_JALR | (X_RA << OP_SH_RS1))))
    return FALSE;

  /* RVV is not exec.it supported by now.  */
  uint32_t major = insn & MASK_MAJOR_OP;
  if (major == MATCH_OP_V)
    return FALSE;
  else
    {
      uint32_t width = (insn >> 12) & 0x7;
      if (major == MATCH_OP_AMO)
        {
	  if (width > 5)
	    return FALSE;
	}
      else if ((major == MATCH_OP_LOAD_FP) ||
	       (major == MATCH_OP_STORE_FP))
        {
	  if ((width == 0) || (width > 4))
	    return FALSE;
	}
    }

  return TRUE;
}

/* Generate EXECIT hash table.  */

static bfd_boolean
riscv_elf_execit_build_hash_table (bfd *abfd, asection *sec,
				   struct bfd_link_info *link_info)
{
  Elf_Internal_Rela *internal_relocs;
  Elf_Internal_Rela *irelend;
  Elf_Internal_Rela *irel;
  Elf_Internal_Rela *jrel;
  Elf_Internal_Rela rel_backup;
  Elf_Internal_Shdr *symtab_hdr;
  Elf_Internal_Sym *isym = NULL;
  asection *isec;
  struct elf_link_hash_entry **sym_hashes;
  bfd_byte *contents = NULL;
  bfd_vma off = 0;
  unsigned long r_symndx;
  uint32_t insn, insn_with_reg;
  struct elf_link_hash_entry *h;
  int data_flag;
  bfd_vma relocation;
  struct riscv_elf_link_hash_table *table;

  sym_hashes = elf_sym_hashes (abfd);
  /* Load the input section instructions, relocations, and symbol table.  */
  if (!riscv_get_section_contents (abfd, sec, &contents, TRUE))
    return FALSE;

  internal_relocs = _bfd_elf_link_read_relocs (abfd, sec, NULL, NULL,
					       TRUE /* keep_memory  */);
  irelend = internal_relocs + sec->reloc_count;
  symtab_hdr = &elf_tdata (abfd)->symtab_hdr;
  if (!riscv_get_local_syms (abfd, sec, &isym))
    return FALSE;

  /* Check the input section enable EXECIT?  */
  irel = find_relocs_at_address (internal_relocs, internal_relocs, irelend,
				 R_RISCV_RELAX_ENTRY);

  /* Check this input section trigger EXECIT relaxation.  */
  if (irel == NULL
      || irel >= irelend
      || ELFNN_R_TYPE (irel->r_info) != R_RISCV_RELAX_ENTRY
      || (ELFNN_R_TYPE (irel->r_info) == R_RISCV_RELAX_ENTRY
	  && !(irel->r_addend & R_RISCV_RELAX_ENTRY_EXECIT_FLAG)))
    return TRUE;

  irel = internal_relocs;
  table = riscv_elf_hash_table (link_info);

  /* Push each insn into the hash table.  */
  while (off < sec->size)
    {
      char code[10];
      struct elf_riscv_code_hash_entry *entry;

      while (irel != NULL && irel < irelend && irel->r_offset < off)
	irel++;

      data_flag = riscv_relocation_check (link_info, &irel, irelend,
					  sec, &off, contents, 1);
      if (data_flag & DATA_EXIST)
	{
	  /* We save the move offset in the highest byte.  */
	  off += (data_flag >> 24);
	  continue;
	}

      /* Ignore 16-bit instruction.  */
      if ((*(contents + off) & 0x3) != 0x3)
	{
	  off += 2;
	  continue;
	}

      insn = bfd_get_32 (abfd, contents + off);

      if (!riscv_elf_execit_check_insn_available (insn))
	{
	  off += 4;
	  continue;
	}

      h = NULL;
      isec = NULL;
      jrel = NULL;
      rel_backup.r_info = 0;
      rel_backup.r_offset = 0;
      rel_backup.r_addend = 0;
      /* Load the instruction and its opcode with register for comparing.  */
      insn_with_reg = 0;
      if (irel != NULL && irel < irelend && irel->r_offset == off)
	{
	  riscv_elf_get_insn_with_reg (abfd, irel, insn, &insn_with_reg);
	  if ((!table->execit_noji && ELFNN_R_TYPE (irel->r_info) == R_RISCV_JAL)
	      || (!table->execit_nols
		&& (ELFNN_R_TYPE (irel->r_info) == R_RISCV_HI20
		  || ELFNN_R_TYPE (irel->r_info) == R_RISCV_LO12_I
		  || ELFNN_R_TYPE (irel->r_info) == R_RISCV_LO12_S
		  || ELFNN_R_TYPE (irel->r_info) == R_RISCV_GPREL_I
		  || ELFNN_R_TYPE (irel->r_info) == R_RISCV_GPREL_S
		  || (ELFNN_R_TYPE (irel->r_info) >= R_RISCV_LGP18S0
		    && ELFNN_R_TYPE (irel->r_info) <= R_RISCV_SGP17S3))))
	    {
	      r_symndx = ELFNN_R_SYM (irel->r_info);
	      jrel = irel;
	      rel_backup = *irel;
	      if (r_symndx < symtab_hdr->sh_info)
		{
		  /* Local symbol.  */
		  int shndx = isym[r_symndx].st_shndx;

		  bfd_vma st_value = (isym + r_symndx)->st_value;
		  isec = elf_elfsections (abfd)[shndx]->bfd_section;
		  relocation = (isec->output_section->vma + isec->output_offset
				+ st_value + irel->r_addend);
		}
	      else
		{
		  /* External symbol.  */
		  bfd_boolean warned ATTRIBUTE_UNUSED;
		  bfd_boolean ignored ATTRIBUTE_UNUSED;
		  bfd_boolean unresolved_reloc ATTRIBUTE_UNUSED;
		  asection *sym_sec;

		  /* Maybe there is a better way to get h and relocation.  */
		  RELOC_FOR_GLOBAL_SYMBOL (link_info, abfd, sec, irel,
					   r_symndx, symtab_hdr, sym_hashes,
					   h, sym_sec, relocation,
					   unresolved_reloc, warned, ignored);
		  relocation += irel->r_addend;

		  /* TODO: the global symbol _FP_BASE_ should be skipped, too.  */
		  if (h->root.u.def.section->output_section == NULL
		      || (h->root.type != bfd_link_hash_defined
			  && h->root.type != bfd_link_hash_defweak))
		    {
		      off += 4;
		      continue;
		    }
		}

	      if (ELFNN_R_TYPE (irel->r_info) == R_RISCV_GPREL_I
		  || ELFNN_R_TYPE (irel->r_info) == R_RISCV_GPREL_S
		  || (ELFNN_R_TYPE (irel->r_info) >= R_RISCV_LGP18S0
		      && ELFNN_R_TYPE (irel->r_info) <= R_RISCV_SGP17S3))
		{
		  bfd_vma gp = riscv_global_pointer_value (link_info);
		  relocation -= gp;
		}

	      /* Check the absolute address is fitable in the .exec.itable.  */
	      if (ELFNN_R_TYPE (irel->r_info) == R_RISCV_JAL)
		{
		  bfd_vma insn_pc;

		  insn_pc = sec_addr(sec) + off;
		  if ((relocation & 0xffe00000) != (insn_pc & 0xffe00000))
		    /* For R_RISCV_JAL, since the high 11 bits of target
		       symbol and pc may be defferent after EXECIT relaxation,
		       we will not replace these error cases with exec.it in the
		       riscv_elf_exec_replace_instruction and
		       exec_check_pchi_for_jal.  */
		    {
		      off += 4;
		      continue;
		    }
		}

	      insn = insn_with_reg
		| riscv_elf_encode_relocation (abfd, irel, relocation);
	    }
	  else
	    {
	      off += 4;
	      continue;
	    }
	}

      snprintf (code, sizeof (code), "%08x", insn);
      /* Copy "code".  */
      entry = (struct elf_riscv_code_hash_entry*)
	bfd_hash_lookup (&execit_code_table, code, TRUE, TRUE);
      if (entry == NULL)
	{
	  (*_bfd_error_handler)
	    (_("Linker: failed creating exec.it %s hash table\n"), code);
	  return FALSE;
	}
      if (h)
	{
	  if (h->root.type == bfd_link_hash_undefined)
	    return TRUE;

	  /* Global symbol.  */
	  /* In order to do lui with different symbol but same value.  */
	  if (entry->m_list == NULL)
	    {
	      struct elf_link_hash_entry_mul_list *m_list_new;
	      struct elf_link_hash_entry_list *h_list_new;

	      m_list_new = (struct elf_link_hash_entry_mul_list *)
		bfd_malloc (sizeof (struct elf_link_hash_entry_mul_list));
	      h_list_new = (struct elf_link_hash_entry_list *)
		bfd_malloc (sizeof (struct elf_link_hash_entry_list));
	      entry->m_list = m_list_new;
	      m_list_new->h_list = h_list_new;
	      m_list_new->rel_backup = rel_backup;
	      m_list_new->times = 1;
	      m_list_new->irel = jrel;
	      m_list_new->next = NULL;
	      h_list_new->h = h;
	      h_list_new->next = NULL;
	    }
	  else
	    {
	      struct elf_link_hash_entry_mul_list *m_list = entry->m_list;
	      struct elf_link_hash_entry_list *h_list;

	      while (m_list)
		{
		  /* Only support the same address with the same symbol because
		     overlay may cause different relaxation size.*/
		  h_list = m_list->h_list;
		  if (h_list->h == h
		      && m_list->rel_backup.r_addend == rel_backup.r_addend)
		    {
		      m_list->times++;
		      m_list->irel = jrel;
		      break;
		    }
		  /* The lui case may have different address but
		     the high part is the same.  */
		  else if (ELFNN_R_TYPE (jrel->r_info) == R_RISCV_HI20
			   && m_list->next == NULL)
		    {
		      struct elf_link_hash_entry_mul_list *m_list_new;
		      struct elf_link_hash_entry_list *h_list_new;

		      m_list_new = (struct elf_link_hash_entry_mul_list *)
			bfd_malloc (sizeof (struct elf_link_hash_entry_mul_list));
		      h_list_new = (struct elf_link_hash_entry_list *)
			bfd_malloc (sizeof (struct elf_link_hash_entry_list));
		      m_list->next = m_list_new;
		      m_list_new->h_list = h_list_new;
		      m_list_new->rel_backup = rel_backup;
		      m_list_new->times = 1;
		      m_list_new->irel = jrel;
		      m_list_new->next = NULL;
		      h_list_new->h = h;
		      h_list_new->next = NULL;
		      break;
		    }
		  m_list = m_list->next;
		}
	      if (!m_list)
		{
		  off += 4;
		  continue;
		}
	    }
	}
      else
	{
	  /* Local symbol and insn without relocation.  */
	  entry->times++;
	  entry->rel_backup = rel_backup;
	}

      /* Use in lui insn with constant and global symbol in same format.  */
      if (!jrel)
	entry->const_insn = 1;
      else
	entry->irel = jrel;
      entry->sec = isec;
      off += 4;
    }
  return TRUE;
}

/* Set the _ITB_BASE_, and point it to .exec.itable.  */

bfd_boolean
riscv_elf_execit_itb_base (struct bfd_link_info *link_info)
{
  asection *sec;
  bfd *output_bfd = NULL;
  struct bfd_link_hash_entry *bh = NULL;

  if (is_ITB_BASE_set == 1)
    return TRUE;

  is_ITB_BASE_set = 1;

  sec = riscv_elf_execit_get_section (link_info->input_bfds);
  if (sec != NULL)
    output_bfd = sec->output_section->owner;

  if (output_bfd == NULL)
    {
      output_bfd = link_info->output_bfd;
      if (output_bfd->sections == NULL)
	return TRUE;
      else
	sec = bfd_abs_section_ptr;
    }

  /* Do not define _ITB_BASE_ if it is not used.
     And remain user to set it if needed.  */

  bh = bfd_link_hash_lookup (link_info->hash, "_ITB_BASE_",
			     FALSE, FALSE, TRUE);
  if (!bh)
    return TRUE;

  return (_bfd_generic_link_add_one_symbol
	  (link_info, output_bfd, "_ITB_BASE_", BSF_GLOBAL | BSF_WEAK,
	   sec, 0, (const char *) NULL, FALSE,
	   get_elf_backend_data (output_bfd)->collect, &bh));
}

static void
riscv_elf_execit_save_local_symbol_value (void)
{
  struct elf_riscv_insn_times_entry *execit_insn = execit_insn_head;
  while (execit_insn)
    {
      if (execit_insn->sec != NULL)
	{
	  Elf_Internal_Sym *isym = NULL;
	  if (riscv_get_local_syms (execit_insn->sec->owner, execit_insn->sec, &isym))
	    {
	      isym = isym + ELFNN_R_SYM (execit_insn->irel->r_info);
	      execit_insn->local_sym_value = isym->st_value;
	    }
	}
      execit_insn = execit_insn->next;
    }
}

/* End of EXECIT Instruction Table Relaxation.  */

/* ROM Patch with Indirect Call Table (ICT).  */

#define RISCV_ICT_SECTION ".nds.ict"

/* Indirect call hash function.  */

static struct bfd_hash_entry *
riscv_elf_ict_hash_newfunc (struct bfd_hash_entry *entry,
			    struct bfd_hash_table *table,
			    const char *string)
{
  struct elf_riscv_ict_hash_entry *ret;

  /* Allocate the structure if it has not already been allocated by a
     subclass.  */
  if (entry == NULL)
    {
      entry = (struct bfd_hash_entry *)
	bfd_hash_allocate (table, sizeof (*ret));
      if (entry == NULL)
	return entry;
    }

  /* Call the allocation method of the superclass.  */
  entry = bfd_hash_newfunc (entry, table, string);
  if (entry == NULL)
    return entry;

  ret = (struct elf_riscv_ict_hash_entry*) entry;
  ret->order = 0;
  return &ret->root;
}

/* Initialize indirect call hash table.  */

static void
riscv_elf_ict_init (void)
{
  if (!bfd_hash_table_init_n (&indirect_call_table, riscv_elf_ict_hash_newfunc,
			      sizeof (struct elf_riscv_ict_hash_entry),
			      1023))
    (*_bfd_error_handler)
      (_("Linker: cannot init indirect call hash table.\n"));
  return;
}

static void
riscv_elf_insert_exported_ict_table (struct elf_riscv_ict_hash_entry *entry)
{
  struct riscv_elf_ict_table_entry *head, *new;

  head = exported_ict_table_head;
  while (head
	 && strcmp (head->h->root.root.string,
		    entry->h->root.root.string) != 0)
    head = head->next;

  if (head)
    /* This symbol is already in the exported ict table.  */
    return;
  else
    {
      /* We need to insert the symbol into the exported ict table.  */
      new = (struct riscv_elf_ict_table_entry *) bfd_malloc
	(sizeof (struct riscv_elf_ict_table_entry));
      new->h = entry->h;
      new->order = entry->order;

      head = exported_ict_table_head;
      if (head == NULL
	  || head->order >= new->order)
	{
	  new->next = head;
	  exported_ict_table_head = new;
	}
      else
	{
	  while (head->next != NULL
		 && head->next->order < new->order)
	    head = head->next;
	  new->next = head->next;
	  head->next = new;
	}
    }
}

static void
riscv_elf_ict_hash_to_exported_table (void)
{
  unsigned int i;

  indirect_call_table.frozen = 1;
  for (i = 0; i < indirect_call_table.size; i++)
    {
      struct bfd_hash_entry *p;

      for (p = indirect_call_table.table[i]; p != NULL; p = p->next)
	{
	  struct elf_riscv_ict_hash_entry *entry;

	  entry = (struct elf_riscv_ict_hash_entry *) p;
	  riscv_elf_insert_exported_ict_table (entry);
	}
    }
  indirect_call_table.frozen = 0;
}

static void
riscv_elf_relocate_ict_table (struct bfd_link_info *info, bfd *output_bfd)
{
  bfd *input_bfd;
  asection *sec;
  bfd_byte *contents = NULL;
  struct elf_link_hash_entry *h;
  struct bfd_link_hash_entry *ict_sym;
  bfd_vma relocation, ict_base;
  bfd_vma insn;
  unsigned int ict_entry_size;
  static bfd_boolean done = FALSE;
  struct riscv_elf_ict_table_entry *head;

  if (done)
    return;
  done = TRUE;

  for (input_bfd = info->input_bfds;
       input_bfd != NULL;
       input_bfd = input_bfd->link.next)
    {
      sec = bfd_get_section_by_name (input_bfd, RISCV_ICT_SECTION);
      if (sec != NULL)
        break;
    }

  if (sec == NULL
      || !riscv_get_section_contents (sec->owner, sec, &contents, TRUE))
    {
      (*_bfd_error_handler)
	(_("Linker: Can not find .nds.ict table or it's contents.\n"));
      return;
    }

  ict_sym = bfd_link_hash_lookup (info->hash, "_INDIRECT_CALL_TABLE_BASE_",
				  FALSE, FALSE, FALSE);
  ict_base = (ict_sym->u.def.value
	      + ict_sym->u.def.section->output_section->vma
	      + ict_sym->u.def.section->output_offset);

  if (ict_model == 1 || ict_model == 2)
    ict_entry_size = 8;
  else
    ict_entry_size = 4;

  head = exported_ict_table_head;
  while (head)
    {
      int order, ict_table_reloc = R_RISCV_NONE;

      h = head->h;
      order = head->order;
      if ((h->root.type == bfd_link_hash_defined
	   || h->root.type == bfd_link_hash_defweak)
	  && h->root.u.def.section != NULL
	  && h->root.u.def.section->output_section != NULL)
	{
	  relocation = h->root.u.def.value
	    + h->root.u.def.section->output_section->vma
	    + h->root.u.def.section->output_offset;

	  if (ict_model == 0)
	    {
	      /* Tiny model: jal ra, 0x0.  */
	      bfd_put_32 (output_bfd, RISCV_UJTYPE (JAL, X_T1, 0x0),
			  contents + (order * ict_entry_size));
	      ict_table_reloc = R_RISCV_JAL;

	      /* PC is the entry of ICT table.  */
	      relocation -= ict_base + (order * ict_entry_size);
	      if (!VALID_UJTYPE_IMM (relocation))
		{
		  (*_bfd_error_handler)
		    (_("Linker: relocate ICT table failed with tiny model.\n"));
		  return;
		}
	      relocation = ENCODE_UJTYPE_IMM (relocation);
	    }
	  else if (ict_model == 1)
	    {
	      /* Small model: tail t1, 0x0.  */
	      bfd_put_32 (output_bfd, RISCV_UTYPE (AUIPC, X_T1, 0x0),
			  contents + (order * ict_entry_size));
	      bfd_put_32 (output_bfd, RISCV_ITYPE (JALR, X_T1, X_T1, 0),
			  contents + (order * ict_entry_size) + 4);
	      ict_table_reloc = R_RISCV_CALL;

	      /* PC is the entry of ICT table.  */
	      relocation -= ict_base + (order * ict_entry_size);
	      if (ARCH_SIZE > 32
		  && !VALID_UTYPE_IMM (RISCV_CONST_HIGH_PART (relocation)))
		{
		  (*_bfd_error_handler)
		    (_("Linker: relocate ICT table failed with small model.\n"));
		  return;
		}
	      relocation =
		ENCODE_UTYPE_IMM (RISCV_CONST_HIGH_PART (relocation))
		| (ENCODE_ITYPE_IMM (relocation) << 32);
	    }
	  else if (ict_model == 2)
	    {
	      /* Large model: .dword 0x0.  */
	      ict_table_reloc =  R_RISCV_64;
	    }
	  else
	    {
	      (*_bfd_error_handler)
		(_("Linker: Unknown ICT model.\n"));
	      return;
	    }

	  BFD_ASSERT (ict_table_reloc != R_RISCV_NONE);
	  reloc_howto_type *howto =
	    riscv_elf_rtype_to_howto (input_bfd, ict_table_reloc);
	  insn = bfd_get (howto->bitsize, output_bfd,
			  contents + (order * ict_entry_size));
	  insn = (insn & ~howto->dst_mask)
	    | (relocation & howto->dst_mask);
	  bfd_put (howto->bitsize, output_bfd, insn,
		   contents + (order * ict_entry_size));
	}
      else
	{
	  /* Should we allow the case that the ict symbol is undefined?  */
	}

      head = head->next;
    }
}

/* End of ROM Patch with Indirect Call Table (ICT).  */

/* Helper functions.  */

/* Sort relocation by r_offset.
   We didn't use qsort () in stdlib, because quick-sort is not a stable sorting
   algorithm.  Relocations at the same r_offset must keep their order.

   Currently, this function implements insertion-sort.

   FIXME: If we already sort them in assembler, why bother sort them
   here again?  */

static void
riscv_insertion_sort (void *base, size_t nmemb, size_t size,
		      int (*compar) (const void *lhs, const void *rhs))
{
  char *ptr = (char *) base;
  int i, j;
  char *tmp = malloc (size);

  /* If i is less than j, i is inserted before j.

     |---- j ----- i --------------|
     \	      / \		  /
     sorted		unsorted
  */

  for (i = 1; i < (int) nmemb; i++)
    {
      for (j = (i - 1); j >= 0; j--)
	if (compar (ptr + i * size, ptr + j * size) >= 0)
	  break;
      j++;

      if (i == j)
	continue; /* i is in order.  */

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

/* Get the contents of the internal symbol of abfd.  */

static int
riscv_get_local_syms (bfd *abfd, asection *sec ATTRIBUTE_UNUSED,
		      Elf_Internal_Sym **isymbuf_p)
{
  Elf_Internal_Shdr *symtab_hdr;
  symtab_hdr = &elf_tdata (abfd)->symtab_hdr;

  /* Read this BFD's local symbols if we haven't done so already.  */
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

/* Get the contents of a section.  */

static int
riscv_get_section_contents (bfd *abfd, asection *sec,
			    bfd_byte **contents_p, bfd_boolean cache)
{
  /* Get the section contents.  */
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

/* Get insn with registers according to relocation type.  */

static void
riscv_elf_get_insn_with_reg (bfd* abfd, Elf_Internal_Rela *irel,
			     uint32_t insn, uint32_t *insn_with_reg)
{
  reloc_howto_type *howto = NULL;

  if (irel == NULL
      || (ELFNN_R_TYPE (irel->r_info) >= number_of_howto_table))
    {
      *insn_with_reg = insn;
      return;
    }

  howto = riscv_elf_rtype_to_howto (abfd, ELFNN_R_TYPE (irel->r_info));
  *insn_with_reg = insn & (~howto->dst_mask);
}

/* Encode relocation into Imm field.  */

static bfd_vma
riscv_elf_encode_relocation (bfd *abfd,
			     Elf_Internal_Rela *irel, bfd_vma relocation)
{
  reloc_howto_type *howto = NULL;

  if (irel == NULL
      || (ELFNN_R_TYPE (irel->r_info) >= number_of_howto_table))
    return 0;

  howto = riscv_elf_rtype_to_howto (abfd, ELFNN_R_TYPE (irel->r_info));
  switch (ELFNN_R_TYPE (irel->r_info))
    {
    case R_RISCV_HI20:
    case R_RISCV_PCREL_HI20:
      if (ARCH_SIZE > 32 && !VALID_UTYPE_IMM (RISCV_CONST_HIGH_PART (relocation)))
	return 0;
      relocation = ENCODE_UTYPE_IMM (RISCV_CONST_HIGH_PART (relocation));
      break;
    case R_RISCV_LO12_I:
    case R_RISCV_PCREL_LO12_I:
    case R_RISCV_GPREL_I:
      relocation = ENCODE_ITYPE_IMM (relocation);
      break;
    case R_RISCV_LO12_S:
    case R_RISCV_PCREL_LO12_S:
    case R_RISCV_GPREL_S:
      relocation = ENCODE_STYPE_IMM (relocation);
      break;
    case R_RISCV_JAL:
      relocation = ENCODE_UJTYPE_IMM (relocation);
      break;
    case R_RISCV_LGP18S0:
      relocation = ENCODE_GPTYPE_LB_IMM (relocation);
      break;
    case R_RISCV_LGP17S1:
      relocation = ENCODE_GPTYPE_LH_IMM (relocation);
      break;
    case R_RISCV_LGP17S2:
      relocation = ENCODE_GPTYPE_LW_IMM (relocation);
      break;
    case R_RISCV_LGP17S3:
      relocation= ENCODE_GPTYPE_LD_IMM (relocation);
      break;
    case R_RISCV_SGP18S0:
      relocation = ENCODE_GPTYPE_SB_IMM (relocation);
      break;
    case R_RISCV_SGP17S1:
      relocation = ENCODE_GPTYPE_SH_IMM (relocation);
      break;
    case R_RISCV_SGP17S2:
      relocation = ENCODE_GPTYPE_SW_IMM (relocation);
      break;
    case R_RISCV_SGP17S3:
      relocation = ENCODE_GPTYPE_SD_IMM (relocation);
      break;
    default:
      return 0;
    }

  return (relocation & howto->dst_mask);
}

/* Find a relocation of type specified by reloc_type
   of the same r_offset with reloc. If not found, return irelend.

   Note that relocations must be sorted by r_offset,
   we find the relocation from "reloc" backward untill relocs,
   or find it from "reloc" forward untill irelend.  */

static Elf_Internal_Rela *
find_relocs_at_address (Elf_Internal_Rela *reloc,
			Elf_Internal_Rela *relocs,
			Elf_Internal_Rela *irelend,
			enum elf_riscv_reloc_type reloc_type)
{
  Elf_Internal_Rela *rel_t;

  /* Find backward.  */
  for (rel_t = reloc;
       rel_t >= relocs && rel_t->r_offset == reloc->r_offset;
       rel_t--)
    if (ELFNN_R_TYPE (rel_t->r_info) == reloc_type)
      return rel_t;

  /* We didn't find it backward.
     Try find it forward.  */
  for (rel_t = reloc;
       rel_t < irelend && rel_t->r_offset == reloc->r_offset;
       rel_t++)
    if (ELFNN_R_TYPE (rel_t->r_info) == reloc_type)
      return rel_t;

  return irelend;
}

/* For target aligned, optimize is zero.
   For EXECIT, optimize is one.  */

static int
riscv_relocation_check (struct bfd_link_info *info,
			Elf_Internal_Rela **irel,
			Elf_Internal_Rela *irelend,
			asection *sec, bfd_vma *off,
			bfd_byte *contents, int optimize)
{
  /* We use the highest 1 byte of result to record
     how many bytes location counter has to move.  */
  int result = 0;
  Elf_Internal_Rela *irel_save = NULL;
  bfd_boolean nested_execit, nested_loop;
  bfd_boolean execit_loop_aware;

  struct riscv_elf_link_hash_table *table;

  table = riscv_elf_hash_table (info);
  execit_loop_aware = table->execit_loop_aware;

  while ((*irel) != NULL && (*irel) < irelend && (*off) == (*irel)->r_offset)
    {
      switch (ELFNN_R_TYPE ((*irel)->r_info))
	{
	case R_RISCV_RELAX_REGION_BEGIN:
	  /* Ignore code block.  */
	  nested_execit = FALSE;
	  nested_loop = FALSE;
	  if (optimize
	      && (((*irel)->r_addend & R_RISCV_RELAX_REGION_NO_EXECIT_FLAG)
		  || (execit_loop_aware
		      && ((*irel)->r_addend & R_RISCV_RELAX_REGION_LOOP_FLAG))))
	    {
	      /* Check the region if loop or not.  If it is true and
		 execit_loop_aware is true, ignore the region till region end.  */
	      /* To save the status for in .no_relax execit region and
		 loop region to conform the block can do EXECIT relaxation.  */
	      nested_execit = ((*irel)->r_addend & R_RISCV_RELAX_REGION_NO_EXECIT_FLAG);
	      nested_loop = (execit_loop_aware
			     && ((*irel)->r_addend & R_RISCV_RELAX_REGION_LOOP_FLAG));
	      while ((*irel) && (*irel) < irelend && (nested_execit || nested_loop))
		{
		  (*irel)++;
		  if (ELFNN_R_TYPE ((*irel)->r_info) == R_RISCV_RELAX_REGION_BEGIN)
		    {
		      /* There may be nested region.  */
		      if (((*irel)->r_addend & R_RISCV_RELAX_REGION_NO_EXECIT_FLAG) != 0)
			nested_execit = TRUE;
		      else if (execit_loop_aware
			       && ((*irel)->r_addend & R_RISCV_RELAX_REGION_LOOP_FLAG))
			nested_loop = TRUE;
		    }
		  else if (ELFNN_R_TYPE ((*irel)->r_info) == R_RISCV_RELAX_REGION_END)
		    {
		      /* The end of region.  */
		      if (((*irel)->r_addend & R_RISCV_RELAX_REGION_NO_EXECIT_FLAG) != 0)
			nested_execit = FALSE;
		      else if (execit_loop_aware
			       && ((*irel)->r_addend & R_RISCV_RELAX_REGION_LOOP_FLAG))
			nested_loop = FALSE;
		    }
		  else if (ELFNN_R_TYPE ((*irel)->r_info) == R_RISCV_ALIGN
			   && ((*irel)->r_addend & (1 << 31)))
		    {
		      /* Estimate the total relaxed size for EXECIT before this point.  */
		      struct elf_riscv_blank *blank_t = blank_list_head;
		      int relax_size = 0;
		      while (blank_t && blank_t->offset < (*off))
			{
			  relax_size += blank_t->size;
			  blank_t = blank_t->next;
			}
		      /* Check whether this point is align or not.  */
		      result |= ALIGN_CLEAN_PRE;
		      if (((*irel)->r_offset
			   + ((*irel)->r_addend & 0x1f)
			   - relax_size)
			  & 0x02)
			result |= ALIGN_PUSH_PRE;
		    }
		}
	      if ((*irel) >= irelend)
		*off = sec->size;
	      else
		*off = (*irel)->r_offset;

	      return result;
	    }
	  break;
	case R_RISCV_ALIGN:
	  /* Just consider 4-byte aligned with EXECIT.  */
	  if (optimize && ((*irel)->r_addend & (1 << 31)))
	    {
	      /* Estimate the total relaxed size for EXECIT before this point.  */
	      struct elf_riscv_blank *blank_t = blank_list_head;
	      int relax_size = 0;
	      while (blank_t && blank_t->offset < (*off))
		{
		  relax_size += blank_t->size;
		  blank_t = blank_t->next;
		}
	      /* Check whether this point is align or not.  */
	      result |= ALIGN_CLEAN_PRE;
	      if (((*irel)->r_offset
		   + ((*irel)->r_addend & 0x1f)
		   - relax_size)
		  & 0x02)
		result |= ALIGN_PUSH_PRE;
	    }
	  break;
	case R_RISCV_DATA:
	  /* Data in text section.  */
	  result |= ((*irel)->r_addend << 24);
	  result |= DATA_EXIST;
	  break;
	  /* Here we regard unsupported relocations as data relocations
	     and then skip them.   */
	  /* Since a pair of R_RISCV_ADD (R_RISCV_SET) and R_RISCV_SUB point
	     to the same address, we only need to skip them once.  */
	case R_RISCV_SUB6:
	case R_RISCV_SUB8:
	  result |= (1 << 24);
	  result |= DATA_EXIST;
	  break;
	case R_RISCV_SUB16:
	  result |= (2 << 24);
	  result |= DATA_EXIST;
	  break;
	case R_RISCV_RVC_LUI:
	case R_RISCV_RVC_JUMP:
	case R_RISCV_RVC_BRANCH:
	  if (!optimize)
	    irel_save = *irel;
	  else
	    {
	      result |= (2 << 24);
	      result |= DATA_EXIST;
	    }
	  break;
	case R_RISCV_32:
	case R_RISCV_SUB32:
	case R_RISCV_PCREL_HI20:
	case R_RISCV_PCREL_LO12_I:
	case R_RISCV_PCREL_LO12_S:
	  result |= (4 << 24);
	  result |= DATA_EXIST;
	  break;
	case R_RISCV_BRANCH:
	  if (!optimize)
	    /* Used for target_align_check_branch_range.  */
	    irel_save = *irel;
	  result |= (4 << 24);
	  result |= DATA_EXIST;
	  break;
	  /* These relocation is supported EXECIT relaxation currently.  */
	  /* We have to save the relocation for using later, since we have
	     to check there is any alignment in the same address.  */
	case R_RISCV_JAL:
	  irel_save = *irel;
	  if (!optimize)
	    {
	      result |= (4 << 24);
	      result |= DATA_EXIST;
	    }
	  break;
	case R_RISCV_HI20:
	case R_RISCV_LO12_I:
	case R_RISCV_LO12_S:
	case R_RISCV_GPREL_I:
	case R_RISCV_GPREL_S:
	case R_RISCV_LGP18S0:
	case R_RISCV_LGP17S1:
	case R_RISCV_LGP17S2:
	case R_RISCV_LGP17S3:
	case R_RISCV_SGP18S0:
	case R_RISCV_SGP17S1:
	case R_RISCV_SGP17S2:
	case R_RISCV_SGP17S3:
	  if (optimize)
	    irel_save = *irel;
	  else
	    {
	      result |= (4 << 24);
	      result |= DATA_EXIST;
	    }
	  break;
	case R_RISCV_64:
	case R_RISCV_SUB64:
	case R_RISCV_CALL:
	  result |= (8 << 24);
	  result |= DATA_EXIST;
	  break;
	case R_RISCV_RELATIVE:
	case R_RISCV_COPY:
	case R_RISCV_JUMP_SLOT:
	case R_RISCV_TLS_DTPMOD32:
	case R_RISCV_TLS_DTPMOD64:
	case R_RISCV_TLS_DTPREL32:
	case R_RISCV_TLS_DTPREL64:
	case R_RISCV_TLS_TPREL32:
	case R_RISCV_TLS_TPREL64:
	  /* These relocations are used by dynamic linker. In general, we
	     should not see them here.  */
	  (*_bfd_error_handler)
	    (_("Linker: find dynamic relocation when doing relaxation\n"));
	  break;
	default:
	  /* Relocation not supported.  */
	  if (ELFNN_R_TYPE ((*irel)->r_info) != R_RISCV_RELAX
	      && ELFNN_R_TYPE ((*irel)->r_info) != R_RISCV_NONE
	      && ELFNN_R_TYPE ((*irel)->r_info) != R_RISCV_RELAX_ENTRY
	      && ELFNN_R_TYPE ((*irel)->r_info) != R_RISCV_ADD8
	      && ELFNN_R_TYPE ((*irel)->r_info) != R_RISCV_ADD16
	      && ELFNN_R_TYPE ((*irel)->r_info) != R_RISCV_ADD32
	      && ELFNN_R_TYPE ((*irel)->r_info) != R_RISCV_ADD64
	      && ELFNN_R_TYPE ((*irel)->r_info) != R_RISCV_SET6
	      && ELFNN_R_TYPE ((*irel)->r_info) != R_RISCV_SET8
	      && ELFNN_R_TYPE ((*irel)->r_info) != R_RISCV_SET16
	      && ELFNN_R_TYPE ((*irel)->r_info) != R_RISCV_SET32
	      && ELFNN_R_TYPE ((*irel)->r_info) != R_RISCV_NO_RVC_REGION_BEGIN
	      && ELFNN_R_TYPE ((*irel)->r_info) != R_RISCV_NO_RVC_REGION_END
	      && ELFNN_R_TYPE ((*irel)->r_info) != R_RISCV_RELAX_REGION_END)
	    {
	      /* Since we already consider all relocations above, this won't
		 happen unless supporting new relocations. */
	      /* TODO: Maybe we should show warning message here.  */
	      result |= DATA_EXIST;
	      if ((*(contents + (*off)) & 0x3) != 0x3)
		/* 16-bit instruction.  */
		result |= (2 << 24);
	      else
		/* 32-bit instruction.  */
		result |= (4 << 24);
	      break;
	    }
	}
      (*irel)++;
    }
  if (irel_save)
    *irel = irel_save;
  return result;
}

/* Find the symbol '__global_pointer$' in the output bfd.
   If we can't find it, set it's value to (sdata + 0x800)
   by default.  */
/* TODO: figure out the best SDA_BASE value.  */

static bfd_boolean
riscv_init_global_pointer (bfd *output_bfd, struct bfd_link_info *info)
{
  struct bfd_link_hash_entry *h;
  asection *section = NULL;
  bfd_vma gp_value = 0x800;

  h = bfd_link_hash_lookup (info->hash, RISCV_GP_SYMBOL, FALSE, FALSE, TRUE);
  /* 1. no GP_SYMBOL found, disable gp relaxation  */
  if (!h)
    {
      struct riscv_elf_link_hash_table *table;
      table = riscv_elf_hash_table (info);
      table->gp_relative_insn = 0;
    }
  /* 2. GP_SYMBOL referenced but not defined, generate one  */
  else if (h->type == bfd_link_hash_undefined)
    {
      /* find a suitable section to insert symbol.  */
      const char *sections[] = {".sdata", ".sbss", ".data", ".bss", NULL};
      int index = 0;
      while (sections[index])
	{
	  section = bfd_get_section_by_name (output_bfd, sections[index]);
	  if (section)
	    break;
	  index++;
	}
      /* if none, just insert it at COMMON (.bss) section blindly.  */
      if (!section)
	{
	  section = bfd_abs_section_ptr;
	  gp_value = 0;
	}

      if (!_bfd_generic_link_add_one_symbol
	  (info, output_bfd, RISCV_GP_SYMBOL, BSF_GLOBAL, section,
	   gp_value, (const char *) NULL, FALSE,
	   get_elf_backend_data (output_bfd)->collect, &h))
	return FALSE;
    }
  return TRUE;
}

/* End of helper functions.  */

#if ARCH_SIZE == 32
# define PRSTATUS_SIZE			0 /* FIXME */
# define PRSTATUS_OFFSET_PR_CURSIG	12
# define PRSTATUS_OFFSET_PR_PID		24
# define PRSTATUS_OFFSET_PR_REG		72
# define ELF_GREGSET_T_SIZE		128
# define PRPSINFO_SIZE			128
# define PRPSINFO_OFFSET_PR_PID		16
# define PRPSINFO_OFFSET_PR_FNAME	32
# define PRPSINFO_OFFSET_PR_PSARGS	48
#else
# define PRSTATUS_SIZE			376
# define PRSTATUS_OFFSET_PR_CURSIG	12
# define PRSTATUS_OFFSET_PR_PID		32
# define PRSTATUS_OFFSET_PR_REG		112
# define ELF_GREGSET_T_SIZE		256
# define PRPSINFO_SIZE			136
# define PRPSINFO_OFFSET_PR_PID		24
# define PRPSINFO_OFFSET_PR_FNAME	40
# define PRPSINFO_OFFSET_PR_PSARGS	56
#endif

/* Support for core dump NOTE sections.  */

static bfd_boolean
riscv_elf_grok_prstatus (bfd *abfd, Elf_Internal_Note *note)
{
  switch (note->descsz)
    {
      default:
	return FALSE;

      case PRSTATUS_SIZE:  /* sizeof(struct elf_prstatus) on Linux/RISC-V.  */
	/* pr_cursig */
	elf_tdata (abfd)->core->signal
	  = bfd_get_16 (abfd, note->descdata + PRSTATUS_OFFSET_PR_CURSIG);

	/* pr_pid */
	elf_tdata (abfd)->core->lwpid
	  = bfd_get_32 (abfd, note->descdata + PRSTATUS_OFFSET_PR_PID);
	break;
    }

  /* Make a ".reg/999" section.  */
  return _bfd_elfcore_make_pseudosection (abfd, ".reg", ELF_GREGSET_T_SIZE,
					  note->descpos + PRSTATUS_OFFSET_PR_REG);
}

static bfd_boolean
riscv_elf_grok_psinfo (bfd *abfd, Elf_Internal_Note *note)
{
  switch (note->descsz)
    {
      default:
	return FALSE;

      case PRPSINFO_SIZE: /* sizeof(struct elf_prpsinfo) on Linux/RISC-V.  */
	/* pr_pid */
	elf_tdata (abfd)->core->pid
	  = bfd_get_32 (abfd, note->descdata + PRPSINFO_OFFSET_PR_PID);

	/* pr_fname */
	elf_tdata (abfd)->core->program = _bfd_elfcore_strndup
	  (abfd, note->descdata + PRPSINFO_OFFSET_PR_FNAME, 16);

	/* pr_psargs */
	elf_tdata (abfd)->core->command = _bfd_elfcore_strndup
	  (abfd, note->descdata + PRPSINFO_OFFSET_PR_PSARGS, 80);
	break;
    }

  /* Note that for some reason, a spurious space is tacked
     onto the end of the args in some (at least one anyway)
     implementations, so strip it off if it exists.  */

  {
    char *command = elf_tdata (abfd)->core->command;
    int n = strlen (command);

    if (0 < n && command[n - 1] == ' ')
      command[n - 1] = '\0';
  }

  return TRUE;
}

/* Set the right mach type.  */
static bfd_boolean
riscv_elf_object_p (bfd *abfd)
{
  static int ict_init = 0;

  /* Build the ict hash table to store all global symbols attached
     with ICT suffix.  */
  if (!ict_init)
    {
      riscv_elf_ict_init ();
      ict_init = 1;
    }

  /* There are only two mach types in RISCV currently.  */
  if (strcmp (abfd->xvec->name, "elf32-littleriscv") == 0)
    bfd_default_set_arch_mach (abfd, bfd_arch_riscv, bfd_mach_riscv32);
  else
    bfd_default_set_arch_mach (abfd, bfd_arch_riscv, bfd_mach_riscv64);

  return TRUE;
}

/* Store the machine number in the flags field.  */

static void
riscv_elf_final_write_processing (bfd *abfd ATTRIBUTE_UNUSED,
				  bfd_boolean linker ATTRIBUTE_UNUSED)
{
  struct riscv_elf_ict_table_entry *head;

  /* Export the ICT table if needed.  */
  /* TODO: should we support new linker option to let user
     can define their own ict table name.  */
  if (exported_ict_table_head)
    {
      ict_table_file = fopen ("nds_ict.s", FOPEN_WT);
      if(ict_table_file == NULL)
	{
	  (*_bfd_error_handler) (_("Error: Fail to genertare nds_ict.s."));
	  return;
	}

      fprintf (ict_table_file, "\t.section " RISCV_ICT_SECTION ", \"ax\"\n");
      /* The exported ict table can not be linked with the patch code
	 that use the different ict model.  */
      if (ict_model == 0)
	fprintf (ict_table_file, "\t.attribute\tTag_ict_model, \"tiny\"\n");
      else if (ict_model == 1)
	fprintf (ict_table_file, "\t.attribute\tTag_ict_model, \"small\"\n");
      else
	fprintf (ict_table_file, "\t.attribute\tTag_ict_model, \"large\"\n");
      fprintf (ict_table_file, ".global _INDIRECT_CALL_TABLE_BASE_\n"
	       "_INDIRECT_CALL_TABLE_BASE_:\n");

      /* Output each entry of ict table according to different
	 ict models.  */
      head = exported_ict_table_head;
      while (head)
	{
	  if (ict_model == 2)
	    fprintf (ict_table_file, "\t.dword\t%s\n",
		     head->h->root.root.string);
	  else if (ict_model == 1)
	    fprintf (ict_table_file, "\ttail\t%s\n",
		     head->h->root.root.string);
	  else
	    fprintf (ict_table_file, "\tjal\tt1, %s\n",
		     head->h->root.root.string);
	  head = head->next;
	}

      /* Finish exporting the ict table, close it
	 and free the unused data.  */
      while (exported_ict_table_head)
	{
	  head = exported_ict_table_head;
	  exported_ict_table_head = exported_ict_table_head->next;
	  free (head);
	}
      fclose (ict_table_file);
    }
}

/* Determine whether an object attribute tag takes an integer, a
   string or both.  */

static int
riscv_elf_obj_attrs_arg_type (int tag)
{
  if (!nds_backward_compatible)
    {
      return (tag & 1) != 0 ? ATTR_TYPE_FLAG_STR_VAL : ATTR_TYPE_FLAG_INT_VAL;
    }
  else
    {
      if (tag >= 'A' && tag < 'X')
	return ATTR_TYPE_FLAG_INT_VAL
	     | ATTR_TYPE_FLAG_STR_VAL;

      switch (tag)
	{
	case Tag_priv_spec:
	case Tag_priv_spec_minor:
	case Tag_priv_spec_revision:
	case Tag_strict_align:
	case Tag_stack_align:
	case Tag_ict_version:
	  return ATTR_TYPE_FLAG_INT_VAL | ATTR_TYPE_FLAG_NO_DEFAULT;
	case Tag_arch:
	case Tag_ict_model:
	  return ATTR_TYPE_FLAG_STR_VAL;
	default:
	  return (tag & 1) != 0 ? ATTR_TYPE_FLAG_STR_VAL : ATTR_TYPE_FLAG_INT_VAL;
	}
    }
}

/* Add a PT_RISCV_ATTRIBUTES program header.  */

static bfd_boolean
riscv_elf_modify_segment_map (bfd *abfd,
			      struct bfd_link_info *info ATTRIBUTE_UNUSED)
{
  struct elf_segment_map *m, *m_prev;
  asection *sec;

  sec = bfd_get_section_by_name (abfd, ".riscv.attributes");
  if (sec != NULL)
    {
      /* If there is already a PT_RISCV_ATTRIBUTES header,
	 then we do not want to add another one.  */
      m = elf_seg_map (abfd);
      m_prev = m;
      while (m && m->p_type != PT_RISCV_ATTRIBUTES)
	{
	  m_prev = m;
	  m = m->next;
	}

      if (!m)
	{
	  m = (struct elf_segment_map *)
	    bfd_zalloc (abfd, sizeof (struct elf_segment_map));
	  if (m == NULL)
	    return FALSE;
	  m->p_type = PT_RISCV_ATTRIBUTES;
	  m->count = 1;
	  m->sections[0] = sec;
	  /* Add it to the last.  */
	  if (m_prev)
	    m_prev->next = m;
	}
    }

  return TRUE;
}

static int
riscv_elf_additional_program_headers (bfd *abfd,
				      struct bfd_link_info *info ATTRIBUTE_UNUSED)
{
  asection *sec;

  sec = bfd_get_section_by_name (abfd, ".riscv.attributes");
  if (sec != NULL)
    return 1;
  else
    return 0;
}

#define TARGET_LITTLE_SYM		riscv_elfNN_vec
#define TARGET_LITTLE_NAME		"elfNN-littleriscv"

#define elf_backend_reloc_type_class	     riscv_reloc_type_class

#define bfd_elfNN_bfd_reloc_name_lookup	     riscv_reloc_name_lookup
#define bfd_elfNN_bfd_link_hash_table_create riscv_elf_link_hash_table_create
#define bfd_elfNN_bfd_reloc_type_lookup	     riscv_reloc_type_lookup
#define bfd_elfNN_bfd_merge_private_bfd_data \
  _bfd_riscv_elf_merge_private_bfd_data

#define elf_backend_copy_indirect_symbol     riscv_elf_copy_indirect_symbol
#define elf_backend_create_dynamic_sections  riscv_elf_create_dynamic_sections
#define elf_backend_check_relocs	     riscv_elf_check_relocs
#define elf_backend_adjust_dynamic_symbol    riscv_elf_adjust_dynamic_symbol
#define elf_backend_size_dynamic_sections    riscv_elf_size_dynamic_sections
#define elf_backend_relocate_section	     riscv_elf_relocate_section
#define elf_backend_finish_dynamic_symbol    riscv_elf_finish_dynamic_symbol
#define elf_backend_finish_dynamic_sections  riscv_elf_finish_dynamic_sections
#define elf_backend_gc_mark_hook	     riscv_elf_gc_mark_hook
#define elf_backend_plt_sym_val		     riscv_elf_plt_sym_val
#define elf_backend_grok_prstatus	     riscv_elf_grok_prstatus
#define elf_backend_grok_psinfo		     riscv_elf_grok_psinfo
#define elf_backend_object_p		     riscv_elf_object_p
#define elf_info_to_howto_rel		     NULL
#define elf_info_to_howto		     riscv_info_to_howto_rela
#define bfd_elfNN_bfd_relax_section	     _bfd_riscv_relax_section
#define elf_backend_link_output_symbol_hook  riscv_elf_output_symbol_hook
#define elf_backend_output_arch_syms	     riscv_elf_output_arch_syms
#define elf_backend_final_write_processing   riscv_elf_final_write_processing

#define elf_backend_init_index_section	     _bfd_elf_init_1_index_section

#define elf_backend_can_gc_sections	1
#define elf_backend_can_refcount	1
#define elf_backend_want_got_plt	1
#define elf_backend_plt_readonly	1
#define elf_backend_plt_alignment	4
#define elf_backend_want_plt_sym	1
#define elf_backend_got_header_size	(ARCH_SIZE / 8)
#define elf_backend_want_dynrelro	1
#define elf_backend_rela_normal		1
#define elf_backend_default_execstack	0

#undef  elf_backend_obj_attrs_vendor
#define elf_backend_obj_attrs_vendor            "riscv"
#undef  elf_backend_obj_attrs_arg_type
#define elf_backend_obj_attrs_arg_type          riscv_elf_obj_attrs_arg_type
#undef  elf_backend_obj_attrs_section_type
#define elf_backend_obj_attrs_section_type      SHT_RISCV_ATTRIBUTES
#undef  elf_backend_obj_attrs_section
#define elf_backend_obj_attrs_section           ".riscv.attributes"
#define elf_backend_additional_program_headers \
  riscv_elf_additional_program_headers
#define elf_backend_modify_segment_map		riscv_elf_modify_segment_map

#include "elfNN-target.h"
