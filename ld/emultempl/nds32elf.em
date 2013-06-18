# This shell script emits a C file. -*- C -*-
# Copyright (C) 2012-2013 Free Software Foundation, Inc.
# Contributed by Andes Technology Corporation.
#
# This file is part of the GNU Binutils.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
# MA 02110-1301, USA.
#

fragment <<EOF

#include "libbfd.h"
#include "elf-bfd.h"
#include "elf/nds32.h"
#include "elf32-nds32.h"

static int relax_fp_as_gp = 1;		/* --mrelax-omit-fp  */
static int eliminate_gc_relocs = 0;	/* --meliminate-gc-relocs  */
static FILE *sym_ld_script = NULL;	/* --mgen-symbol-ld-script=<file>  */
static int hyper_relax = 1;	/* --mhyper-relax  */
/* Disable if linking a dynamically linked executable.  */
static int load_store_relax = 1;
static int target_optimize = 0;	/* Switch optimization.  */
static int relax_status = 0;	/* Finished optimization.  */
static int relax_round = 0;		/* Going optimization.  */
static char *ex9_export_file = NULL;	/* --mexport-ex9=<file>  */
static FILE *ex9_import_file = NULL;	/* --mimport-ex9=<file>  */
static int update_ex9_table = 0;	/* --mupdate-ex9.  */
static int keep_import_ex9 = 0;		/* --mkeep-import-ex9.  */
static int ex9_limit = -1;		/* Default set it to 512 entries.  */
static bfd_boolean ex9_loop_aware = FALSE;	/* Ignore ex9 if inside a loop.  */
static bfd_boolean ifc_loop_aware = FALSE;	/* Ignore ifc if inside a loop.  */
static int tls_desc_trampoline = 0;	/* --m[no]tlsdesc-trampoline.  */
static bfd_boolean ex9_ji_limit = FALSE;
static bfd_boolean ex9_noji = FALSE;
static bfd_boolean ex9_nols = FALSE;
static char *set_output_abi = NULL;	/* --mabi.  */
static char *isps_file_name = NULL;	/* --misps=<file>  */

/* Save the target options into output bfd to avoid using to many global
   variables. Do this after the output has been created, but before
   inputs are read.  */
static void
nds32_elf_create_output_section_statements (void)
{
  if (strstr (bfd_get_target (link_info.output_bfd), "nds32") == NULL)
    {
      /* Check the output target is nds32.  */
      einfo ("%F%X%P: error: Cannot change output format whilst linking NDS32 binaries.\n");
      return;
    }

  bfd_elf32_nds32_set_target_option (&link_info, relax_fp_as_gp,
				     eliminate_gc_relocs,
				     sym_ld_script,
				     load_store_relax,
				     target_optimize, relax_status, relax_round,
				     ex9_export_file, ex9_import_file,
				     update_ex9_table, ex9_limit,
				     ex9_loop_aware, ifc_loop_aware,
				     hyper_relax,
				     tls_desc_trampoline,
				     ex9_ji_limit,
				     ex9_noji,
				     ex9_nols,
				     set_output_abi,
				     isps_file_name,
				     keep_import_ex9);
}

static void
nds32_elf_after_parse (void)
{
#ifdef NDS32_LINUX_TOOLCHAIN
  if (RELAXATION_ENABLED)
    {
      einfo ("%P: warning: The relaxation isn't supported yet.\n");
      DISABLE_RELAXATION;
    }
#endif

  if (link_info.relocatable)
    DISABLE_RELAXATION;

  if (!RELAXATION_ENABLED)
    {
      target_optimize &= ~(NDS32_RELAX_IFC_ON | NDS32_RELAX_EX9_ON);
      relax_fp_as_gp = 0;
    }

  /* TODO: Enhance the warning/error message here for
     ex9 export/import/update.  */
  if (!ex9_import_file)
    {
      /* ex9 update must be set with ex9 import.  */
      update_ex9_table = 0;
    }

  if (link_info.shared)
    {
      target_optimize &= ~(NDS32_RELAX_IFC_ON | NDS32_RELAX_EX9_ON);
    }

  after_parse_default ();

  /* Backward compatible for linker script output_format.  */
  if (output_target && strcmp (output_target, "elf32-nds32") == 0)
    output_target = default_target;
}

static void
nds32_elf_after_open (void)
{
  unsigned int arch_ver = (unsigned int)-1;
  unsigned int abi_ver = (unsigned int)-1;
  bfd *abfd;

  /* For now, make sure all object files are of the same architecture.
     We may try to merge object files with different architecture together.  */
  for (abfd = link_info.input_bfds; abfd != NULL; abfd = abfd->link_next)
    {
      if (arch_ver == (unsigned int)-1
	  && E_N1_ARCH != (elf_elfheader (abfd)->e_flags & EF_NDS_ARCH))
	arch_ver = elf_elfheader (abfd)->e_flags & EF_NDS_ARCH ;

      if (set_output_abi != NULL)
	{
	  /* do not check ABI.  */
	}
      else if (abi_ver == (unsigned int)-1)
	{
	  /* Initialize ABI version, if not ABI0.
	     (OS uses empty file to create empty ELF with ABI0).  */
	  if ((elf_elfheader (abfd)->e_flags & EF_NDS_ABI) != 0)
	    abi_ver = elf_elfheader (abfd)->e_flags & EF_NDS_ABI ;
	}
      else if ((elf_elfheader (abfd)->e_flags & EF_NDS_ABI) != 0
	       && abi_ver != (elf_elfheader (abfd)->e_flags & EF_NDS_ABI))
	{
	  asection *section = NULL;
	  bfd_byte *contents = NULL;
	  section = bfd_get_section_by_name (abfd, ".note.v2abi_compatible");
	  if (section)
	    bfd_get_full_section_contents (abfd, section, &contents);

	  /* Incompatible objects.  */
	  if ((contents == NULL)
	      || bfd_getb32 (contents) != 1
	      || abi_ver != E_NDS_ABI_V2FP_PLUS)
	    einfo (_("%F%B: ABI version of object files mismatched\n"), abfd);
	}

      /* Append target needed section in the last input object file.  */
      if (abfd->link_next == NULL)
	bfd_elf32_nds32_append_section (&link_info, abfd, target_optimize);
    }

  /* Check object files if the target is dynamic linked executable
     or shared object.  */
  if (elf_hash_table (&link_info)->dynamic_sections_created
      || link_info.shared || link_info.pie)
    {
      /* Dynamic linked executable with SDA and non-PIC.
	 Turn off load/store relaxtion.  */
      /* TODO: This may support in the future.  */
      load_store_relax = 0 ;
      relax_fp_as_gp = 0;
    }

  /* Call the standard elf routine.  */
  gld${EMULATION_NAME}_after_open ();
}

static void
nds32_elf_after_allocation (void)
{
  struct bfd_link_hash_entry *h;

  /* Call default after allocation callback.
     1. This is where relaxation is done.
     2. It calls gld${EMULATION_NAME}_map_segments to build ELF segment table.
     3. Any relaxation requires relax being done must be called after it.  */
  gld${EMULATION_NAME}_after_allocation ();

  /* Add a symbol for linker script check the max size.  */
  if (link_info.output_bfd->sections)
    {
      h = bfd_link_hash_lookup (link_info.hash, "_RELAX_END_",
				FALSE, FALSE, FALSE);
      if (!h)
	_bfd_generic_link_add_one_symbol
	  (&link_info, link_info.output_bfd, "_RELAX_END_",
	   BSF_GLOBAL | BSF_WEAK, link_info.output_bfd->sections,
	   0, (const char *) NULL, FALSE,
	   get_elf_backend_data (link_info.output_bfd)->collect, &h);
    }
}

EOF
# Define some shell vars to insert bits of code into the standard elf
# parse_args and list_options functions.
#
PARSE_AND_LIST_PROLOGUE='
#define OPTION_BASELINE			301
#define OPTION_ELIM_GC_RELOCS		(OPTION_BASELINE + 1)
#define OPTION_FP_AS_GP			(OPTION_BASELINE + 2)
#define OPTION_NO_FP_AS_GP		(OPTION_BASELINE + 3)
#define OPTION_REDUCE_FP_UPDATE		(OPTION_BASELINE + 4)
#define OPTION_NO_REDUCE_FP_UPDATE	(OPTION_BASELINE + 5)
#define OPTION_EXPORT_SYMBOLS		(OPTION_BASELINE + 6)
#define OPTION_HYPER_RELAX		(OPTION_BASELINE + 7)
#define OPTION_TLSDESC_TRAMPOLINE	(OPTION_BASELINE + 8)
#define OPTION_NO_TLSDESC_TRAMPOLINE	(OPTION_BASELINE + 9)
#define OPTION_SET_ABI			(OPTION_BASELINE + 10)
#define OPTION_ISPS			(OPTION_BASELINE + 11)

/* These are only available to ex9.  */
#if defined NDS32_EX9_EXT
#define OPTION_EX9_BASELINE		320
#define OPTION_EX9_TABLE		(OPTION_EX9_BASELINE + 1)
#define OPTION_NO_EX9_TABLE		(OPTION_EX9_BASELINE + 2)
#define OPTION_EXPORT_EX9		(OPTION_EX9_BASELINE + 3)
#define OPTION_IMPORT_EX9		(OPTION_EX9_BASELINE + 4)
#define OPTION_UPDATE_EX9		(OPTION_EX9_BASELINE + 5)
#define OPTION_EX9_LIMIT		(OPTION_EX9_BASELINE + 6)
#define OPTION_EX9_LOOP			(OPTION_EX9_BASELINE + 7)
#define OPTION_EX9_JI_LIMIT		(OPTION_EX9_BASELINE + 8)
#define OPTION_KEEP_IMPORT_EX9		(OPTION_EX9_BASELINE + 9)
#define OPTION_EX9_NO_JI		(OPTION_EX9_BASELINE + 10)
#define OPTION_EX9_NO_LS		(OPTION_EX9_BASELINE + 11)
#define OPTION_EX9_NO_REL		(OPTION_EX9_BASELINE + 12)
#endif

/* These are only available to link-time ifc.  */
#if defined NDS32_IFC_EXT
#define OPTION_IFC_BASELINE		340
#define OPTION_IFC			(OPTION_IFC_BASELINE + 1)
#define OPTION_NO_IFC			(OPTION_IFC_BASELINE + 2)
#define OPTION_IFC_LOOP			(OPTION_IFC_BASELINE + 3)
#endif
'
PARSE_AND_LIST_LONGOPTS='
  { "mfp-as-gp", no_argument, NULL, OPTION_FP_AS_GP},
  { "mno-fp-as-gp", no_argument, NULL, OPTION_NO_FP_AS_GP},
  { "mexport-symbols", required_argument, NULL, OPTION_EXPORT_SYMBOLS},
  { "mhyper-relax", required_argument, NULL, OPTION_HYPER_RELAX},
  { "mtlsdesc-trampoline", no_argument, NULL, OPTION_TLSDESC_TRAMPOLINE},
  { "mno-tlsdesc-trampoline", no_argument, NULL, OPTION_NO_TLSDESC_TRAMPOLINE},
  { "mabi", required_argument, NULL, OPTION_SET_ABI},
  { "misps", required_argument, NULL, OPTION_ISPS},
  /* These are deprecated options.  Remove them in the future.  */
  { "mrelax-reduce-fp-update", no_argument, NULL, OPTION_REDUCE_FP_UPDATE},
  { "mrelax-no-reduce-fp-update", no_argument, NULL, OPTION_NO_REDUCE_FP_UPDATE},
  { "mbaseline", required_argument, NULL, OPTION_BASELINE},
  { "meliminate-gc-relocs", no_argument, NULL, OPTION_ELIM_GC_RELOCS},
  { "mrelax-omit-fp", no_argument, NULL, OPTION_FP_AS_GP},
  { "mrelax-no-omit-fp", no_argument, NULL, OPTION_NO_FP_AS_GP},
  { "mgen-symbol-ld-script", required_argument, NULL, OPTION_EXPORT_SYMBOLS},
  /* These are specific optioins for ex9-ext support.  */
#if defined NDS32_EX9_EXT
  { "mex9", no_argument, NULL, OPTION_EX9_TABLE},
  { "mno-ex9", no_argument, NULL, OPTION_NO_EX9_TABLE},
  { "mexport-ex9", required_argument, NULL, OPTION_EXPORT_EX9},
  { "mimport-ex9", required_argument, NULL, OPTION_IMPORT_EX9},
  { "mupdate-ex9", no_argument, NULL, OPTION_UPDATE_EX9},
  { "mkeep-import-ex9", no_argument, NULL, OPTION_KEEP_IMPORT_EX9},
  { "mex9-limit", required_argument, NULL, OPTION_EX9_LIMIT},
  { "mex9-loop-aware", no_argument, NULL, OPTION_EX9_LOOP},
  { "mex9-ji-limit", no_argument, NULL, OPTION_EX9_JI_LIMIT},
  { "mex9-noji", no_argument, NULL, OPTION_EX9_NO_JI},
  { "mex9-nols", no_argument, NULL, OPTION_EX9_NO_LS},
  { "mex9-norel", no_argument, NULL, OPTION_EX9_NO_REL},
#endif
  /* These are specific optioins for ifc-ext support.  */
#if defined NDS32_IFC_EXT
  { "mifc", no_argument, NULL, OPTION_IFC},
  { "mno-ifc", no_argument, NULL, OPTION_NO_IFC},
  { "mifc-loop-aware", no_argument, NULL, OPTION_IFC_LOOP},
#endif
'
PARSE_AND_LIST_OPTIONS='
  fprintf (file, _("\
  --m[no-]fp-as-gp            Disable/enable fp-as-gp relaxation\n\
  --mexport-symbols=FILE      Exporting symbols in linker script\n\
  --mhyper-relax=level        Adjust relax level (low|medium|high). default: medium\n\
  --m[no-]tlsdesc-trampoline  Disable/enable TLS DESC trampoline\n\
  --misps=FILE                Enbale ISPS\n\
"));

#if defined NDS32_EX9_EXT
  fprintf (file, _("\
  --m[no-]ex9                 Disable/enable link-time EX9 relaxation\n\
  --mexport-ex9=FILE          Export EX9 table after linking\n\
  --mimport-ex9=FILE          Import Ex9 table for EX9 relaxation\n\
  --mupdate-ex9               Update existing EX9 table\n\
  --mex9-limit=NUM            Maximum number of entries in ex9 table for this times\n\
  --mex9-loop-aware           Avoid generate EX9 instruction inside loop\n\
"));
#endif

#if defined NDS32_IFC_EXT
  fprintf (file, _("\
  --m[no-]ifc                 Disable/enable link-time IFC optimization\n\
  --mifc-loop-aware           Avoid generate IFC instruction inside loop\n\
"));
#endif
'
PARSE_AND_LIST_ARGS_CASES='
  case OPTION_BASELINE:
    einfo ("%P: --mbaseline is not used anymore.\n");
    break;
  case OPTION_ELIM_GC_RELOCS:
    eliminate_gc_relocs = 1;
    break;
  case OPTION_FP_AS_GP:
  case OPTION_NO_FP_AS_GP:
    relax_fp_as_gp = (optc == OPTION_FP_AS_GP);
    break;
  case OPTION_REDUCE_FP_UPDATE:
  case OPTION_NO_REDUCE_FP_UPDATE:
    einfo ("%P: --relax-[no-]reduce-fp-updat is not used anymore.\n");
    break;
  case OPTION_EXPORT_SYMBOLS:
    if (!optarg)
      einfo (_("Missing file for --mexport-symbols.\n"), optarg);

    if(strcmp (optarg, "-") == 0)
      sym_ld_script = stdout;
    else
      {
	sym_ld_script = fopen (optarg, FOPEN_WT);
	if(sym_ld_script == NULL)
	  einfo (_("%P%F: cannot open map file %s: %E.\n"), optarg);
      }
    break;
  case OPTION_HYPER_RELAX:
    if (!optarg)
      einfo (_("Valid arguments to --mhyper-relax=(low|medium|high).\n"));

    if (strcmp (optarg, "low") == 0)
      hyper_relax = 0;
    else if (strcmp (optarg, "medium") == 0)
      hyper_relax = 1;
    else if (strcmp (optarg, "high") == 0)
      hyper_relax = 2;
    else
      einfo (_("Valid arguments to --mhyper-relax=(low|medium|high).\n"));

      break;
  case OPTION_TLSDESC_TRAMPOLINE:
    tls_desc_trampoline = 1;
    break;
  case OPTION_NO_TLSDESC_TRAMPOLINE:
    tls_desc_trampoline = 0;
    break;
  case OPTION_SET_ABI:
    if (strcmp (optarg, "AABI") != 0
	&& strcmp (optarg, "V2FP+") != 0)
      einfo (_("Valid arguments to --mabi=(AABI|V2FP+).\n"));
    else
      set_output_abi = optarg;
    break;
  case OPTION_ISPS:
    if (!optarg || strlen (optarg) == 0)
      einfo (_("Missing file for --misps=<file>.\n"));
    isps_file_name = optarg;
    break;
#if defined NDS32_EX9_EXT
  case OPTION_EX9_TABLE:
    target_optimize |= NDS32_RELAX_EX9_ON;
    break;
  case OPTION_NO_EX9_TABLE:
    target_optimize &= ~NDS32_RELAX_EX9_ON;
    break;
  case OPTION_EXPORT_EX9:
    if (!optarg)
      einfo (_("Missing file for --mexport-ex9=<file>.\n"));

    ex9_export_file = optarg;
    /* Open file in the nds32_elf_relocate_ex9_table.  */
    break;
  case OPTION_IMPORT_EX9:
    if (!optarg)
      einfo (_("Missing file for --mimport-ex9=<file>.\n"));

    ex9_import_file = fopen (optarg, "rb+");
    if(ex9_import_file == NULL)
      einfo (_("ERROR %P%F: cannot open ex9 import file %s.\n"), optarg);
    break;
  case OPTION_UPDATE_EX9:
    update_ex9_table = 1;
    break;
  case OPTION_KEEP_IMPORT_EX9:
    keep_import_ex9 = 1;
    break;
  case OPTION_EX9_LIMIT:
    if (optarg)
      {
	ex9_limit = atoi (optarg);
	if (ex9_limit > 512 || ex9_limit < 0)
	  {
	    einfo (_("ERROR: the range of ex9_limit must between 0 and 512\n"));
	    exit (1);
	  }
      }
    break;
  case OPTION_EX9_LOOP:
    target_optimize |= NDS32_RELAX_EX9_ON;
    ex9_loop_aware = 1;
    break;
  case OPTION_EX9_JI_LIMIT:
    ex9_ji_limit = 1;
    break;
  case OPTION_EX9_NO_JI:
    ex9_noji = 1;
    break;
  case OPTION_EX9_NO_LS:
    ex9_nols = 1;
    break;
  case OPTION_EX9_NO_REL:
    ex9_noji = 1;
    ex9_nols = 1;
    break;
#endif
#if defined NDS32_IFC_EXT
  case OPTION_IFC:
    target_optimize |= NDS32_RELAX_IFC_ON;
    break;
  case OPTION_NO_IFC:
    target_optimize &= ~NDS32_RELAX_IFC_ON;
    break;
  case OPTION_IFC_LOOP:
    target_optimize |= NDS32_RELAX_IFC_ON;
    ifc_loop_aware = 1;
    break;
#endif
'
LDEMUL_AFTER_OPEN=nds32_elf_after_open
LDEMUL_AFTER_PARSE=nds32_elf_after_parse
LDEMUL_AFTER_ALLOCATION=nds32_elf_after_allocation
LDEMUL_CREATE_OUTPUT_SECTION_STATEMENTS=nds32_elf_create_output_section_statements
