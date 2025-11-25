/* Commands for communication with ANDES remote target.

   Copyright (C) 2006-2013 Free Software Foundation, Inc.
   Contributed by Andes Technology Corporation.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include "defs.h"
#include <string.h>
#include <sys/stat.h>

#ifndef __MINGW32__
#include <sys/utsname.h>
#endif
#include <unistd.h>
#include "gdbcore.h"
#include "gdbcmd.h"
#include "gdbtypes.h"
#include "cli/cli-decode.h"
#include "remote.h"
#include "regcache.h"
#include "user-regs.h"
#include "inferior.h"		/* get_inferior_args () */
#include "top.h"		/* set_prompt () */
#include "ui-out.h"		/* current_uiout */
#include "exceptions.h"
#include <ctype.h>

#include "elf-bfd.h"		/* elf_elfheader () */
#include "objfiles.h"
//#ifndef __MINGW32__
#include "nds-elf.h"
//#endif
#include "dis-asm.h"
#include "opcode/riscv.h"

void nds_init_remote_cmds (void);
static int nds_elf_check_by_tbl(void);
static void nds_elf_check_by_default(void);
static void nds_set_cpu_extension(void);
static void nds_show_cpu_extension(void);
static int nds_parse_riscv_isa_string(const char *p_str);

//#define DEBUG_MSG  printf_unfiltered
#define DEBUG_MSG(fmt, ...)

enum nds_remote_type
{
  nds_rt_unknown = 0,
  nds_rt_sid,
  nds_rt_ocd,
};

static struct
{
  enum nds_remote_type type;
  char cpuid[16];
  enum bfd_endian endian;
} nds_remote_info;

/* Callback for "nds query" command.  */

static void
nds_query_command (const char *args, int from_tty)
{
  error (_("Usage: nds query (profiling|perf-meter) [cpu] [human|ide]"));
}

/* Callback for "nds reset" command.  */

static void
nds_reset_command (const char *args, int from_tty)
{
  error (_("Usage: nds reset (profiling|perf-meter) [cpu]"));
}

/* Callback for "nds pipeline" command.  */

static void
nds_pipeline_command (const char *args, int from_tty)
{
  error (_("Usage: nds pipeline (on|off) [cpu]"));
}

static int
nds_issue_qrcmd (const char *cmd, string_file &str)
{
  std::string whitespaces (" \t\f\v\n\r");

  /* make_cleanup outside TRY_CACHE,
     because it save and reset cleanup-chain.  */
  scoped_restore save_stdtarg = make_scoped_restore (&gdb_stdtarg, &str);
  /* Supress error messages from gdbserver
     if gdbserver doesn't support the monitor command.  */

  str.clear ();
  try
    {
      target_rcmd (cmd, &str);
    }
  catch (const gdb_exception &exception)
    {
      if (exception.reason == RETURN_ERROR)
        {
          return -1;
        }
    }

  /* Trim trailing newline characters.  */
	std::string tmp_str = str.release ();
	std::size_t found = tmp_str.find_last_not_of (whitespaces);
	if (found != std::string::npos)
		tmp_str.erase (found + 1);
	else
		// all whitespace
		tmp_str.clear ();
	str = std::move(tmp_str);
  return 0;
}

/* Pretty-print for profiling data.  */

static void
nds_print_human_table (int col, int row, const char *scsv)
{
  int i;
  char *buf = NULL;
  char symbol_text[256];
  /* struct cleanup *cleanup = NULL; mark do_cleanups */

  buf = xstrdup (scsv);
  /* cleanup = make_cleanup (xfree, buf); mark do_cleanups */

  /* Allocate header structures.  */
  gdb::unique_xmalloc_ptr<char *[]> col_fldname
    ((char **) xmalloc (sizeof (char *) * col));
  gdb::unique_xmalloc_ptr<char *[]> col_hdrtext
    ((char **) xmalloc (sizeof (char *) * col));
  gdb::unique_xmalloc_ptr<int[]> col_width
    ((int *) xmalloc (sizeof (int) * col));
  gdb::unique_xmalloc_ptr<enum ui_align[]> col_align
    ((enum ui_align *) xmalloc (sizeof (enum ui_align) * col));

  /* Parsing column header.  */
  i = 0;
  while (*buf != '\0' && i < col)
    {
      char *sc = strchr (buf, ';');

      *sc = '\0';
      col_fldname[i] = buf;
      col_hdrtext[i] = col_fldname[i];
      if (col_fldname[i][0] == '%')
	col_width[i] = 6;
      else
	col_width[i] = strlen (col_hdrtext[i]) + 1;

      col_align[i] = ui_right;

      i++;
      buf = sc + 1;
    }

  gdb_assert (col == i);

  /* Output table.  */
  ui_out_emit_table table_emitter (current_uiout, col, row - 1, "ProfilingTable");
  for (i = 0; i < col; i++)
    current_uiout->table_header (col_width[i], col_align[i],
				 col_fldname[i], col_hdrtext[i]);

  current_uiout->table_body ();

  /* Parse buf into col/row.  */
  while (*buf != '\0')
    {
      ui_out_emit_tuple tuple_emitter (current_uiout, "row");
      char *sc = NULL;

      symbol_text[0] = '\0';
      for (i = 0; i < col; i++, buf = sc + 1)
	{
	  sc = strchr (buf, ';');

	  if (sc == NULL)
	    /* Expected ';' is not found, finish display.  */
	    goto bye;

	  *sc = '\0';
	  current_uiout->field_string (col_fldname[i], buf);

	  if (i == 0)
	    {
	      /* Assume first column is address.  */
	      CORE_ADDR addr = strtol (buf, NULL, 16);
	      struct bound_minimal_symbol msymbol
		= lookup_minimal_symbol_by_pc (addr);

	      /* Get msymbol name to be output at end of row.  */
	      if (!msymbol.minsym)
		{
		  strcpy (symbol_text, "\n");
		}
	      else
		{
		  const char *name = msymbol.minsym->print_name ();
		  int offset = addr - msymbol.value_address ();

		  if (offset)
		    xsnprintf (symbol_text, sizeof (symbol_text),
			       "%s + 0x%x\n", name, offset);
		  else
		    xsnprintf (symbol_text, sizeof (symbol_text), "%s\n",
			       name);
		}
	    }
	}

      current_uiout->text (symbol_text);
    }

bye:
	;
  /* do_cleanups (cleanup); mark do_cleanups */
}

/* Callback for "nds query profiling" command.  */

static void
nds_query_profiling_command (const char *args, int from_tty)
{
  /* For profiling, there will be multiple responses.  */
  char cmd[256];
  int row, col;
  string_file res;
  int i;
  const char *arg_cpu = "cpu";
  int arg_human = 1;
  const char *p;

  scoped_restore save_stdtarg = make_scoped_restore (&gdb_stdtarg, &res);

  gdb_argv argv (args);

  /* operator!= is overloading, so it can be used to check if args is NULL.  */
  if (argv != NULL)
    {
      if (argv[0] != NULL && *argv[0] != '\0')
	arg_cpu = argv[0];

      if (argv[1] != NULL && strcmp (argv[1], "ide") == 0)
	arg_human = 0;
    }

  xsnprintf (cmd, sizeof (cmd), "set %s profiling ide-query", arg_cpu);
  if (nds_issue_qrcmd (cmd, res) == -1)
    return;

  if (arg_human == 0)
    {
      gdb_printf (gdb_stdtarg,
			  "=profiling,reason=\"fast_l1_profiling\",data=\"%s\"\n",
			  res.c_str() );
      return;
    }

  /* The first response is Row=%d;Column=%d;
     and then comes 'Row' rows, including head row */
  i = sscanf (res.c_str (), "Row=%d;Column=%d;", &row, &col);
  if (i != 2)
    error (_("Failed to query profiling data"));

  p = res.c_str ();

  /* Skip "Row=r;Column=c;".  */
  for (i = 0; i < 2 && p; i++)
    p = strchr (p + 1, ';');
  p++;

  /* Print human-mode table here.  */
  nds_print_human_table (col, row, p);
}

/* Callback for "nds query perfmeter" command.  */

static void
nds_query_perfmeter_command (const char *args, int from_tty)
{
  /* For perfmeter, there will be only one response.  */
  char cmd[256];

  xsnprintf (cmd, sizeof (cmd), "set %s perf-meter query",
	     args == NULL ? "cpu" : args);
  target_rcmd (cmd, gdb_stdtarg);
}

/* Callback for "nds reset profiling" command.  */

static void
nds_reset_profiling_command (const char *args, int from_tty)
{
  char cmd[256];

  xsnprintf (cmd, sizeof (cmd), "set %s profiling reset",
	     args == NULL ? "cpu" : args);
  target_rcmd (cmd, gdb_stdtarg);
}

/* Callback for "nds reset perfmeter" command.  */

static void
nds_reset_perfmeter_command (const char *args, int from_tty)
{
  char cmd[256];

  xsnprintf (cmd, sizeof (cmd), "set %s perf-meter reset",
	     args == NULL ? "cpu" : args);
  target_rcmd (cmd, gdb_stdtarg);
}

/* Callback for "nds pipeline on" command.  */

static void
nds_pipeline_on_command (const char *args, int from_tty)
{
  char cmd[256];

  xsnprintf (cmd, sizeof (cmd), "set %s pipeline-on 1",
	     args == NULL ? "cpu" : args);
  target_rcmd (cmd, gdb_stdtarg);
}

/* Callback for "nds pipeline off" command.  */

static void
nds_pipeline_off_command (const char *args, int from_tty)
{
  char cmd[256];

  xsnprintf (cmd, sizeof (cmd), "set %s pipeline-on 0",
	     args == NULL ? "cpu" : args);
  target_rcmd (cmd, gdb_stdtarg);
}

static void
nds_remote_info_init (void)
{
  nds_remote_info.type = nds_rt_unknown;
  nds_remote_info.endian = BFD_ENDIAN_UNKNOWN;
  nds_remote_info.cpuid[0] = '\0';
}

/* Query target information.  */

static struct value *
nds_target_type_make_value (struct gdbarch *gdbarch, struct internalvar *var,
			    void *ignore)
{
  int val = 0;

  if (strcmp (target_shortname (), "remote") == 0
      || strcmp (target_shortname (), "extended-remote") == 0)
    val = target_has_registers() ? nds_remote_info.type
			       : nds_rt_unknown;

  return value_from_longest (builtin_type (gdbarch)->builtin_int,
			     val);
}

static int
nds_query_target_using_qrcmd (void)
{
  string_file str;
  const char *buf;
  const char *sstr = NULL;

  if (nds_issue_qrcmd ("nds query target", str) == -1)
    return -1;

  buf = str.c_str ();
  if (strcmp (buf, "SID") == 0)
    nds_remote_info.type = nds_rt_sid;
  else if (strcmp (buf, "OCD") == 0)
    nds_remote_info.type = nds_rt_ocd;
  else
    {
      printf_unfiltered (_("Other remote target %s\n"), buf);
      return -1;
    }

  if (nds_issue_qrcmd ("nds query endian", str) == -1)
    return -1;

  buf = str.c_str ();
  /* to match target_name: LE or target_name: BE.  */
  sstr = strstr (buf, ":");
  if (sstr == NULL)
    nds_remote_info.endian = BFD_ENDIAN_LITTLE;
  else
    {
      sstr += 2;
      if (strcmp (sstr , "LE") == 0)
	nds_remote_info.endian = BFD_ENDIAN_LITTLE;
      else if (strcmp (sstr, "BE") == 0)
	nds_remote_info.endian = BFD_ENDIAN_BIG;
    }

  if (nds_issue_qrcmd ("nds query cpuid", str) == -1)
    return -1;

  buf = str.c_str ();
  strncpy (nds_remote_info.cpuid, buf, sizeof (nds_remote_info.cpuid) - 1);

  return 0;
}

static void
nds_query_target_command (const char *args, int from_tty)
{
  char buf[64];

  nds_remote_info_init ();

  if (strcmp (target_shortname (), "remote") != 0
      && strcmp (target_shortname (), "extended-remote") != 0)
    return;

  /* Try to find out the type of target - SID or OCD.  */
  nds_query_target_using_qrcmd ();

  /* Prepend anything target return to prompt.  */
  xsnprintf (buf, sizeof (buf), "%s(gdb) ", nds_remote_info.cpuid);
  set_prompt (buf);
}

//#ifndef __MINGW32__
/* Callback for elf-check.  */

static reg_t
nds_elf_check_get_register (unsigned int csr_no)
{
  ULONGEST regval;
  struct regcache *regcache = get_thread_regcache (inferior_thread ());
  struct gdbarch *gdbarch = regcache->arch ();
  enum bfd_endian byte_order;
  int regnum = -1;
  gdb_byte regbuf[8] = { 0 };

  if (nds_remote_info.endian == BFD_ENDIAN_UNKNOWN)
    byte_order = gdbarch_byte_order (gdbarch);
  else
    byte_order = nds_remote_info.endian;

  switch (csr_no)
    {
    case 0x301: /* misa */
      regnum = user_reg_map_name_to_regnum (gdbarch, "misa", -1);
      break;
    case 0xfc2: /* mmsc_cfg */
      regnum = user_reg_map_name_to_regnum (gdbarch, "mmsc_cfg", -1);
      break;
    case 0xfc3: /* mmsc_cfg2 */
      regnum = user_reg_map_name_to_regnum (gdbarch, "mmsc_cfg2", -1);
      break;
    case 0xfca: /* mrvarch_cfg */
      regnum = user_reg_map_name_to_regnum (gdbarch, "mrvarch_cfg", -1);
      break;
    case 0xfcb: /* mrvarch_cfg2 */
      regnum = user_reg_map_name_to_regnum (gdbarch, "mrvarch_cfg2", -1);
      break;
    default:
      break;
    }

  if (regnum == -1)
    error ("Fail to access system registers for elf-check.");

  /* Use target-endian instead of gdbarch-endian.  */
  if (regcache->cooked_read (regnum, regbuf) != REG_VALID)
    return -1;
  regval = extract_unsigned_integer (regbuf, 8, byte_order);

  return regval;
}
//#endif

static unsigned long long reg_misa = 0, reg_mmsc_cfg = 0, reg_mmsc_cfg2 = 0;
static unsigned long long reg_mrvarch_cfg = 0, reg_mrvarch_cfg2 = 0;
static unsigned int misa_mxl = 0;
static unsigned int elf_check_n_error = 0;
__attribute__ ((__unused__)) static int elf_check_new(void *file_data, unsigned int file_size, unsigned int if_load_table)
{
  elf_check_n_error = 0;
  buf_t file = {.data = (uint8_t *)file_data, .size = file_size};

  //NEC_buf_init(buf, len);
  if (file.size < EI_NIDENT) {
    printf_unfiltered("Not an ELF file.\n");
    return -1;
  }

  const unsigned char *e_ident = (const unsigned char *)file.data;
  if (memcmp(e_ident, ELFMAG, SELFMAG) != 0) {
    printf_unfiltered("Not an ELF file.\n");
    return -1;
  }

  const bool is64 = e_ident[EI_CLASS] == ELFCLASS64;
  buf_t sec;
  int ret = is64 ? elf64_get_riscv_attribute_section(file, &sec) : elf32_get_riscv_attribute_section(file, &sec);

  if (ret == 1)
    /* No RISCV attribute sections found, exit normally.  */
    return 0;
  else if (ret == -1)
    return -1;

  DEBUG_MSG("RISC-V attribute section at file offset 0x%lx with size 0x%lx\n", sec.data - file.data, sec.size);

  reg_misa = nds_elf_check_get_register(0x301);
  reg_mmsc_cfg = nds_elf_check_get_register(0xFC2);
  misa_mxl = (reg_misa >> 30) & 0x3;
  if (misa_mxl == 0) /* 64bit CPU */
    misa_mxl = (reg_misa >> 62) & 0x3;

  if (misa_mxl == 1) {
    /* RV32 */
    if (reg_mmsc_cfg & 0x80000000) {
      reg_mmsc_cfg2 = nds_elf_check_get_register(0xFC3);
      if (reg_mmsc_cfg2 & 0x100000)
        reg_mrvarch_cfg = nds_elf_check_get_register(0xFCA);
      if (reg_mmsc_cfg2 & 0x10000000)
        reg_mrvarch_cfg2 = nds_elf_check_get_register(0xFCB);
    }
  } else {
    /* RV64 */
    if ((reg_mmsc_cfg & (1UL << 52)) != 0) {
      reg_mrvarch_cfg = nds_elf_check_get_register(0xFCA);
    }
  }
  DEBUG_MSG("reg_misa = 0x%llx\n", reg_misa);
  DEBUG_MSG("reg_mmsc_cfg = 0x%llx\n", reg_mmsc_cfg);
  DEBUG_MSG("misa_mxl = 0x%x\n", misa_mxl);
  DEBUG_MSG("reg_mmsc_cfg2 = 0x%llx\n", reg_mmsc_cfg2);
  DEBUG_MSG("reg_mrvarch_cfg = 0x%llx\n", reg_mrvarch_cfg);

  ret = parse_elf_attribute_section(sec.data, sec.data + sec.size);
  if (pStr_Tag_RISCV_arch) {
  	//printf_unfiltered("pStr_Tag_RISCV_arch = %s\n", pStr_Tag_RISCV_arch);
  	if (if_load_table) {
  	  if (nds_elf_check_by_tbl() != 0)
  	  	nds_elf_check_by_default();
  	}
  	else
  	  nds_elf_check_by_default();
    nds_parse_riscv_isa_string(pStr_Tag_RISCV_arch);
    nds_set_cpu_extension();
    nds_show_cpu_extension();
  }
  else {
  	DEBUG_MSG("pStr_Tag_RISCV_arch = NULL !\n");
  	return -1;
  }
  if (elf_check_n_error)
    return -1;
	return 0;
}

/* Callback for "nds32 elf-check" command.  */
char check_msg[0x1000];
static void
nds_elf_check_command (const char *args, int from_tty)
{
//#ifndef __MINGW32__
  const char *filename = NULL;
  struct stat st;
  int fd;
  void *data = NULL;
  //char check_msg[0x1000];
  int err;

  if (current_program_space->exec_bfd () == NULL || current_program_space->exec_bfd ()->filename == NULL)
    error (_("Cannot check ELF without executable.\n"
	     "Use the \"file\" or \"exec-file\" command."));

  /* elf-check with SID/ICE only. */
  if (nds_remote_info.type == nds_rt_unknown)
    error (_("Cannot check ELF on Other remote target.\n"));

  filename = current_program_space->exec_bfd ()->filename;
  fd = open (filename, O_RDONLY, 0);

  if (fd < 0)
    error (_("Cannot open `%s': %s"), filename, strerror (errno));

  if (fstat (fd, &st) < 0)
    error (_("Cannot stat `%s': %s"), filename, strerror (errno));
/*
  data = mmap (0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

  if (data == MAP_FAILED)
    error (_("Cannot mmap `%s': %s"), filename, strerror (errno));
*/
	FILE *fp = fopen (filename, "rb");
	char *get_buf = (char *) malloc (st.st_size);
	unsigned int read_size = fread (get_buf, 1, st.st_size, fp);
	//DEBUG_MSG (_("read_size: 0x%x, st.st_size: 0x%x \n"), read_size, st.st_size);
	if (read_size != st.st_size)
		error (_("Cannot read `%s': %s"), filename, strerror (errno));
	data = get_buf;
	fclose (fp);
  close(fd);

  /* new version of elf_check */
  unsigned int if_load_table = 0;
  if (args != NULL)
  {
    if ((strcmp (args, "new") == 0) || (strcmp (args, "file") == 0)) {
      if (strcmp (args, "file") == 0) {
      	if_load_table = 1;
        DEBUG_MSG("elf_check_table ...\n");
      } else {
        DEBUG_MSG("elf_check_new ...\n");
      }
      err = elf_check_new (data, st.st_size, if_load_table);
      if (err)
        error ("elf_check_ERROR...");
      return;
    }
  }

  err = elf_check (data, st.st_size, nds_elf_check_get_register,
		   check_msg, sizeof (check_msg));
  if ((args != NULL) && (strcmp (args, "show") == 0))
  {
    printf_unfiltered ("%s", check_msg);
    return;
  }

  if (err)
    {
      /* internal test */
      if ((args != NULL) && (strcmp (args, "test") == 0))
	warning ("%s", check_msg);
      else
	error ("%s", check_msg);
    }
//#endif
}

static void
nds_endian_check_command (const char *args, int from_tty)
{
  enum bfd_endian elf_endian = BFD_ENDIAN_UNKNOWN;

  /* ELF file is necessary for endian comparison.  */
  if (current_program_space->exec_bfd () == NULL)
    return;

  /* The comparison is only for remote debugging.  */
  if (strcmp (target_shortname (), "remote") != 0
      && strcmp (target_shortname (), "extended-remote") != 0)
    return;

  if (nds_remote_info.type == nds_rt_unknown)
    return;

  elf_endian = current_program_space->exec_bfd ()->xvec->byteorder;

  if (nds_remote_info.endian != elf_endian)
    warning ("Target and elf have different endian");
}

static void
nds_set_args_command (const char *args, int from_tty)
{
  const std::string &infargs = current_inferior ()->args ();

  if (!infargs.empty ()) {
    /*printf_unfiltered (_("nds_set_args: current_inferior->args = %s\n"), current_inferior ()->args ().c_str ());*/
    if (current_inferior ()->args ().c_str ()) {
      char cmd[512];
      xsnprintf (cmd, sizeof (cmd), "nds set_args %s", current_inferior ()->args ().c_str ());
      target_rcmd (cmd, gdb_stdtarg);
    }
  }
}

/* for debugging overlay mapping compunits */
unsigned int nds_cu_overlay_debugging = 0;
static void nds_set_overlay_command (const char *args, int from_tty)
{
  nds_cu_overlay_debugging = 1;
}

/* Invoke the disassembler hook function to specify the path for the ACE ECA file. */
static void
nds_handle_ace (const char *ace_eca_path)
{
  char *err = andes_ace_load_hooks (ace_eca_path);
  if (err)
    fprintf (stderr, _("Failed to load ACE ECA file: %s\n"), err);
}

/* Callback for the "nds read_acedesc" command. */
static void
nds_read_ace_desc_command (const char *args, int from_tty)
{
  string_file str;
  char qrcmd[80];
  const char *filename = NULL;

  /* Construct the query command to request the GDB server to send the
     libacetool.eca file to the GDB client. This file is used for
     disassembling ACE instructions.

     [NOTE]: In the previous design, the third word in the query command
     specified the platform on which the GDB client was running (e.g., Linux or MinGW).
     However, this information is now redundant in the current design. Therefore,
     a placeholder value is passed instead. */
  sprintf (qrcmd, "nds ace %s", "ECA");

  /* Send the query command to the GDB server. */
  if (nds_issue_qrcmd (qrcmd, str) == -1)
    return;

  filename = str.c_str ();
  if (strlen (filename) != 0)
    {
      /* Seed the random number generator. */
      srand ((unsigned int) time (NULL));

      /* Generate a random number. */
      int random_number = rand ();

      /* Define a suffix for the file name. */
      const char *suffix = "_libacetool.eca";

      /* Allocate memory for the full file name. */
      char *file_name = (char *) malloc (30);

      /* Format the file name with the random number and suffix. */
      snprintf(file_name, 30, "%05d%s", random_number % 100000, suffix);

      /* Declare the file name as a const char *. */
      const char *ace_eca = file_name;

      /* Save the received libacetool.eca file locally */
      remote_file_get (filename, ace_eca, from_tty);

      /* Process the received file. */
      nds_handle_ace (ace_eca);

      /* Remove the temporary local file. */
      unlink (ace_eca);

      /* Free the allocated memory for the file name. */
      free (file_name);
    }
}

static int
nds_get_acr_info (struct gdbarch *gdbarch, const char *name,
		  int *regnum, int *len)
{
  int regno;

  if (name[0] == '$')
    name++;
  regno = user_reg_map_name_to_regnum (gdbarch, name, strlen (name));
  if (regno == -1)
    return -1;

  /* Get the size of register in byte.  */
  *len = register_size (gdbarch, regno);
  *regnum = regno;

  return 0;
}

#define MAX_ACR_BIT		1024
#define MAX_ACR_HEX_DIGIT	(MAX_ACR_BIT/4)

static char tohex[] = "0123456789abcdef";

/* Callback for "nds print" command, which is used to construct a
   hex string from the content of ACR.  */

static void
nds_print_acr_command (const char *args, int from_tty)
{
  struct regcache *regcache = get_thread_regcache (inferior_thread ());
  struct gdbarch *gdbarch = regcache->arch ();
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  int regnum;
  char *name = NULL;
  int len, i;
  /* Flag used to trim leading-zero.  */
  int flag_lz;
  /* +1 for null terminating char.  */
  char val_str[MAX_ACR_HEX_DIGIT + 1];
  char *str_p;
  gdb_byte *acr_content;

  /* Parse arguments.  */
  gdb_argv argv (args);

  /* operator== is overloading, so it can be used to check if args is NULL.  */
  if (argv == NULL || argv[0] == NULL)
    {
      gdb_printf (gdb_stdout, "<usage>: nds print <acr_name>\n");
      return;
    }

  name = argv[0];
  if (nds_get_acr_info (gdbarch, name, &regnum, &len) == -1)
    return;

  /* Allocate space for ACR.  */
  acr_content = (gdb_byte *) xcalloc (1, len);

  get_frame_register (get_selected_frame (NULL), regnum, acr_content);

  /* Construct val_str from ACR byte buffer, and start from the MSB of
     val_str, so that the leading zero case can be handled more easily.  */
  flag_lz = 1;
  str_p = val_str;
  if (byte_order == BFD_ENDIAN_BIG)
    {
      for (i = 0; i < len; i++)
	{
	  gdb_byte b;

	  b = acr_content[i];
	  if (flag_lz == 1 && b == 0)
	    continue;
	  else
	    flag_lz = 0;

	  str_p[0] = tohex[(b >> 4) & 0xf];
	  str_p[1] = tohex[(b & 0xf)];
	  str_p += 2;
	}
    }
  else
    {
      for (i = len - 1; i >= 0; i--)
	{
	  gdb_byte b;

	  b = acr_content[i];
	  if (flag_lz == 1 && b == 0)
	    continue;
	  else
	    flag_lz = 0;

	  str_p[0] = tohex[(b >> 4) & 0xf];
	  str_p[1] = tohex[(b & 0xf)];
	  str_p += 2;
	}
    }
  str_p[0] = '\0';

  /* Handle null string specially.  */
  str_p = val_str;
  while (*str_p == '0')
    str_p++;
  if (*str_p == '\0')
    {
      str_p[0] = '0';
      str_p[1] = '\0';
    }

  gdb_printf (gdb_stdout, "The value of %s is 0x%s\n", name, str_p);

  xfree (acr_content);
}

/* Convert hex digit A to a number.  */
#if 0
static int
fromhex (int a)
{
  if (a >= '0' && a <= '9')
    return a - '0';
  else if (a >= 'a' && a <= 'f')
    return a - 'a' + 10;
  else if (a >= 'A' && a <= 'F')
    return a - 'A' + 10;
  else
    error (_("Given value contains invalid hex digit %d"), a);
}
#endif
/* Callback for "nds set" command, which is used to construct
   the content of ACR from the given hex string.  */

static void
nds_set_acr_command (const char *args, int from_tty)
{
  struct regcache *regcache = get_thread_regcache (inferior_thread ());
  struct gdbarch *gdbarch = regcache->arch ();
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  int regnum;
  char *name = NULL;
  int len, i;
  const char *val_str, *str_p;
  gdb_byte *acr_content = NULL;

  /* Parse arguments.  */
  gdb_argv argv (args);

  /* operator== is overloading, so it can be used to check if args is NULL.  */
  if (argv == NULL || argv[0] == NULL || argv[1] == NULL)
    {
      gdb_printf (gdb_stdout,
			  "<usage>: nds set <acr_name> <hex_str>\n");
      return;
    }

  name = argv[0];
  if (nds_get_acr_info (gdbarch, name, &regnum, &len) == -1)
    return;

  val_str = argv[1];
  if (val_str[0] == '0' && (val_str[1] == 'x' || val_str[1] == 'X'))
    val_str += 2;

  acr_content = (gdb_byte *) xcalloc (1, len);

  /* Construct ACR byte buffer from val_str, and start from the LSB of
     val_str, so that the leading zero case can be handled more easily.  */
  str_p = val_str + strlen (val_str);
  if (byte_order == BFD_ENDIAN_BIG)
    {
      for (i = len - 1; i >= 0; i--)
	{
	  str_p -= 2;
	  if (str_p >= val_str)
	    acr_content[i] = (fromhex (str_p[0]) << 4) + fromhex (str_p[1]);
	  else if (str_p == val_str - 1)
	    acr_content[i] = fromhex (str_p[1]);
	  else
	    break;
	}
    }
  else
    {
      for (i = 0; i < len; i++)
	{
	  str_p -= 2;
	  if (str_p >= val_str)
	    acr_content[i] = (fromhex (str_p[0]) << 4) + fromhex (str_p[1]);
	  else if (str_p == val_str - 1)
	    acr_content[i] = fromhex (str_p[1]);
	  else
	    break;
	}
    }

  /* put_frame_register (get_selected_frame (NULL), regnum, acr_content); */
	auto array_view = gdb::make_array_view (acr_content, len);
	put_frame_register (get_selected_frame (NULL), regnum, array_view);

  /* The accurate bitsize info is necessary to do the truncation in GDB.
     Currently, the truncation is actually done at target side, so the
     regcache invalidation is necessary.  */
  regcache->invalidate (regnum);

  xfree (acr_content);
}

/* nds_insertion_sort sorts an array with nmemb elements of size size.
   This prototype is the same as qsort ().  */

static void
nds_insertion_sort (void *base, size_t nmemb, size_t size,
		    int (*compar) (const void *lhs, const void *rhs))
{
  char *ptr = (char *) base;
  int i, j;
  char *tmp = (char *) xmalloc (size);

  /* If i is less than j, i is inserted before j.

     |---- j ----- i --------------|
      \		 / \		  /
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
  free (tmp);
}

void
qsort (void *base, size_t nmemb, size_t size,
       int (*compar) (const void *lhs, const void *rhs))
{
  nds_insertion_sort (base, nmemb, size, compar);
}

static struct cmd_list_element *nds_pipeline_cmdlist;
static struct cmd_list_element *nds_query_cmdlist;
static struct cmd_list_element *nds_reset_cmdlist;

static const struct internalvar_funcs nds_target_type_funcs =
{
  nds_target_type_make_value,
  NULL
};

extern struct cmd_list_element *nds_cmdlist;

void
nds_init_remote_cmds (void)
{
  /* Hook for query remote target information.  */

  nds_remote_info_init ();

  add_cmd ("set_args", class_files, nds_set_args_command,
    _("Specify the arguments to the target program."),
    &nds_cmdlist);

  /* nds elf-check */
  add_cmd ("elf-check", class_files, nds_elf_check_command,
	   _("Check elf/target compatibility before loading. "
	     "Throwing error if failed."),
	   &nds_cmdlist);

  add_cmd ("endian-check", class_files, nds_endian_check_command,
	   _("Check endian consistency between elf and target. "
	     "Throwing warning if failed."),
	   &nds_cmdlist);

  /* nds query (profiling|perf-meter|target)  */
  add_prefix_cmd ("query", no_class, nds_query_command,
		  _("Query remote data."), &nds_query_cmdlist,
		  0, &nds_cmdlist);
  add_cmd ("profiling", no_class, nds_query_profiling_command,
	   _("Query profiling results."), &nds_query_cmdlist);
  add_cmd ("perf-meter", no_class, nds_query_perfmeter_command,
	   _("Query perf-meter results."), &nds_query_cmdlist);
  add_cmd ("target", no_class, nds_query_target_command,
	   _("Query target information."), &nds_query_cmdlist);

  /* nds reset (profiling|perf-meter)  */
  add_prefix_cmd ("reset", no_class, nds_reset_command,
		  _("Reset profiling."), &nds_reset_cmdlist,
		  0, &nds_cmdlist);
  add_cmd ("profiling", no_class, nds_reset_profiling_command,
	   _("Query profiling results."), &nds_reset_cmdlist);
  add_cmd ("perf-meter", no_class, nds_reset_perfmeter_command,
	   _("Query perf-meter results."), &nds_reset_cmdlist);

  /* nds pipeline (on|off) */
  add_prefix_cmd ("pipeline", no_class, nds_pipeline_command,
		  _("nds-sid profiling commands."),
		  &nds_pipeline_cmdlist, 0, &nds_cmdlist);
  add_cmd ("on", no_class, nds_pipeline_on_command,
	   _("Turn on pipeline for profiling."), &nds_pipeline_cmdlist);
  add_cmd ("off", no_class, nds_pipeline_off_command,
	   _("Turn off pipeline for profiling."), &nds_pipeline_cmdlist);

  /* nds read_acedesc  */
  add_cmd ("read_acedesc", no_class, nds_read_ace_desc_command,
	   _("Request the ACE or coprocessor description file from remote."),
	     &nds_cmdlist);

  /* nds print  */
  add_cmd ("print", no_class, nds_print_acr_command,
	   _("Print the value of ACR in hex format."), &nds_cmdlist);

  /* nds set  */
  add_cmd ("set", no_class, nds_set_acr_command,
	   _("Set the value of ACR in hex format."), &nds_cmdlist);

  /* nds set_overlay */
  add_cmd ("set_overlay", class_files, nds_set_overlay_command,
	  _("Specify nds overlay_debugging."), &nds_cmdlist);

  create_internalvar_type_lazy ("_nds_target_type", &nds_target_type_funcs,
				NULL);
}

struct nds_ext_check_info
{
  const char *p_ext_name;
  unsigned long long bit_mask_misa;
  unsigned long long bit_mask_mmsc;
  unsigned long long bit_mask_mrvarch;
} nds_ext_check_info_t;

struct nds_ext_info
{
  const char *p_ext_name;
  unsigned long long bit_mask_misa;
  unsigned long long bit_mask_mmsc;
  unsigned long long bit_mask_mrvarch;
  unsigned char cpu;
  unsigned char elf;
} nds_ext_info_t;

#define NUMS_EXT_INFO 100
static int nums_ext_info = NUMS_EXT_INFO;
static struct nds_ext_info nds_ext_info[NUMS_EXT_INFO];
#define EXT_COUNT 15
#define NUMS_EXT_INFO_DEFAULT  51
static struct nds_ext_check_info nds_ext_check_info_default[NUMS_EXT_INFO_DEFAULT] = {
{"M", 0x1000, 0x0, 0x0},
{"A", 0x01, 0x00, 0x00},
{"F", 0x20, 0x00, 0x00},
{"D", 0x08, 0x00, 0x00},
{"Q", 0x010000, 0x00, 0x00},
{"C", 0x04, 0x00, 0x00},
{"B", 0x02, 0x00, 0x00},
{"K", 0x0400, 0x00, 0x00},
{"J", 0x0200, 0x00, 0x00},
{"P", 0x8000, 0x020000000, 0x00},
{"V", 0x0200000, 0x00, 0x00},
{"Z", 0x02000000, 0x00, 0x00},
{"S", 0x040000, 0x00, 0x00},
{"H", 0x080, 0x00, 0x00},
{"X", 0x0800000, 0x00, 0x00},
{"Zca", 0x04, 0x00, 0x4000000},
{"Zcb", 0x00, 0x00, 0x8000000},
{"Zcd", 0x0C, 0x00, 0x10000000},
{"Zcf", 0x24, 0x00, 0x20000000},
{"Zcmp", 0x00, 0x00, 0x40000000},
{"Zcmt", 0x00, 0x00, 0x80000000},
{"Zba", 0x00, 0x00, 0x01},
{"Zbb", 0x00, 0x00, 0x02},
{"Zbc", 0x00, 0x00, 0x04},
{"Zbkb", 0x00, 0x00, 0x1000},
{"Zbkc", 0x00, 0x00, 0x1000},
{"Zbkx", 0x00, 0x00, 0x1000},
{"Zbk", 0x00, 0x00, 0x1000},
{"Zbs", 0x00, 0x00, 0x08},
{"Zknd", 0x00, 0x00, 0x2000},
{"Zkne", 0x00, 0x00, 0x2000},
{"Zknh", 0x00, 0x00, 0x2000},
{"Zkn", 0x00, 0x00, 0x2000},
{"Zksed", 0x00, 0x00, 0x4000},
{"Zksh", 0x00, 0x00, 0x4000},
{"Zks", 0x00, 0x00, 0x4000},
{"Zkt", 0x00, 0x00, 0x8000},
{"Zkr", 0x00, 0x00, 0x10000},
{"Zk", 0x00, 0x00, 0x1E000},
{"Zicbom", 0x00, 0x00, 0x200},
{"Zicbop", 0x00, 0x00, 0x400},
{"Zicboz", 0x00, 0x00, 0x800},
{"Svinval", 0x00, 0x00, 0x20},
{"Zilsd", 0x00, 0x00, 0x100},
{"Zcmlsd", 0x00, 0x00, 0x2000},
{"Zclsd", 0x00, 0x00, 0x2000},
{"xandesv", 0x00, 0x2008, 0x00},
{"Xv5-", 0x00, 0x2008, 0x00},
{"xdsp", 0x00, 0x20000000, 0x00},
{"xefhw", 0x00, 0x20000, 0x00},
{"xnexecit", 0x00, 0x08, 0x00}
};

static char ext_name_buf[512];
static char *p_ext_name = (char *)&ext_name_buf[0];

#define LINE_BUF_SIZE 256
__attribute__ ((__unused__)) static int nds_elf_check_by_tbl (void)
{
  char buffer[LINE_BUF_SIZE];
  int i, nums = 0, idx = 0;
  unsigned long long bit_mask_misa = 0;
  unsigned long long bit_mask_mmsc = 0;
  unsigned long long bit_mask_mrvarch = 0;

  p_ext_name = (char *)&ext_name_buf[0];
  FILE *fp_ext_tbl = fopen ("nds_ext_tbl.txt", "r");
  if (fp_ext_tbl == NULL) {
  	printf_unfiltered("ERROR: file is NOT exist !!\n");
    return -1;
  }
  if (fgets(buffer, LINE_BUF_SIZE, fp_ext_tbl) == NULL)
		return -1;
  i = sscanf (buffer, "int nums_ext_info = %d;", &nums);
  if (i != 1)
    return -1;
  nums_ext_info = nums;
  DEBUG_MSG ("nums_ext_info: %d\n", nums_ext_info);

  if (fgets(buffer, LINE_BUF_SIZE, fp_ext_tbl) == NULL)
		return -1;
  // struct nds_ext_check_info nds_ext_check_info[] = {

  while (fgets(buffer, 256, fp_ext_tbl) != NULL) {
    i = sscanf(buffer, "%s, ", p_ext_name);
		i = strlen(p_ext_name);
		if (i > 2)
		  p_ext_name[i-2] = 0; // string end
    //DEBUG_MSG ("i: %d %s**\n", i, p_ext_name);
    //DEBUG_MSG ("buf:%s", &buffer[i]);
    i = sscanf(&buffer[i], " 0x%llx, 0x%llx, 0x%llx", &bit_mask_misa, &bit_mask_mmsc, &bit_mask_mrvarch);
    if (i != 3)
    	break;
    p_ext_name += 2;

    nds_ext_info[idx].p_ext_name = p_ext_name;
    nds_ext_info[idx].bit_mask_misa = bit_mask_misa;
    nds_ext_info[idx].bit_mask_mmsc = bit_mask_mmsc;
    nds_ext_info[idx].bit_mask_mrvarch = bit_mask_mrvarch;
    nds_ext_info[idx].cpu = 0;
    nds_ext_info[idx].elf = 0;
    idx ++;
    p_ext_name += strlen(p_ext_name) + 1;
  }

  if (idx != nums_ext_info) {
  	DEBUG_MSG ("nums not match!! nums_ext_info: %d, idx: %d\n", nums_ext_info, idx);
    nums_ext_info = idx;
  }
  fclose(fp_ext_tbl);
  /*
  for (i = 0; i < nums_ext_info; i++) {
    DEBUG_MSG ("%s ", nds_ext_info[i].p_ext_name);
    DEBUG_MSG ("bit_mask_misa: 0x%llx ", nds_ext_info[i].bit_mask_misa);
    DEBUG_MSG ("bit_mask_mmsc: 0x%llx ", nds_ext_info[i].bit_mask_mmsc);
    DEBUG_MSG ("bit_mask_mrvarch: 0x%llx \n", nds_ext_info[i].bit_mask_mrvarch);
  }*/
  return 0;
}

__attribute__ ((__unused__)) static void nds_elf_check_by_default (void)
{
  int i;
  nums_ext_info = NUMS_EXT_INFO_DEFAULT;

  for (i = 0; i < nums_ext_info; i++) {
    nds_ext_info[i].p_ext_name = nds_ext_check_info_default[i].p_ext_name;
    nds_ext_info[i].bit_mask_misa = nds_ext_check_info_default[i].bit_mask_misa;
    nds_ext_info[i].bit_mask_mmsc = nds_ext_check_info_default[i].bit_mask_mmsc;
    nds_ext_info[i].bit_mask_mrvarch = nds_ext_check_info_default[i].bit_mask_mrvarch;
    nds_ext_info[i].cpu = 0;
    nds_ext_info[i].elf = 0;
  }
}

static void nds_set_nonstandard_extension(void)
{
  int i;
  unsigned long long CPU_PP16 = 0, CPU_ECDV = 0;

  for (i = 0; i < nums_ext_info; i++) {
  	if ((strcmp (nds_ext_info[i].p_ext_name, "Zilsd") == 0) ||
  	   (strcmp (nds_ext_info[i].p_ext_name, "Zcmlsd") == 0) ||
  		 (strcmp (nds_ext_info[i].p_ext_name, "Zclsd") == 0)) {
      if ((nds_ext_info[i].bit_mask_mrvarch != 0) && ((reg_mrvarch_cfg2 & nds_ext_info[i].bit_mask_mrvarch) == nds_ext_info[i].bit_mask_mrvarch))
        nds_ext_info[i].cpu = 1;
      else
        nds_ext_info[i].cpu = 0;
    } else if ((strcmp (nds_ext_info[i].p_ext_name, "xefhw") == 0) && (nds_ext_info[i].cpu == 1)) {
      if (reg_misa & (1 << 21))
        nds_ext_info[i].cpu = 0;
    } else if ((strcmp (nds_ext_info[i].p_ext_name, "xnexecit") == 0) && (nds_ext_info[i].cpu == 1)) {
       //#     CPU_ECD = (mmsc_cfg & (1 << 3)) != 0;
       //#     bool CPU_PP16 = is64 ? (mmsc_cfg & (1 << 38)) != 0 : (mmsc_cfg2 & (1 << 6)) != 0;
       //#     bool CPU_ECDV = is64 ? ((mmsc_cfg >> 41) & 3) == 1 : ((mmsc_cfg2 >> 9) & 3) == 1;
       //#     return CPU_ECD && !CPU_PP16 && CPU_ECDV;
       if (misa_mxl == 1) {
         CPU_PP16 = (reg_mmsc_cfg2 & (1 << 6));
         CPU_ECDV = ((reg_mmsc_cfg2 >> 9) & 3);
       } else {
         CPU_PP16 = (reg_mmsc_cfg & (1UL << 38));
         CPU_ECDV = ((reg_mmsc_cfg >> 41) & 3);
       }
       if ((CPU_PP16 == 0) && (CPU_ECDV == 1))
         nds_ext_info[i].cpu = 1;
       else
         nds_ext_info[i].cpu = 0;
    }
  }
}

__attribute__ ((__unused__)) static void nds_set_cpu_extension(void)
{
  int i;

  for (i = 0; i < nums_ext_info; i++) {
    if ((nds_ext_info[i].bit_mask_misa != 0) && ((reg_misa & nds_ext_info[i].bit_mask_misa) == nds_ext_info[i].bit_mask_misa))
      nds_ext_info[i].cpu = 1;
    if ((nds_ext_info[i].bit_mask_mmsc != 0) && ((reg_mmsc_cfg & nds_ext_info[i].bit_mask_mmsc) == nds_ext_info[i].bit_mask_mmsc))
      nds_ext_info[i].cpu = 1;
    if ((nds_ext_info[i].bit_mask_mrvarch != 0) && ((reg_mrvarch_cfg & nds_ext_info[i].bit_mask_mrvarch) == nds_ext_info[i].bit_mask_mrvarch))
      nds_ext_info[i].cpu = 1;
  }
  nds_set_nonstandard_extension();
}

__attribute__ ((__unused__)) static void nds_show_other_error_info(struct nds_ext_info *p_ext_info)
{
  if (strcmp(p_ext_info->p_ext_name, "Zca") == 0) {
  	printf_unfiltered("RVC(imply zca) not support or ZCE:Zca not support");
  } else if (strcmp(p_ext_info->p_ext_name, "Zcb") == 0) {
  	printf_unfiltered("ZCE:Zcb not support");
  } else if (strcmp(p_ext_info->p_ext_name, "Zcd") == 0) {
  	printf_unfiltered("Need RVC+RVD(imply zcd) support and both ZCE:zcmp and ZCE:zcmt all disable");
  } else if (strcmp(p_ext_info->p_ext_name, "Zcf") == 0) {
  	printf_unfiltered("RVC+RVF(imply zcf) not support or ZCE:Zcf not support");
  } else if (strcmp(p_ext_info->p_ext_name, "Zcmp") == 0) {
  	printf_unfiltered("ZCE:Zcmp not support");
  } else if (strcmp(p_ext_info->p_ext_name, "Zcmt") == 0) {
  	printf_unfiltered("ZCE:Zcmt not support");
  }
}

__attribute__ ((__unused__)) static void nds_show_cpu_extension(void)
{
  int i;
  const char *p_ON_OFF[2] = {"OFF", "ON"};
  const char *p_str_cpu, *p_str_elf;
/*
  for (i = 0; i < nums_ext_info; i++) {
    DEBUG_MSG ("%s %d %d\n",
      nds_ext_info[i].p_ext_name, nds_ext_info[i].cpu, nds_ext_info[i].elf);
  }
*/

  /* Check extensions. */
  printf_unfiltered("\t   %9s   %9s  \n", "CPU", "ELF");

  for (i = 0; i < nums_ext_info; i++) {
  	p_str_cpu = p_ON_OFF[nds_ext_info[i].cpu];
  	p_str_elf = p_ON_OFF[nds_ext_info[i].elf];

  	if (i < EXT_COUNT) {
      // misa.c not enough to represent ELF 'C' instruction set so ignore it.
      if (*nds_ext_info[i].p_ext_name == 'C')
        continue;
      printf_unfiltered("\t | %9s | %9s | Extension '%s'", p_str_cpu, p_str_elf, nds_ext_info[i].p_ext_name);
    } else {
      if (!nds_ext_info[i].elf)
        continue;
      printf_unfiltered("\t | %9s | %9s | '%s' extension", p_str_cpu, p_str_elf, nds_ext_info[i].p_ext_name);
    }
    if (!nds_ext_info[i].cpu && nds_ext_info[i].elf) {
      printf_unfiltered(" Error: Not supported by CPU. ");
      nds_show_other_error_info(&nds_ext_info[i]);
      elf_check_n_error ++;
    }
    printf_unfiltered("\n");
  }

  if (elf_check_n_error) {
    printf_unfiltered("Error: ELF and CPU mismatch\n"
                   "Total Error: %d\n", elf_check_n_error);
    printf_unfiltered("Usage error, Consult Andes Toolchains and their compatible Andes cores for the Toolchain-CPU compatibility.\n");
    printf_unfiltered("The Loader Checking can be disabled under Debug Configuration.\n");
  } else {
    printf_unfiltered("NDS ELF checking pass\n");
  }
}

static void nds_set_elf_ext(char *p_ext_name)
{
  int i;

  for (i = 0; i < nums_ext_info; i++) {
    if (strcmp (nds_ext_info[i].p_ext_name, p_ext_name) == 0)
      nds_ext_info[i].elf = 1;
  }
}

static unsigned int nds_get_elf_ext(char *p_ext_name)
{
  int i;

  for (i = 0; i < nums_ext_info; i++) {
    if (strcmp (nds_ext_info[i].p_ext_name, p_ext_name) == 0)
      return nds_ext_info[i].elf;
  }
  return 0;
}

static unsigned int nds_get_multi_letter_ext_info_idx(void)
{
	int i;

  for (i = 0; i < nums_ext_info; i++) {
    if (strcmp (nds_ext_info[i].p_ext_name, "X") == 0)
      return (i + 1);
  }
  return 0;
}

// The ISA string must begin with one of these four.
static const char *riscv_base_isas[] = {"RV32E", "RV32I", "RV64I", "RV128I"};
static unsigned int nds_elf_base_isa = 0xff;
/*
  func: nds_parse_riscv_base_isa()   parse riscv base isa name
        return the string length of base_isa_name
*/
static unsigned int nds_parse_riscv_base_isa(const char *p_str)
{
  unsigned int i, error_type = 0, str_length = 0;

  for (i = 0; i < 4; i++) {
    if (strncasecmp(p_str, riscv_base_isas[i], strlen(riscv_base_isas[i])) == 0) {
      nds_elf_base_isa = i;
      break;
    }
  }

  if (nds_elf_base_isa == 0xff) {
    printf_unfiltered ("Invalid base ISA %s\n", p_str);
    return 0;
  } else if (nds_elf_base_isa == 0) {  //#BASE_ISA_RV32E, mxl must be 1 (32bit) for RV32E
    if ((misa_mxl != 1) || ((reg_misa & (0x01 << 4)) == 0))
      error_type = 1;
  } else {
    if ((misa_mxl != nds_elf_base_isa) || ((reg_misa & (0x01 << 8)) == 0))
      error_type = 1;
  }
  if (error_type == 1) {
    printf_unfiltered ("Error: Base ISA does not match\n");
    printf_unfiltered ("ELF: %s\n", riscv_base_isas[nds_elf_base_isa]);
    printf_unfiltered ("CPU: %s\n", riscv_base_isas[misa_mxl]);
    elf_check_n_error ++;
    return 0;
  }
  //# ex: rv64i2p0_
  str_length = strlen(riscv_base_isas[nds_elf_base_isa]);
  str_length += 3;
  return str_length;
}

/*
  func: nds_is_multi_letter_extension()   check if multi_letter_extension
        c must be lowercase
*/
static unsigned int nds_is_multi_letter_extension(char c)
{
  if ((c == 'z') || (c == 's') || (c == 'h') || (c == 'x'))
    return 1;
  return 0;
}

/*
  func: nds_set_riscv_CEXT_subset_atrribute_accroding_ELF_CDF()
        complement ELF attribute: C imply zca, C+F imply zca +zcf, C+D  imply  zca +zcf +zcd
*/
static void nds_set_riscv_CEXT_subset_atrribute_accroding_ELF_CDF(void)
{
  if (nds_get_elf_ext((char *)"C")) {
    nds_set_elf_ext((char *)"Zca");
    if ((nds_elf_base_isa == 0) || (nds_elf_base_isa == 1)) {   // #BASE_ISA_RV32E  BASE_ISA_RV32I
      if ((nds_get_elf_ext((char *)"F")) || (nds_get_elf_ext((char *)"D"))) {
        nds_set_elf_ext((char *)"Zcf");
      }
    }
    if (nds_get_elf_ext((char *)"D")) {
    	if ((nds_get_elf_ext((char *)"Zcmp") == 0) && (nds_get_elf_ext((char *)"Zcmt") == 0))
        nds_set_elf_ext((char *)"Zcd");
    }
  }
}

//static const char *riscv_extensions = "MAFDQCBKJPVZSHX"; // It will be updated to "MAFDQLCBKJTPVNZSHX" in the future.
__attribute__ ((__unused__)) static int nds_parse_riscv_isa_string(const char *p_str)
{
  unsigned int i, str_length = 0, tbl_idx = 0, str_index = 0, str2_index = 0;
  unsigned int find_ext, nums_single_letter_ext;
  char tmp_buf[64];
  char *p_str2 = (char *)&tmp_buf[0];

  DEBUG_MSG ("Base ISA: %s\n", p_str);
  str_length = strlen(p_str);

  // The ISA string starts with the base ISA.
  str_index = nds_parse_riscv_base_isa(p_str);
  DEBUG_MSG ("base_isa str_length: %d\n", str_index);
  if (str_index == 0)
    return -1;

  // Followed by multiple extensions.
  DEBUG_MSG ("Extensions:");
  while (str_index < str_length) {
    // Skip over underscores
    while (p_str[str_index] ==  '_')
      str_index += 1;

    str2_index = 0;
    for (i = str_index; i < str_length; i++) {
      if (p_str[i] == '_')
        break;
      p_str2[str2_index] = p_str[i];
      str2_index++;
    }
    p_str2[str2_index] = 0;
    DEBUG_MSG ("p_str2: %s\n", p_str2);

    // RISC-V Standard extensions, must appear in this order.
    find_ext = 0;
    nums_single_letter_ext = nds_get_multi_letter_ext_info_idx();
    DEBUG_MSG ("nums_single_letter_ext: %d\n", nums_single_letter_ext);

    for (i = 0; i < nums_single_letter_ext; i++) {
      if (nds_ext_info[i].p_ext_name[0] == toupper(p_str[str_index])) {
        if (nds_ext_info[i].elf == 1) {
        	if ((p_str[str_index] != 'x') && (p_str[str_index] != 'z'))
            printf_unfiltered ("Duplicate extension: %c\n", p_str[str_index]);
        } else {
          nds_ext_info[i].elf = 1;
        }
        find_ext = 1;
        break;
      }
    }

    if (find_ext == 0)
      printf_unfiltered ("Invalid extension: %c\n", p_str[str_index]);
    else if (i < tbl_idx)
      printf_unfiltered ("Out of order extension: %c\n", p_str[str_index]);
    else
      tbl_idx = i;

    if (nds_is_multi_letter_extension(p_str[str_index]) == 1) {
      DEBUG_MSG ("multi_letter_extension: %c\n", p_str[str_index]);
      for (i = nums_single_letter_ext; i < nums_ext_info; i++) {
        if (strncasecmp(p_str2, nds_ext_info[i].p_ext_name, strlen(nds_ext_info[i].p_ext_name)) == 0) {
          DEBUG_MSG ("match p_str2: %s\n", p_str2);
          nds_ext_info[i].elf = 1;
          break;
        }
      }
    }
    str_index += strlen(p_str2);
  }
  nds_set_riscv_CEXT_subset_atrribute_accroding_ELF_CDF();
  return 0;
}
