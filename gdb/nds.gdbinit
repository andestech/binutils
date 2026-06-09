# gdbinit for NDS systems.
#
# Copyright (C) 2006-2013 Free Software Foundation, Inc.
# Contributed by Andes Technology Corporation.
#
# This file is part of GDB.
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
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# This commands are used for NDS OpenOCD/SID.

echo [info] Loading .Andesgdbinit.\n

# Reduce remote memory access.
set trust-readonly-sections 0

# Add command alias nds32
alias nds32 = nds

# Set limit to workaround issues about backtrace in ISR or broken debug information.
set backtrace limit 100

# Set Timeout limit to wait for target to respond to 60 seconds (defualt=2)
# Reason: 'monitor reset run' may take over 2s and the communication
#	  would be a mess because the next command will be replied
#	  with previous response
set remotetimeout 60

# Handle elf-check and cache control only if the target (sid/iceman) requires.
# In other words, do not handle elf-check and cache control for sim.
# $_nds_target_type is built-in convenience variable for target type:
#  0 - unknown (linux gdbserver or sim)
#  1 - SID
#  2 - OpenOCD

# Enable elf-check by default. Users(IDE) can disable it by setting it to 0.
set $nds_elf_check = 1

# bug-31346, warning: could not convert 'main' from the host encoding (CP1252) to UTF-32.
set charset UTF-8

# Turn off frame argument displaying when connecting to remote.
define target hook-remote
  set print frame-arguments none
end

define target hook-extended-remote
  set print frame-arguments none
end

define target hookpost-remote
  nds query target
  nds endian-check
  set print frame-arguments scalars
end

define target hookpost-extended-remote
  nds query target
  nds endian-check
  set print frame-arguments scalars
end

define hookpost-file
  nds endian-check
end

define hookpost-exec-file
  nds endian-check
end

# reset and hold
define reset-and-hold
  monitor reset halt
  # Clear $ra and $sp when reset-and-hold in order to avoid backtrace. (bug8032)
  set $ra = 0
  set $sp = 0
  maintenance flush register-cache
end

# reset and run
define reset-and-run
  monitor reset run
  maintenance flush register-cache
end

define hook-load
  if $_nds_target_type
    if $nds_elf_check
      nds elf-check
    end

    monitor nds mem_access cpu
  end
end

define hook-restore
  if $_nds_target_type
    monitor nds mem_access cpu
  end
end

# bug-35667, Support SW reset for the crash debugging.
define clr_crash_state
  set $mstatus = (unsigned long) 0
  set $misa = (unsigned long) 0
  set $mie = (unsigned long) 0
  set $mtvec = (unsigned long) 0
  set $mxstatus = (unsigned long) 0
  set $mmisc_ctl = (unsigned long) 0
  set $milmb = (unsigned long) 0
  set $mdlmb = (unsigned long) 0
  set $mnvec = (unsigned long) 0
  set $mcache_ctl = (unsigned long) 0
  set $mpft_ctl = (unsigned long) 0
  set $mclk_ctl = (unsigned long) 0
  set $mhsp_ctl = (unsigned long) 0
  set $pmpcfg0 = (unsigned long) 0
  set $pmpcfg1 = (unsigned long) 0
  set $pmpcfg2 = (unsigned long) 0
  set $pmpcfg3 = (unsigned long) 0
  set $pmpcfg4 = (unsigned long) 0
  set $pmpcfg5 = (unsigned long) 0
  set $pmpcfg6 = (unsigned long) 0
  set $pmpcfg7 = (unsigned long) 0
  set $pmpcfg8 = (unsigned long) 0
  set $pmpcfg9 = (unsigned long) 0
  set $pmpcfg10 = (unsigned long) 0
  set $pmpcfg11 = (unsigned long) 0
  set $pmpcfg12 = (unsigned long) 0
  set $pmpcfg13 = (unsigned long) 0
  set $pmpcfg14 = (unsigned long) 0
  set $pmpcfg15 = (unsigned long) 0
  maintenance flush register-cache
end

echo [info] .Andesgdbinit loaded.\n
