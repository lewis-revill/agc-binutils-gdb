/* Disassemble AGC instructions.

   Copyright 2022 Free Software Foundation, Inc.

   This file is part of libopcodes.

   This library is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   It is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
   or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
   License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

#include "sysdep.h"
#include "dis-asm.h"
#include "disassemble.h"
#include "opintl.h"
#include "libiberty.h"

/* Disassembler for AGC instructions.  */

int
print_insn_agc (bfd_vma addr, disassemble_info *info)
{
  (void) addr;
  uint32_t insn_len = 1;
  (*info->fprintf_func) (info->stream, "todo");
  return insn_len ;
}
