/* BFD library support routines for the agc architecture.

   Copyright 2022 Free Software Foundation, Inc.

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
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

#include "sysdep.h"
#include "bfd.h"
#include "libbfd.h"

const bfd_arch_info_type bfd_agc_arch =
{
  16,                     /* bits per word */
  16,                     /* bits per address */
  16,                     /* bits per byte */
  bfd_arch_agc,           /* architecture */
  bfd_mach_agc,           /* machine */
  "agc",                  /* architecture name */
  "agc",                  /* printable name */
  2,                      /* section align power */
  true,                   /* the default ? */
  bfd_default_compatible, /* architecture comparison fn */
  bfd_default_scan,       /* string to architecture convert fn */
  bfd_arch_default_fill,  /* agc fill.  */
  NULL,                   /* next in list */
  0                       /* max offset of a reloc from the start of an insn */
};
