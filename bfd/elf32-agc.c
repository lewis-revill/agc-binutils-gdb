/* AGC specific support for 32-bit ELF.

   Copyright (C) 2022 Free Software Foundation, Inc.

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
#include "elf-bfd.h"
#include "elf/agc.h"
#include "elf32-agc.h"


#define BANKTABLE_START 0x800
#define CONSTPOOL_START 0x828


/* Read and return the section contents at DATA converted to a host
   integer (bfd_vma).  The number of bytes read is given by the HOWTO.  */

static bfd_vma
read_reloc (bfd *abfd, bfd_byte *data, reloc_howto_type *howto)
{
  switch (howto->size)
    {
    case 0:
      break;

    case 1:
      return bfd_get_8 (abfd, data);

    case 2:
      return bfd_get_16 (abfd, data);

    default:
      abort ();
    }
  return 0;
}


/* Convert VAL to target format and write to DATA.  The number of
   bytes written is given by the HOWTO.  */

static void
write_reloc (bfd *abfd, bfd_vma val, bfd_byte *data, reloc_howto_type *howto)
{
  switch (howto->size)
    {
    case 0:
      break;

    case 1:
      bfd_put_8 (abfd, val, data);
      break;

    case 2:
      bfd_put_16 (abfd, val, data);
      break;

    default:
      abort ();
    }
}


/* Apply RELOCATION value to target bytes at DATA, according to
   HOWTO.  */

static void
apply_reloc (bfd *abfd, bfd_byte *data, reloc_howto_type *howto,
             bfd_vma relocation)
{
  bfd_vma val = read_reloc (abfd, data, howto);

  if (howto->negate)
    relocation = -relocation;

  val = ((val & ~howto->dst_mask)
        | (((val & howto->src_mask) + relocation) & howto->dst_mask));

  write_reloc (abfd, val, data, howto);
}


/* A data structure to hold the representation of an address on AGC.  */

typedef struct
{
  bfd_vma lo12_bits;
  bfd_vma eb_bits;
  bfd_vma fb_bits;
  bfd_vma sb_bit;
} agc_addr;


/* Compute the actual representation of an address on AGC, accounting
   for bits distributed across bank selection registers.  */

static agc_addr
fixup_reloc_addr (bfd_vma relocation)
{
  agc_addr addr;

  /* Original address assumes 8-bit byte addressed, so we must convert it to
     address 16-bit bytes.  */
  relocation >>= 1;

  /* Erasable address, which is in the range to be used 'as-is'.  */
  if (relocation < 0x300)
  {
    addr.lo12_bits = relocation;
    return addr;
  }

  /* Erasable address requiring erasable bank bits.  */
  if (relocation < 0x800)
  {
    addr.lo12_bits = (relocation & 0xff) | 0x300;
    addr.eb_bits = (relocation & 0x700) >> 8;
    return addr;
  }

  /* Fixed address, which is in the range to be used 'as-is'.  */
  if (relocation < 0x1000)
  {
    addr.lo12_bits = relocation;
    return addr;
  }

  /* Fixed address requiring fixed bank bits.  */
  if (relocation < 0x6000)
  {
    addr.lo12_bits = (relocation & 0x3ff) | 0x400;
    addr.fb_bits = (relocation & 0x7c00) >> 10;
    return addr;
  }

  /* Fixed address requiring fixed bank bits and a superbank bit.  */
  BFD_ASSERT (relocation < 0xa000);
  addr.lo12_bits = (relocation & 0x3ff) | 0x400;
  addr.fb_bits = ((relocation & 0x7c00) >> 10) | 0x18;
  addr.sb_bit = 0x1;
  return addr;
}


/* Retrieve the correct address to access the table entry containing the
   desired bank select bits.  */

static bfd_vma
get_banktable_addr (agc_addr addr)
{
  if (addr.eb_bits)
    return BANKTABLE_START + addr.eb_bits;

  if (addr.fb_bits && !addr.sb_bit)
    return BANKTABLE_START + addr.fb_bits;

  if (addr.sb_bit)
    return BANKTABLE_START + 0x20 + (addr.fb_bits & 0x3);

  return BANKTABLE_START;
}


/* Retrieve the correct address to access the constant pool entry containing the
   desired constant.  */

static bfd_vma
get_constpool_addr (bfd_vma constant)
{
  return CONSTPOOL_START + constant;
}


/* Helper for computing the value to patch into a relocation.  Used by the
   different relocation patching paths.  */

static bfd_vma
agc_fixup_relocation_value (bfd_vma relocation, reloc_howto_type *howto)
{
  agc_addr addr;

  addr = fixup_reloc_addr (relocation);
  switch (howto->type)
    {
    case R_AGC_CPI12:
      relocation = get_constpool_addr (relocation);
      break;
    case R_AGC_BANKS12:
      addr = fixup_reloc_addr (relocation);
      relocation = get_banktable_addr (addr);
      break;
    case R_AGC_LO12:
      addr = fixup_reloc_addr (relocation);
      relocation = addr.lo12_bits;
      break;
    default:
      relocation = 0;
      break;
    }

  return relocation;
}


/* Special handling of AGC relocations.  */

static bfd_reloc_status_type
agc_reloc_handler (bfd *abfd,
                   arelent *reloc_entry,
                   asymbol *symbol,
                   void *data,
                   asection *input_section,
                   bfd *output_bfd,
                   char **error_message ATTRIBUTE_UNUSED)
{
  bfd_vma relocation;
  bfd_reloc_status_type flag = bfd_reloc_ok;
  bfd_size_type octets;
  bfd_vma output_base = 0;
  reloc_howto_type *howto = reloc_entry->howto;
  asection *reloc_target_output_section;

  /* Is the address of the relocation really within the section?  */
  octets = reloc_entry->address * bfd_octets_per_byte (abfd, input_section);
  if (!bfd_reloc_offset_in_range (howto, abfd, input_section, octets))
    return bfd_reloc_outofrange;

  /* First we need to figure out the value that we're going to patch into
     the reloc, and perform overflow checking.  Then we can patch the value
     into memory.  Most of this code is copied directly from
     bfd_perform_relocation in reloc.c, but with code that definitely
     doesn't apply to AGC removed.  */

  /* Get symbol value.  (Common symbols are special.)  */
  if (bfd_is_com_section (symbol->section))
    relocation = 0;
  else
    relocation = symbol->value;

  reloc_target_output_section = symbol->section->output_section;

  /* Convert input-section-relative symbol value to absolute.  */
  if ((output_bfd && ! howto->partial_inplace)
      || reloc_target_output_section == NULL)
    output_base = 0;
  else
    output_base = reloc_target_output_section->vma;

  output_base += symbol->section->output_offset;

  /* If symbol addresses are in octets, convert to bytes.  */
  if (bfd_get_flavour (abfd) == bfd_target_elf_flavour
      && (symbol->section->flags & SEC_ELF_OCTETS))
    output_base *= bfd_octets_per_byte (abfd, input_section);

  relocation += output_base;

  /* Add in supplied addend.  */
  relocation += reloc_entry->addend;

  /* Here the variable relocation holds the final address of the
     symbol we are relocating against, plus any addend.  */

  if (howto->pc_relative)
    {
      /* This is a PC relative relocation.  We want to set RELOCATION
         to the distance between the address of the symbol and the
         location.  RELOCATION is already the address of the symbol.

         We start by subtracting the address of the section containing
         the location.

         If pcrel_offset is set, we must further subtract the position
         of the location within the section.  Some targets arrange for
         the addend to be the negative of the position of the location
         within the section; for example, i386-aout does this.  For
         i386-aout, pcrel_offset is FALSE.  Some other targets do not
         include the position of the location; for example, ELF.
         For those targets, pcrel_offset is TRUE.

         If we are producing relocatable output, then we must ensure
         that this reloc will be correctly computed when the final
         relocation is done.  If pcrel_offset is FALSE we want to wind
         up with the negative of the location within the section,
         which means we must adjust the existing addend by the change
         in the location within the section.  If pcrel_offset is TRUE
         we do not want to adjust the existing addend at all.

         FIXME: This seems logical to me, but for the case of
         producing relocatable output it is not what the code
         actually does.  I don't want to change it, because it seems
         far too likely that something will break.  */

      relocation -=
        input_section->output_section->vma + input_section->output_offset;

      if (howto->pcrel_offset)
        relocation -= reloc_entry->address;
    }

  /* AGC-specific code.  Modify the computed relocation value.  */
  relocation = agc_fixup_relocation_value (relocation, howto);
  /* End of AGC-specific code.  */

  /* FIXME: This overflow checking is incomplete, because the value
     might have overflowed before we get here.  For a correct check we
     need to compute the value in a size larger than bitsize, but we
     can't reasonably do that for a reloc the same size as a host
     machine word.
     FIXME: We should also do overflow checking on the result after
     adding in the value contained in the object file.  */
  if (howto->complain_on_overflow != complain_overflow_dont
      && flag == bfd_reloc_ok)
    flag = bfd_check_overflow (howto->complain_on_overflow,
                               howto->bitsize,
                               howto->rightshift,
                               bfd_arch_bits_per_address (abfd),
                               relocation);

  /* Now prepare to apply the reloc.  This is again taken from the common
     code.  */
  relocation >>= (bfd_vma) howto->rightshift;

  /* Shift everything up to where it's going to be used.  */
  relocation <<= (bfd_vma) howto->bitpos;

  data = (bfd_byte *) data + octets;

  apply_reloc (abfd, data, howto, relocation);
  return flag;
}


/* How to patch relocations for AGC.  */

static reloc_howto_type agc_howto_table[] =
{
  /* No relocation.  */
  HOWTO (R_AGC_NONE,			/* type */
	 0,				/* rightshift */
	 0,				/* size */
	 0,				/* bitsize */
	 false,				/* pc_relative */
	 0,				/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 agc_reloc_handler,		/* special_function */
	 "R_AGC_NONE",			/* name */
	 false,				/* partial_inplace */
	 0,				/* src_mask */
	 0,				/* dst_mask */
	 false),			/* pcrel_offset */

  /* 16 bit relocation.  */
  HOWTO (R_AGC_16,			/* type */
	 0,				/* rightshift */
	 2,				/* size */
	 16,				/* bitsize */
	 false,				/* pc_relative */
	 0,				/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 agc_reloc_handler,		/* special_function */
	 "R_AGC_16",			/* name */
	 false,				/* partial_inplace */
	 0,				/* src_mask */
	 0xffff,			/* dst_mask */
	 false),			/* pcrel_offset */

  /* 12 bit const pool index relocation.  */
  HOWTO (R_AGC_CPI12,			/* type */
	 0,				/* rightshift */
	 2,				/* size */
	 16,				/* bitsize */
	 false,				/* pc_relative */
	 0,				/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 agc_reloc_handler,		/* special_function */
	 "R_AGC_CPI12",			/* name */
	 false,				/* partial_inplace */
	 0,				/* src_mask */
	 0x0fff,			/* dst_mask */
	 false),			/* pcrel_offset */

  /* 12 bit bank select bits relocation.  */
  HOWTO (R_AGC_BANKS12,			/* type */
	 0,				/* rightshift */
	 2,				/* size */
	 16,				/* bitsize */
	 false,				/* pc_relative */
	 0,				/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 agc_reloc_handler,		/* special_function */
	 "R_AGC_BANKS12",		/* name */
	 false,				/* partial_inplace */
	 0,				/* src_mask */
	 0x0fff,			/* dst_mask */
	 false),			/* pcrel_offset */

  /* 12 bit lower address bits relocation.  */
  HOWTO (R_AGC_LO12,			/* type */
	 0,				/* rightshift */
	 2,				/* this one is variable size */
	 16,				/* bitsize */
	 false,				/* pc_relative */
	 0,				/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 agc_reloc_handler,		/* special_function */
	 "R_AGC_LO12",			/* name */
	 false,				/* partial_inplace */
	 0,				/* src_mask */
	 0x0fff,			/* dst_mask */
	 false),			/* pcrel_offset */
};


/* Set the howto pointer for an AGC ELF reloc.  */

static bool
agc_info_to_howto_rel (bfd *abfd,
                          arelent *cache_ptr,
                          Elf_Internal_Rela *dst)
{
  unsigned int r_type = ELF32_R_TYPE (dst->r_info);
  if (r_type >= (unsigned int) R_AGC_max)
    {
      /* xgettext:c-format */
      _bfd_error_handler (_("%pB: unsupported relocation type %#x"),
                             abfd, r_type);
      bfd_set_error (bfd_error_bad_value);
      return false;
    }

  cache_ptr->howto = &agc_howto_table[r_type];
  return true;
}


/* Given a relocation type R_TYPE, return the howto.  */

static reloc_howto_type *
agc_reloc_type_lookup (bfd * abfd ATTRIBUTE_UNUSED,
                       unsigned int r_type)
{
  if (r_type <= R_AGC_max)
    return &agc_howto_table [r_type];

  return (reloc_howto_type *) NULL;
}


/* Actually patch a relocation into the section contents.  */

static bfd_reloc_status_type
agc_final_link_relocate (bfd *output_bfd ATTRIBUTE_UNUSED,
			 reloc_howto_type *howto,
                         bfd *input_bfd,
                         asection *input_section ATTRIBUTE_UNUSED,
                         bfd_byte *contents,
                         Elf_Internal_Rela *rel ATTRIBUTE_UNUSED,
                         bfd_vma relocation,
                         asection *symbol_section ATTRIBUTE_UNUSED,
                         const char *symbol_name ATTRIBUTE_UNUSED,
                         struct elf_link_hash_entry *h ATTRIBUTE_UNUSED,
                         struct bfd_link_info *info ATTRIBUTE_UNUSED)
{
  bfd_size_type octets = (rel->r_offset * bfd_octets_per_byte (input_bfd,
							       input_section));
  relocation = agc_fixup_relocation_value (relocation, howto);

  return _bfd_relocate_contents (howto, input_bfd, relocation,
				 contents + octets);
}


/* Relocate an AGC ELF section.  */

static int
elf_agc_relocate_section (bfd *output_bfd,
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
  Elf_Internal_Shdr *symtab_hdr;
  struct elf_link_hash_entry **sym_hashes;

  symtab_hdr = &elf_symtab_hdr (input_bfd);
  sym_hashes = elf_sym_hashes (input_bfd);

  relend = relocs + input_section->reloc_count;
  for (rel = relocs; rel < relend; rel ++)
    {
      reloc_howto_type *howto;
      unsigned long r_symndx;
      Elf_Internal_Sym *sym;
      asection *sec;
      struct elf_link_hash_entry *h;
      bfd_vma relocation;
      bfd_reloc_status_type r;
      const char *name = NULL;
      int r_type;

      r_type = ELF32_R_TYPE (rel->r_info);
      r_symndx = ELF32_R_SYM (rel->r_info);
      howto = agc_reloc_type_lookup (input_bfd, r_type);
      h = NULL;
      sym = NULL;
      sec = NULL;

      if (r_symndx < symtab_hdr->sh_info)
	{
	    /* A relocation against a local symbol.  */

	  asection *osec;

	  sym = local_syms + r_symndx;
	  sec = local_sections [r_symndx];
	  osec = sec;

	  if ((sec->flags & SEC_MERGE)
	      && ELF_ST_TYPE (sym->st_info) == STT_SECTION)
	    {
	      /* This relocation is relative to a section symbol that is going
		  to be merged.  Change it so that it is relative to the merged
		  section symbol.  */
	      rel->r_addend = _bfd_elf_rel_local_sym (output_bfd, sym, &sec,
						      rel->r_addend);
	    }

	  /* Name of the symbol.  */
	  name = bfd_elf_string_from_elf_section
	    (input_bfd, symtab_hdr->sh_link, sym->st_name);
	  name = (name == NULL) ? bfd_section_name (osec) : name;

	  relocation = (sec->output_section->vma + sec->output_offset
			  + sym->st_value);
	}
      else
	{
	  /* A relocation against a global symbol.  */

	  bool unresolved_reloc, warned, ignored;

	  RELOC_FOR_GLOBAL_SYMBOL (info, input_bfd, input_section, rel,
				   r_symndx, symtab_hdr, sym_hashes,
				   h, sec, relocation,
				   unresolved_reloc, warned, ignored);

	  name = h->root.root.string;
	}

      if (sec != NULL && discarded_section (sec))
	RELOC_AGAINST_DISCARDED_SECTION (info, input_bfd, input_section,
                                         rel, 1, relend, howto, 0, contents);

      if (bfd_link_relocatable (info))
	continue;

      /* Patch in the relocation.  This is not needed if we are
	performing a relocatable link.  */
      r = agc_final_link_relocate (output_bfd, howto, input_bfd,
				    input_section, contents, rel,
				    relocation, sec, name, h, info);

      /* Handle any errors.  */
      if (r != bfd_reloc_ok)
	{
	  const char * msg = NULL;

	  switch (r)
	    {
	    case bfd_reloc_overflow:
	      info->callbacks->reloc_overflow
		(info, (h ? &h->root : NULL), name, howto->name,
		(bfd_vma) 0, input_bfd, input_section, rel->r_offset);
	      break;

	    case bfd_reloc_undefined:
	      info->callbacks->undefined_symbol
		(info, name, input_bfd, input_section, rel->r_offset, true);
	      break;

	    case bfd_reloc_outofrange:
	      msg = _("internal error: out of range error");
	      break;

	    case bfd_reloc_notsupported:
	      if (sym != NULL) /* Only if it's not an unresolved symbol.  */
		msg = _("unsupported relocation between data/insn address spaces");
	      break;

	    case bfd_reloc_dangerous:
	      msg = _("internal error: dangerous relocation");
	      break;

	    default:
	      msg = _("internal error: unknown error");
	      break;
	    }

	  if (msg)
	    info->callbacks->warning
	      (info, msg, name, input_bfd, input_section, rel->r_offset);

	  if (!r)
	    return false;
	}
    }

  return true;
}


#define ELF_ARCH               bfd_arch_agc
#define ELF_MACHINE_CODE       EM_AGC

#define ELF_MAXPAGESIZE        0x400

#define TARGET_LITTLE_SYM      agc_elf32_vec
#define TARGET_LITTLE_NAME     "elf32-agc"

#define bfd_elf32_bfd_reloc_type_lookup            agc_reloc_type_lookup
#define bfd_elf32_bfd_reloc_name_lookup            NULL

#define elf_backend_relocate_section               elf_agc_relocate_section

#define elf_info_to_howto_rel			   agc_info_to_howto_rel
#define elf_info_to_howto			   NULL

#include "elf32-target.h"
