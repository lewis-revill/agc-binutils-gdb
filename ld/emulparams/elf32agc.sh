# TODO: Work through this file, figure out what else we need.

SCRIPT_NAME=elf
TEMPLATE_NAME=elf
OUTPUT_FORMAT="elf32-agc"
ARCH=agc
ELFSIZE=32

NO_REL_RELOCS=yes
EMBEDDED=yes

ENTRY=_start
TEXT_START_ADDR=0x1000
MAXPAGESIZE=0x400
