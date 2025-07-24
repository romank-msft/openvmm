/*
 * Copyright(c) Microsoft Corporation.
 *
 * Licensed under the MIT License.
 */

/*
 * This is a linker script for the minimal runtime on aarch64.
 * 
 * It provides the section layout suitable for the bootcode running
 * without the standard library. It also provides linker symbols
 * required for the minimal runtime to initialize correctly when
 * relocating the executable.
 *
 * There are no baremetal stable Rust targets producing static PIE files
 * for aarch64 and relying on the system toolchain comes with the perils
 * of the toolchain and distribution differences. This linker script
 * removes variance in the section layout and most importantly symbols
 * defined by the linker across toolchains and distributions.
 *
 * The unwind tabdles are discarded, as they cannot be handled
 * by the minimal runtime. The initialization and finalization
 * sections are not kept as they shouldn't be produced for the
 * minimal runtime -- there is no main function, and the running code
 * before the code's entry point is not possible. PLT sections are
 * discarded as weell as they can't be used meaningfully in the bootcode.
 *
 * There is page alignment after the text section and after the read-only
 * data section to ensure that the data sections can be granted appropriate
 * permissions if desired.
 */

OUTPUT_FORMAT("elf64-littleaarch64")
OUTPUT_ARCH("aarch64")
ENTRY(_start)

SECTIONS
{
  . = SEGMENT_START("text-segment", 0) + SIZEOF_HEADERS;

  /* Code section */
  .text : ALIGN(4K) { *(.text.*unlikely*) *(.text.*hot*) *(.text .text.*) }

  /* Read-only data */  
  .rodata : ALIGN(4K) { *(.rodata .rodata.*) }

  . = ALIGN(8);

  /* Relocation data */
  .dynamic :    { *(.dynamic) }
  .rela.dyn :   { *(.rela .rela.*) }
  .relr.dyn :   { *(.relr.dyn .relr.dyn.*) }

  . = ALIGN(8);

  /* Data */
  .data : ALIGN(4K) {*(.data .data.*) }

  . = ALIGN(8);

  /* Uninitialized data */
  PROVIDE (__bss_start__ = .);
  .bss (NOLOAD) : {*(.bss .bss.*) *(COMMON) }

  . = ALIGN(8);

  PROVIDE (__bss_end__ = .);

  /* For binary provenance */
  .note.gnu.build-id : ALIGN(8) { *(.note.gnu.build-id) }

  /* Keep the link to the debug info file when the file is stripped */
  .gnu_debuglink :     ALIGN(8) { *(.gnu_debuglink) }

  /* DWARF debug sections */

  /* DWARF 1.  */
  .debug 0 : { *(.debug) }
  .line 0 :  { *(.line) }

  /* GNU DWARF 1 extensions.  */
  .debug_srcinfo 0 : { *(.debug_srcinfo) }
  .debug_sfnames 0 : { *(.debug_sfnames) }

  /* DWARF 1.1 and DWARF 2.  */
  .debug_aranges 0 : { *(.debug_aranges) }
  .debug_pubnames 0 : { *(.debug_pubnames) }

  /* DWARF 2.  */
  .debug_info 0 :    { *(.debug_info .gnu.linkonce.wi.*) }
  .debug_abbrev 0 :  { *(.debug_abbrev) }
  .debug_line 0 :    { *(.debug_line .debug_line.* .debug_line_end) }
  .debug_frame 0 :   { *(.debug_frame) }
  .debug_str 0 :     { *(.debug_str) }
  .debug_loc 0 :     { *(.debug_loc) }
  .debug_macinfo 0 : { *(.debug_macinfo) }

  /* DWARF 3.  */
  .debug_pubtypes 0 :  { *(.debug_pubtypes) }
  .debug_ranges 0 :    { *(.debug_ranges) }

  /* DWARF 5.  */
  .debug_addr 0 :        { *(.debug_addr) }
  .debug_line_str 0 :    { *(.debug_line_str) }
  .debug_loclists 0 :    { *(.debug_loclists) }
  .debug_macro 0 :       { *(.debug_macro) }
  .debug_names 0 :       { *(.debug_names) }
  .debug_rnglists 0 :    { *(.debug_rnglists) }
  .debug_str_offsets 0 : { *(.debug_str_offsets) }
  .debug_sup 0 :         { *(.debug_sup) }
  .gnu.attributes 0 :   { KEEP (*(.gnu.attributes)) }

  /DISCARD/ : {
    *(.note.GNU-stack)
    *(.gnu.lto_*)
    *(.gnu_object_only)
    *(.eh_frame)
    *(.eh_frame_hdr)
    *(.gcc_except_table)
    *(.gcc_except_table.*)
    *(.init_array.*)
    *(.fini_array.*)
    *(.ctors)
    *(.dtors)
    *(.init)
    *(.dynsym)
    *(.dynsym.*)
    *(.dynstr)
    *(.dynstr.*)
    *(.interp)
    *(.comment)
    *(.gnu.version)
    *(.gnu.hash)   
  }
}
