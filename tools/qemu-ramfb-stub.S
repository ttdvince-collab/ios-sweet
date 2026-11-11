// Boot stub for tools/qemu-sweet.py --ramfb: before jumping into the kernel,
// point QEMU's ramfb display device (-device ramfb) at the SWEET panel memory,
// so QEMU itself scans it out (VNC/SDL) instead of the host copying 10 MB
// frames over QMP. The guest only has to write "etc/ramfb" once through the
// fw_cfg DMA interface; no kernel change.
//
// QEMU virt fw_cfg MMIO (big-endian registers): data 0x09020000 (byte reads),
// selector 0x09020008 (16 bit), DMA address 0x09020010 (writing the low word
// at +0x14 starts the transfer).
//
// qemu-sweet.py fills the data block at DATA:
//   +0x00 u64 boot_args_pa, +0x08 u64 kernel_entry_pa,
//   +0x10 FWCfgDmaAccess {be32 control, be32 length, be64 address} (control's
//         selector is filled in here), +0x20 RAMFBCfg (28 bytes, big-endian)
// Build:
//   aarch64-linux-gnu-as -o s.o qemu-ramfb-stub.S
//   aarch64-linux-gnu-objcopy -O binary s.o qemu-ramfb-stub.bin

	.equ	FWCFG, 0x09020000
	.equ	DATA, 0x400
	.equ	DIR_SELECT, 0x0019

	.text
	.globl	_start
_start:
base:
	ldr	x20, =FWCFG
	adr	x21, base
	add	x21, x21, #DATA

	// fw_cfg file directory: be32 count, then 64-byte entries
	// {be32 size, be16 select, u16 reserved, char name[56]}
	mov	w0, #DIR_SELECT
	rev16	w0, w0
	strh	w0, [x20, #8]
	bl	read_be32
	mov	w22, w0			// entries left
	mov	w23, #0			// selector found (0 = none)
next_entry:
	cbz	w22, done_search
	sub	w22, w22, #1
	bl	read_be32		// size (unused)
	bl	read_byte		// select, big-endian
	lsl	w24, w0, #8
	bl	read_byte
	orr	w24, w24, w0
	bl	read_byte		// reserved
	bl	read_byte
	adr	x25, name		// compare the 56-byte name with "etc/ramfb\0"
	mov	w26, #0			// mismatch flag
	mov	w27, #56
name_loop:
	bl	read_byte
	cmp	w27, #(56 - 10)		// only the first 10 bytes matter
	b.le	name_skip
	ldrb	w1, [x25], #1
	cmp	w0, w1
	csinc	w26, w26, w26, eq	// w26++ on mismatch
name_skip:
	subs	w27, w27, #1
	b.ne	name_loop
	cbnz	w26, next_entry
	mov	w23, w24
done_search:
	cbz	w23, boot		// no ramfb device: just boot

	// control = (select << 16) | SELECT (0x08) | WRITE (0x10), big-endian
	lsl	w0, w23, #16
	orr	w0, w0, #0x18
	rev	w0, w0
	str	w0, [x21, #0x10]
	add	x0, x21, #0x10		// physical address of the DMA descriptor
	dsb	sy
	lsr	x1, x0, #32
	rev	w1, w1
	str	w1, [x20, #0x10]	// high word
	rev	w0, w0
	str	w0, [x20, #0x14]	// low word: starts the DMA
wait_dma:
	ldr	w0, [x21, #0x10]
	rev	w0, w0
	tst	w0, #0x1		// error bit: give up waiting, boot anyway
	b.ne	boot
	cbnz	w0, wait_dma

boot:
	ldr	x0, [x21]		// boot args
	ldr	x1, [x21, #8]		// kernel entry
	br	x1

read_byte:				// w0 = next fw_cfg data byte
	ldrb	w0, [x20]
	ret

read_be32:				// w0 = next 4 data bytes, big-endian
	mov	x28, x30
	bl	read_byte
	lsl	w2, w0, #24
	bl	read_byte
	orr	w2, w2, w0, lsl #16
	bl	read_byte
	orr	w2, w2, w0, lsl #8
	bl	read_byte
	orr	w0, w2, w0
	mov	x30, x28
	ret

name:
	.asciz	"etc/ramfb"
	.ltorg

	.org	DATA
	.fill	0x40, 1, 0
