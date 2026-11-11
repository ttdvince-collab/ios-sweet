#!/usr/bin/env python3
"""Boot a SWEETXNU payload (tools/mkpayload.py) in QEMU's virt board.

  qemu-sweet.py PAYLOAD OUTDIR [--secs N] [--gdb] [--live-serial]

Does what shim/loader.c does on the phone, but on the host: places the
kernel segments, ADT and boot_args at their physical addresses and starts
the CPU at a 6-instruction stub that jumps to the entry with x0 = boot_args.
virt RAM starts at 0x40000000; with 4G it covers the phone's framebuffer
(0x9c000000) and the kernel's phys_base (0xb0000000) as plain memory.

After N seconds (or when the guest stops) it writes into OUTDIR:
  fb.png     the 1080x2400 framebuffer (what the phone screen would show)
  regs.txt   QEMU's view of CPU state
  qemu.log   exceptions with ESR/FAR/ELR (-d int,guest_errors)

With --kernel KERNEL (the matching unstripped Mach-O), also decode the
framebuffer using its iso_font into fb.txt and write result.json. This is a
snapshot of the circular screen, not a complete boot log. --fail-on-panic
returns 2 when a panic is visible; absence of a panic does not prove boot.
An undecodable or blank screen returns 3 with --fail-on-panic.
"""
import argparse, json, os, shutil, socket, struct, subprocess, sys, time, zlib

FB_BASE, FB_W, FB_H = 0x9c000000, 1080, 2400
FB_STRIDE = FB_W * 4
PAGE = 0x4000
STUB_PA = 0x40200000	# above the dtb QEMU places at RAM base
BOOT_LINE_LENGTH = 608


def check_qemu_dependency(cpu='cortex-a76'):
    """Verify qemu-system-aarch64 binary and CPU model support."""
    qemu_bin = shutil.which('qemu-system-aarch64')
    if not qemu_bin:
        print('[!] Error: qemu-system-aarch64 not found in PATH.', file=sys.stderr)
        print('    Install instructions:', file=sys.stderr)
        print('      Arch Linux:    sudo pacman -S qemu-system-aarch64', file=sys.stderr)
        print('      Ubuntu/Debian: sudo apt install qemu-system-arm', file=sys.stderr)
        print('      Fedora:         sudo dnf install qemu-system-aarch64', file=sys.stderr)
        print('      macOS:          brew install qemu', file=sys.stderr)
        return False
    try:
        ver = subprocess.check_output([qemu_bin, '--version'], text=True).splitlines()[0]
        print(f'[*] Found QEMU: {ver}', file=sys.stderr)
    except Exception as e:
        print(f'[!] Warning: Failed to query QEMU version: {e}', file=sys.stderr)
        return False

    try:
        cpu_list = subprocess.check_output([qemu_bin, '-M', 'virt', '-cpu', 'help'], text=True)
        if cpu in cpu_list:
            print(f'[*] CPU model {cpu} supported', file=sys.stderr)
        else:
            print(f'[!] Warning: CPU model {cpu} not explicitly listed in qemu-system-aarch64 -cpu help', file=sys.stderr)
    except Exception:
        pass
    return True


def check_kernel_tools(kernel_path):
    """--kernel needs only the Mach-O itself (symbols are read in Python, no llvm-nm)."""
    if not os.path.isfile(kernel_path):
        print(f'[!] Error: kernel file does not exist: {kernel_path}', file=sys.stderr)
        return False
    return True


def macho_symbols(path, *names):
    """Return {name: value} for defined symbols of a 64-bit Mach-O (LC_SYMTAB)."""
    data = open(path, 'rb').read()
    magic, _, _, _, ncmds, _, _, _ = struct.unpack_from('<8I', data, 0)
    assert magic == 0xfeedfacf, 'not a 64-bit Mach-O'
    off, want, found = 32, {n.encode() for n in names}, {}
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<2I', data, off)
        if cmd == 0x2:	# LC_SYMTAB
            symoff, nsyms, stroff, _ = struct.unpack_from('<4I', data, off + 8)
            for i in range(nsyms):
                strx, ntype, _, _, value = struct.unpack_from('<IBBHQ', data, symoff + 16 * i)
                if ntype & 0x0e == 0:	# N_UNDF
                    continue
                end = data.index(b'\0', stroff + strx)
                name = data[stroff + strx:end]
                if name in want:
                    found[name.decode()] = value
        off += size
    return found


def qmp_memsave(mon, va, size, path):
    """Save guest VIRTUAL memory (current CPU translation) to path over QMP."""
    if isinstance(mon, tuple):
        s = socket.create_connection(mon)
    else:
        s = socket.socket(socket.AF_UNIX)
        s.connect(mon)
    f = s.makefile('rw')
    f.readline()
    for execute, args in (('qmp_capabilities', {}),
                          ('memsave', {'val': va, 'size': size, 'filename': path})):
        f.write(json.dumps({'execute': execute, 'arguments': args}) + '\n')
        f.flush()
        while True:
            r = json.loads(f.readline())
            if 'return' in r or 'error' in r:
                break
        if 'error' in r:
            s.close()
            raise RuntimeError(f'memsave {va:#x}: {r["error"]}')
    s.close()
    data = open(path, 'rb').read()
    os.unlink(path)
    return data


def dump_msgbuf(mon, msgbufp, out):
    """Write the kernel message buffer (struct msgbuf, bsd/sys/msgbuf.h) to out/kernel-log.txt."""
    ptr = struct.unpack('<Q', qmp_memsave(mon, msgbufp, 8, f'{out}/mb.tmp'))[0]
    magic, size, bufx, _, bufc = struct.unpack('<4IQ', qmp_memsave(mon, ptr, 24, f'{out}/mb.tmp'))
    if magic != 0x63061:
        raise RuntimeError(f'msgbuf magic {magic:#x} (kernel log not set up yet?)')
    raw = qmp_memsave(mon, bufc, size, f'{out}/mb.tmp')
    text = (raw[bufx:] + raw[:bufx]).replace(b'\0', b'').decode('utf-8', 'replace')
    open(f'{out}/kernel-log.txt', 'w', encoding='utf-8').write(text)
    return text


def build_image(payload):
    """Return (phys_base, [(pa, bytes)...], boot_args_pa, entry_pa, external_ramdisk_pa).

    A segment with no file data of 64 MB or more (mkpayload.py --ramdisk-external)
    is left out of the chunks: guest RAM starts zeroed and QEMU loads the file there.
    """
    magic, ver, nsegs = struct.unpack_from('<8sII', payload, 0)
    assert magic == b'SWEETXNU' and ver == 1, 'not a SWEETXNU v1 payload'
    virt_base, entry_va, adt_off, adt_size, kernel_end, phys_base, mem_size = \
        struct.unpack_from('<7Q', payload, 0x10)
    cmdline = payload[0x48:0x48 + BOOT_LINE_LENGTH]
    delta = phys_base - virt_base
    adt_pa = kernel_end + delta
    ba_pa = (adt_pa + adt_size + PAGE - 1) & ~(PAGE - 1)
    top = ba_pa + PAGE
    hole = None
    for i in range(nsegs):
        vmaddr, vmsize, foff, fsize = struct.unpack_from('<4Q', payload, 0x2a8 + 32 * i)
        if fsize == 0 and vmsize >= 64 << 20:
            hole = (vmaddr + delta, vmsize)
    low_top = hole[0] if hole else top
    img = bytearray(low_top - phys_base)
    hi_base = hole[0] + hole[1] if hole else top
    hi = bytearray(top - hi_base)
    def place(pa, data):
        if pa < low_top:
            img[pa - phys_base:pa - phys_base + len(data)] = data
        else:
            hi[pa - hi_base:pa - hi_base + len(data)] = data
    for i in range(nsegs):
        vmaddr, vmsize, foff, fsize = struct.unpack_from('<4Q', payload, 0x2a8 + 32 * i)
        if fsize:
            place(vmaddr + delta, payload[foff:foff + fsize])
    place(adt_pa, payload[adt_off:adt_off + adt_size])
    ba = struct.pack('<HH4x4Q6QI4xQI', 2, 2, virt_base, phys_base, mem_size, top,
                     FB_BASE, 1, FB_STRIDE, FB_W, FB_H, 32, 0, adt_pa - delta, adt_size)
    ba += cmdline + b'\0' * 4 + struct.pack('<QQ', 0, mem_size)
    assert len(ba) == 736
    place(ba_pa, ba)
    chunks = [(phys_base, bytes(img))] + ([(hi_base, bytes(hi))] if hole else [])
    return phys_base, chunks, ba_pa, entry_va + delta, hole[0] if hole else None


def stub(ba_pa, entry_pa):
    # ldr x0, =ba ; ldr x1, =entry ; br x1 ; nop ; .quad ba ; .quad entry
    return struct.pack('<4I2Q', 0x58000080, 0x580000a1, 0xd61f0020, 0xd503201f, ba_pa, entry_pa)


def write_png(path, raw):
    rows = []
    for y in range(FB_H):
        line = raw[y * FB_STRIDE:(y + 1) * FB_STRIDE]
        rgb = bytearray(FB_W * 3)	# a8r8g8b8 little endian = B G R A in memory
        rgb[0::3], rgb[1::3], rgb[2::3] = line[2::4], line[1::4], line[0::4]
        rows.append(b'\0' + bytes(rgb))
    chunk = lambda t, d: struct.pack('>I', len(d)) + t + d + struct.pack('>I', zlib.crc32(t + d))
    png = b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', FB_W, FB_H, 8, 2, 0, 0, 0))
    png += chunk(b'IDAT', zlib.compress(b''.join(rows), 6)) + chunk(b'IEND', b'')
    open(path, 'wb').write(png)


def payload_data(payload, va, size):
    """Read initialized segment bytes by VA (the payload has no slide)."""
    nsegs = struct.unpack_from('<I', payload, 12)[0]
    for i in range(nsegs):
        vmaddr, _, foff, fsize = struct.unpack_from('<4Q', payload, 0x2a8 + 32 * i)
        if vmaddr <= va and va + size <= vmaddr + fsize:
            offset = foff + va - vmaddr
            return payload[offset:offset + size]
    raise ValueError(f'VA {va:#x}+{size:#x} not in initialized payload segments')


def decode_screen(raw, font):
    """Exact glyph matching for pe_serial.c's 2x, white-on-black fbcon."""
    glyphs = {font[c * 16:(c + 1) * 16]: chr(c) for c in range(32, 127)}
    rows, unknown = [], 0
    for row in range(FB_H // 32):
        chars = []
        for col in range(FB_W // 16):
            glyph = bytearray(16)
            for y in range(16):
                offset = (row * 32 + y * 2) * FB_STRIDE + col * 16 * 4
                for x in range(8):
                    if raw[offset + x * 8:offset + x * 8 + 4] == b'\xff' * 4:
                        glyph[y] |= 1 << x
            key = bytes(glyph)
            char = glyphs.get(key, '?')
            unknown += key not in glyphs
            chars.append(char)
        rows.append(''.join(chars).rstrip())
    return '\n'.join(rows).rstrip() + '\n', unknown


def screen_result(screen, unknown):
    if 'panic(cpu ' in screen or 'SWEET EARLY PANIC:' in screen:
        status = 'panic'
    elif unknown:
        status = 'incomplete_decode'
    elif screen.strip():
        status = 'no_panic_observed'
    else:
        status = 'blank_screen'
    return {'status': status, 'unknown_glyphs': unknown, 'snapshot_only': True}


def qmp(sock_path, *cmds, pmemsave=None):
    """Run QEMU human-monitor commands over QMP (synchronous, unlike the echoing HMP socket)."""
    if isinstance(sock_path, tuple):	# Windows: no AF_UNIX in Python, use TCP
        s = socket.create_connection(sock_path)
    else:
        s = socket.socket(socket.AF_UNIX)
        s.connect(sock_path)
    f = s.makefile('rw')
    f.readline()

    def call(execute, **args):
        f.write(json.dumps({'execute': execute, 'arguments': args}) + '\n')
        f.flush()
        while True:
            r = json.loads(f.readline())
            if 'return' in r or 'error' in r:
                return r

    call('qmp_capabilities')
    out = []
    for c in cmds:
        r = call('human-monitor-command', **{'command-line': c})
        if 'error' in r:
            print(f'qmp {c!r}: {r["error"]}', file=sys.stderr)
        out.append(r.get('return', ''))
    if pmemsave:	# native QMP: HMP's argument parser chokes on '-' in paths
        r = call('pmemsave', val=pmemsave[0], size=pmemsave[1], filename=pmemsave[2])
        if 'error' in r:
            print(f'qmp pmemsave: {r["error"]}', file=sys.stderr)
    s.close()
    return out


def stream_serial_file(serial_path, file_pos, out_stream=sys.stdout):
    """Read newly appended content from serial.txt and write directly to stream."""
    if not os.path.exists(serial_path):
        return file_pos
    try:
        with open(serial_path, 'r', errors='replace') as f:
            f.seek(file_pos)
            data = f.read()
            if data:
                out_stream.write(data)
                out_stream.flush()
                return f.tell()
    except Exception:
        pass
    return file_pos


def main():
    ap = argparse.ArgumentParser(
        description="Boot a SWEETXNU payload in QEMU's virt board.",
        epilog="Examples:\n"
               "  qemu-sweet.py payload.bin out/\n"
               "  qemu-sweet.py payload.bin out/ --live-serial\n"
               "  qemu-sweet.py payload.bin out/ --kernel kernel.macho --fail-on-panic\n"
               "  qemu-sweet.py --check-env\n",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument('payload', nargs='?', help='SWEETXNU payload binary (from mkpayload.py)')
    ap.add_argument('outdir', nargs='?', help='Output directory for fb.png, regs.txt, and logs')
    ap.add_argument('--secs', type=float, default=20, help='Duration to run QEMU in seconds (default: 20; 0 = until OUTDIR/STOP exists)')
    ap.add_argument('--live-interval', type=float, default=0, help='save OUTDIR/live.png every N seconds while running')
    ap.add_argument('--live-raw', action='store_true', help='live frames as raw BGRA OUTDIR/live.raw instead of PNG')
    ap.add_argument('--vinput', type=int, default=0, help='serial (PL011) as TCP server on this port for virtual input (patch 0084)')
    ap.add_argument('--vnc', type=int, help='ramfb display + VNC server on 127.0.0.1:5900+N (fast live screen)')
    ap.add_argument('--trace', action='store_true', help='log every guest interrupt/exception to OUTDIR/qemu.log (slow)')
    ap.add_argument('--gdb', action='store_true', help='start halted, gdb stub on :1234, no timeout')
    ap.add_argument('--hmp', action='append', default=[], help='extra monitor command run after stop (repeatable), e.g. "x /8gx 0xfffffe..."')
    ap.add_argument('--cpu', default='cortex-a76', help='QEMU CPU model (default: cortex-a76)')
    ap.add_argument('--kernel', help='matching unstripped kernel, for exact framebuffer text decoding (also saves the full kernel log)')
    ap.add_argument('--fail-on-panic', action='store_true', help='exit 2 for a visible panic, 3 for incomplete/blank decoding; requires --kernel')
    ap.add_argument('--live-serial', action='store_true', help='stream serial console output to stdout in real time')
    ap.add_argument('--ramdisk', help='md0 root image for a payload built with mkpayload.py --ramdisk-external')
    ap.add_argument('--disk', help='root image as a virtio-blk disk (patch 0085: rd=ufsroot0 ufsvirtio=1)')
    ap.add_argument('--smp', type=int, default=1, help='CPU cores (boot-arg cpus= must match)')
    ap.add_argument('--check-env', action='store_true', help='check QEMU installation and dependencies without running a payload')
    a = ap.parse_args()

    if a.check_env:
        ok = check_qemu_dependency(a.cpu)
        if shutil.which('llvm-nm'):
            print('[*] llvm-nm found in PATH', file=sys.stderr)
        else:
            print('[!] Optional: llvm-nm not found (needed only when using --kernel for text decoding)', file=sys.stderr)
        return 0 if ok else 1

    if not a.payload or not a.outdir:
        ap.error('payload and outdir are required unless --check-env is specified')

    if a.fail_on_panic and not a.kernel:
        ap.error('--fail-on-panic requires --kernel')

    if not check_qemu_dependency(a.cpu):
        return 1

    if a.kernel and not check_kernel_tools(a.kernel):
        return 1

    payload = open(a.payload, 'rb').read()
    font = None
    if a.kernel:
        syms = macho_symbols(a.kernel, '_iso_font', '_msgbufp')
        if '_iso_font' not in syms:
            ap.error('kernel must contain an _iso_font symbol')
        font = payload_data(payload, syms['_iso_font'], 256 * 16)
    os.makedirs(a.outdir, exist_ok=True)
    out = os.path.abspath(a.outdir)

    phys_base, chunks, ba_pa, entry_pa, rd_pa = build_image(payload)
    if rd_pa is not None and not a.ramdisk:
        ap.error('payload was built with --ramdisk-external: pass the same image with --ramdisk')
    loaders = []
    for n, (pa, data) in enumerate(chunks):
        open(f'{out}/ram{n}.bin', 'wb').write(data)
        loaders += ['-device', f'loader,file={out}/ram{n}.bin,addr={pa:#x},force-raw=on']
    if rd_pa is not None:
        loaders += ['-device', f'loader,file={os.path.abspath(a.ramdisk)},addr={rd_pa:#x},force-raw=on']
        print(f'md0 root {a.ramdisk} at {rd_pa:#x}', file=sys.stderr)
    if a.vnc is not None:	# ramfb boot stub (tools/qemu-ramfb-stub.S)
        rs = bytearray(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'qemu-ramfb-stub.bin'), 'rb').read())
        d = 0x400
        struct.pack_into('<QQ', rs, d, ba_pa, entry_pa)
        # FWCfgDmaAccess: control (selector filled in by the stub), length, address of RAMFBCfg
        struct.pack_into('>IIQ', rs, d + 0x10, 0, 28, STUB_PA + d + 0x20)
        # RAMFBCfg: addr, fourcc XR24 (XRGB8888 = the panel's BGRA bytes), flags, width, height, stride
        # Shown to QEMU as 2160x1200 with two panel rows per line: QEMU's VNC server caps
        # the height at 2160, the panel is 2400 tall. Same bytes; the viewer reads them
        # back as 1080x2400 (launcher VncClient, tools-bin/vncgrab.py).
        struct.pack_into('>QIIIII', rs, d + 0x20, FB_BASE, 0x34325258, 0, FB_W * 2, FB_H // 2, FB_STRIDE * 2)
        open(f'{out}/stub.bin', 'wb').write(rs)
    else:
        open(f'{out}/stub.bin', 'wb').write(stub(ba_pa, entry_pa))
    print(f'phys_base={phys_base:#x} boot_args={ba_pa:#x} entry={entry_pa:#x}', file=sys.stderr)

    if hasattr(socket, 'AF_UNIX') and os.name != 'nt':
        mon = f'{out}/mon.sock'
        if os.path.exists(mon):
            os.unlink(mon)
        qmp_arg = f'unix:{mon},server,nowait'
    else:
        mon = ('127.0.0.1', 4444)
        qmp_arg = 'tcp:127.0.0.1:4444,server,nowait'
    # virt RAM starts at 0x40000000: cover the payload's RAM (mkadt.py --highmem needs 8G).
    mem_size = struct.unpack_from('<Q', payload, 0x40)[0]
    ram_gib = max(4, -(-(phys_base + mem_size - 0x40000000) // (1 << 30)))
    machine = 'virt,gic-version=3'	# no EL2/EL3: QEMU emulates PSCI over HVC (sweethvc=1)
    serial = f'tcp:127.0.0.1:{a.vinput},server,nowait' if a.vinput else f'file:{out}/serial.txt'
    trace = ['-d', 'int,guest_errors,unimp', '-D', f'{out}/qemu.log'] if a.trace else []
    cmd = ['qemu-system-aarch64', '-M', machine, '-accel', 'tcg,thread=multi,tb-size=1024', '-cpu', a.cpu,
           '-smp', str(a.smp), '-m', f'{ram_gib}G',
           *(['-display', 'none', '-monitor', 'none', '-device', 'ramfb', '-vnc', f'127.0.0.1:{a.vnc}']
             if a.vnc is not None else ['-nographic']),
           '-serial', serial, '-qmp', qmp_arg, *trace, '-no-reboot',
           *loaders,
           *(['-drive', f'file={os.path.abspath(a.disk)},if=none,format=raw,id=root,cache=writeback',
              '-device', 'virtio-blk-device,drive=root',
              '-global', 'virtio-mmio.force-legacy=false'] if a.disk else []),
           '-device', f'loader,file={out}/stub.bin,addr={STUB_PA:#x},force-raw=on',
           '-device', f'loader,addr={STUB_PA:#x},cpu-num=0']
    if a.gdb:
        cmd += ['-S', '-gdb', 'tcp::1234']

    p = None
    serial_file = f'{out}/serial.txt'
    serial_pos = 0

    try:
        p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL)
        if a.gdb:
            print('gdb stub on :1234; QMP socket:', mon, file=sys.stderr)
            p.wait()
            return 0

        t0 = last_live = time.time()
        stop_file = f'{out}/STOP'
        if os.path.exists(stop_file):
            os.unlink(stop_file)
        while p.poll() is None and (a.secs <= 0 or time.time() - t0 < a.secs):
            if os.path.exists(stop_file):
                print('[*] stop requested', file=sys.stderr)
                break
            if a.live_serial:
                serial_pos = stream_serial_file(serial_file, serial_pos)
            if a.live_interval and time.time() - last_live >= a.live_interval:
                last_live = time.time()
                try:	# pmemsave works while the guest keeps running
                    qmp(mon, pmemsave=(FB_BASE, FB_STRIDE * FB_H, f'{out}/live.tmp.raw'))
                    if a.live_raw:	# the launcher reads raw BGRA: no PNG encoding
                        os.replace(f'{out}/live.tmp.raw', f'{out}/live.raw')
                    else:
                        write_png(f'{out}/live.tmp.png', open(f'{out}/live.tmp.raw', 'rb').read())
                        os.replace(f'{out}/live.tmp.png', f'{out}/live.png')
                    print(f'[live] {time.time() - t0:.0f}s', file=sys.stderr, flush=True)
                except (OSError, ValueError) as e:	# QMP not up yet, or a reader holds the file
                    print(f'[live] skipped: {e}', file=sys.stderr, flush=True)
            time.sleep(0.03 if a.live_raw else 0.2)

        if a.live_serial:
            stream_serial_file(serial_file, serial_pos)

        result = {'status': 'qemu_exited', 'qemu_returncode': p.returncode}
        if p.poll() is None:
            _, regs, *extra = qmp(mon, 'stop', 'info registers', *a.hmp, pmemsave=(FB_BASE, FB_STRIDE * FB_H, f'{out}/fb.raw'))
            open(f'{out}/regs.txt', 'w').write(regs + ''.join(f'\n(qemu) {c}\n{r}' for c, r in zip(a.hmp, extra)))
            if a.kernel and '_msgbufp' in syms:
                try:
                    log = dump_msgbuf(mon, syms['_msgbufp'], out)
                    print(f'[*] kernel log: {len(log.splitlines())} lines -> {out}/kernel-log.txt', file=sys.stderr)
                except Exception as e:
                    print(f'[!] kernel log not read: {e}', file=sys.stderr)
            p.kill()
            p.wait()
            raw = open(f'{out}/fb.raw', 'rb').read()
            write_png(f'{out}/fb.png', raw)
            result = {'status': 'not_decoded'}
            if font is not None:
                screen, unknown = decode_screen(raw, font)
                open(f'{out}/fb.txt', 'w').write(screen)
                result = screen_result(screen, unknown)
            os.unlink(f'{out}/fb.raw')
        else:
            print(f'qemu exited early: {p.returncode}', file=sys.stderr)

        open(f'{out}/result.json', 'w').write(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result), file=sys.stderr)
        print(f'{out}/fb.png  {out}/regs.txt  {out}/qemu.log', file=sys.stderr)
        if a.fail_on_panic and result['status'] == 'panic':
            return 2
        if a.fail_on_panic and result['status'] in ('incomplete_decode', 'blank_screen'):
            return 3
        if result['status'] == 'qemu_exited':
            return 1
        return 0

    except KeyboardInterrupt:
        print('\n[!] Interrupted by user, stopping QEMU...', file=sys.stderr)
        if p and p.poll() is None:
            p.kill()
            p.wait()
        return 130
    finally:
        for n in range(2):
            ram_file = f'{out}/ram{n}.bin'
            if os.path.exists(ram_file):
                try:
                    os.unlink(ram_file)
                except Exception:
                    pass


if __name__ == '__main__':
    sys.exit(main())
