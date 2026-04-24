#!/usr/bin/env python3
"""
drm_stimulate.py — Background DRM activity generator for trace tests.

Triggers bpftrace probes that need active GPU/display:
  - xe_sched_job_run   (via NOP Xe GPU job loop on BCS engine)
  - dma_fence_signal   (side-effect of GPU jobs completing)
  - drm_handle_vblank  (via pygame color cycling through the compositor)

Usage: sudo python3 drm_stimulate.py [--render /dev/dri/renderD128]
       Run in background; send SIGTERM to stop.

Requires: python3-pygame (sudo apt install python3-pygame)
"""
import argparse
import ctypes
import ctypes.util
import glob
import mmap
import os
import signal
import sys
import time

# ── Signal handling ───────────────────────────────────────────────────────────
_running = True
def _on_sig(*_):
    global _running
    _running = False
signal.signal(signal.SIGTERM, _on_sig)
signal.signal(signal.SIGINT,  _on_sig)

# ── libc ioctl wrapper ────────────────────────────────────────────────────────
def _libc():
    lib = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    lib.ioctl.restype  = ctypes.c_int
    lib.ioctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_void_p]
    return lib

_LC = _libc()

def _ioctl(fd, req, arg=None):
    if arg is None:
        return _LC.ioctl(fd, ctypes.c_ulong(req), ctypes.c_void_p(0))
    if isinstance(arg, ctypes.Structure):
        return _LC.ioctl(fd, ctypes.c_ulong(req), ctypes.byref(arg))
    return _LC.ioctl(fd, ctypes.c_ulong(req), arg)

# ── ioctl number helpers ──────────────────────────────────────────────────────
def _IOC(d, t, n, s): return (d << 30) | (t << 8) | n | (s << 16)
_IOWR = lambda t, n, s: _IOC(3, t, n, s)
_IOW  = lambda t, n, s: _IOC(1, t, n, s)
B   = ord('d')
CMD = 0x40   # DRM_COMMAND_BASE

# ── DRM core ─────────────────────────────────────────────────────────────────
class DrmGemClose(ctypes.Structure):
    _fields_ = [("handle", ctypes.c_uint32), ("pad", ctypes.c_uint32)]
DRM_IOCTL_GEM_CLOSE  = _IOW(B, 0x09, ctypes.sizeof(DrmGemClose))

# ── Xe structures ─────────────────────────────────────────────────────────────
class XeVmCreate(ctypes.Structure):
    _fields_ = [
        ("extensions", ctypes.c_uint64), ("flags", ctypes.c_uint32),
        ("vm_id", ctypes.c_uint32), ("reserved", ctypes.c_uint64 * 2),
    ]
DRM_XE_VM_CREATE_FLAG_SCRATCH_PAGE = 1
DRM_IOCTL_XE_VM_CREATE = _IOWR(B, CMD + 0x03, ctypes.sizeof(XeVmCreate))

class XeVmDestroy(ctypes.Structure):
    _fields_ = [
        ("vm_id", ctypes.c_uint32), ("pad", ctypes.c_uint32),
        ("reserved", ctypes.c_uint64 * 2),
    ]
DRM_IOCTL_XE_VM_DESTROY = _IOW(B, CMD + 0x04, ctypes.sizeof(XeVmDestroy))

class XeGemCreate(ctypes.Structure):
    _fields_ = [
        ("extensions", ctypes.c_uint64), ("size", ctypes.c_uint64),
        ("placement", ctypes.c_uint32), ("flags", ctypes.c_uint32),
        ("vm_id", ctypes.c_uint32), ("handle", ctypes.c_uint32),
        ("cpu_caching", ctypes.c_uint16), ("pad", ctypes.c_uint16 * 3),
        ("reserved", ctypes.c_uint64 * 2),
    ]
DRM_XE_GEM_CPU_CACHING_WB = 1
DRM_IOCTL_XE_GEM_CREATE = _IOWR(B, CMD + 0x01, ctypes.sizeof(XeGemCreate))

class XeGemMmapOffset(ctypes.Structure):
    _fields_ = [
        ("extensions", ctypes.c_uint64), ("handle", ctypes.c_uint32),
        ("flags", ctypes.c_uint32), ("offset", ctypes.c_uint64),
        ("reserved", ctypes.c_uint64 * 2),
    ]
DRM_IOCTL_XE_GEM_MMAP_OFFSET = _IOWR(B, CMD + 0x02, ctypes.sizeof(XeGemMmapOffset))

# VM_BIND with inline bind_op (num_binds=1) — mirrors struct drm_xe_vm_bind
# when num_binds==1: the union field 'bind' is an inline drm_xe_vm_bind_op.
# Layout matches kernel 6.17+ UAPI where pat_index is u16 right after obj.
class XeVmBind(ctypes.Structure):
    _fields_ = [
        ("extensions",      ctypes.c_uint64),   # offset  0
        ("vm_id",           ctypes.c_uint32),   #         8
        ("exec_queue_id",   ctypes.c_uint32),   #        12
        ("pad",             ctypes.c_uint32),   #        16
        ("num_binds",       ctypes.c_uint32),   #        20
        # inline drm_xe_vm_bind_op at offset 24
        ("bind_extensions", ctypes.c_uint64),   #        24
        ("bind_obj",        ctypes.c_uint32),   #        32  (GEM handle; 0 for unmap)
        ("bind_pat_index",  ctypes.c_uint16),   #        36  (PAT index for caching/coherency)
        ("bind_obj_pad",    ctypes.c_uint16),   #        38
        ("bind_obj_offset", ctypes.c_uint64),   #        40
        ("bind_range",      ctypes.c_uint64),   #        48
        ("bind_addr",       ctypes.c_uint64),   #        56
        ("bind_op",         ctypes.c_uint32),   #        64  (0=MAP, 1=UNMAP)
        ("bind_flags",      ctypes.c_uint32),   #        68
        ("bind_prefetch",   ctypes.c_uint32),   #        72
        ("bind_op_pad",     ctypes.c_uint32),   #        76
        ("bind_reserved",   ctypes.c_uint64 * 2), #      80–96
        ("pad2",            ctypes.c_uint32),   #        96
        ("num_syncs",       ctypes.c_uint32),   #       100
        ("syncs",           ctypes.c_uint64),   #       104
        ("reserved",        ctypes.c_uint64 * 2), #     112–128
    ]
DRM_XE_VM_BIND_OP_MAP   = 0
DRM_XE_VM_BIND_OP_UNMAP = 1
DRM_IOCTL_XE_VM_BIND = _IOWR(B, CMD + 0x05, ctypes.sizeof(XeVmBind))

class XeEngineClassInstance(ctypes.Structure):
    _fields_ = [
        ("engine_class", ctypes.c_uint16), ("engine_instance", ctypes.c_uint16),
        ("gt_id", ctypes.c_uint16), ("pad", ctypes.c_uint16),
    ]

class XeExecQueueCreate(ctypes.Structure):
    _fields_ = [
        ("extensions", ctypes.c_uint64),
        ("width", ctypes.c_uint16), ("num_placements", ctypes.c_uint16),
        ("vm_id", ctypes.c_uint32), ("flags", ctypes.c_uint32),
        ("exec_queue_id", ctypes.c_uint32), ("instances", ctypes.c_uint64),
        ("reserved", ctypes.c_uint64 * 2),
    ]
DRM_XE_ENGINE_CLASS_COPY = 1
DRM_IOCTL_XE_EXEC_QUEUE_CREATE = _IOWR(B, CMD + 0x06, ctypes.sizeof(XeExecQueueCreate))

class XeExecQueueDestroy(ctypes.Structure):
    _fields_ = [
        ("exec_queue_id", ctypes.c_uint32), ("pad", ctypes.c_uint32),
        ("reserved", ctypes.c_uint64 * 2),
    ]
DRM_IOCTL_XE_EXEC_QUEUE_DESTROY = _IOW(B, CMD + 0x07, ctypes.sizeof(XeExecQueueDestroy))

class XeExec(ctypes.Structure):
    _fields_ = [
        ("extensions", ctypes.c_uint64),
        ("exec_queue_id", ctypes.c_uint32), ("num_syncs", ctypes.c_uint32),
        ("syncs", ctypes.c_uint64), ("address", ctypes.c_uint64),
        ("num_batch_buffer", ctypes.c_uint16), ("pad", ctypes.c_uint16 * 3),
        ("reserved", ctypes.c_uint64 * 2),
    ]
DRM_IOCTL_XE_EXEC = _IOW(B, CMD + 0x09, ctypes.sizeof(XeExec))

PAGE_SIZE    = 4096
BATCH_GPU_VA = 0x1_000_000   # 16 MiB into GPU VA space
# MI_NOOP (0x00000000) + MI_BATCH_BUFFER_END (0x05000000) in little-endian
NOP_BATCH = b'\x00\x00\x00\x00\x00\x00\x00\x05'

# ── Device helpers ────────────────────────────────────────────────────────────
def _find_xe_card():
    for card in sorted(glob.glob("/dev/dri/card[0-9]*")):
        idx = card.replace("/dev/dri/card", "")
        try:
            drv = os.path.basename(
                os.readlink(f"/sys/class/drm/card{idx}/device/driver"))
            if "xe" in drv:
                # Find actual render node via sysfs
                render_nodes = glob.glob(f"/sys/class/drm/card{idx}/device/drm/renderD*")
                if render_nodes:
                    rn = os.path.basename(render_nodes[0])
                    return card, f"/dev/dri/{rn}"
                return card, None
        except (OSError, ValueError):
            pass
    return None, None

# ── Xe NOP GPU loop ───────────────────────────────────────────────────────────
def xe_nop_loop(render_dev: str) -> None:
    """Submit NOP BCS jobs in a tight loop — triggers xe_sched_job_run."""
    try:
        fd = os.open(render_dev, os.O_RDWR)
    except OSError as e:
        print(f"[stimulate] Cannot open {render_dev}: {e}", flush=True)
        return

    vm_id = eq_id = handle = 0
    mapped = None
    try:
        # VM
        vm = XeVmCreate(flags=DRM_XE_VM_CREATE_FLAG_SCRATCH_PAGE)
        if _ioctl(fd, DRM_IOCTL_XE_VM_CREATE, vm) != 0:
            return
        vm_id = vm.vm_id

        # GEM (4 KB system memory)
        gem = XeGemCreate(size=PAGE_SIZE, placement=1, vm_id=0,
                          cpu_caching=DRM_XE_GEM_CPU_CACHING_WB)
        if _ioctl(fd, DRM_IOCTL_XE_GEM_CREATE, gem) != 0:
            return
        handle = gem.handle

        # CPU map
        mmap_arg = XeGemMmapOffset(handle=handle)
        if _ioctl(fd, DRM_IOCTL_XE_GEM_MMAP_OFFSET, mmap_arg) != 0:
            return
        mapped = mmap.mmap(fd, PAGE_SIZE, mmap.MAP_SHARED,
                           mmap.PROT_READ | mmap.PROT_WRITE,
                           offset=mmap_arg.offset)
        mapped.write(NOP_BATCH)
        # No flush — GPU WC/WB mapping doesn't support msync

        # VM_BIND: map GEM at BATCH_GPU_VA (synchronous, exec_queue_id=0)
        # pat_index=1 required for WB-cached objects (coherent mapping)
        bind = XeVmBind(vm_id=vm_id, num_binds=1,
                        bind_obj=handle, bind_range=PAGE_SIZE,
                        bind_addr=BATCH_GPU_VA, bind_pat_index=1,
                        bind_op=DRM_XE_VM_BIND_OP_MAP)
        if _ioctl(fd, DRM_IOCTL_XE_VM_BIND, bind) != 0:
            return

        # Exec queue (BCS/copy engine)
        inst = XeEngineClassInstance(engine_class=DRM_XE_ENGINE_CLASS_COPY)
        eq = XeExecQueueCreate(width=1, num_placements=1, vm_id=vm_id,
                               instances=ctypes.addressof(inst))
        if _ioctl(fd, DRM_IOCTL_XE_EXEC_QUEUE_CREATE, eq) != 0:
            return
        eq_id = eq.exec_queue_id
        print(f"[stimulate] Xe NOP loop started (vm={vm_id} eq={eq_id})", flush=True)

        # Submit NOP jobs until asked to stop
        while _running:
            ex = XeExec(exec_queue_id=eq_id, num_batch_buffer=1,
                        address=BATCH_GPU_VA)
            _ioctl(fd, DRM_IOCTL_XE_EXEC, ex)
            time.sleep(0.05)   # 20 jobs/s keeps the scheduler busy

    finally:
        if eq_id:
            d = XeExecQueueDestroy(exec_queue_id=eq_id)
            _ioctl(fd, DRM_IOCTL_XE_EXEC_QUEUE_DESTROY, d)
        if handle:
            # Unbind from GPU VA
            unbind = XeVmBind(vm_id=vm_id, num_binds=1,
                              bind_range=PAGE_SIZE, bind_addr=BATCH_GPU_VA,
                              bind_op=DRM_XE_VM_BIND_OP_UNMAP)
            _ioctl(fd, DRM_IOCTL_XE_VM_BIND, unbind)
            if mapped:
                mapped.close()
            cl = DrmGemClose(handle=handle)
            _ioctl(fd, DRM_IOCTL_GEM_CLOSE, cl)
        if vm_id:
            vmd = XeVmDestroy(vm_id=vm_id)
            _ioctl(fd, DRM_IOCTL_XE_VM_DESTROY, vmd)
        os.close(fd)
        print("[stimulate] Xe NOP loop stopped", flush=True)

# ── Display flash loop (triggers vblank via compositor scanout) ────────────────
def flash_screen_loop():
    """Cycle colors via pygame/SDL on Wayland — forces compositor page flips."""
    # Find Wayland socket
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    if xdg:
        socks = sorted(glob.glob(os.path.join(xdg, "wayland-*")))
        if not socks:
            socks = []
    else:
        socks = []

    if not socks:
        candidates = sorted(glob.glob("/run/user/*/wayland-*"))
        candidates = [c for c in candidates if not c.endswith(".lock")]
        if not candidates:
            print("[stimulate] No Wayland socket found — display flash skipped",
                  flush=True)
            return
        xdg = os.path.dirname(candidates[0])
        socks = [candidates[0]]

    wayland_display = os.path.basename(socks[0])
    os.environ["XDG_RUNTIME_DIR"] = xdg
    os.environ["WAYLAND_DISPLAY"] = wayland_display
    os.environ.setdefault("SDL_VIDEODRIVER", "wayland")

    try:
        import pygame
    except ImportError:
        print("[stimulate] pygame not installed — display flash skipped\n"
              "  Install with: sudo apt install python3-pygame", flush=True)
        return

    pygame.init()
    try:
        info = pygame.display.Info()
        w, h = info.current_w, info.current_h
        if not w or not h:
            w, h = 1920, 1080
    except Exception:
        w, h = 1920, 1080

    screen = pygame.display.set_mode((w, h), pygame.SCALED)
    colors = [(255, 0, 0), (0, 255, 0), (0, 0, 255),
              (255, 255, 255), (0, 0, 0)]
    print(f"[stimulate] Display flash started ({w}×{h})", flush=True)

    idx = 0
    clock = pygame.time.Clock()
    while _running:
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                pygame.quit()
                print("[stimulate] Display flash stopped", flush=True)
                return
        screen.fill(colors[idx % len(colors)])
        pygame.display.flip()
        idx += 1
        clock.tick(2)   # ~2 fps, enough to keep scanout busy

    pygame.quit()
    print("[stimulate] Display flash stopped", flush=True)

# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        description="Background DRM stimulator — triggers vblank + GPU probes")
    ap.add_argument("--render", default=None)
    args = ap.parse_args()

    xe_card, xe_render = _find_xe_card()
    render = args.render or xe_render or "/dev/dri/renderD128"

    import threading
    flash = threading.Thread(target=flash_screen_loop, daemon=True)
    flash.start()

    if render and os.path.exists(render):
        xe_nop_loop(render)
    else:
        while _running:
            time.sleep(0.1)

    flash.join(timeout=3)

if __name__ == "__main__":
    main()
