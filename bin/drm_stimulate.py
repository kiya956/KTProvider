#!/usr/bin/env python3
"""
drm_stimulate.py — Background DRM activity generator for trace tests.

Triggers bpftrace probes that need active GPU/display:
  - xe_sched_job_run   (via NOP Xe GPU job loop on BCS engine)
  - dma_fence_signal   (side-effect of GPU jobs completing)
  - drm_handle_vblank  (via KMS page-flip loop if a display is connected)

Usage: sudo python3 drm_stimulate.py [--card /dev/dri/card1]
       Run in background; send SIGTERM to stop.
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
_IO   = lambda t, n:    _IOC(0, t, n, 0)
B   = ord('d')
CMD = 0x40   # DRM_COMMAND_BASE

# ── DRM core ─────────────────────────────────────────────────────────────────
class DrmGemClose(ctypes.Structure):
    _fields_ = [("handle", ctypes.c_uint32), ("pad", ctypes.c_uint32)]
DRM_IOCTL_GEM_CLOSE  = _IOW(B, 0x09, ctypes.sizeof(DrmGemClose))
DRM_IOCTL_SET_MASTER  = _IO(B, 0x1e)
DRM_IOCTL_DROP_MASTER = _IO(B, 0x1f)

# ── KMS structures ────────────────────────────────────────────────────────────
class DrmModeCardRes(ctypes.Structure):
    _fields_ = [
        ("fb_id_ptr", ctypes.c_uint64), ("crtc_id_ptr", ctypes.c_uint64),
        ("connector_id_ptr", ctypes.c_uint64), ("encoder_id_ptr", ctypes.c_uint64),
        ("count_fbs", ctypes.c_uint32), ("count_crtcs", ctypes.c_uint32),
        ("count_connectors", ctypes.c_uint32), ("count_encoders", ctypes.c_uint32),
        ("min_width", ctypes.c_uint32), ("max_width", ctypes.c_uint32),
        ("min_height", ctypes.c_uint32), ("max_height", ctypes.c_uint32),
    ]

class DrmModeModeInfo(ctypes.Structure):
    _fields_ = [
        ("clock", ctypes.c_uint32),
        ("hdisplay",   ctypes.c_uint16), ("hsync_start", ctypes.c_uint16),
        ("hsync_end",  ctypes.c_uint16), ("htotal",      ctypes.c_uint16),
        ("hskew",      ctypes.c_uint16),
        ("vdisplay",   ctypes.c_uint16), ("vsync_start", ctypes.c_uint16),
        ("vsync_end",  ctypes.c_uint16), ("vtotal",      ctypes.c_uint16),
        ("vscan",      ctypes.c_uint16),
        ("vrefresh", ctypes.c_uint32), ("flags", ctypes.c_uint32),
        ("type", ctypes.c_uint32), ("name", ctypes.c_char * 32),
    ]

class DrmModeGetConnector(ctypes.Structure):
    _fields_ = [
        ("encoders_ptr", ctypes.c_uint64), ("modes_ptr", ctypes.c_uint64),
        ("props_ptr", ctypes.c_uint64), ("prop_values_ptr", ctypes.c_uint64),
        ("count_modes", ctypes.c_uint32), ("count_props", ctypes.c_uint32),
        ("count_encoders", ctypes.c_uint32), ("encoder_id", ctypes.c_uint32),
        ("connector_id", ctypes.c_uint32), ("connector_type", ctypes.c_uint32),
        ("connector_type_id", ctypes.c_uint32), ("connection", ctypes.c_uint32),
        ("mm_width", ctypes.c_uint32), ("mm_height", ctypes.c_uint32),
        ("subpixel", ctypes.c_uint32), ("pad", ctypes.c_uint32),
    ]

class DrmModeGetEncoder(ctypes.Structure):
    _fields_ = [
        ("encoder_id", ctypes.c_uint32), ("encoder_type", ctypes.c_uint32),
        ("crtc_id", ctypes.c_uint32),
        ("possible_crtcs", ctypes.c_uint32), ("possible_clones", ctypes.c_uint32),
    ]

class DrmModeCreateDumb(ctypes.Structure):
    _fields_ = [
        ("height", ctypes.c_uint32), ("width", ctypes.c_uint32),
        ("bpp", ctypes.c_uint32), ("flags", ctypes.c_uint32),
        ("handle", ctypes.c_uint32), ("pitch", ctypes.c_uint32),
        ("size", ctypes.c_uint64),
    ]

class DrmModeMapDumb(ctypes.Structure):
    _fields_ = [
        ("handle", ctypes.c_uint32), ("pad", ctypes.c_uint32),
        ("offset", ctypes.c_uint64),
    ]

class DrmModeFbCmd(ctypes.Structure):
    _fields_ = [
        ("fb_id", ctypes.c_uint32), ("width", ctypes.c_uint32),
        ("height", ctypes.c_uint32), ("pitch", ctypes.c_uint32),
        ("bpp", ctypes.c_uint32), ("depth", ctypes.c_uint32),
        ("handle", ctypes.c_uint32),
    ]

class DrmModeFbId(ctypes.Structure):
    _fields_ = [("fb_id", ctypes.c_uint32)]

class DrmModeCrtc(ctypes.Structure):
    _fields_ = [
        ("set_connectors_ptr", ctypes.c_uint64),
        ("count_connectors", ctypes.c_uint32), ("crtc_id", ctypes.c_uint32),
        ("fb_id", ctypes.c_uint32),
        ("x", ctypes.c_uint32), ("y", ctypes.c_uint32),
        ("gamma_size", ctypes.c_uint32), ("mode_valid", ctypes.c_uint32),
        ("mode", DrmModeModeInfo),
    ]

class DrmModePageFlip(ctypes.Structure):
    _fields_ = [
        ("crtc_id", ctypes.c_uint32), ("fb_id", ctypes.c_uint32),
        ("flags", ctypes.c_uint32), ("reserved", ctypes.c_uint32),
        ("user_data", ctypes.c_uint64),
    ]

class DrmModeDestroyDumb(ctypes.Structure):
    _fields_ = [("handle", ctypes.c_uint32), ("pad", ctypes.c_uint32),
                ("size", ctypes.c_uint64)]

DRM_IOCTL_MODE_GETRESOURCES = _IOWR(B, 0xA0, ctypes.sizeof(DrmModeCardRes))
DRM_IOCTL_MODE_GETCONNECTOR = _IOWR(B, 0xA7, ctypes.sizeof(DrmModeGetConnector))
DRM_IOCTL_MODE_GETENCODER   = _IOWR(B, 0xA6, ctypes.sizeof(DrmModeGetEncoder))
DRM_IOCTL_MODE_CREATE_DUMB  = _IOWR(B, 0xB2, ctypes.sizeof(DrmModeCreateDumb))
DRM_IOCTL_MODE_MAP_DUMB     = _IOWR(B, 0xB3, ctypes.sizeof(DrmModeMapDumb))
DRM_IOCTL_MODE_ADDFB        = _IOWR(B, 0xAE, ctypes.sizeof(DrmModeFbCmd))
DRM_IOCTL_MODE_RMFB         = _IOWR(B, 0xAF, ctypes.sizeof(DrmModeFbId))
DRM_IOCTL_MODE_SETCRTC      = _IOWR(B, 0xA2, ctypes.sizeof(DrmModeCrtc))
DRM_IOCTL_MODE_PAGE_FLIP    = _IOWR(B, 0xB0, ctypes.sizeof(DrmModePageFlip))
DRM_IOCTL_MODE_DESTROY_DUMB = _IOWR(B, 0xB4, ctypes.sizeof(DrmModeDestroyDumb))
DRM_MODE_PAGE_FLIP_EVENT    = 0x01

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
        ("bind_obj_pad",    ctypes.c_uint32),   #        36
        ("bind_obj_offset", ctypes.c_uint64),   #        40
        ("bind_range",      ctypes.c_uint64),   #        48
        ("bind_addr",       ctypes.c_uint64),   #        56
        ("bind_pat_index",  ctypes.c_uint32),   #        64
        ("bind_flags",      ctypes.c_uint32),   #        68  low byte = op (0=MAP,1=UNMAP)
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
                return card, f"/dev/dri/renderD{128 + int(idx)}"
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
        mapped.flush()

        # VM_BIND: map GEM at BATCH_GPU_VA (synchronous, exec_queue_id=0)
        bind = XeVmBind(vm_id=vm_id, num_binds=1,
                        bind_obj=handle, bind_range=PAGE_SIZE,
                        bind_addr=BATCH_GPU_VA,
                        bind_flags=DRM_XE_VM_BIND_OP_MAP)
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
                              bind_flags=DRM_XE_VM_BIND_OP_UNMAP)
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

# ── KMS page-flip loop ────────────────────────────────────────────────────────
def _connector_info(fd: int, conn_id: int):
    """Return (mode, crtc_id) for a connected connector, or None."""
    c = DrmModeGetConnector(connector_id=conn_id)
    _ioctl(fd, DRM_IOCTL_MODE_GETCONNECTOR, c)
    if c.connection != 1 or c.count_modes == 0:   # 1 = DRM_MODE_CONNECTED
        return None
    modes    = (DrmModeModeInfo * c.count_modes)()
    encoders = (ctypes.c_uint32 * max(c.count_encoders, 1))()
    c2 = DrmModeGetConnector(
        connector_id=conn_id,
        modes_ptr=ctypes.addressof(modes),
        encoders_ptr=ctypes.addressof(encoders),
        count_modes=c.count_modes,
        count_encoders=c.count_encoders,
    )
    if _ioctl(fd, DRM_IOCTL_MODE_GETCONNECTOR, c2) != 0 or c2.encoder_id == 0:
        return None
    enc = DrmModeGetEncoder(encoder_id=c2.encoder_id)
    if _ioctl(fd, DRM_IOCTL_MODE_GETENCODER, enc) != 0 or enc.crtc_id == 0:
        return None
    return modes[0], enc.crtc_id

def kms_flip_loop(card_dev: str) -> None:
    """KMS double-buffer page-flip loop — triggers drm_handle_vblank."""
    try:
        fd = os.open(card_dev, os.O_RDWR)
    except OSError as e:
        print(f"[stimulate] Cannot open {card_dev}: {e}", flush=True)
        return

    if _ioctl(fd, DRM_IOCTL_SET_MASTER) != 0:
        print("[stimulate] Cannot get DRM master — KMS flips skipped", flush=True)
        os.close(fd)
        return

    fb_handles: list[tuple[int, int, int]] = []   # (handle, fb_id, size)
    maps: list[mmap.mmap] = []

    try:
        res = DrmModeCardRes()
        if _ioctl(fd, DRM_IOCTL_MODE_GETRESOURCES, res) != 0 or res.count_connectors == 0:
            return

        conn_ids = (ctypes.c_uint32 * res.count_connectors)()
        crtc_ids = (ctypes.c_uint32 * max(res.count_crtcs, 1))()
        res2 = DrmModeCardRes(
            connector_id_ptr=ctypes.addressof(conn_ids),
            crtc_id_ptr=ctypes.addressof(crtc_ids),
            count_connectors=res.count_connectors,
            count_crtcs=res.count_crtcs,
        )
        if _ioctl(fd, DRM_IOCTL_MODE_GETRESOURCES, res2) != 0:
            return

        conn_result = None
        for cid in conn_ids:
            info = _connector_info(fd, cid)
            if info:
                conn_result = info
                break
        if not conn_result:
            print("[stimulate] No connected display — KMS flips skipped", flush=True)
            return

        mode, crtc_id = conn_result
        w, h = mode.hdisplay, mode.vdisplay
        print(f"[stimulate] KMS flip loop: {w}×{h} CRTC={crtc_id}", flush=True)

        for _ in range(2):
            cd = DrmModeCreateDumb(width=w, height=h, bpp=32)
            if _ioctl(fd, DRM_IOCTL_MODE_CREATE_DUMB, cd) != 0:
                return
            md = DrmModeMapDumb(handle=cd.handle)
            _ioctl(fd, DRM_IOCTL_MODE_MAP_DUMB, md)
            fb = DrmModeFbCmd(width=w, height=h, pitch=cd.pitch,
                              bpp=32, depth=24, handle=cd.handle)
            _ioctl(fd, DRM_IOCTL_MODE_ADDFB, fb)
            m = mmap.mmap(fd, cd.size, mmap.MAP_SHARED,
                          mmap.PROT_READ | mmap.PROT_WRITE, offset=md.offset)
            # Fill with random noise
            m.write(os.urandom(min(int(cd.size), 1 << 20)))
            m.flush()
            fb_handles.append((cd.handle, fb.fb_id, int(cd.size)))
            maps.append(m)

        if len(fb_handles) < 2:
            return

        # Initial mode-set
        conn_arr = (ctypes.c_uint32 * 1)(conn_ids[0])
        crtc_cmd = DrmModeCrtc(
            set_connectors_ptr=ctypes.addressof(conn_arr),
            count_connectors=1, crtc_id=crtc_id,
            fb_id=fb_handles[0][1], mode_valid=1, mode=mode,
        )
        if _ioctl(fd, DRM_IOCTL_MODE_SETCRTC, crtc_cmd) != 0:
            print("[stimulate] SETCRTC failed — KMS flips skipped", flush=True)
            return

        cur = 0
        while _running:
            nxt = 1 - cur
            # Write a 4 KB noise stripe so the display visibly changes
            maps[nxt].seek(0)
            maps[nxt].write(os.urandom(PAGE_SIZE))
            maps[nxt].flush()

            flip = DrmModePageFlip(crtc_id=crtc_id, fb_id=fb_handles[nxt][1],
                                   flags=DRM_MODE_PAGE_FLIP_EVENT)
            if _ioctl(fd, DRM_IOCTL_MODE_PAGE_FLIP, flip) == 0:
                try:
                    os.read(fd, 32)   # consume the DRM_EVENT_FLIP_COMPLETE
                except OSError:
                    pass
                cur = nxt
            else:
                time.sleep(0.016)   # ~60 Hz fallback

    finally:
        for m in maps:
            m.close()
        for handle, fb_id, _ in fb_handles:
            rmfb = DrmModeFbId(fb_id=fb_id)
            _ioctl(fd, DRM_IOCTL_MODE_RMFB, rmfb)
            dd = DrmModeDestroyDumb(handle=handle)
            _ioctl(fd, DRM_IOCTL_MODE_DESTROY_DUMB, dd)
        _ioctl(fd, DRM_IOCTL_DROP_MASTER)
        os.close(fd)
        print("[stimulate] KMS flip loop stopped", flush=True)

# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        description="Background DRM stimulator — triggers vblank + GPU probes")
    ap.add_argument("--card",   default=None)
    ap.add_argument("--render", default=None)
    args = ap.parse_args()

    xe_card, xe_render = _find_xe_card()
    card   = args.card   or xe_card   or "/dev/dri/card0"
    render = args.render or xe_render or "/dev/dri/renderD128"

    import threading
    kms = threading.Thread(target=kms_flip_loop, args=(card,), daemon=True)
    kms.start()

    if render and os.path.exists(render):
        xe_nop_loop(render)
    else:
        while _running:
            time.sleep(0.1)

    kms.join(timeout=3)

if __name__ == "__main__":
    main()
