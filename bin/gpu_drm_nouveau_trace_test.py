#!/usr/bin/env python3
"""
Nouveau Driver — bpftrace Workflow Verification
================================================
Traces the nouveau GPU driver submission pipeline step by step and marks
each stage PASS or FAIL.

Verified paths:
  Step 0  — prerequisites (root, bpftrace, /dev/dri/card0, nouveau module)
  Step 1  — nouveau driver open / DRM_IOCTL_VERSION
  Step 2  — NOUVEAU_GETPARAM (chipset ID, VRAM size)
  Step 3  — NOUVEAU_GEM_NEW (GEM buffer object allocation)
  Step 4  — NOUVEAU_GEM_INFO (query BO placement / map handle)
  Step 5  — NOUVEAU_GEM_CPU_PREP (wait for GPU idle — CPU access barrier)
  Step 6  — NOUVEAU_GEM_CPU_FINI (release CPU-access lock)
  Step 7  — NOUVEAU_GEM_PUSHBUF dispatch (command submission ioctl entry)
  Step 8  — nouveau_fence_emit (GPU fence creation, passive)
  Step 9  — nvkm_subdev use/enable (NVKM engine wakeup, passive)
  Step 10 — nouveau_bo_move (TTM buffer eviction/migration, passive)
  Step 11 — GEM handle close (buffer object teardown)

Requirements:
  - bpftrace >= 0.16  (sudo apt install bpftrace)
  - Root privileges   (sudo python3 trace_test.py)
  - NVIDIA GPU with nouveau loaded (/dev/dri/card0)
  - Kernel built with CONFIG_DEBUG_INFO_BTF=y

Usage:
  sudo python3 trace_test.py [--dev /dev/dri/card0] [--timeout 15]
"""

import argparse
import ctypes
import ctypes.util
import os
import subprocess
import sys
import threading
import time

import glob

# ──────────────────────────────────────────────────────────────────────────────
# Device auto-detection
# ──────────────────────────────────────────────────────────────────────────────

def _find_drm_card(driver=None):
    """Return the first /dev/dri/cardN, optionally matching a driver name."""
    for card in sorted(glob.glob("/dev/dri/card[0-9]*")):
        if not os.path.exists(card):
            continue
        if driver is None:
            return card
        idx = card.replace("/dev/dri/card", "")
        try:
            drv = os.path.basename(os.readlink(f"/sys/class/drm/card{idx}/device/driver"))
            if driver in drv:
                return card
        except OSError:
            pass
    return "/dev/dri/card0"

def _find_render_node(card_path):
    """Return the render node that pairs with the given card path."""
    try:
        idx = int(card_path.replace("/dev/dri/card", ""))
        render = f"/dev/dri/renderD{128 + idx}"
        return render if os.path.exists(render) else "/dev/dri/renderD128"
    except ValueError:
        return "/dev/dri/renderD128"

# ──────────────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────────────

DRM_DEV_DEFAULT    = _find_drm_card("nouveau")
RENDER_DEV_DEFAULT = _find_render_node(DRM_DEV_DEFAULT)
BPFTRACE_BIN       = "bpftrace"
PROBE_TIMEOUT      = 10  # seconds per step

# ──────────────────────────────────────────────────────────────────────────────
# ioctl number helpers
# ──────────────────────────────────────────────────────────────────────────────

def _IOC(dir_, type_, nr, size):
    IOC_NRBITS   = 8;  IOC_TYPEBITS = 8
    IOC_SIZEBITS = 14; IOC_DIRBITS  = 2
    IOC_NRSHIFT   = 0
    IOC_TYPESHIFT = IOC_NRSHIFT   + IOC_NRBITS
    IOC_SIZESHIFT = IOC_TYPESHIFT + IOC_TYPEBITS
    IOC_DIRSHIFT  = IOC_SIZESHIFT + IOC_SIZEBITS
    return (dir_ << IOC_DIRSHIFT) | (type_ << IOC_TYPESHIFT) | \
           (nr  << IOC_NRSHIFT)  | (size  << IOC_SIZESHIFT)

_IOWR = lambda t, nr, sz: _IOC(3, t, nr, sz)
_IOW  = lambda t, nr, sz: _IOC(1, t, nr, sz)
_IOR  = lambda t, nr, sz: _IOC(2, t, nr, sz)
_IO   = lambda t, nr:     _IOC(0, t, nr, 0)

DRM_IOCTL_BASE   = ord('d')
DRM_COMMAND_BASE = 0x40

# ──────────────────────────────────────────────────────────────────────────────
# DRM core ioctls
# ──────────────────────────────────────────────────────────────────────────────

class DrmVersion(ctypes.Structure):
    _fields_ = [
        ("version_major",      ctypes.c_int),
        ("version_minor",      ctypes.c_int),
        ("version_patchlevel", ctypes.c_int),
        ("name_len",           ctypes.c_size_t),
        ("name",               ctypes.c_char_p),
        ("date_len",           ctypes.c_size_t),
        ("date",               ctypes.c_char_p),
        ("desc_len",           ctypes.c_size_t),
        ("desc",               ctypes.c_char_p),
    ]

DRM_IOCTL_VERSION = _IOWR(DRM_IOCTL_BASE, 0x00, ctypes.sizeof(DrmVersion))

class DrmGemClose(ctypes.Structure):
    _fields_ = [("handle", ctypes.c_uint32), ("pad", ctypes.c_uint32)]

DRM_IOCTL_GEM_CLOSE = _IOW(DRM_IOCTL_BASE, 0x09, ctypes.sizeof(DrmGemClose))

# ──────────────────────────────────────────────────────────────────────────────
# Nouveau ioctls  (from include/uapi/drm/nouveau_drm.h)
# ──────────────────────────────────────────────────────────────────────────────

# DRM_NOUVEAU_GETPARAM (0x00)
NOUVEAU_GETPARAM_PCI_VENDOR  = 3
NOUVEAU_GETPARAM_PCI_DEVICE  = 4
NOUVEAU_GETPARAM_CHIPSET_ID  = 11
NOUVEAU_GETPARAM_FB_SIZE     = 8
NOUVEAU_GETPARAM_PTIMER_TIME = 14

class DrmNouveauGetparam(ctypes.Structure):
    _fields_ = [
        ("param", ctypes.c_uint64),
        ("value", ctypes.c_uint64),
    ]

DRM_NOUVEAU_GETPARAM      = 0x00
DRM_IOCTL_NOUVEAU_GETPARAM = _IOWR(DRM_IOCTL_BASE,
                                    DRM_COMMAND_BASE + DRM_NOUVEAU_GETPARAM,
                                    ctypes.sizeof(DrmNouveauGetparam))

# DRM_NOUVEAU_GEM_NEW (0x40)
NOUVEAU_GEM_DOMAIN_CPU  = (1 << 0)
NOUVEAU_GEM_DOMAIN_VRAM = (1 << 1)
NOUVEAU_GEM_DOMAIN_GART = (1 << 2)

class DrmNouveauGemInfo(ctypes.Structure):
    _fields_ = [
        ("handle",     ctypes.c_uint32),
        ("domain",     ctypes.c_uint32),
        ("size",       ctypes.c_uint64),
        ("offset",     ctypes.c_uint64),
        ("map_handle", ctypes.c_uint64),
        ("tile_mode",  ctypes.c_uint32),
        ("tile_flags", ctypes.c_uint32),
    ]

class DrmNouveauGemNew(ctypes.Structure):
    _fields_ = [
        ("info",         DrmNouveauGemInfo),
        ("channel_hint", ctypes.c_uint32),
        ("align",        ctypes.c_uint32),
    ]

DRM_NOUVEAU_GEM_NEW      = 0x40
DRM_IOCTL_NOUVEAU_GEM_NEW = _IOWR(DRM_IOCTL_BASE,
                                   DRM_COMMAND_BASE + DRM_NOUVEAU_GEM_NEW,
                                   ctypes.sizeof(DrmNouveauGemNew))

# DRM_NOUVEAU_GEM_INFO (0x44)
DRM_NOUVEAU_GEM_INFO      = 0x44
DRM_IOCTL_NOUVEAU_GEM_INFO = _IOWR(DRM_IOCTL_BASE,
                                    DRM_COMMAND_BASE + DRM_NOUVEAU_GEM_INFO,
                                    ctypes.sizeof(DrmNouveauGemInfo))

# DRM_NOUVEAU_GEM_CPU_PREP (0x42)
NOUVEAU_GEM_CPU_PREP_NOWAIT   = 0x00000001
NOUVEAU_GEM_CPU_PREP_WRITE    = 0x00000004

class DrmNouveauGemCpuPrep(ctypes.Structure):
    _fields_ = [
        ("handle", ctypes.c_uint32),
        ("flags",  ctypes.c_uint32),
    ]

DRM_NOUVEAU_GEM_CPU_PREP      = 0x42
DRM_IOCTL_NOUVEAU_GEM_CPU_PREP = _IOW(DRM_IOCTL_BASE,
                                       DRM_COMMAND_BASE + DRM_NOUVEAU_GEM_CPU_PREP,
                                       ctypes.sizeof(DrmNouveauGemCpuPrep))

# DRM_NOUVEAU_GEM_CPU_FINI (0x43)
class DrmNouveauGemCpuFini(ctypes.Structure):
    _fields_ = [
        ("handle", ctypes.c_uint32),
        ("flags",  ctypes.c_uint32),
    ]

DRM_NOUVEAU_GEM_CPU_FINI      = 0x43
DRM_IOCTL_NOUVEAU_GEM_CPU_FINI = _IOW(DRM_IOCTL_BASE,
                                       DRM_COMMAND_BASE + DRM_NOUVEAU_GEM_CPU_FINI,
                                       ctypes.sizeof(DrmNouveauGemCpuFini))

# DRM_NOUVEAU_GEM_PUSHBUF (0x41) — minimal empty submit
class DrmNouveauGemPushbuf(ctypes.Structure):
    _fields_ = [
        ("channel",      ctypes.c_uint32),
        ("nr_buffers",   ctypes.c_uint32),
        ("buffers",      ctypes.c_uint64),  # ptr to drm_nouveau_gem_pushbuf_bo[]
        ("nr_relocs",    ctypes.c_uint32),
        ("nr_push",      ctypes.c_uint32),
        ("relocs",       ctypes.c_uint64),
        ("push",         ctypes.c_uint64),
        ("suffix0",      ctypes.c_uint32),
        ("suffix1",      ctypes.c_uint32),
        ("vram_available", ctypes.c_uint64),
        ("gart_available", ctypes.c_uint64),
    ]

DRM_NOUVEAU_GEM_PUSHBUF      = 0x41
DRM_IOCTL_NOUVEAU_GEM_PUSHBUF = _IOWR(DRM_IOCTL_BASE,
                                       DRM_COMMAND_BASE + DRM_NOUVEAU_GEM_PUSHBUF,
                                       ctypes.sizeof(DrmNouveauGemPushbuf))

# ──────────────────────────────────────────────────────────────────────────────
# Terminal colours
# ──────────────────────────────────────────────────────────────────────────────

GREEN = "\033[92m"; RED = "\033[91m"; CYAN = "\033[96m"
BOLD  = "\033[1m";  RESET = "\033[0m"

def pass_(msg): print(f"  {GREEN}[PASS]{RESET} {msg}")
def fail_(msg): print(f"  {RED}[FAIL]{RESET} {msg}")
def info_(msg): print(f"  {CYAN}[INFO]{RESET} {msg}")

# ──────────────────────────────────────────────────────────────────────────────
# bpftrace helpers
# ──────────────────────────────────────────────────────────────────────────────

def bpftrace_available() -> bool:
    try:
        r = subprocess.run([BPFTRACE_BIN, "--version"], capture_output=True, timeout=5)
        return r.returncode == 0
    except FileNotFoundError:
        return False


class BpfProbe:
    """Run a bpftrace one-liner in background; set event when probe fires."""

    def __init__(self, probe: str, predicate: str = ""):
        self._probe     = probe
        self._predicate = predicate
        self._event     = threading.Event()
        self._proc      = None
        self._thread    = None

    def _monitor(self):
        filt   = f"/{self._predicate}/" if self._predicate else ""
        script = f'{self._probe} {filt} {{ printf("HIT\\n"); }}'
        self._proc = subprocess.Popen(
            [BPFTRACE_BIN, "-e", script],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        for line in self._proc.stdout:
            if "HIT" in line:
                self._event.set()
                break
        self._proc.wait()

    def start(self):
        self._thread = threading.Thread(target=self._monitor, daemon=True)
        self._thread.start()
        time.sleep(1.5)  # let bpftrace attach

    def wait(self, timeout: float = PROBE_TIMEOUT) -> bool:
        return self._event.wait(timeout=timeout)

    def stop(self):
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
        if self._thread:
            self._thread.join(timeout=2)


# ──────────────────────────────────────────────────────────────────────────────
# libc ioctl wrapper
# ──────────────────────────────────────────────────────────────────────────────

def _libc():
    return ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

def ioctl(fd, request, arg):
    return _libc().ioctl(fd, ctypes.c_ulong(request), ctypes.byref(arg))

def open_drm(path: str) -> "int | None":
    try:
        return os.open(path, os.O_RDWR | os.O_CLOEXEC)
    except OSError as e:
        info_(f"Cannot open {path}: {e}")
        return None

# ──────────────────────────────────────────────────────────────────────────────
# Result tracking
# ──────────────────────────────────────────────────────────────────────────────

RESULTS: "list[tuple[str, bool]]" = []

def record(name: str, ok: bool):
    RESULTS.append((name, ok))
    (pass_ if ok else fail_)(name)

# ──────────────────────────────────────────────────────────────────────────────
# Steps
# ──────────────────────────────────────────────────────────────────────────────

def step0_prerequisites(dev: str) -> bool:
    print(f"\n{BOLD}Step 0 — Prerequisites{RESET}")
    ok = True

    if os.geteuid() != 0:
        fail_("Must run as root"); ok = False
    else:
        pass_("Running as root")

    if not bpftrace_available():
        fail_("bpftrace not found — apt install bpftrace"); ok = False
    else:
        pass_("bpftrace available")

    for p in [dev, RENDER_DEV_DEFAULT]:
        if os.path.exists(p):
            pass_(f"Device node exists: {p}")
        else:
            info_(f"Device node missing: {p}")

    if os.path.exists("/sys/module/nouveau"):
        pass_("nouveau kernel module loaded (/sys/module/nouveau)")
    else:
        fail_("nouveau module not loaded — is this an NVIDIA GPU?")
        ok = False

    if os.path.exists("/sys/kernel/btf/vmlinux"):
        pass_("BTF available (/sys/kernel/btf/vmlinux)")
    else:
        info_("BTF not found — kfunc probes may fail")

    record("prerequisites", ok)
    return ok


def step1_driver_version(dev: str) -> "int | None":
    print(f"\n{BOLD}Step 1 — nouveau driver open / DRM_IOCTL_VERSION{RESET}")
    info_("Probing kfunc:drm_ioctl")

    probe = BpfProbe("kfunc:drm_ioctl")
    probe.start()

    fd = open_drm(dev)
    if fd is None:
        probe.stop(); record("nouveau drm_open + version", False); return None

    ver = DrmVersion()
    name_buf = ctypes.create_string_buffer(64)
    date_buf = ctypes.create_string_buffer(32)
    desc_buf = ctypes.create_string_buffer(256)
    ver.name = ctypes.cast(name_buf, ctypes.c_char_p); ver.name_len = 64
    ver.date = ctypes.cast(date_buf, ctypes.c_char_p); ver.date_len = 32
    ver.desc = ctypes.cast(desc_buf, ctypes.c_char_p); ver.desc_len = 256
    ret = ioctl(fd, DRM_IOCTL_VERSION, ver)
    hit = probe.wait(); probe.stop()

    driver_name = name_buf.value.decode(errors="replace") if ret == 0 else "?"
    ok = (ret == 0) and hit and (driver_name == "nouveau")
    record("nouveau drm_open + version (driver=nouveau)", ok)
    if ret == 0:
        info_(f"  ↳ driver={driver_name}  v{ver.version_major}.{ver.version_minor}.{ver.version_patchlevel}")
    if driver_name not in ("nouveau", "?"):
        info_(f"  ↳ Not a nouveau device ({driver_name}) — remaining steps may fail")
    return fd


def step2_getparam(fd: int) -> bool:
    print(f"\n{BOLD}Step 2 — NOUVEAU_GETPARAM (chipset ID + VRAM){RESET}")
    info_("Probing kfunc:nouveau_abi16_ioctl_getparam")

    probe = BpfProbe("kfunc:nouveau_abi16_ioctl_getparam")
    probe.start()

    gp = DrmNouveauGetparam(param=NOUVEAU_GETPARAM_CHIPSET_ID, value=0)
    ret = ioctl(fd, DRM_IOCTL_NOUVEAU_GETPARAM, gp)
    hit = probe.wait(); probe.stop()

    ok = hit
    record("nouveau_abi16_ioctl_getparam (CHIPSET_ID)", ok)
    if ret == 0:
        info_(f"  ↳ chipset_id=0x{gp.value:08x}")

    # Also query VRAM size
    gp2 = DrmNouveauGetparam(param=NOUVEAU_GETPARAM_FB_SIZE, value=0)
    ret2 = ioctl(fd, DRM_IOCTL_NOUVEAU_GETPARAM, gp2)
    if ret2 == 0:
        info_(f"  ↳ fb_size={gp2.value >> 20} MiB")

    return ok


def step3_gem_new(fd: int) -> int:
    print(f"\n{BOLD}Step 3 — NOUVEAU_GEM_NEW (GEM buffer object allocation){RESET}")
    info_("Probing kfunc:nouveau_gem_ioctl_new")

    probe = BpfProbe("kfunc:nouveau_gem_ioctl_new")
    probe.start()

    req = DrmNouveauGemNew()
    req.info.size   = 4096
    req.info.domain = NOUVEAU_GEM_DOMAIN_GART  # system RAM — works without VRAM
    req.align       = 4096

    ret = ioctl(fd, DRM_IOCTL_NOUVEAU_GEM_NEW, req)
    hit = probe.wait(); probe.stop()

    ok = (ret == 0) and hit
    handle = req.info.handle if ret == 0 else 0
    record("nouveau_gem_ioctl_new (4 KiB GART BO)", ok)
    if ret == 0:
        info_(f"  ↳ handle={handle}  domain=0x{req.info.domain:x}  offset=0x{req.info.offset:x}")
    else:
        info_(f"  ↳ ioctl returned {ret}")
    return handle


def step4_gem_info(fd: int, handle: int) -> bool:
    print(f"\n{BOLD}Step 4 — NOUVEAU_GEM_INFO (query BO placement / map handle){RESET}")
    if handle == 0:
        info_("  ↳ No valid handle — skipping")
        record("nouveau_gem_ioctl_info", False); return False

    info_("Probing kfunc:nouveau_gem_ioctl_info")

    probe = BpfProbe("kfunc:nouveau_gem_ioctl_info")
    probe.start()

    info_req = DrmNouveauGemInfo(handle=handle)
    ret = ioctl(fd, DRM_IOCTL_NOUVEAU_GEM_INFO, info_req)
    hit = probe.wait(); probe.stop()

    ok = hit
    record("nouveau_gem_ioctl_info (BO placement query)", ok)
    if ret == 0:
        info_(f"  ↳ domain=0x{info_req.domain:x}  map_handle=0x{info_req.map_handle:x}")
    else:
        info_(f"  ↳ ioctl returned {ret}")
    return ok


def step5_gem_cpu_prep(fd: int, handle: int) -> bool:
    print(f"\n{BOLD}Step 5 — NOUVEAU_GEM_CPU_PREP (CPU access barrier){RESET}")
    if handle == 0:
        info_("  ↳ No valid handle — skipping")
        record("nouveau_gem_ioctl_cpu_prep", False); return False

    info_("Probing kfunc:nouveau_gem_ioctl_cpu_prep")

    probe = BpfProbe("kfunc:nouveau_gem_ioctl_cpu_prep")
    probe.start()

    prep = DrmNouveauGemCpuPrep(handle=handle,
                                 flags=NOUVEAU_GEM_CPU_PREP_NOWAIT)
    ret = ioctl(fd, DRM_IOCTL_NOUVEAU_GEM_CPU_PREP, prep)
    hit = probe.wait(); probe.stop()

    ok = hit
    record("nouveau_gem_ioctl_cpu_prep (CPU access, NOWAIT)", ok)
    if ret == 0:
        pass_("  ↳ BO is GPU-idle — CPU can safely access it")
    else:
        info_(f"  ↳ ioctl returned {ret} (EAGAIN=BO busy, EINVAL=flags; function still entered)")
    return ok


def step6_gem_cpu_fini(fd: int, handle: int) -> bool:
    print(f"\n{BOLD}Step 6 — NOUVEAU_GEM_CPU_FINI (release CPU-access lock){RESET}")
    if handle == 0:
        info_("  ↳ No valid handle — skipping")
        record("nouveau_gem_ioctl_cpu_fini", False); return False

    info_("Probing kfunc:nouveau_gem_ioctl_cpu_fini")

    probe = BpfProbe("kfunc:nouveau_gem_ioctl_cpu_fini")
    probe.start()

    fini = DrmNouveauGemCpuFini(handle=handle, flags=0)
    ret = ioctl(fd, DRM_IOCTL_NOUVEAU_GEM_CPU_FINI, fini)
    hit = probe.wait(); probe.stop()

    ok = hit
    record("nouveau_gem_ioctl_cpu_fini (CPU lock release)", ok)
    if ret == 0:
        info_("  ↳ CPU-access lock released")
    else:
        info_(f"  ↳ ioctl returned {ret}")
    return ok


def step7_pushbuf_dispatch(fd: int) -> bool:
    """
    Submit an empty PUSHBUF (channel=0, nr_push=0, nr_buffers=0).
    The kernel validates inputs and returns -EINVAL/ENOENT for an
    invalid channel, but nouveau_gem_ioctl_pushbuf IS entered.
    """
    print(f"\n{BOLD}Step 7 — NOUVEAU_GEM_PUSHBUF dispatch (command submission entry){RESET}")
    info_("Probing kfunc:nouveau_gem_ioctl_pushbuf  (expect error for empty/invalid channel)")

    probe = BpfProbe("kfunc:nouveau_gem_ioctl_pushbuf")
    probe.start()

    pb = DrmNouveauGemPushbuf()  # all zeros — invalid channel 0
    ioctl(fd, DRM_IOCTL_NOUVEAU_GEM_PUSHBUF, pb)
    hit = probe.wait(); probe.stop()

    record("nouveau_gem_ioctl_pushbuf dispatch (ioctl entry)", hit)
    if hit:
        info_("  ↳ pushbuf ioctl reached (returned error as expected for invalid channel)")
    return hit


def step8_fence_emit(fd: int) -> bool:
    print(f"\n{BOLD}Step 8 — nouveau_fence_emit (GPU fence creation, passive){RESET}")
    info_("Probing kfunc:nouveau_fence_emit for 5 seconds")

    probe = BpfProbe("kfunc:nouveau_fence_emit")
    probe.start()
    hit = probe.wait(timeout=5); probe.stop()

    record("nouveau_fence_emit (passive)", hit)
    if hit:
        info_("  ↳ GPU fences are being emitted on this system")
    else:
        info_("  ↳ No fence emissions in 5 s (idle or no GPU activity)")
    return hit


def step9_nvkm_subdev_use(fd: int) -> bool:
    print(f"\n{BOLD}Step 9 — nvkm_subdev use/enable (NVKM engine wakeup, passive){RESET}")
    info_("Probing kfunc:nvkm_subdev_unuse,kfunc:nvkm_subdev_use for 5 seconds")

    probe = BpfProbe("kfunc:nvkm_subdev_unuse,kfunc:nvkm_subdev_use")
    probe.start()
    hit = probe.wait(timeout=5); probe.stop()

    record("nvkm_subdev use/unuse (engine wakeref, passive)", hit)
    if hit:
        info_("  ↳ NVKM subdevices being woken / released")
    else:
        info_("  ↳ No NVKM subdev transitions in 5 s (idle)")
    return hit


def step10_bo_move(fd: int) -> bool:
    print(f"\n{BOLD}Step 10 — nouveau_bo_move (TTM buffer migration, passive){RESET}")
    info_("Probing kfunc:nouveau_bo_move for 5 seconds")

    probe = BpfProbe("kfunc:nouveau_bo_move")
    probe.start()
    hit = probe.wait(timeout=5); probe.stop()

    record("nouveau_bo_move (TTM VRAM↔GART eviction, passive)", hit)
    if hit:
        info_("  ↳ Buffer objects are being migrated between memory domains")
    else:
        info_("  ↳ No BO migrations in 5 s (system may have adequate VRAM)")
    return hit


def step11_gem_close(fd: int, handle: int) -> bool:
    print(f"\n{BOLD}Step 11 — DRM_IOCTL_GEM_CLOSE (buffer object teardown){RESET}")
    if handle == 0:
        info_("  ↳ No valid handle — skipping")
        record("drm_gem_close (BO teardown)", False); return False

    info_("Probing kfunc:drm_gem_close_ioctl")

    probe = BpfProbe("kfunc:drm_gem_close_ioctl")
    probe.start()

    close_arg = DrmGemClose(handle=handle)
    ret = _libc().ioctl(fd, ctypes.c_ulong(DRM_IOCTL_GEM_CLOSE),
                        ctypes.byref(close_arg))
    hit = probe.wait(); probe.stop()

    ok = (ret == 0) and hit
    record("drm_gem_close_ioctl (BO teardown)", ok)
    if ret == 0:
        info_(f"  ↳ handle={handle} closed and freed")
    else:
        info_(f"  ↳ close returned {ret}")
    return ok


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def main():
    global PROBE_TIMEOUT
    parser = argparse.ArgumentParser(description="nouveau bpftrace workflow test")
    parser.add_argument("--dev",     default=DRM_DEV_DEFAULT)
    parser.add_argument("--timeout", type=int, default=PROBE_TIMEOUT)
    args = parser.parse_args()

    PROBE_TIMEOUT = args.timeout

    print(f"""
{BOLD}╔══════════════════════════════════════════════════════════════╗
║      Nouveau Driver — bpftrace Workflow Verification         ║
╚══════════════════════════════════════════════════════════════╝{RESET}
  Device:   {args.dev}
  Timeout:  {PROBE_TIMEOUT}s per step
""")

    if not step0_prerequisites(args.dev):
        print(f"\n{RED}Cannot continue without prerequisites.{RESET}")
        sys.exit(1)

    fd = step1_driver_version(args.dev)
    if fd is None:
        print(f"\n{RED}Cannot open DRM device — aborting.{RESET}")
        sys.exit(1)

    step2_getparam(fd)
    handle = step3_gem_new(fd)
    step4_gem_info(fd, handle)
    step5_gem_cpu_prep(fd, handle)
    step6_gem_cpu_fini(fd, handle)
    step7_pushbuf_dispatch(fd)
    step8_fence_emit(fd)
    step9_nvkm_subdev_use(fd)
    step10_bo_move(fd)
    step11_gem_close(fd, handle)

    try:
        os.close(fd)
    except OSError:
        pass

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n{BOLD}══════════════════════ Results ══════════════════════{RESET}")
    passed = sum(1 for _, ok in RESULTS if ok)
    total  = len(RESULTS)
    for name, ok in RESULTS:
        status = f"{GREEN}PASS{RESET}" if ok else f"{RED}FAIL{RESET}"
        print(f"  [{status}] {name}")

    print(f"\n  Score: {passed}/{total}")
    if passed == total:
        print(f"  {GREEN}{BOLD}All steps passed!{RESET}")
    else:
        print(f"  {RED}{BOLD}{total - passed} step(s) failed.{RESET}")
        print("""
  Common failure reasons:
    • Not a nouveau GPU → steps 2-12 will fail (driver name differs)
    • BTF not available: check /sys/kernel/btf/vmlinux
    • kfunc names changed: use  bpftrace -l 'kfunc:nouveau*'  to verify
    • Passive steps (8-11): idle system → expected FAIL for no-workload cases
    • GSP mode (Turing+): some internal function names may differ
    • CPU_PREP step 5: EAGAIN is normal for a just-allocated idle BO
    • BO move step 11: only fires under VRAM pressure or explicit migrate
""")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
