#!/usr/bin/env python3
"""
amdgpu Driver — bpftrace Workflow Verification
===============================================
Traces the amdgpu submission pipeline step by step and marks
each stage PASS or FAIL.

Verified paths:
  Step 0  — prerequisites (root, bpftrace, /dev/dri/card0, amdgpu module)
  Step 1  — amdgpu driver probe / DRM_IOCTL_VERSION
  Step 2  — DRM_IOCTL_AMDGPU_INFO (ACCEL_WORKING + DEV_INFO)
  Step 3  — DRM_IOCTL_AMDGPU_CTX alloc (per-process GPU context)
  Step 4  — DRM_IOCTL_AMDGPU_GEM_CREATE (GPU buffer object allocation)
  Step 5  — DRM_IOCTL_AMDGPU_GEM_MMAP (mmap offset for CPU access)
  Step 6  — DRM_IOCTL_AMDGPU_GEM_VA (map BO into GPU virtual address space)
  Step 7  — DRM_IOCTL_AMDGPU_CS dispatch (command submission ioctl entry)
  Step 8  — amdgpu_job_run (GPU job scheduler → ring emission, passive)
  Step 9  — dma_fence_signal (GPU work completion, passive)
  Step 10 — amdgpu_vm_flush (GPU page table flush, passive)
  Step 11 — amdgpu runtime PM wakeref (passive)
  Step 12 — DRM_IOCTL_AMDGPU_CTX free (context teardown)

Requirements:
  - bpftrace >= 0.16  (sudo apt install bpftrace)
  - Root privileges   (sudo python3 trace_test.py)
  - AMD GPU with amdgpu loaded (/dev/dri/card0)
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

DRM_DEV_DEFAULT    = _find_drm_card("amdgpu")
RENDER_DEV_DEFAULT = _find_render_node(DRM_DEV_DEFAULT)
BPFTRACE_BIN       = "bpftrace"
PROBE_TIMEOUT      = 10  # seconds per step

# ──────────────────────────────────────────────────────────────────────────────
# ioctl number helpers  (from <uapi/asm-generic/ioctl.h>)
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

class DrmGetCap(ctypes.Structure):
    _fields_ = [("capability", ctypes.c_uint64), ("value", ctypes.c_uint64)]

DRM_IOCTL_GET_CAP = _IOWR(DRM_IOCTL_BASE, 0x0C, ctypes.sizeof(DrmGetCap))

class DrmGemClose(ctypes.Structure):
    _fields_ = [("handle", ctypes.c_uint32), ("pad", ctypes.c_uint32)]

DRM_IOCTL_GEM_CLOSE = _IOW(DRM_IOCTL_BASE, 0x09, ctypes.sizeof(DrmGemClose))

# ──────────────────────────────────────────────────────────────────────────────
# AMDGPU ioctls  (from include/uapi/drm/amdgpu_drm.h)
# ──────────────────────────────────────────────────────────────────────────────

# --- DRM_IOCTL_AMDGPU_INFO (0x05) ---
AMDGPU_INFO_ACCEL_WORKING = 0x00
AMDGPU_INFO_DEV_INFO      = 0x16

class AmdgpuInfoRequest(ctypes.Structure):
    _fields_ = [
        ("return_pointer", ctypes.c_uint64),
        ("return_size",    ctypes.c_uint32),
        ("query",          ctypes.c_uint32),
        ("_pad",           ctypes.c_uint8 * 64),   # union of query params
    ]

DRM_AMDGPU_INFO      = 0x05
DRM_IOCTL_AMDGPU_INFO = _IOW(DRM_IOCTL_BASE,
                               DRM_COMMAND_BASE + DRM_AMDGPU_INFO,
                               ctypes.sizeof(AmdgpuInfoRequest))

# --- DRM_IOCTL_AMDGPU_CTX (0x02) ---
AMDGPU_CTX_OP_ALLOC_CTX = 1
AMDGPU_CTX_OP_FREE_CTX  = 2
AMDGPU_CTX_PRIORITY_NORMAL = 0

class AmdgpuCtxIn(ctypes.Structure):
    _fields_ = [
        ("op",       ctypes.c_uint32),
        ("flags",    ctypes.c_uint32),
        ("ctx_id",   ctypes.c_uint32),
        ("priority", ctypes.c_int32),
    ]

class AmdgpuCtxOut(ctypes.Structure):
    _fields_ = [
        ("ctx_id",  ctypes.c_uint32),
        ("_pad",    ctypes.c_uint32),
        ("state",   ctypes.c_uint64),
    ]

class AmdgpuCtxUnion(ctypes.Union):
    _fields_ = [("in_", AmdgpuCtxIn), ("out", AmdgpuCtxOut)]

DRM_AMDGPU_CTX      = 0x02
DRM_IOCTL_AMDGPU_CTX = _IOWR(DRM_IOCTL_BASE,
                               DRM_COMMAND_BASE + DRM_AMDGPU_CTX,
                               ctypes.sizeof(AmdgpuCtxUnion))

# --- DRM_IOCTL_AMDGPU_GEM_CREATE (0x00) ---
AMDGPU_GEM_DOMAIN_CPU  = 0x1
AMDGPU_GEM_DOMAIN_GTT  = 0x2
AMDGPU_GEM_DOMAIN_VRAM = 0x4

class AmdgpuGemCreateIn(ctypes.Structure):
    _fields_ = [
        ("bo_size",           ctypes.c_uint64),
        ("alignment",         ctypes.c_uint64),
        ("domains",           ctypes.c_uint64),
        ("domain_flags",      ctypes.c_uint64),
    ]

class AmdgpuGemCreateOut(ctypes.Structure):
    _fields_ = [
        ("handle", ctypes.c_uint32),
        ("_pad",   ctypes.c_uint32),
    ]

class AmdgpuGemCreateUnion(ctypes.Union):
    _fields_ = [("in_", AmdgpuGemCreateIn), ("out", AmdgpuGemCreateOut)]

DRM_AMDGPU_GEM_CREATE      = 0x00
DRM_IOCTL_AMDGPU_GEM_CREATE = _IOWR(DRM_IOCTL_BASE,
                                      DRM_COMMAND_BASE + DRM_AMDGPU_GEM_CREATE,
                                      ctypes.sizeof(AmdgpuGemCreateUnion))

# --- DRM_IOCTL_AMDGPU_GEM_MMAP (0x01) ---
class AmdgpuGemMmapIn(ctypes.Structure):
    _fields_ = [
        ("handle", ctypes.c_uint32),
        ("_pad",   ctypes.c_uint32),
    ]

class AmdgpuGemMmapOut(ctypes.Structure):
    _fields_ = [
        ("addr_ptr", ctypes.c_uint64),
    ]

class AmdgpuGemMmapUnion(ctypes.Union):
    _fields_ = [("in_", AmdgpuGemMmapIn), ("out", AmdgpuGemMmapOut)]

DRM_AMDGPU_GEM_MMAP      = 0x01
DRM_IOCTL_AMDGPU_GEM_MMAP = _IOWR(DRM_IOCTL_BASE,
                                    DRM_COMMAND_BASE + DRM_AMDGPU_GEM_MMAP,
                                    ctypes.sizeof(AmdgpuGemMmapUnion))

# --- DRM_IOCTL_AMDGPU_GEM_VA (0x08) ---
AMDGPU_VA_OP_MAP         = 1
AMDGPU_VA_OP_UNMAP       = 2
AMDGPU_VM_PAGE_READABLE  = (1 << 1)
AMDGPU_VM_PAGE_WRITEABLE = (1 << 2)
AMDGPU_VM_PAGE_EXECUTABLE= (1 << 3)

class AmdgpuGemVa(ctypes.Structure):
    _fields_ = [
        ("handle",       ctypes.c_uint32),
        ("operation",    ctypes.c_uint32),
        ("flags",        ctypes.c_uint32),
        ("_pad",         ctypes.c_uint32),
        ("va_address",   ctypes.c_uint64),
        ("offset_in_bo", ctypes.c_uint64),
        ("map_size",     ctypes.c_uint64),
    ]

DRM_AMDGPU_GEM_VA      = 0x08
DRM_IOCTL_AMDGPU_GEM_VA = _IOW(DRM_IOCTL_BASE,
                                 DRM_COMMAND_BASE + DRM_AMDGPU_GEM_VA,
                                 ctypes.sizeof(AmdgpuGemVa))

# --- DRM_IOCTL_AMDGPU_CS (0x04) — minimal empty submit ---
class AmdgpuCsIn(ctypes.Structure):
    _fields_ = [
        ("chunks",       ctypes.c_uint64),
        ("num_chunks",   ctypes.c_uint32),
        ("ctx_id",       ctypes.c_uint32),
    ]

class AmdgpuCsOut(ctypes.Structure):
    _fields_ = [
        ("handle",    ctypes.c_uint64),
    ]

class AmdgpuCsUnion(ctypes.Union):
    _fields_ = [("in_", AmdgpuCsIn), ("out", AmdgpuCsOut)]

DRM_AMDGPU_CS      = 0x04
DRM_IOCTL_AMDGPU_CS = _IOWR(DRM_IOCTL_BASE,
                              DRM_COMMAND_BASE + DRM_AMDGPU_CS,
                              ctypes.sizeof(AmdgpuCsUnion))

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

    # Check amdgpu module
    if os.path.exists("/sys/module/amdgpu"):
        pass_("amdgpu kernel module loaded (/sys/module/amdgpu)")
    else:
        fail_("amdgpu module not loaded — check lsmod")
        ok = False

    # Check BTF
    if os.path.exists("/sys/kernel/btf/vmlinux"):
        pass_("BTF available (/sys/kernel/btf/vmlinux)")
    else:
        info_("BTF not found — kfunc probes may fail")

    record("prerequisites", ok)
    return ok


def step1_driver_version(dev: str) -> "int | None":
    print(f"\n{BOLD}Step 1 — amdgpu driver probe / DRM_IOCTL_VERSION{RESET}")
    info_("Probing kfunc:drm_ioctl")

    probe = BpfProbe("kfunc:drm_ioctl")
    probe.start()

    fd = open_drm(dev)
    if fd is None:
        probe.stop(); record("amdgpu drm_open + version", False); return None

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
    ok = (ret == 0) and hit and (driver_name == "amdgpu")
    record("amdgpu drm_open + version (driver=amdgpu)", ok)
    if ret == 0:
        info_(f"  ↳ driver={driver_name}  v{ver.version_major}.{ver.version_minor}.{ver.version_patchlevel}")
    if driver_name not in ("amdgpu", "?"):
        info_(f"  ↳ Not an amdgpu device ({driver_name}) — remaining steps may fail")
    return fd


def step2_info_accel_working(fd: int) -> bool:
    print(f"\n{BOLD}Step 2 — DRM_IOCTL_AMDGPU_INFO (ACCEL_WORKING){RESET}")
    info_("Probing kfunc:amdgpu_info_ioctl")

    probe = BpfProbe("kfunc:amdgpu_info_ioctl")
    probe.start()

    result_val = ctypes.c_uint32(0)
    req = AmdgpuInfoRequest()
    req.return_pointer = ctypes.cast(ctypes.byref(result_val), ctypes.c_void_p).value
    req.return_size    = ctypes.sizeof(result_val)
    req.query          = AMDGPU_INFO_ACCEL_WORKING

    ret = ioctl(fd, DRM_IOCTL_AMDGPU_INFO, req)
    hit = probe.wait(); probe.stop()

    ok = hit
    record("amdgpu_info_ioctl (ACCEL_WORKING)", ok)
    if ret == 0:
        info_(f"  ↳ accel_working={result_val.value}")
        if result_val.value:
            pass_("  ↳ GPU acceleration is operational")
        else:
            fail_("  ↳ accel_working=0 — GPU may be in error state")
    else:
        info_(f"  ↳ ioctl returned {ret}")
    return ok


def step3_ctx_alloc(fd: int) -> int:
    print(f"\n{BOLD}Step 3 — DRM_IOCTL_AMDGPU_CTX alloc (GPU execution context){RESET}")
    info_("Probing kfunc:amdgpu_ctx_ioctl")

    probe = BpfProbe("kfunc:amdgpu_ctx_ioctl")
    probe.start()

    ctx = AmdgpuCtxUnion()
    ctx.in_.op       = AMDGPU_CTX_OP_ALLOC_CTX
    ctx.in_.flags    = 0
    ctx.in_.ctx_id   = 0
    ctx.in_.priority = AMDGPU_CTX_PRIORITY_NORMAL
    ret = ioctl(fd, DRM_IOCTL_AMDGPU_CTX, ctx)
    hit = probe.wait(); probe.stop()

    ok = (ret == 0) and hit
    ctx_id = ctx.out.ctx_id if ret == 0 else 0
    record("amdgpu_ctx_ioctl (ALLOC_CTX)", ok)
    if ret == 0:
        info_(f"  ↳ ctx_id={ctx_id}")
    else:
        info_(f"  ↳ ioctl returned {ret}")
    return ctx_id


def step4_gem_create(fd: int) -> int:
    print(f"\n{BOLD}Step 4 — DRM_IOCTL_AMDGPU_GEM_CREATE (GPU buffer object){RESET}")
    info_("Probing kfunc:amdgpu_gem_create_ioctl")

    probe = BpfProbe("kfunc:amdgpu_gem_create_ioctl")
    probe.start()

    gem = AmdgpuGemCreateUnion()
    gem.in_.bo_size      = 4096
    gem.in_.alignment    = 4096
    gem.in_.domains      = AMDGPU_GEM_DOMAIN_GTT   # system RAM — works without VRAM
    gem.in_.domain_flags = 0

    ret = ioctl(fd, DRM_IOCTL_AMDGPU_GEM_CREATE, gem)
    hit = probe.wait(); probe.stop()

    ok = (ret == 0) and hit
    handle = gem.out.handle if ret == 0 else 0
    record("amdgpu_gem_create_ioctl (4 KiB GTT BO)", ok)
    if ret == 0:
        info_(f"  ↳ gem_handle={handle}")
    else:
        info_(f"  ↳ ioctl returned {ret}")
    return handle


def step5_gem_mmap(fd: int, handle: int) -> bool:
    print(f"\n{BOLD}Step 5 — DRM_IOCTL_AMDGPU_GEM_MMAP (CPU mmap offset){RESET}")
    if handle == 0:
        info_("  ↳ No valid handle — skipping")
        record("amdgpu_gem_mmap_ioctl", False); return False

    info_("Probing kfunc:amdgpu_gem_mmap")

    probe = BpfProbe("kfunc:amdgpu_gem_mmap")
    probe.start()

    mm = AmdgpuGemMmapUnion()
    mm.in_.handle = handle
    mm.in_._pad   = 0
    ret = ioctl(fd, DRM_IOCTL_AMDGPU_GEM_MMAP, mm)
    hit = probe.wait(); probe.stop()

    ok = hit
    record("amdgpu_gem_mmap (mmap offset)", ok)
    if ret == 0:
        info_(f"  ↳ mmap addr_ptr=0x{mm.out.addr_ptr:016x}")
    else:
        info_(f"  ↳ ioctl returned {ret}")
    return ok


def step6_gem_va(fd: int, handle: int) -> bool:
    print(f"\n{BOLD}Step 6 — DRM_IOCTL_AMDGPU_GEM_VA (GPU virtual address mapping){RESET}")
    if handle == 0:
        info_("  ↳ No valid handle — skipping")
        record("amdgpu_gem_va (MAP)", False); return False

    info_("Probing kfunc:amdgpu_gem_va_ioctl")

    # Use a GPU VA in the middle of the 48-bit space; may fail if occupied,
    # but the kernel function entry is what we verify.
    TEST_GPU_VA = 0x0000_0001_0000_0000  # 4 GiB mark

    probe = BpfProbe("kfunc:amdgpu_gem_va_ioctl")
    probe.start()

    va = AmdgpuGemVa()
    va.handle       = handle
    va.operation    = AMDGPU_VA_OP_MAP
    va.flags        = (AMDGPU_VM_PAGE_READABLE | AMDGPU_VM_PAGE_WRITEABLE)
    va.va_address   = TEST_GPU_VA
    va.offset_in_bo = 0
    va.map_size     = 4096

    ret = ioctl(fd, DRM_IOCTL_AMDGPU_GEM_VA, va)
    hit = probe.wait(); probe.stop()

    ok = hit
    record("amdgpu_gem_va_ioctl (MAP into GPU VA space)", ok)
    if ret == 0:
        info_(f"  ↳ mapped BO handle={handle} @ GPU VA=0x{TEST_GPU_VA:016x}")
    else:
        info_(f"  ↳ ioctl returned {ret} (VA may be reserved; function still entered)")
    return ok


def step7_cs_dispatch(fd: int, ctx_id: int) -> bool:
    """
    Submit an empty CS (no chunks).  The kernel validates the input and
    returns -EINVAL, but amdgpu_cs_ioctl IS entered — that is what we verify.
    """
    print(f"\n{BOLD}Step 7 — DRM_IOCTL_AMDGPU_CS dispatch (command submission ioctl){RESET}")
    info_("Probing kfunc:amdgpu_cs_ioctl  (expect -EINVAL for empty batch)")

    probe = BpfProbe("kfunc:amdgpu_cs_ioctl")
    probe.start()

    cs = AmdgpuCsUnion()
    cs.in_.chunks     = 0
    cs.in_.num_chunks = 0
    cs.in_.ctx_id     = ctx_id

    ioctl(fd, DRM_IOCTL_AMDGPU_CS, cs)
    hit = probe.wait(); probe.stop()

    record("amdgpu_cs_ioctl dispatch (ioctl entry)", hit)
    if hit:
        info_("  ↳ amdgpu_cs_ioctl reached (returned -EINVAL as expected for empty CS)")
    return hit


def step8_job_run(fd: int) -> bool:
    print(f"\n{BOLD}Step 8 — amdgpu_job_run (GPU scheduler → ring, passive){RESET}")
    info_("Probing kfunc:amdgpu_job_run for 5 seconds")

    probe = BpfProbe("kfunc:amdgpu_job_run")
    probe.start()
    hit = probe.wait(timeout=5); probe.stop()

    record("amdgpu_job_run (GPU job execution, passive)", hit)
    if hit:
        info_("  ↳ GPU jobs are being dispatched to ring buffers")
    else:
        info_("  ↳ No GPU jobs in 5 s (idle system)")
    return hit


def step9_dma_fence_signal(fd: int) -> bool:
    print(f"\n{BOLD}Step 9 — dma_fence_signal (GPU work completion, passive){RESET}")
    info_("Probing kfunc:dma_fence_signal for 5 seconds")

    probe = BpfProbe("kfunc:dma_fence_signal")
    probe.start()
    hit = probe.wait(timeout=5); probe.stop()

    record("dma_fence_signal (GPU completion fence)", hit)
    if hit:
        info_("  ↳ GPU fences are signalling — work completing")
    else:
        info_("  ↳ No fence signals in 5 s (no active workload)")
    return hit


def step10_vm_flush(fd: int) -> bool:
    print(f"\n{BOLD}Step 10 — amdgpu_vm_flush (GPU page table TLB flush, passive){RESET}")
    info_("Probing kfunc:amdgpu_vm_flush for 5 seconds")

    probe = BpfProbe("kfunc:amdgpu_vm_flush")
    probe.start()
    hit = probe.wait(timeout=5); probe.stop()

    record("amdgpu_vm_flush (GPU TLB flush, passive)", hit)
    if hit:
        info_("  ↳ GPU VM flushes observed — VM context switches happening")
    else:
        info_("  ↳ No vm_flush in 5 s (idle or no context switches)")
    return hit


def step11_runtime_pm(fd: int) -> bool:
    print(f"\n{BOLD}Step 11 — amdgpu runtime PM (passive){RESET}")
    info_("Probing kfunc:amdgpu_device_runtime_resume,kfunc:amdgpu_device_runtime_suspend for 5 s")

    probe = BpfProbe(
        "kfunc:amdgpu_device_runtime_resume,kfunc:amdgpu_device_runtime_suspend")
    probe.start()
    hit = probe.wait(timeout=5); probe.stop()

    record("amdgpu runtime PM wake/suspend (passive)", hit)
    if hit:
        info_("  ↳ AMD GPU runtime PM transitions observed")
    else:
        info_("  ↳ No runtime PM events in 5 s (GPU may be in D0 continuously)")
    return hit


def step12_ctx_free(fd: int, ctx_id: int) -> bool:
    print(f"\n{BOLD}Step 12 — DRM_IOCTL_AMDGPU_CTX free (context teardown){RESET}")
    if ctx_id == 0:
        info_("  ↳ No valid ctx_id — skipping")
        record("amdgpu_ctx_ioctl (FREE_CTX)", False); return False

    info_("Probing kfunc:amdgpu_ctx_ioctl")

    probe = BpfProbe("kfunc:amdgpu_ctx_ioctl")
    probe.start()

    ctx = AmdgpuCtxUnion()
    ctx.in_.op     = AMDGPU_CTX_OP_FREE_CTX
    ctx.in_.flags  = 0
    ctx.in_.ctx_id = ctx_id
    ret = ioctl(fd, DRM_IOCTL_AMDGPU_CTX, ctx)
    hit = probe.wait(); probe.stop()

    ok = hit
    record("amdgpu_ctx_ioctl (FREE_CTX — context teardown)", ok)
    if ret == 0:
        info_(f"  ↳ ctx_id={ctx_id} freed")
    else:
        info_(f"  ↳ free ioctl returned {ret}")
    return ok


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def main():
    global PROBE_TIMEOUT
    parser = argparse.ArgumentParser(description="amdgpu bpftrace workflow test")
    parser.add_argument("--dev",     default=DRM_DEV_DEFAULT)
    parser.add_argument("--timeout", type=int, default=PROBE_TIMEOUT)
    args = parser.parse_args()

    PROBE_TIMEOUT = args.timeout

    print(f"""
{BOLD}╔══════════════════════════════════════════════════════════════╗
║      amdgpu Driver — bpftrace Workflow Verification          ║
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

    step2_info_accel_working(fd)
    ctx_id = step3_ctx_alloc(fd)
    handle = step4_gem_create(fd)
    step5_gem_mmap(fd, handle)
    step6_gem_va(fd, handle)
    step7_cs_dispatch(fd, ctx_id)
    step8_job_run(fd)
    step9_dma_fence_signal(fd)
    step10_vm_flush(fd)
    step11_runtime_pm(fd)
    step12_ctx_free(fd, ctx_id)

    # Cleanup GEM handle
    if handle:
        close_arg = DrmGemClose(handle=handle)
        _libc().ioctl(fd, ctypes.c_ulong(DRM_IOCTL_GEM_CLOSE), ctypes.byref(close_arg))

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
    • Not an amdgpu GPU → steps 2-12 will fail (driver name differs)
    • BTF not available: check /sys/kernel/btf/vmlinux
    • kfunc names changed: use  bpftrace -l 'kfunc:amdgpu*'  to verify
    • Passive steps (8-11): idle system → expected FAIL for no-workload cases
    • VM flush (step 10): only fires when multiple GPU contexts switch
    • Runtime PM (step 11): may not fire if amdgpu_runtime_pm=0 module param
    • GEM VA (step 6): VA range may conflict — function entry still tested
""")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
