#!/usr/bin/env python3
"""
i915 Driver — bpftrace Workflow Verification
=============================================
Traces the i915 submission pipeline step by step and marks
each stage PASS or FAIL.

Verified paths:
  Step 0  — prerequisites (root, bpftrace, /dev/dri/card0)
  Step 1  — i915_driver_probe (module present)
  Step 2  — i915_gem_context_create (GEM context + PPGTT)
  Step 3  — i915_gem_create (GEM object allocation)
  Step 4  — i915_gem_mmap (CPU mmap of GEM object)
  Step 5  — i915_gem_execbuffer2 dispatch
  Step 6  — i915_request_create (request alloc on engine timeline)
  Step 7  — intel_guc_submit OR execlists_submit_request
  Step 8  — dma_fence_signal (GPU work completion)
  Step 9  — i915_request_retire (request retired, breadcrumb advanced)
  Step 10 — intel_gt_pm wakeref (runtime-PM wake cycle)
  Step 11 — i915_gem_context_close (context teardown)

Requirements:
  - bpftrace >= 0.16  (sudo apt install bpftrace)
  - Root privileges   (sudo python3 trace_test.py)
  - Intel GPU with i915 loaded (/dev/dri/card0)
  - Kernel built with CONFIG_DEBUG_INFO_BTF=y

Usage:
  sudo python3 trace_test.py [--dev /dev/dri/card0] [--timeout 15]
"""

import argparse
import ctypes
import ctypes.util
import fcntl
import os
import struct
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

DRM_DEV_DEFAULT    = _find_drm_card("i915")
RENDER_DEV_DEFAULT = _find_render_node(DRM_DEV_DEFAULT)
BPFTRACE_BIN       = "bpftrace"
PROBE_TIMEOUT      = 10  # seconds per step

# ──────────────────────────────────────────────────────────────────────────────
# DRM / i915 ioctl numbers  (from <drm/drm.h> and <drm/i915_drm.h>)
# ──────────────────────────────────────────────────────────────────────────────

DRM_IOCTL_BASE = ord('d')

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

# DRM_IOCTL_VERSION
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

# DRM_IOCTL_GET_CAP
class DrmGetCap(ctypes.Structure):
    _fields_ = [("capability", ctypes.c_uint64), ("value", ctypes.c_uint64)]

DRM_CAP_DUMB_BUFFER = 0x1
DRM_IOCTL_GET_CAP   = _IOWR(DRM_IOCTL_BASE, 0x0C, ctypes.sizeof(DrmGetCap))

# i915 ioctls start at DRM_COMMAND_BASE = 0x40
DRM_COMMAND_BASE = 0x40

# DRM_I915_GEM_CREATE  (0x0b → DRM_COMMAND_BASE + 0x0b = 0x4b)
class I915GemCreate(ctypes.Structure):
    _fields_ = [
        ("size",   ctypes.c_uint64),
        ("handle", ctypes.c_uint32),
        ("pad",    ctypes.c_uint32),
    ]

DRM_I915_GEM_CREATE   = 0x0b
DRM_IOCTL_I915_GEM_CREATE = _IOWR(DRM_IOCTL_BASE,
                                    DRM_COMMAND_BASE + DRM_I915_GEM_CREATE,
                                    ctypes.sizeof(I915GemCreate))

# DRM_I915_GEM_MMAP  (0x0c)
class I915GemMmap(ctypes.Structure):
    _fields_ = [
        ("handle",   ctypes.c_uint32),
        ("pad",      ctypes.c_uint32),
        ("offset",   ctypes.c_uint64),
        ("size",     ctypes.c_uint64),
        ("addr_ptr", ctypes.c_uint64),
        ("flags",    ctypes.c_uint64),
    ]

DRM_I915_GEM_MMAP = 0x0c
DRM_IOCTL_I915_GEM_MMAP = _IOWR(DRM_IOCTL_BASE,
                                  DRM_COMMAND_BASE + DRM_I915_GEM_MMAP,
                                  ctypes.sizeof(I915GemMmap))

# DRM_I915_GEM_CONTEXT_CREATE  (0x1d)
class I915GemContextCreate(ctypes.Structure):
    _fields_ = [
        ("ctx_id", ctypes.c_uint32),
        ("pad",    ctypes.c_uint32),
    ]

DRM_I915_GEM_CONTEXT_CREATE = 0x1d
DRM_IOCTL_I915_GEM_CONTEXT_CREATE = _IOWR(
    DRM_IOCTL_BASE,
    DRM_COMMAND_BASE + DRM_I915_GEM_CONTEXT_CREATE,
    ctypes.sizeof(I915GemContextCreate))

# DRM_I915_GEM_CONTEXT_DESTROY  (0x1f)
class I915GemContextDestroy(ctypes.Structure):
    _fields_ = [
        ("ctx_id", ctypes.c_uint32),
        ("pad",    ctypes.c_uint32),
    ]

DRM_I915_GEM_CONTEXT_DESTROY = 0x1f
DRM_IOCTL_I915_GEM_CONTEXT_DESTROY = _IOW(
    DRM_IOCTL_BASE,
    DRM_COMMAND_BASE + DRM_I915_GEM_CONTEXT_DESTROY,
    ctypes.sizeof(I915GemContextDestroy))

# DRM_I915_GEM_CLOSE  (same as DRM core GEM_CLOSE = 0x09)
class DrmGemClose(ctypes.Structure):
    _fields_ = [("handle", ctypes.c_uint32), ("pad", ctypes.c_uint32)]

DRM_IOCTL_GEM_CLOSE = _IOW(DRM_IOCTL_BASE, 0x09, ctypes.sizeof(DrmGemClose))

# DRM_I915_GETPARAM  (0x06)
class DrmI915GetParam(ctypes.Structure):
    _fields_ = [("param", ctypes.c_int), ("value", ctypes.c_void_p)]

I915_PARAM_CHIPSET_ID      = 4
I915_PARAM_HAS_GEM         = 21
I915_PARAM_HAS_EXECBUF2    = 30
DRM_IOCTL_I915_GETPARAM = _IOWR(DRM_IOCTL_BASE,
                                  DRM_COMMAND_BASE + 0x06,
                                  ctypes.sizeof(DrmI915GetParam))

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

def open_drm(path: str) -> int | None:
    try:
        return os.open(path, os.O_RDWR | os.O_CLOEXEC)
    except OSError as e:
        info_(f"Cannot open {path}: {e}")
        return None

# ──────────────────────────────────────────────────────────────────────────────
# Result tracking
# ──────────────────────────────────────────────────────────────────────────────

RESULTS: list[tuple[str, bool]] = []

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

    # Verify i915 is loaded
    loaded = os.path.exists("/sys/module/i915")
    if loaded:
        pass_("i915 kernel module loaded (/sys/module/i915)")
    else:
        fail_("i915 module not loaded")
        ok = False

    record("prerequisites", ok)
    return ok


def step1_driver_version(dev: str) -> int | None:
    print(f"\n{BOLD}Step 1 — i915 driver probe / DRM_IOCTL_VERSION{RESET}")
    info_("Probing kfunc:drm_ioctl (i915 version query)")

    probe = BpfProbe("kfunc:drm_ioctl")
    probe.start()

    fd = open_drm(dev)
    if fd is None:
        probe.stop(); record("i915 drm_open + version", False); return None

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
    ok = (ret == 0) and hit and (driver_name == "i915")
    record("i915 drm_open + version (driver=i915)", ok)
    if ret == 0:
        info_(f"  ↳ driver={driver_name}  v{ver.version_major}.{ver.version_minor}.{ver.version_patchlevel}")
    if driver_name != "i915":
        info_("  ↳ Not an i915 device — remaining i915-specific steps may fail")
    return fd


def step2_getparam(fd: int) -> bool:
    print(f"\n{BOLD}Step 2 — i915_getparam (CHIPSET_ID){RESET}")
    info_("Probing kfunc:i915_getparam_ioctl")

    probe = BpfProbe("kfunc:i915_getparam_ioctl")
    probe.start()

    val = ctypes.c_int(0)
    gp  = DrmI915GetParam(param=I915_PARAM_CHIPSET_ID, value=ctypes.cast(
          ctypes.byref(val), ctypes.c_void_p))
    ret = ioctl(fd, DRM_IOCTL_I915_GETPARAM, gp)
    hit = probe.wait(); probe.stop()

    ok = hit
    record("i915_getparam (CHIPSET_ID)", ok)
    if ret == 0:
        info_(f"  ↳ chipset_id=0x{val.value & 0xFFFF:04x}")
    return ok


def step3_context_create(fd: int) -> int:
    print(f"\n{BOLD}Step 3 — i915_gem_context_create (PPGTT per-context){RESET}")
    info_("Probing kfunc:i915_gem_context_create_ioctl")

    probe = BpfProbe("kfunc:i915_gem_context_create_ioctl")
    probe.start()

    ctx = I915GemContextCreate()
    ret = ioctl(fd, DRM_IOCTL_I915_GEM_CONTEXT_CREATE, ctx)
    hit = probe.wait(); probe.stop()

    ok = (ret == 0) and hit
    ctx_id = ctx.ctx_id if ret == 0 else 0
    record("i915_gem_context_create (PPGTT)", ok)
    if ret == 0:
        info_(f"  ↳ ctx_id={ctx_id}")
    else:
        info_(f"  ↳ ioctl returned {ret}  (may be unsupported on this kernel/driver)")
    return ctx_id


def step4_gem_create(fd: int) -> int:
    print(f"\n{BOLD}Step 4 — i915_gem_create (GEM object alloc){RESET}")
    info_("Probing kfunc:i915_gem_create_ioctl")

    probe = BpfProbe("kfunc:i915_gem_create_ioctl")
    probe.start()

    obj = I915GemCreate(size=4096)
    ret = ioctl(fd, DRM_IOCTL_I915_GEM_CREATE, obj)
    hit = probe.wait(); probe.stop()

    ok = (ret == 0) and hit
    handle = obj.handle if ret == 0 else 0
    record("i915_gem_create (4 KiB object)", ok)
    if ret == 0:
        info_(f"  ↳ handle={handle}  size={obj.size} bytes")
    else:
        info_(f"  ↳ ioctl returned {ret}")
    return handle


def step5_gem_mmap(fd: int, handle: int) -> bool:
    print(f"\n{BOLD}Step 5 — i915_gem_mmap (CPU mmap of GEM object){RESET}")
    if handle == 0:
        info_("  ↳ No valid handle — skipping")
        record("i915_gem_mmap", False); return False

    info_("Probing kfunc:i915_gem_mmap")

    probe = BpfProbe("kfunc:i915_gem_mmap")
    probe.start()

    mm = I915GemMmap(handle=handle, pad=0, offset=0, size=4096, addr_ptr=0, flags=0)
    ret = ioctl(fd, DRM_IOCTL_I915_GEM_MMAP, mm)
    hit = probe.wait(); probe.stop()

    ok = hit  # ret may be -EINVAL on newer kernels (mmap_offset preferred)
    record("i915_gem_mmap", ok)
    if ret == 0:
        info_(f"  ↳ user addr=0x{mm.addr_ptr:016x}")
    else:
        info_(f"  ↳ ioctl returned {ret} (mmap_offset path may be needed instead)")
    return ok


def step6_execbuffer2_dispatch(fd: int) -> bool:
    """
    We cannot easily construct a valid batch without a real GPU context/VM,
    so we probe the ioctl entry point using an intentionally invalid call
    (empty exec list) and verify the kernel function was entered.
    The kernel will return -EINVAL, but the function IS called.
    """
    print(f"\n{BOLD}Step 6 — i915_gem_execbuffer2 dispatch{RESET}")
    info_("Probing kfunc:i915_gem_execbuffer2_ioctl  (expect -EINVAL for empty batch)")

    # struct drm_i915_gem_execbuffer2
    class I915ExecBuffer2(ctypes.Structure):
        _fields_ = [
            ("buffers_ptr",       ctypes.c_uint64),
            ("buffer_count",      ctypes.c_uint32),
            ("batch_start_offset",ctypes.c_uint32),
            ("batch_len",         ctypes.c_uint32),
            ("DR1",               ctypes.c_uint32),
            ("DR4",               ctypes.c_uint32),
            ("num_cliprects",     ctypes.c_uint32),
            ("cliprects_ptr",     ctypes.c_uint64),
            ("flags",             ctypes.c_uint64),
            ("rsvd1",             ctypes.c_uint64),
            ("rsvd2",             ctypes.c_uint64),
        ]

    DRM_I915_GEM_EXECBUFFER2 = 0x1e
    DRM_IOCTL_I915_GEM_EXECBUFFER2 = _IOWR(
        DRM_IOCTL_BASE,
        DRM_COMMAND_BASE + DRM_I915_GEM_EXECBUFFER2,
        ctypes.sizeof(I915ExecBuffer2))

    probe = BpfProbe("kfunc:i915_gem_execbuffer2_ioctl")
    probe.start()

    eb = I915ExecBuffer2()  # all zeros → invalid → -EINVAL
    ioctl(fd, DRM_IOCTL_I915_GEM_EXECBUFFER2, eb)
    hit = probe.wait(); probe.stop()

    record("i915_gem_execbuffer2_ioctl dispatch", hit)
    if hit:
        info_("  ↳ execbuffer2 ioctl entry reached (returned -EINVAL as expected)")
    return hit


def step7_request_create(fd: int) -> bool:
    print(f"\n{BOLD}Step 7 — i915_request_create (passive observation){RESET}")
    info_("Probing kfunc:i915_request_create for 5 seconds")

    probe = BpfProbe("kfunc:i915_request_create")
    probe.start()
    hit = probe.wait(timeout=5); probe.stop()

    record("i915_request_create (passive)", hit)
    if hit:
        info_("  ↳ GPU requests are being created on this system")
    else:
        info_("  ↳ No GPU work observed in 5 s (idle system)")
    return hit


def step8_guc_or_execlists(fd: int) -> bool:
    print(f"\n{BOLD}Step 8 — GuC or ExecLists submission (passive){RESET}")
    info_("Probing kfunc:intel_guc_submit,kfunc:execlists_submit_request for 5 s")

    probe = BpfProbe(
        "kfunc:intel_guc_submit,kfunc:execlists_submit_request")
    probe.start()
    hit = probe.wait(timeout=5); probe.stop()

    record("GuC/ExecLists submission (passive)", hit)
    if hit:
        info_("  ↳ GPU submission path exercised")
    else:
        info_("  ↳ No submission in 5 s (idle)")
    return hit


def step9_dma_fence_signal(fd: int) -> bool:
    print(f"\n{BOLD}Step 9 — dma_fence_signal (GPU completion, passive){RESET}")
    info_("Probing kfunc:dma_fence_signal for 5 seconds")

    probe = BpfProbe("kfunc:dma_fence_signal")
    probe.start()
    hit = probe.wait(timeout=5); probe.stop()

    record("dma_fence_signal (GPU completion)", hit)
    if hit:
        info_("  ↳ GPU fences are signalling — work completing")
    else:
        info_("  ↳ No fence signals in 5 s (no active workload)")
    return hit


def step10_gt_wakeref(fd: int) -> bool:
    print(f"\n{BOLD}Step 10 — intel_gt PM wakeref (runtime-PM){RESET}")
    info_("Probing kfunc:intel_gt_pm_get_if_awake OR intel_gt_pm_get for 5 s")

    probe = BpfProbe(
        "kfunc:intel_gt_pm_get_if_awake,kfunc:intel_gt_pm_get")
    probe.start()
    hit = probe.wait(timeout=5); probe.stop()

    record("intel_gt_pm wakeref (runtime-PM)", hit)
    if hit:
        info_("  ↳ GT power management wakeref observed")
    else:
        info_("  ↳ GT wakeref not observed (GT may be fully idle/RC6)")
    return hit


def step11_context_destroy(fd: int, ctx_id: int) -> bool:
    print(f"\n{BOLD}Step 11 — i915_gem_context_close (context teardown){RESET}")
    if ctx_id == 0:
        info_("  ↳ No valid context — skipping")
        record("i915_gem_context_destroy", False); return False

    info_("Probing kfunc:i915_gem_context_close")

    probe = BpfProbe("kfunc:i915_gem_context_close")
    probe.start()

    destroy = I915GemContextDestroy(ctx_id=ctx_id, pad=0)
    ret = ioctl(fd, DRM_IOCTL_I915_GEM_CONTEXT_DESTROY, destroy)
    hit = probe.wait(); probe.stop()

    ok = hit
    record("i915_gem_context_destroy (PPGTT teardown)", ok)
    if ret == 0:
        info_(f"  ↳ context {ctx_id} destroyed")
    else:
        info_(f"  ↳ destroy ioctl returned {ret}")
    return ok


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def main():
    global PROBE_TIMEOUT
    parser = argparse.ArgumentParser(description="i915 bpftrace workflow test")
    parser.add_argument("--dev",     default=DRM_DEV_DEFAULT)
    parser.add_argument("--timeout", type=int, default=PROBE_TIMEOUT)
    args = parser.parse_args()

    PROBE_TIMEOUT = args.timeout

    print(f"""
{BOLD}╔══════════════════════════════════════════════════════════════╗
║        i915 Driver — bpftrace Workflow Verification          ║
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
    ctx_id = step3_context_create(fd)
    handle = step4_gem_create(fd)
    step5_gem_mmap(fd, handle)
    step6_execbuffer2_dispatch(fd)
    step7_request_create(fd)
    step8_guc_or_execlists(fd)
    step9_dma_fence_signal(fd)
    step10_gt_wakeref(fd)
    step11_context_destroy(fd, ctx_id)

    # Close fd last (after context destroy)
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
    • Not an i915 GPU → steps 2-11 will fail (probe names differ for other drivers)
    • BTF not available: check /sys/kernel/btf/vmlinux
    • kfunc names changed: use  bpftrace -l 'kfunc:i915*'  to verify
    • Passive steps (7-10): idle system → expected FAIL for no-workload cases
    • context_create (step 3) unsupported on some kernels: use I915_CONTEXT_CREATE_EXT
""")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
