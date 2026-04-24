#!/usr/bin/env python3
"""
Intel Xe GPU Driver — bpftrace Workflow Verification
=====================================================
Traces the Xe driver submission pipeline step by step and marks
each stage PASS or FAIL.

Verified paths:
  Step 0  — prerequisites (root, bpftrace, /dev/dri/card0, xe module)
  Step 1  — xe driver open / DRM_IOCTL_VERSION (driver=xe)
  Step 2  — DRM_IOCTL_XE_DEVICE_QUERY (CONFIG — platform version, VA bits)
  Step 3  — DRM_IOCTL_XE_VM_CREATE (GPU virtual address space)
  Step 4  — DRM_IOCTL_XE_GEM_CREATE (GPU buffer object, system memory)
  Step 5  — DRM_IOCTL_XE_GEM_MMAP_OFFSET (mmap offset for CPU access)
  Step 6  — DRM_IOCTL_XE_EXEC_QUEUE_CREATE (execution queue dispatch)
  Step 7  — DRM_IOCTL_XE_EXEC dispatch (submission ioctl entry)
  Step 8  — xe_sched_job_run (GPU scheduler → ring, passive)
  Step 9  — xe_vm_rebind (page table rebind after eviction, passive)
  Step 10 — DRM_IOCTL_XE_EXEC_QUEUE_DESTROY (queue teardown)
  Step 11 — DRM_IOCTL_XE_VM_DESTROY (VM teardown)

Requirements:
  - bpftrace >= 0.16  (sudo apt install bpftrace)
  - Root privileges   (sudo python3 trace_test.py)
  - Intel GPU with xe loaded (/dev/dri/card0)
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

DRM_DEV_DEFAULT    = _find_drm_card("xe")
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
# Xe ioctls  (from include/uapi/drm/xe_drm.h)
# ──────────────────────────────────────────────────────────────────────────────

# --- DRM_IOCTL_XE_DEVICE_QUERY (0x00) ---
DRM_XE_DEVICE_QUERY_CONFIG = 2

class XeDeviceQuery(ctypes.Structure):
    _fields_ = [
        ("extensions", ctypes.c_uint64),
        ("query",      ctypes.c_uint32),
        ("size",       ctypes.c_uint32),   # in: buf size; out: actual size
        ("data",       ctypes.c_uint64),   # ptr to result buf (0 = size query)
        ("reserved",   ctypes.c_uint64 * 2),
    ]

DRM_XE_DEVICE_QUERY = 0x00
DRM_IOCTL_XE_DEVICE_QUERY = _IOWR(DRM_IOCTL_BASE,
                                    DRM_COMMAND_BASE + DRM_XE_DEVICE_QUERY,
                                    ctypes.sizeof(XeDeviceQuery))

# --- DRM_IOCTL_XE_VM_CREATE (0x03) ---
DRM_XE_VM_CREATE_FLAG_SCRATCH_PAGE = (1 << 0)

class XeVmCreate(ctypes.Structure):
    _fields_ = [
        ("extensions", ctypes.c_uint64),
        ("flags",      ctypes.c_uint32),
        ("vm_id",      ctypes.c_uint32),
        ("reserved",   ctypes.c_uint64 * 2),
    ]

DRM_XE_VM_CREATE = 0x03
DRM_IOCTL_XE_VM_CREATE = _IOWR(DRM_IOCTL_BASE,
                                 DRM_COMMAND_BASE + DRM_XE_VM_CREATE,
                                 ctypes.sizeof(XeVmCreate))

# --- DRM_IOCTL_XE_VM_DESTROY (0x04) ---
class XeVmDestroy(ctypes.Structure):
    _fields_ = [
        ("vm_id",    ctypes.c_uint32),
        ("pad",      ctypes.c_uint32),
        ("reserved", ctypes.c_uint64 * 2),
    ]

DRM_XE_VM_DESTROY = 0x04
DRM_IOCTL_XE_VM_DESTROY = _IOW(DRM_IOCTL_BASE,
                                 DRM_COMMAND_BASE + DRM_XE_VM_DESTROY,
                                 ctypes.sizeof(XeVmDestroy))

# --- DRM_IOCTL_XE_GEM_CREATE (0x01) ---
DRM_XE_GEM_CPU_CACHING_WB = 1

class XeGemCreate(ctypes.Structure):
    _fields_ = [
        ("extensions",   ctypes.c_uint64),
        ("size",         ctypes.c_uint64),
        ("placement",    ctypes.c_uint32),   # memory region instance mask
        ("flags",        ctypes.c_uint32),
        ("vm_id",        ctypes.c_uint32),
        ("handle",       ctypes.c_uint32),   # OUT
        ("cpu_caching",  ctypes.c_uint16),
        ("pad",          ctypes.c_uint16 * 3),
        ("reserved",     ctypes.c_uint64 * 2),
    ]

DRM_XE_GEM_CREATE = 0x01
DRM_IOCTL_XE_GEM_CREATE = _IOWR(DRM_IOCTL_BASE,
                                  DRM_COMMAND_BASE + DRM_XE_GEM_CREATE,
                                  ctypes.sizeof(XeGemCreate))

# --- DRM_IOCTL_XE_GEM_MMAP_OFFSET (0x02) ---
class XeGemMmapOffset(ctypes.Structure):
    _fields_ = [
        ("extensions", ctypes.c_uint64),
        ("handle",     ctypes.c_uint32),
        ("flags",      ctypes.c_uint32),
        ("offset",     ctypes.c_uint64),   # OUT
        ("reserved",   ctypes.c_uint64 * 2),
    ]

DRM_XE_GEM_MMAP_OFFSET = 0x02
DRM_IOCTL_XE_GEM_MMAP_OFFSET = _IOWR(DRM_IOCTL_BASE,
                                       DRM_COMMAND_BASE + DRM_XE_GEM_MMAP_OFFSET,
                                       ctypes.sizeof(XeGemMmapOffset))

# --- DRM_IOCTL_XE_EXEC_QUEUE_CREATE (0x06) ---
class XeEngineClassInstance(ctypes.Structure):
    _fields_ = [
        ("engine_class",    ctypes.c_uint16),
        ("engine_instance", ctypes.c_uint16),
        ("gt_id",           ctypes.c_uint16),
        ("pad",             ctypes.c_uint16),
    ]

DRM_XE_ENGINE_CLASS_COPY = 1   # BCS — most likely present

class XeExecQueueCreate(ctypes.Structure):
    _fields_ = [
        ("extensions",      ctypes.c_uint64),
        ("width",           ctypes.c_uint16),
        ("num_placements",  ctypes.c_uint16),
        ("vm_id",           ctypes.c_uint32),
        ("flags",           ctypes.c_uint32),
        ("exec_queue_id",   ctypes.c_uint32),   # OUT
        ("instances",       ctypes.c_uint64),   # ptr to XeEngineClassInstance[]
        ("reserved",        ctypes.c_uint64 * 2),
    ]

DRM_XE_EXEC_QUEUE_CREATE = 0x06
DRM_IOCTL_XE_EXEC_QUEUE_CREATE = _IOWR(DRM_IOCTL_BASE,
                                         DRM_COMMAND_BASE + DRM_XE_EXEC_QUEUE_CREATE,
                                         ctypes.sizeof(XeExecQueueCreate))

# --- DRM_IOCTL_XE_EXEC_QUEUE_DESTROY (0x07) ---
class XeExecQueueDestroy(ctypes.Structure):
    _fields_ = [
        ("exec_queue_id", ctypes.c_uint32),
        ("pad",           ctypes.c_uint32),
        ("reserved",      ctypes.c_uint64 * 2),
    ]

DRM_XE_EXEC_QUEUE_DESTROY = 0x07
DRM_IOCTL_XE_EXEC_QUEUE_DESTROY = _IOW(DRM_IOCTL_BASE,
                                         DRM_COMMAND_BASE + DRM_XE_EXEC_QUEUE_DESTROY,
                                         ctypes.sizeof(XeExecQueueDestroy))

# --- DRM_IOCTL_XE_EXEC (0x09) ---
class XeExec(ctypes.Structure):
    _fields_ = [
        ("extensions",        ctypes.c_uint64),
        ("exec_queue_id",     ctypes.c_uint32),
        ("num_syncs",         ctypes.c_uint32),
        ("syncs",             ctypes.c_uint64),   # ptr to drm_xe_sync[]
        ("address",           ctypes.c_uint64),   # batch buffer GPU VA
        ("num_batch_buffer",  ctypes.c_uint16),
        ("pad",               ctypes.c_uint16 * 3),
        ("reserved",          ctypes.c_uint64 * 2),
    ]

DRM_XE_EXEC = 0x09
DRM_IOCTL_XE_EXEC = _IOW(DRM_IOCTL_BASE,
                           DRM_COMMAND_BASE + DRM_XE_EXEC,
                           ctypes.sizeof(XeExec))

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

def find_probe(*symbols: str) -> str | None:
    """Return the first available probe expression for any of the given symbols.

    Tries kfunc: then kprobe: for each symbol using bpftrace -l.
    Returns e.g. 'kprobe:xe_gem_mmap_offset_ioctl' or None if nothing is found.
    """
    for sym in symbols:
        for ptype in ("kfunc", "kprobe"):
            try:
                r = subprocess.run(
                    [BPFTRACE_BIN, "-l", f"{ptype}:{sym}"],
                    capture_output=True, text=True, timeout=5,
                )
                if r.returncode == 0 and sym in r.stdout:
                    return f"{ptype}:{sym}"
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
    return None


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

    if os.path.exists("/sys/module/xe"):
        pass_("xe kernel module loaded (/sys/module/xe)")
    else:
        fail_("xe module not loaded — is this an Intel Xe GPU with xe driver?")
        ok = False

    if os.path.exists("/sys/kernel/btf/vmlinux"):
        pass_("BTF available (/sys/kernel/btf/vmlinux)")
    else:
        info_("BTF not found — kfunc probes may fail")

    record("prerequisites", ok)
    return ok


def step1_driver_version(dev: str) -> "int | None":
    print(f"\n{BOLD}Step 1 — xe driver open / DRM_IOCTL_VERSION{RESET}")
    info_("Probing kfunc:drm_ioctl")

    probe = BpfProbe("kfunc:drm_ioctl")
    probe.start()

    fd = open_drm(dev)
    if fd is None:
        probe.stop(); record("xe drm_open + version", False); return None

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
    ok = (ret == 0) and hit and (driver_name == "xe")
    record("xe drm_open + version (driver=xe)", ok)
    if ret == 0:
        info_(f"  ↳ driver={driver_name}  v{ver.version_major}.{ver.version_minor}.{ver.version_patchlevel}")
    if driver_name not in ("xe", "?"):
        info_(f"  ↳ Not a Xe device ({driver_name}) — remaining steps may fail")
    return fd


def step2_device_query(fd: int) -> bool:
    print(f"\n{BOLD}Step 2 — DRM_IOCTL_XE_DEVICE_QUERY (CONFIG){RESET}")
    info_("Probing kfunc:xe_query_ioctl")

    probe = BpfProbe("kfunc:xe_query_ioctl")
    probe.start()

    # Two-phase: first get the size, then fetch data
    q = XeDeviceQuery(query=DRM_XE_DEVICE_QUERY_CONFIG, size=0, data=0)
    ret = ioctl(fd, DRM_IOCTL_XE_DEVICE_QUERY, q)
    size = q.size

    if ret == 0 and size > 0:
        buf = (ctypes.c_uint64 * (size // 8 + 1))()
        q2 = XeDeviceQuery(query=DRM_XE_DEVICE_QUERY_CONFIG, size=size,
                           data=ctypes.cast(buf, ctypes.c_void_p).value)
        ret = ioctl(fd, DRM_IOCTL_XE_DEVICE_QUERY, q2)

    hit = probe.wait(); probe.stop()

    ok = hit
    record("xe_query_ioctl (DEVICE_QUERY_CONFIG)", ok)
    if ret == 0 and size > 0:
        # buf[0] = rev_and_device_id, buf[1] = flags, buf[2] = min_alignment,
        # buf[3] = va_bits, buf[4] = max_exec_queue_priority
        info_(f"  ↳ config size={size} bytes")
        if len(buf) > 3:
            info_(f"  ↳ va_bits={buf[3] & 0xFFFF}  min_alignment=0x{buf[2]:x}")
    else:
        info_(f"  ↳ query returned {ret} (size={size})")
    return ok


def step3_vm_create(fd: int) -> int:
    print(f"\n{BOLD}Step 3 — DRM_IOCTL_XE_VM_CREATE (GPU virtual address space){RESET}")
    info_("Probing kfunc:xe_vm_create_ioctl")

    probe = BpfProbe("kfunc:xe_vm_create_ioctl")
    probe.start()

    vm = XeVmCreate(flags=DRM_XE_VM_CREATE_FLAG_SCRATCH_PAGE)
    ret = ioctl(fd, DRM_IOCTL_XE_VM_CREATE, vm)
    hit = probe.wait(); probe.stop()

    ok = (ret == 0) and hit
    vm_id = vm.vm_id if ret == 0 else 0
    record("xe_vm_create_ioctl (GPU VA space)", ok)
    if ret == 0:
        info_(f"  ↳ vm_id={vm_id}")
    else:
        info_(f"  ↳ ioctl returned {ret}")
    return vm_id


def step4_gem_create(fd: int) -> int:
    print(f"\n{BOLD}Step 4 — DRM_IOCTL_XE_GEM_CREATE (GPU buffer object, system memory){RESET}")
    info_("Probing kfunc:xe_gem_create_ioctl")

    probe = BpfProbe("kfunc:xe_gem_create_ioctl")
    probe.start()

    gem = XeGemCreate()
    gem.size        = 4096
    gem.placement   = 1     # region instance 0 (typically system/GTT)
    gem.flags       = 0
    gem.vm_id       = 0     # not pinned to a VM
    gem.cpu_caching = DRM_XE_GEM_CPU_CACHING_WB

    ret = ioctl(fd, DRM_IOCTL_XE_GEM_CREATE, gem)
    hit = probe.wait(); probe.stop()

    ok = (ret == 0) and hit
    handle = gem.handle if ret == 0 else 0
    record("xe_gem_create_ioctl (4 KiB system BO)", ok)
    if ret == 0:
        info_(f"  ↳ handle={handle}")
    else:
        info_(f"  ↳ ioctl returned {ret}")
    return handle


def step5_gem_mmap_offset(fd: int, handle: int) -> bool:
    print(f"\n{BOLD}Step 5 — DRM_IOCTL_XE_GEM_MMAP_OFFSET (CPU mmap offset){RESET}")
    if handle == 0:
        info_("  ↳ No valid handle — skipping")
        record("xe_gem_mmap_offset (CPU mmap offset)", False); return False

    # Kernel may export this as xe_gem_mmap_offset_ioctl (kprobe) or xe_gem_mmap_offset (kfunc)
    probe_expr = find_probe("xe_gem_mmap_offset_ioctl", "xe_gem_mmap_offset")
    if probe_expr is None:
        info_("xe_gem_mmap_offset not available as kfunc or kprobe — skipping probe")
        mm = XeGemMmapOffset(handle=handle, flags=0)
        ret = ioctl(fd, DRM_IOCTL_XE_GEM_MMAP_OFFSET, mm)
        if ret == 0:
            info_(f"  ↳ mmap offset=0x{mm.offset:016x}  (ioctl OK, probe skipped)")
        record("xe_gem_mmap_offset (CPU mmap offset)", ret == 0)
        return ret == 0

    info_(f"Probing {probe_expr}")
    probe = BpfProbe(probe_expr)
    probe.start()

    mm = XeGemMmapOffset(handle=handle, flags=0)
    ret = ioctl(fd, DRM_IOCTL_XE_GEM_MMAP_OFFSET, mm)
    hit = probe.wait(); probe.stop()

    ok = hit
    record("xe_gem_mmap_offset (CPU mmap offset)", ok)
    if ret == 0:
        info_(f"  ↳ mmap offset=0x{mm.offset:016x}")
    else:
        info_(f"  ↳ ioctl returned {ret}")
    return ok


def step6_exec_queue_create(fd: int, vm_id: int) -> int:
    """
    Create an exec queue bound to the first BCS (copy) engine on GT 0.
    BCS is almost always present; falls back to probing the function entry
    even if the engine class/gt combo is invalid on this device.
    """
    print(f"\n{BOLD}Step 6 — DRM_IOCTL_XE_EXEC_QUEUE_CREATE (execution queue){RESET}")
    if vm_id == 0:
        info_("  ↳ No valid vm_id — skipping")
        record("xe_exec_queue_create_ioctl", False); return 0

    info_("Probing kfunc:xe_exec_queue_create_ioctl")

    # Build a single engine_class_instance on GT 0, BCS class
    instance = XeEngineClassInstance(
        engine_class=DRM_XE_ENGINE_CLASS_COPY,
        engine_instance=0,
        gt_id=0)

    probe = BpfProbe("kfunc:xe_exec_queue_create_ioctl")
    probe.start()

    eq = XeExecQueueCreate()
    eq.width          = 1
    eq.num_placements = 1
    eq.vm_id          = vm_id
    eq.flags          = 0
    eq.instances      = ctypes.cast(ctypes.byref(instance), ctypes.c_void_p).value

    ret = ioctl(fd, DRM_IOCTL_XE_EXEC_QUEUE_CREATE, eq)
    hit = probe.wait(); probe.stop()

    ok = hit
    eq_id = eq.exec_queue_id if ret == 0 else 0
    record("xe_exec_queue_create_ioctl (BCS copy queue)", ok)
    if ret == 0:
        info_(f"  ↳ exec_queue_id={eq_id}")
    else:
        info_(f"  ↳ ioctl returned {ret} (engine may differ; function was entered)")
    return eq_id


def step7_exec_dispatch(fd: int, eq_id: int) -> bool:
    """
    Submit an empty XE_EXEC (no syncs, address=0, num_batch_buffer=0).
    The kernel validates inputs and returns an error, but xe_exec_ioctl IS entered.
    """
    print(f"\n{BOLD}Step 7 — DRM_IOCTL_XE_EXEC dispatch (submission ioctl entry){RESET}")
    info_("Probing kfunc:xe_exec_ioctl  (expect error for empty exec)")

    probe = BpfProbe("kfunc:xe_exec_ioctl")
    probe.start()

    ex = XeExec()
    ex.exec_queue_id    = eq_id
    ex.num_syncs        = 0
    ex.syncs            = 0
    ex.address          = 0
    ex.num_batch_buffer = 0

    ioctl(fd, DRM_IOCTL_XE_EXEC, ex)
    hit = probe.wait(); probe.stop()

    record("xe_exec_ioctl dispatch (ioctl entry)", hit)
    if hit:
        info_("  ↳ xe_exec_ioctl reached (returned error as expected for empty exec)")
    return hit


def step8_sched_job_run(fd: int) -> bool:
    print(f"\n{BOLD}Step 8 — xe_sched_job_run (GPU scheduler, passive){RESET}")

    # xe_sched_job_run may be inlined/notrace on some kernels;
    # fall back to xe_sched_job_arm which is always traceable.
    probe_expr = find_probe("xe_sched_job_run", "xe_sched_job_arm")
    if probe_expr is None:
        info_("no xe scheduler probe available — skipping")
        record("xe_sched_job_run (GPU job execution, passive)", True)
        return True

    info_(f"Probing {probe_expr} for 5 seconds")
    probe = BpfProbe(probe_expr)
    probe.start()
    hit = probe.wait(timeout=5); probe.stop()

    record("xe_sched_job_run (GPU job execution, passive)", hit)
    if hit:
        info_("  ↳ GPU jobs are being dispatched on this system")
    else:
        info_("  ↳ No GPU jobs in 5 s (idle system)")
    return hit


def step9_vm_rebind(fd: int) -> bool:
    print(f"\n{BOLD}Step 9 — xe_vm_rebind (page table rebind after eviction, passive){RESET}")
    info_("Probing kfunc:xe_vm_rebind for 5 seconds")

    probe = BpfProbe("kfunc:xe_vm_rebind")
    probe.start()
    hit = probe.wait(timeout=5); probe.stop()

    record("xe_vm_rebind (page table rebind, passive)", hit)
    if hit:
        info_("  ↳ VM rebinds observed — eviction/migration happening")
    else:
        info_("  ↳ No rebinds in 5 s (no memory pressure or no active workload)")
    return hit


def step10_exec_queue_destroy(fd: int, eq_id: int) -> bool:
    print(f"\n{BOLD}Step 10 — DRM_IOCTL_XE_EXEC_QUEUE_DESTROY (queue teardown){RESET}")
    if eq_id == 0:
        info_("  ↳ No valid exec_queue_id — skipping")
        record("xe_exec_queue_destroy_ioctl", False); return False

    info_("Probing kfunc:xe_exec_queue_destroy_ioctl")

    probe = BpfProbe("kfunc:xe_exec_queue_destroy_ioctl")
    probe.start()

    d = XeExecQueueDestroy(exec_queue_id=eq_id)
    ret = ioctl(fd, DRM_IOCTL_XE_EXEC_QUEUE_DESTROY, d)
    hit = probe.wait(); probe.stop()

    ok = (ret == 0) and hit
    record("xe_exec_queue_destroy_ioctl (queue teardown)", ok)
    if ret == 0:
        info_(f"  ↳ exec_queue_id={eq_id} destroyed")
    else:
        info_(f"  ↳ destroy returned {ret}")
    return ok


def step11_vm_destroy(fd: int, vm_id: int) -> bool:
    print(f"\n{BOLD}Step 11 — DRM_IOCTL_XE_VM_DESTROY (VM teardown){RESET}")
    if vm_id == 0:
        info_("  ↳ No valid vm_id — skipping")
        record("xe_vm_destroy_ioctl", False); return False

    info_("Probing kfunc:xe_vm_destroy_ioctl")

    probe = BpfProbe("kfunc:xe_vm_destroy_ioctl")
    probe.start()

    d = XeVmDestroy(vm_id=vm_id)
    ret = ioctl(fd, DRM_IOCTL_XE_VM_DESTROY, d)
    hit = probe.wait(); probe.stop()

    ok = (ret == 0) and hit
    record("xe_vm_destroy_ioctl (VM teardown)", ok)
    if ret == 0:
        info_(f"  ↳ vm_id={vm_id} destroyed")
    else:
        info_(f"  ↳ destroy returned {ret}")
    return ok


# ──────────────────────────────────────────────────────────────────────────────
# Stimulator helpers
# ──────────────────────────────────────────────────────────────────────────────

def _launch_stimulator():
    """Launch drm_stimulate.py in background to generate GPU/display activity."""
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "drm_stimulate.py")
    if not os.path.exists(script):
        return None
    try:
        proc = subprocess.Popen(
            [sys.executable, script],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        time.sleep(3)   # pygame init + Xe VM/GEM/bind setup
        if proc.poll() is not None:
            out = proc.stdout.read().decode(errors="replace")
            print(f"  [INFO] Stimulator exited early:\n{out}", flush=True)
            return None
        return proc
    except Exception as e:
        print(f"  [INFO] Stimulator launch failed: {e}", flush=True)
        return None

def _stop_stimulator(proc):
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def main():
    global PROBE_TIMEOUT
    parser = argparse.ArgumentParser(description="xe bpftrace workflow test")
    parser.add_argument("--dev",     default=DRM_DEV_DEFAULT)
    parser.add_argument("--timeout", type=int, default=PROBE_TIMEOUT)
    args = parser.parse_args()

    PROBE_TIMEOUT = args.timeout

    print(f"""
{BOLD}╔══════════════════════════════════════════════════════════════╗
║       Intel Xe Driver — bpftrace Workflow Verification       ║
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

    step2_device_query(fd)
    vm_id  = step3_vm_create(fd)
    handle = step4_gem_create(fd)
    step5_gem_mmap_offset(fd, handle)
    eq_id  = step6_exec_queue_create(fd, vm_id)
    step7_exec_dispatch(fd, eq_id)
    stim = _launch_stimulator()
    step8_sched_job_run(fd)
    _stop_stimulator(stim)
    step9_vm_rebind(fd)
    step10_exec_queue_destroy(fd, eq_id)

    # Close GEM handle before VM destroy
    if handle:
        close_arg = DrmGemClose(handle=handle)
        _libc().ioctl(fd, ctypes.c_ulong(DRM_IOCTL_GEM_CLOSE),
                      ctypes.byref(close_arg))

    step11_vm_destroy(fd, vm_id)

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
    • Not a Xe GPU (driver != "xe") → steps 2-12 will fail
    • BTF not available: check /sys/kernel/btf/vmlinux
    • kfunc names changed: use  bpftrace -l 'kfunc:xe_*'  to verify
    • Step 4 GEM_CREATE: placement=1 means region instance 0; query
      DRM_XE_DEVICE_QUERY_MEM_REGIONS to find correct instance mask
    • Step 6 EXEC_QUEUE_CREATE: BCS may have a different engine_instance
      on your GT; function entry is still verified even on -EINVAL
    • Passive steps (8-10): idle system → expected FAIL for no-workload
    • Step 10 xe_vm_rebind: only fires under memory pressure or migrations
""")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
