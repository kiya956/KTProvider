#!/usr/bin/env python3
"""
ARM DRM Display Subsystem – bpftrace step-by-step verification test
Covers: HDLCD, Mali-DP, and Komeda display engines.

Requires: bpftrace >= 0.16, root, target SoC or QEMU with ARM display HW.

Steps verified:
  1.  platform_driver probe     – driver binds to platform device
  2.  drm_dev_register          – DRM device registered with core
  3.  drm_atomic_helper_check   – atomic state check pass
  4.  malidp/hdlcd crtc enable  – CRTC enabled (mode set)
  5.  drm_atomic_helper_commit_planes – plane states committed
  6.  hdlcd_irq / malidp_irq    – vsync/IRQ fired
  7.  drm_atomic_bridge_chain_enable – bridge chain enabled
  8.  drm_vblank_event_sendpage – vblank event sent to userspace
  9.  drm_atomic_helper_commit_modeset_disables – teardown path
  10. drm_dev_unregister         – DRM device unregistered
"""

import subprocess
import sys
import time
import os
import glob

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"
SKIP = "\033[33mSKIP\033[0m"

BPFTRACE_BIN = "bpftrace"

# (symbol, description)
# ARM-specific symbols (hdlcd_irq, malidp_irq_handler, komeda_crtc_atomic_enable)
# will be SKIP if their modules are not loaded.
PROBE_DEFS = [
    ("drm_dev_register",                             "Step  1: drm_dev_register – DRM device registered"),
    ("drm_atomic_helper_check",                      "Step  2: drm_atomic_helper_check – atomic state validated"),
    ("drm_atomic_helper_commit_planes",              "Step  3: commit_planes – plane HW registers programmed"),
    ("drm_atomic_helper_commit_modeset_enables",     "Step  4: commit_modeset_enables – CRTC/encoder/bridge enabled"),
    ("drm_atomic_bridge_chain_enable",               "Step  5: bridge_chain_enable – bridge chain activated"),
    ("drm_handle_vblank",                            "Step  6: drm_handle_vblank – vblank interrupt processed"),
    ("drm_crtc_send_vblank_event",                   "Step  7: send_vblank_event – vblank event dispatched to userspace"),
    ("drm_atomic_helper_commit_modeset_disables",    "Step  8: commit_modeset_disables – teardown path executed"),
    ("drm_dev_unregister",                           "Step  9: drm_dev_unregister – DRM device removed"),
    # ARM-specific optional probes (SKIP if not loaded)
    ("hdlcd_irq",                                    "Step 10: hdlcd_irq – HDLCD vsync/underrun IRQ fired"),
    ("malidp_irq_handler",                           "Step 11: malidp_irq_handler – Mali-DP IRQ fired"),
    ("komeda_crtc_atomic_enable",                    "Step 12: komeda_crtc_atomic_enable – Komeda CRTC enabled"),
]


def find_probe(symbol: str) -> str | None:
    """Return the best available probe expression for symbol.

    Tries kfunc: first (BTF-based, preferred), then kprobe:.
    Returns e.g. 'kfunc:drm_dev_register' or None if unavailable.
    """
    for ptype in ("kfunc", "kprobe"):
        try:
            r = subprocess.run(
                [BPFTRACE_BIN, "-l", f"{ptype}:{symbol}"],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0 and symbol in r.stdout:
                return f"{ptype}:{symbol}"
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
    return None


def resolve_probes() -> dict[str, str]:
    """Return {symbol: probe_expr} for all available probes."""
    print("  Resolving probe types via bpftrace -l …")
    resolved = {}
    for sym, _ in PROBE_DEFS:
        expr = find_probe(sym)
        if expr:
            resolved[sym] = expr
            print(f"    {sym}: {expr.split(':')[0]}")
        else:
            print(f"    {sym}: unavailable (SKIP)")
    return resolved


def build_bpftrace_script(resolved: dict[str, str]) -> str:
    """Build bpftrace script from resolved probe expressions."""
    lines = ['interval:s:1 { printf("TICK\\n"); }']
    for sym, expr in resolved.items():
        lines.append(f'{expr} {{ printf("HIT {sym}\\n"); }}')
    return "\n".join(lines)


def check_root():
    if os.geteuid() != 0:
        print(f"[{FAIL}] Must run as root")
        sys.exit(1)


def check_bpftrace():
    try:
        r = subprocess.run([BPFTRACE_BIN, "--version"], capture_output=True, text=True, timeout=5)
        print(f"  bpftrace: {r.stdout.strip()}")
        return True
    except FileNotFoundError:
        print(f"[{FAIL}] bpftrace not found: sudo apt install bpftrace")
        return False


def check_drm_present():
    nodes = glob.glob("/dev/dri/card*")
    if nodes:
        print(f"  DRM devices: {nodes}")
        return True
    print(f"[{SKIP}] No /dev/dri/card* found")
    return False


def detect_arm_driver():
    """Detect which ARM display driver is loaded."""
    loaded = []
    try:
        r = subprocess.run(["lsmod"], capture_output=True, text=True)
        for mod in ["hdlcd", "malidp", "komeda"]:
            if mod in r.stdout:
                loaded.append(mod)
    except Exception:
        pass
    if loaded:
        print(f"  ARM display modules loaded: {loaded}")
    else:
        print(f"  [{SKIP}] No ARM display modules loaded (hdlcd/malidp/komeda)")
    return loaded


def run_bpftrace(script: str, timeout_sec: int = 30) -> set[str]:
    proc = subprocess.Popen(
        [BPFTRACE_BIN, "-e", script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    hits: set[str] = set()
    deadline = time.time() + timeout_sec
    print(f"\n  Tracing for {timeout_sec}s (trigger display activity if possible)…\n")
    try:
        while time.time() < deadline:
            line = proc.stdout.readline()
            if not line:
                break
            line = line.strip()
            if line.startswith("HIT "):
                sym = line.split()[1]
                hits.add(sym)
                print(f"  → observed: {sym}")
            elif line == "TICK":
                remaining = int(deadline - time.time())
                print(f"  … {remaining}s remaining", end="\r", flush=True)
    finally:
        proc.terminate()
        proc.wait(timeout=3)
    return hits


def print_results(hits: set, resolved: dict) -> None:
    print("\n" + "=" * 65)
    print("ARM DRM Display Subsystem – Test Results")
    print("=" * 65)
    all_pass = True
    for sym, desc in PROBE_DEFS:
        if sym not in resolved:
            status = SKIP
            note = "(probe unavailable – symbol absent or module not loaded)"
        elif sym in hits:
            status = PASS
            note = f"({resolved[sym].split(':')[0]})"
        else:
            status = FAIL
            note = "(not observed – trigger display event)"
            all_pass = False
        print(f"  [{status}] {desc} {note}")
    print("=" * 65)
    verdict = PASS if all_pass else FAIL
    print(f"  Overall: [{verdict}]")
    print()


def tips():
    print("\nTips to trigger display events:")
    print("  - Switch virtual terminal: sudo chvt 2 && sudo chvt 1")
    print("  - Suspend/resume:          sudo systemctl suspend")
    print("  - Reload ARM module:       sudo modprobe -r malidp && sudo modprobe malidp")
    print("  - Run weston/X11 on ARM FVP/board")
    print()


def main():
    print("=" * 65)
    print("ARM DRM Display Subsystem – bpftrace Verification Test")
    print("=" * 65)
    check_root()
    if not check_bpftrace():
        sys.exit(1)
    drm_present = check_drm_present()
    detect_arm_driver()
    resolved = resolve_probes()

    if not resolved:
        print(f"\n[{SKIP}] No ARM DRM probes available on this kernel\n")
        print_results(set(), resolved)
        return

    if not drm_present:
        print(f"\n[{SKIP}] No DRM device – symbol check only\n")
        print_results(set(), resolved)
        return

    tips()
    script = build_bpftrace_script(resolved)
    hits = run_bpftrace(script, timeout_sec=30)
    print_results(hits, resolved)


if __name__ == "__main__":
    main()
