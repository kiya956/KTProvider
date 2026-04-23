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

BPFTRACE_SCRIPT = r"""
interval:s:1 { printf("TICK\n"); }

/* DRM core device lifecycle */
kprobe:drm_dev_register   { printf("HIT drm_dev_register dev=%lx\n",   arg0); }
kprobe:drm_dev_unregister { printf("HIT drm_dev_unregister dev=%lx\n", arg0); }

/* Atomic commit path */
kprobe:drm_atomic_helper_check {
    printf("HIT drm_atomic_helper_check dev=%lx\n", arg0);
}
kprobe:drm_atomic_helper_commit_planes {
    printf("HIT drm_atomic_helper_commit_planes dev=%lx\n", arg0);
}
kprobe:drm_atomic_helper_commit_modeset_enables {
    printf("HIT drm_atomic_helper_commit_modeset_enables dev=%lx\n", arg0);
}
kprobe:drm_atomic_helper_commit_modeset_disables {
    printf("HIT drm_atomic_helper_commit_modeset_disables dev=%lx\n", arg0);
}

/* Bridge chain */
kprobe:drm_atomic_bridge_chain_enable {
    printf("HIT drm_atomic_bridge_chain_enable bridge=%lx\n", arg0);
}

/* Vblank */
kprobe:drm_crtc_send_vblank_event {
    printf("HIT drm_crtc_send_vblank_event crtc=%lx\n", arg0);
}
kprobe:drm_handle_vblank {
    printf("HIT drm_handle_vblank dev=%lx pipe=%d\n", arg0, arg1);
}

/* ARM-specific: HDLCD */
kprobe:hdlcd_irq {
    printf("HIT hdlcd_irq irq=%d\n", arg0);
}

/* ARM-specific: Mali-DP */
kprobe:malidp_irq_handler {
    printf("HIT malidp_irq_handler irq=%d\n", arg0);
}
kprobe:malidp_atomic_commit_hw_done {
    printf("HIT malidp_atomic_commit_hw_done\n");
}

/* ARM-specific: Komeda */
kprobe:komeda_pipeline_unbound {
    printf("HIT komeda_pipeline_unbound pipeline=%lx\n", arg0);
}
kprobe:komeda_crtc_atomic_enable {
    printf("HIT komeda_crtc_atomic_enable crtc=%lx\n", arg0);
}
"""

# (probe_symbol, description)
STEPS = [
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


def check_root():
    if os.geteuid() != 0:
        print(f"[{FAIL}] Must run as root")
        sys.exit(1)


def check_bpftrace():
    try:
        r = subprocess.run(["bpftrace", "--version"], capture_output=True, text=True, timeout=5)
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


def resolve_symbols():
    available = set()
    try:
        with open("/proc/kallsyms") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3:
                    available.add(parts[2])
    except PermissionError:
        return {fn for fn, _ in STEPS}
    return {fn for fn, _ in STEPS if fn in available}


def run_bpftrace(timeout_sec=30):
    proc = subprocess.Popen(
        ["bpftrace", "-e", BPFTRACE_SCRIPT],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    hits = set()
    deadline = time.time() + timeout_sec
    print(f"\n  Tracing for {timeout_sec}s (trigger display activity if possible)…\n")
    try:
        while time.time() < deadline:
            line = proc.stdout.readline()
            if not line:
                break
            line = line.strip()
            if line.startswith("HIT "):
                fn = line.split()[1]
                hits.add(fn)
                print(f"  → observed: {fn}")
            elif line == "TICK":
                remaining = int(deadline - time.time())
                print(f"  … {remaining}s remaining", end="\r", flush=True)
    finally:
        proc.terminate()
        proc.wait(timeout=3)
    return hits


def print_results(hits, available):
    print("\n" + "=" * 65)
    print("ARM DRM Display Subsystem – Test Results")
    print("=" * 65)
    all_pass = True
    for fn, desc in STEPS:
        if fn not in available:
            status = SKIP
            note = "(symbol absent – driver not loaded?)"
        elif fn in hits:
            status = PASS
            note = ""
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
    available = resolve_symbols()
    unavail = {fn for fn, _ in STEPS} - available
    if unavail:
        print(f"\n  Symbols not in kallsyms (SKIP): {unavail}")
    if not drm_present:
        print(f"\n[{SKIP}] No DRM device – symbol check only\n")
        print_results(set(), available)
        return
    tips()
    hits = run_bpftrace(timeout_sec=30)
    print_results(hits, available)


if __name__ == "__main__":
    main()
