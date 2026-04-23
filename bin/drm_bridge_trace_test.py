#!/usr/bin/env python3
"""
DRM Bridge Subsystem – bpftrace step-by-step verification test
Requires: bpftrace >= 0.16, root, a DRM device present

Steps verified:
  1. drm_bridge_add         – bridge registers into global list
  2. drm_bridge_attach      – bridge attaches to encoder chain
  3. drm_bridge_chain_mode_set – mode propagated to each bridge
  4. drm_atomic_bridge_chain_pre_enable  – pre-enable forward pass
  5. drm_atomic_bridge_chain_enable      – enable forward pass
  6. drm_atomic_bridge_chain_disable     – disable reverse pass
  7. drm_atomic_bridge_chain_post_disable – post-disable pass
  8. drm_bridge_hpd_notify  – HPD event propagation
  9. drm_bridge_detach       – bridge detached from chain
 10. drm_bridge_remove       – bridge removed from global list
"""

import subprocess
import sys
import time
import re
import os

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"
SKIP = "\033[33mSKIP\033[0m"

BPFTRACE_SCRIPT = r"""
interval:s:1 { printf("TICK\n"); }

kprobe:drm_bridge_add         { printf("HIT drm_bridge_add ptr=%lx\n",         arg0); }
kprobe:drm_bridge_remove      { printf("HIT drm_bridge_remove ptr=%lx\n",      arg0); }
kprobe:drm_bridge_attach      { printf("HIT drm_bridge_attach enc=%lx bridge=%lx\n", arg0, arg1); }
kprobe:drm_bridge_detach      { printf("HIT drm_bridge_detach ptr=%lx\n",      arg0); }
kprobe:drm_bridge_chain_mode_set {
    printf("HIT drm_bridge_chain_mode_set bridge=%lx\n", arg0);
}
kprobe:drm_atomic_bridge_chain_pre_enable {
    printf("HIT drm_atomic_bridge_chain_pre_enable bridge=%lx\n", arg0);
}
kprobe:drm_atomic_bridge_chain_enable {
    printf("HIT drm_atomic_bridge_chain_enable bridge=%lx\n", arg0);
}
kprobe:drm_atomic_bridge_chain_disable {
    printf("HIT drm_atomic_bridge_chain_disable bridge=%lx\n", arg0);
}
kprobe:drm_atomic_bridge_chain_post_disable {
    printf("HIT drm_atomic_bridge_chain_post_disable bridge=%lx\n", arg0);
}
kprobe:drm_bridge_hpd_notify  { printf("HIT drm_bridge_hpd_notify bridge=%lx status=%d\n", arg0, arg1); }
"""

STEPS = [
    ("drm_bridge_add",                          "Step 1: bridge_add – bridge registered into global list"),
    ("drm_bridge_attach",                       "Step 2: bridge_attach – bridge linked to encoder chain"),
    ("drm_bridge_chain_mode_set",               "Step 3: chain_mode_set – timing mode propagated"),
    ("drm_atomic_bridge_chain_pre_enable",      "Step 4: chain_pre_enable – forward pre-enable pass"),
    ("drm_atomic_bridge_chain_enable",          "Step 5: chain_enable – forward enable pass"),
    ("drm_atomic_bridge_chain_disable",         "Step 6: chain_disable – reverse disable pass"),
    ("drm_atomic_bridge_chain_post_disable",    "Step 7: chain_post_disable – post-disable pass"),
    ("drm_bridge_hpd_notify",                   "Step 8: hpd_notify – HPD event propagated"),
    ("drm_bridge_detach",                       "Step 9: bridge_detach – bridge removed from chain"),
    ("drm_bridge_remove",                       "Step 10: bridge_remove – bridge removed from global list"),
]


def check_root():
    if os.geteuid() != 0:
        print(f"[{FAIL}] Must run as root (bpftrace requires CAP_BPF / root)")
        sys.exit(1)


def check_bpftrace():
    try:
        r = subprocess.run(["bpftrace", "--version"], capture_output=True, text=True, timeout=5)
        print(f"  bpftrace version: {r.stdout.strip()}")
        return True
    except FileNotFoundError:
        print(f"[{FAIL}] bpftrace not found – install with: sudo apt install bpftrace")
        return False


def check_drm_present():
    """Return True if at least one DRM device node exists."""
    import glob
    nodes = glob.glob("/dev/dri/card*")
    if nodes:
        print(f"  DRM devices found: {nodes}")
        return True
    print(f"[{SKIP}] No /dev/dri/card* found – running in symbol-probe-only mode")
    return False


def resolve_kprobe_symbols():
    """Check which bridge symbols are present in kallsyms."""
    available = set()
    try:
        with open("/proc/kallsyms") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3:
                    available.add(parts[2])
    except PermissionError:
        # kallsyms may be restricted; assume all present
        return {name for name, _ in STEPS}
    return {name for name, _ in STEPS if name in available}


def run_bpftrace(timeout_sec=30):
    """Run bpftrace and collect hit events, return set of hit function names."""
    proc = subprocess.Popen(
        ["bpftrace", "-e", BPFTRACE_SCRIPT],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    hits = set()
    deadline = time.time() + timeout_sec
    print(f"\n  Tracing for {timeout_sec}s (trigger display events if possible)…\n")

    try:
        while time.time() < deadline:
            line = proc.stdout.readline()
            if not line:
                break
            line = line.strip()
            if line.startswith("HIT "):
                parts = line.split()
                fn = parts[1]
                hits.add(fn)
                print(f"  → observed: {fn}")
            elif line == "TICK":
                remaining = int(deadline - time.time())
                print(f"  … {remaining}s remaining", end="\r", flush=True)
    finally:
        proc.terminate()
        proc.wait(timeout=3)

    return hits


def print_results(hits, available_symbols):
    print("\n" + "=" * 60)
    print("DRM Bridge Subsystem – Test Results")
    print("=" * 60)
    all_pass = True
    for fn, description in STEPS:
        if fn not in available_symbols:
            status = SKIP
            note = "(symbol not in kernel)"
        elif fn in hits:
            status = PASS
            note = ""
        else:
            status = FAIL
            note = "(not observed – may need display event)"
            all_pass = False
        print(f"  [{status}] {description} {note}")
    print("=" * 60)
    if all_pass:
        print(f"  Overall: [{PASS}] All observable steps passed")
    else:
        print(f"  Overall: [{FAIL}] Some steps not observed (see notes above)")
    print()


def trigger_hints():
    print("\nTips to trigger bridge chain events:")
    print("  - Plug/unplug an HDMI or DP monitor")
    print("  - Run: sudo modprobe -r <bridge_module> && sudo modprobe <bridge_module>")
    print("  - Suspend/resume: sudo systemctl suspend")
    print("  - Switch virtual terminal: chvt 2 && chvt 1")
    print()


def main():
    print("=" * 60)
    print("DRM Bridge Subsystem – bpftrace Verification Test")
    print("=" * 60)

    check_root()

    if not check_bpftrace():
        sys.exit(1)

    drm_present = check_drm_present()
    available_symbols = resolve_kprobe_symbols()

    unavailable = {name for name, _ in STEPS} - available_symbols
    if unavailable:
        print(f"\n  Note: symbols not in kallsyms (will be SKIP): {unavailable}")

    if not drm_present:
        print(f"\n[{SKIP}] No DRM device – symbol availability check only\n")
        print_results(set(), available_symbols)
        return

    trigger_hints()

    hits = run_bpftrace(timeout_sec=30)
    print_results(hits, available_symbols)


if __name__ == "__main__":
    main()
