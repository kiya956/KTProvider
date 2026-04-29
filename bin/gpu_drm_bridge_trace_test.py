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
import os
import glob

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"
SKIP = "\033[33mSKIP\033[0m"

BPFTRACE_BIN = "bpftrace"

PROBE_DEFS = [
    ("drm_bridge_add",                       "Step 1:  bridge_add – bridge registered into global list"),
    ("drm_bridge_attach",                    "Step 2:  bridge_attach – bridge linked to encoder chain"),
    ("drm_bridge_chain_mode_set",            "Step 3:  chain_mode_set – timing mode propagated"),
    ("drm_atomic_bridge_chain_pre_enable",   "Step 4:  chain_pre_enable – forward pre-enable pass"),
    ("drm_atomic_bridge_chain_enable",       "Step 5:  chain_enable – forward enable pass"),
    ("drm_atomic_bridge_chain_disable",      "Step 6:  chain_disable – reverse disable pass"),
    ("drm_atomic_bridge_chain_post_disable", "Step 7:  chain_post_disable – post-disable pass"),
    ("drm_bridge_hpd_notify",                "Step 8:  hpd_notify – HPD event propagated"),
    ("drm_bridge_detach",                    "Step 9:  bridge_detach – bridge removed from chain"),
    ("drm_bridge_remove",                    "Step 10: bridge_remove – bridge removed from global list"),
]


def find_probe(symbol: str) -> str | None:
    """Return the best available probe expression for symbol.

    Tries kfunc: first (BTF-based, preferred), then kprobe:.
    Returns e.g. 'kfunc:drm_bridge_add' or None if unavailable.
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
        print(f"[{FAIL}] Must run as root (bpftrace requires CAP_BPF / root)")
        sys.exit(1)


def check_bpftrace():
    try:
        r = subprocess.run([BPFTRACE_BIN, "--version"], capture_output=True, text=True, timeout=5)
        print(f"  bpftrace version: {r.stdout.strip()}")
        return True
    except FileNotFoundError:
        print(f"[{FAIL}] bpftrace not found – install with: sudo apt install bpftrace")
        return False


def check_drm_present():
    """Return True if at least one DRM device node exists."""
    nodes = glob.glob("/dev/dri/card*")
    if nodes:
        print(f"  DRM devices found: {nodes}")
        return True
    print(f"[{SKIP}] No /dev/dri/card* found – running in symbol-probe-only mode")
    return False


def detect_drm_bridges() -> bool:
    """Return True if at least one DRM display bridge is registered.

    Checks debugfs bridge list and sysfs for bridge-related encoders.
    """
    # Method 1: debugfs bridge list (most reliable when available)
    bridge_file = "/sys/kernel/debug/dri/bridge_list"
    if os.path.isfile(bridge_file):
        try:
            with open(bridge_file) as f:
                content = f.read().strip()
            if content:
                print(f"  DRM bridges detected via debugfs ({len(content.splitlines())} entries)")
                return True
        except PermissionError:
            pass

    # Method 2: look for drm_bridge entries via debugfs per-device
    for card_debug in glob.glob("/sys/kernel/debug/dri/*/"):
        for name in ("bridge", "bridges"):
            path = os.path.join(card_debug, name)
            if os.path.exists(path):
                try:
                    with open(path) as f:
                        content = f.read().strip()
                    if content:
                        print(f"  DRM bridge info found in {path}")
                        return True
                except (PermissionError, IsADirectoryError):
                    pass

    # Method 3: check if any known DRM bridge modules are loaded
    drm_bridge_modules = {
        "analogix_dp", "anx7625", "cadence_dsi", "cdns_mhdp",
        "cros_ec_anx7688", "display_connector", "dw_hdmi", "dw_mipi_dsi",
        "lontium_lt9611", "megachips", "nwl_dsi", "parade_ps8640",
        "ptn3460", "sii902x", "simple_bridge", "tc358767", "tc358768",
        "ti_sn65dsi86", "ti_tfp410",
    }
    try:
        with open("/proc/modules") as f:
            loaded = {line.split()[0] for line in f}
        found = loaded & drm_bridge_modules
        if found:
            print(f"  DRM bridge modules loaded: {found}")
            return True
    except OSError:
        pass

    return False


def run_bpftrace(script: str, timeout_sec: int = 30) -> set[str]:
    """Run bpftrace and collect hit events, return set of hit symbol names."""
    proc = subprocess.Popen(
        [BPFTRACE_BIN, "-e", script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    hits: set[str] = set()
    deadline = time.time() + timeout_sec
    print(f"\n  Tracing for {timeout_sec}s (trigger display events if possible)…\n")

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


def print_results(hits: set, resolved: dict) -> bool:
    """Print results table. Returns True if all observable steps passed."""
    print("\n" + "=" * 60)
    print("DRM Bridge Subsystem – Test Results")
    print("=" * 60)
    all_pass = True
    for sym, description in PROBE_DEFS:
        if sym not in resolved:
            status = SKIP
            note = "(probe unavailable – symbol not exported or inlined)"
        elif sym in hits:
            status = PASS
            note = f"({resolved[sym].split(':')[0]})"
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
    return all_pass


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
    resolved = resolve_probes()

    if not resolved:
        print(f"\n[{SKIP}] No bridge probes available on this kernel\n")
        print_results(set(), resolved)
        return

    if not drm_present:
        print(f"\n[{SKIP}] No DRM device – symbol availability check only\n")
        print_results(set(), resolved)
        return

    # Skip early if no DRM display bridge hardware is present
    if not detect_drm_bridges():
        print(f"\n[{SKIP}] No DRM display bridges detected on this system")
        print("  (bridge test is not applicable without bridge hardware)\n")
        sys.exit(1)

    trigger_hints()

    script = build_bpftrace_script(resolved)
    hits = run_bpftrace(script, timeout_sec=30)
    all_pass = print_results(hits, resolved)
    if not all_pass:
        sys.exit(1)


if __name__ == "__main__":
    main()
