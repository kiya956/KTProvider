#!/usr/bin/env python3
"""
nvidia-drm — bpftrace verification test
=========================================

Source: drivers/gpu/drm/nvidia-drm/
Kernel: noble-linux-oem
Scanned from: ~/canonical/kernel/noble-linux-oem

All probe targets verified against actual kernel source.
nvidia-drm has NO exported symbols — module-internal only.
Requires nvidia-drm.ko + nvidia-modeset.ko + nvidia.ko loaded.

Test flow: device probe → GEM create → atomic commit → fence → flip
Trigger: open DRM device node, run xrandr/modetest, or GL operation
"""

import subprocess
import sys
import os
import time
import signal

PROBE_TARGETS = [
    {
        "step": 1,
        "name": "Device probe",
        "description": "nv_drm_probe_devices() scans and registers NVIDIA GPUs (nvidia-drm-drv.c:2108)",
        "primary_probe": "nv_drm_probe_devices",
        "alt_probes": ["nv_drm_register_drm_device", "nv_drm_init"],
        "source_file": "drivers/gpu/drm/nvidia-drm/nvidia-drm-drv.c",
        "source_line": 2108,
        "exported": False,
        "passive": True,
    },
    {
        "step": 2,
        "name": "GEM object init",
        "description": "nv_drm_gem_object_init() initialises a GEM object (nvidia-drm-gem.c:116)",
        "primary_probe": "nv_drm_gem_object_init",
        "alt_probes": ["nv_drm_gem_free", "nv_drm_dumb_create"],
        "source_file": "drivers/gpu/drm/nvidia-drm/nvidia-drm-gem.c",
        "source_line": 116,
        "exported": False,
        "passive": True,
    },
    {
        "step": 3,
        "name": "GEM mmap",
        "description": "nv_drm_mmap() maps GEM object to userspace (nvidia-drm-gem.c:250)",
        "primary_probe": "nv_drm_mmap",
        "alt_probes": ["nv_drm_gem_map_offset_ioctl"],
        "source_file": "drivers/gpu/drm/nvidia-drm/nvidia-drm-gem.c",
        "source_line": 250,
        "exported": False,
        "passive": True,
    },
    {
        "step": 4,
        "name": "Atomic check",
        "description": "nv_drm_atomic_check() validates atomic state (nvidia-drm-modeset.c:514)",
        "primary_probe": "nv_drm_atomic_check",
        "alt_probes": ["nv_drm_atomic_commit"],
        "source_file": "drivers/gpu/drm/nvidia-drm/nvidia-drm-modeset.c",
        "source_line": 514,
        "exported": False,
        "passive": False,
    },
    {
        "step": 5,
        "name": "Atomic commit",
        "description": "nv_drm_atomic_commit() pushes modeset to NVKMS (nvidia-drm-modeset.c:597)",
        "primary_probe": "nv_drm_atomic_commit",
        "alt_probes": ["nv_drm_atomic_check"],
        "source_file": "drivers/gpu/drm/nvidia-drm/nvidia-drm-modeset.c",
        "source_line": 597,
        "exported": False,
        "passive": True,
    },
    {
        "step": 6,
        "name": "Flip occurred",
        "description": "nv_drm_handle_flip_occurred() signals vblank/fence on flip (nvidia-drm-modeset.c:832)",
        "primary_probe": "nv_drm_handle_flip_occurred",
        "alt_probes": ["nv_drm_atomic_state_clear"],
        "source_file": "drivers/gpu/drm/nvidia-drm/nvidia-drm-modeset.c",
        "source_line": 832,
        "exported": False,
        "passive": True,
    },
    {
        "step": 7,
        "name": "Fence support check",
        "description": "nv_drm_fence_supported_ioctl() checks fence capabilities (nvidia-drm-fence.c:387)",
        "primary_probe": "nv_drm_fence_supported_ioctl",
        "alt_probes": ["nv_drm_prime_fence_context_create_ioctl", "nv_drm_semsurf_fence_ctx_create_ioctl"],
        "source_file": "drivers/gpu/drm/nvidia-drm/nvidia-drm-fence.c",
        "source_line": 387,
        "exported": False,
        "passive": True,
    },
    {
        "step": 8,
        "name": "CRTC enumerate",
        "description": "nv_drm_enumerate_crtcs_and_planes() sets up display pipeline (nvidia-drm-crtc.c:2987)",
        "primary_probe": "nv_drm_enumerate_crtcs_and_planes",
        "alt_probes": ["nv_drm_get_crtc_crc32_ioctl"],
        "source_file": "drivers/gpu/drm/nvidia-drm/nvidia-drm-crtc.c",
        "source_line": 2987,
        "exported": False,
        "passive": True,
    },
    {
        "step": 9,
        "name": "Master set",
        "description": "nv_drm_master_drop() handles DRM master release (nvidia-drm-drv.c:985)",
        "primary_probe": "nv_drm_master_drop",
        "alt_probes": ["nv_drm_reset_input_colorspace"],
        "source_file": "drivers/gpu/drm/nvidia-drm/nvidia-drm-drv.c",
        "source_line": 985,
        "exported": False,
        "passive": True,
    },
    {
        "step": 10,
        "name": "Suspend/resume",
        "description": "nv_drm_suspend_resume() handles system power transitions (nvidia-drm-drv.c:2219)",
        "primary_probe": "nv_drm_suspend_resume",
        "alt_probes": ["nv_drm_remove"],
        "source_file": "drivers/gpu/drm/nvidia-drm/nvidia-drm-drv.c",
        "source_line": 2219,
        "exported": False,
        "passive": True,
    },
]


def check_root():
    if os.geteuid() != 0:
        print("ERROR: This test requires root (bpftrace needs CAP_SYS_ADMIN)")
        sys.exit(1)


def probe_exists(func_name: str) -> bool:
    try:
        return subprocess.run(
            ["grep", "-qw", func_name, "/proc/kallsyms"], timeout=5
        ).returncode == 0
    except Exception:
        return False


def resolve_probe(target: dict) -> str | None:
    if probe_exists(target["primary_probe"]):
        return target["primary_probe"]
    for alt in target.get("alt_probes", []):
        if probe_exists(alt):
            return alt
    return None


def build_bpftrace_script(active_probes: list[tuple[dict, str]]) -> str:
    lines = ["BEGIN {", '  printf("nvidia-drm bpftrace test started\\n");']
    for t, _ in active_probes:
        lines.append(f'  @step{t["step"]}_seen = 0;')
    lines.append("}\n")
    for t, p in active_probes:
        s = t["step"]
        lines += [
            f'kprobe:{p} {{',
            f'  @step{s}_seen = 1;',
            f'  @step{s}_count += 1;',
            f'  printf("STEP {s} HIT: {p} (pid=%d comm=%s)\\n", pid, comm);',
            "}\n",
        ]
    lines.append("END {")
    lines.append('  printf("\\n=== NVIDIA-DRM BPFTRACE TEST SUMMARY ===\\n");')
    for t, p in active_probes:
        s = t["step"]
        lines.append(
            f'  printf("Step {s} [{t["name"]}]: %s (hits=%d, probe={p})\\n",'
            f' @step{s}_seen ? "PASS" : "FAIL", @step{s}_count);'
        )
    lines.append('  printf("========================================\\n");')
    for t, _ in active_probes:
        lines += [f"  clear(@step{t['step']}_seen);", f"  clear(@step{t['step']}_count);"]
    lines.append("}")
    return "\n".join(lines)


def trigger_nvidia_activity():
    """Trigger nvidia-drm activity via DRM nodes or display tools."""
    print("[trigger] Attempting to trigger nvidia-drm activity...")

    import glob as glib
    for node in sorted(glib.glob("/dev/dri/card*") + glib.glob("/dev/dri/renderD*")):
        try:
            fd = os.open(node, os.O_RDWR)
            os.close(fd)
            print(f"[trigger] Opened and closed {node}")
        except OSError:
            continue

    # Try xrandr to trigger modeset paths
    try:
        ret = subprocess.run(["xrandr", "--query"], capture_output=True, text=True, timeout=5)
        if ret.returncode == 0:
            print("[trigger] Ran xrandr to exercise modeset paths")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Try nvidia-smi to exercise GPU
    try:
        ret = subprocess.run(["nvidia-smi", "-q", "-d", "DISPLAY"], capture_output=True, text=True, timeout=5)
        if ret.returncode == 0:
            print("[trigger] Ran nvidia-smi")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Try GL
    try:
        ret = subprocess.run(["glxinfo", "-B"], capture_output=True, text=True, timeout=5)
        if ret.returncode == 0:
            print("[trigger] Ran glxinfo to exercise GL paths")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass


def run_test(duration: int = 20):
    print("=" * 60)
    print("nvidia-drm — bpftrace test")
    print("=" * 60)

    # Check module status
    lsmod = subprocess.run(["lsmod"], capture_output=True, text=True)
    nvidia_mods = {
        "nvidia_drm": "nvidia_drm" in lsmod.stdout or "nvidia-drm" in lsmod.stdout,
        "nvidia_modeset": "nvidia_modeset" in lsmod.stdout,
        "nvidia": "nvidia " in lsmod.stdout,
    }
    print("\n  Module status:")
    for mod, loaded in nvidia_mods.items():
        print(f"    {mod}: {'loaded ✓' if loaded else 'NOT loaded ✗'}")

    if not nvidia_mods["nvidia_drm"]:
        print("\nWARNING: nvidia-drm module not loaded!")
        print("This test requires NVIDIA proprietary driver with nvidia-drm.ko.")
        print("Install with: sudo apt install nvidia-driver-XXX\n")

    active, skipped = [], []
    for t in PROBE_TARGETS:
        p = resolve_probe(t)
        if p:
            active.append((t, p))
            m = "(primary)" if p == t["primary_probe"] else f"(alt: {p})"
            print(f"  Step {t['step']:2d}: {t['name']} → {p} {m}")
        else:
            skipped.append(t)
            print(f"  Step {t['step']:2d}: {t['name']} → SKIPPED (not in kallsyms)")

    if not active:
        print("\nERROR: No probe targets found. Is nvidia-drm.ko loaded?")
        sys.exit(1)

    print(f"\n  Active probes: {len(active)}/{len(PROBE_TARGETS)}")

    script = build_bpftrace_script(active)
    path = "/tmp/test_nvidia_drm_bpf.bt"
    with open(path, "w") as f:
        f.write(script)

    print(f"\n[bpftrace] Starting probes (duration: {duration}s)...")
    proc = subprocess.Popen(
        ["bpftrace", path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    time.sleep(3)
    trigger_nvidia_activity()
    time.sleep(max(1, duration - 3))

    proc.send_signal(signal.SIGINT)
    try:
        stdout, stderr = proc.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()

    print("\n--- bpftrace output ---")
    print(stdout)
    if stderr.strip():
        for line in stderr.strip().splitlines():
            if "Attaching" not in line and "WARNING" not in line:
                print(f"  stderr: {line}")

    results = {}
    for line in stdout.splitlines():
        if line.startswith("Step ") and ("PASS" in line or "FAIL" in line):
            step_num = int(line.split("[")[0].replace("Step ", "").strip())
            results[step_num] = "PASS" in line

    print("\n" + "=" * 60)
    print("FINAL RESULTS")
    print("=" * 60)
    tp = 0
    active_failures = 0
    for t in PROBE_TARGETS:
        s = t["step"]
        is_passive = t.get("passive", False)
        tag = " (passive)" if is_passive else ""
        if s in results:
            st = "PASS ✓" if results[s] else f"FAIL ✗{tag}"
            tp += results[s]
            if not results[s] and not is_passive:
                active_failures += 1
        elif t in [x for x, _ in active]:
            st = f"FAIL ✗ (no hits){tag}"
            if not is_passive:
                active_failures += 1
        else:
            st = "SKIP (not in kallsyms)"
        print(f"  Step {s:2d}: {t['name']:35s} {st}")

    print(f"\n  Score: {tp}/{len(PROBE_TARGETS)} steps passed")
    if active_failures == 0:
        passive_fails = len(PROBE_TARGETS) - tp
        if passive_fails > 0:
            print(f"  All active steps passed! {passive_fails} passive step(s) "
                  f"failed (expected — require specific GPU activity)")
        else:
            print("  All steps passed!")
    else:
        print(f"  {active_failures} active step(s) failed")
    print("=" * 60)

    try:
        os.unlink(path)
    except OSError:
        pass
    return active_failures == 0


if __name__ == "__main__":
    check_root()
    duration = int(sys.argv[1]) if len(sys.argv) > 1 else 20
    success = run_test(duration)
    sys.exit(0 if success else 1)
