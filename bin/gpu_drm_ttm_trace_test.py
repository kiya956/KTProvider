#!/usr/bin/env python3
"""
TTM (Translation Table Maps) bpftrace workflow test.

Traces the BO lifecycle: init → validate → pool_alloc → move_to_lru → put.
Trigger: load/unload a DRM driver that uses TTM (e.g. vkms or virtio-gpu),
or run a simple gem_create ioctl via libdrm.

Source: drivers/gpu/drm/ttm/
Verified probe targets: ttm_bo.c, ttm_pool.c (noble-linux-oem)
"""

import argparse
import subprocess
import sys
import time

PROBE_TIMEOUT = 30

BPFTRACE_PROGRAM = r"""
BEGIN {
    printf("TTM trace started\n");
    @step[1] = 0; @step[2] = 0; @step[3] = 0; @step[4] = 0; @step[5] = 0;
}

kprobe:ttm_bo_init_reserved {
    @step[1]++;
    printf("[PROBE] ttm_bo_init_reserved called (bo=0x%lx)\n", arg1);
}

kprobe:ttm_bo_validate {
    @step[2]++;
    printf("[PROBE] ttm_bo_validate called (bo=0x%lx)\n", arg0);
}

kprobe:ttm_pool_alloc {
    @step[3]++;
    printf("[PROBE] ttm_pool_alloc called\n");
}

kprobe:ttm_bo_move_to_lru_tail {
    @step[4]++;
    printf("[PROBE] ttm_bo_move_to_lru_tail called (bo=0x%lx)\n", arg0);
}

kprobe:ttm_bo_put {
    @step[5]++;
    printf("[PROBE] ttm_bo_put called (bo=0x%lx)\n", arg0);
}

END {
    printf("TTM trace ended\n");
}
"""

STEPS = [
    (1, "ttm_bo_init_reserved", ["ttm_bo_init_reserved"]),
    (2, "ttm_bo_validate",      ["ttm_bo_validate"]),
    (3, "ttm_pool_alloc",       ["ttm_pool_alloc"]),
    (4, "ttm_bo_move_to_lru_tail", ["ttm_bo_move_to_lru_tail"]),
    (5, "ttm_bo_put",           ["ttm_bo_put"]),
]


def run_trigger():
    """Trigger TTM activity by probing /dev/dri availability or modprobing vkms."""
    # Try loading vkms (uses TTM via GEM) if not already loaded
    subprocess.run(["modprobe", "vkms"], capture_output=True)
    time.sleep(2)
    # A simple read of the DRI device list exercises TTM init paths
    subprocess.run(["ls", "/dev/dri/"], capture_output=True)
    time.sleep(2)
    subprocess.run(["modprobe", "-r", "vkms"], capture_output=True)
    time.sleep(1)


def main():
    global PROBE_TIMEOUT
    parser = argparse.ArgumentParser(description="TTM bpftrace workflow test")
    parser.add_argument("--timeout", type=int, default=PROBE_TIMEOUT,
                        help="Seconds to run bpftrace")
    args = parser.parse_args()
    PROBE_TIMEOUT = args.timeout

    print("=== TTM Workflow Trace Test ===")
    print(f"Timeout: {PROBE_TIMEOUT}s")
    print()

    # Write bpftrace program to temp file
    import tempfile, os
    with tempfile.NamedTemporaryFile(mode='w', suffix='.bt', delete=False) as f:
        f.write(BPFTRACE_PROGRAM)
        bt_file = f.name

    try:
        proc = subprocess.Popen(
            ["bpftrace", bt_file],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True
        )

        # Give bpftrace a moment to attach probes
        time.sleep(3)

        # Run the trigger
        run_trigger()

        # Wait for timeout
        time.sleep(max(0, PROBE_TIMEOUT - 5))
        proc.terminate()
        stdout, stderr = proc.communicate(timeout=10)
    finally:
        os.unlink(bt_file)

    output = stdout + stderr
    print("--- bpftrace output ---")
    print(output)
    print("--- end output ---")
    print()

    # Parse results
    hit_counts = {}
    for line in output.splitlines():
        for step_num, name, _ in STEPS:
            if f"[PROBE] {name}" in line:
                hit_counts[step_num] = hit_counts.get(step_num, 0) + 1

    print("=== Results ===")
    all_pass = True
    for step_num, name, alt_probes in STEPS:
        hits = hit_counts.get(step_num, 0)
        if hits > 0:
            status = "PASS"
        else:
            status = "FAIL"
            all_pass = False
        print(f"  Step {step_num}: {name:35s} [{status}]  (hits={hits})")
        if status == "FAIL":
            print(f"           alt_probes: {alt_probes}")

    print()
    if all_pass:
        print("Summary: ALL STEPS PASSED")
        sys.exit(0)
    else:
        print("Summary: SOME STEPS FAILED")
        sys.exit(1)


if __name__ == "__main__":
    main()
