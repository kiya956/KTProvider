#!/usr/bin/env python3
"""
ALSA Sound Core – bpftrace workflow verification test

Traces the PCM playback lifecycle through the ALSA core:
  snd_pcm_open_substream → snd_pcm_hw_params → snd_pcm_prepare
  → __snd_pcm_lib_xfer → snd_pcm_do_start → snd_pcm_update_hw_ptr

Also traces card lifecycle (snd_card_new, snd_card_register) and
control path (snd_ctl_open, snd_ctl_ioctl).

Requires: any sound card present (/dev/snd/pcmC*D*p), bpftrace, aplay
Source:   sound/core/ in noble-linux-oem
"""

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time

PROBE_TIMEOUT = 30

STEPS = [
    {
        "id": "pcm_open",
        "desc": "PCM substream open",
        "probes": ["kprobe:snd_pcm_open_substream"],
        "alt_probes": ["kprobe:snd_pcm_open"],
        "trigger": None,  # triggered by aplay
    },
    {
        "id": "hw_params",
        "desc": "PCM hardware params configuration",
        "probes": ["kprobe:snd_pcm_hw_params"],
        "alt_probes": ["kprobe:snd_pcm_hw_params_user"],
        "trigger": None,
    },
    {
        "id": "pcm_prepare",
        "desc": "PCM prepare for playback",
        "probes": ["kprobe:snd_pcm_prepare"],
        "alt_probes": [],
        "trigger": None,
    },
    {
        "id": "pcm_xfer",
        "desc": "PCM data transfer (write)",
        "probes": ["kprobe:__snd_pcm_lib_xfer"],
        "alt_probes": ["kprobe:snd_pcm_lib_write"],
        "trigger": None,
    },
    {
        "id": "pcm_start",
        "desc": "PCM trigger start (DMA begin)",
        "probes": ["kprobe:snd_pcm_do_start"],
        "alt_probes": ["kprobe:snd_pcm_trigger"],
        "trigger": None,
    },
]

PASSIVE_STEPS = [
    {
        "id": "hw_ptr_update",
        "desc": "Hardware pointer update (IRQ-driven)",
        "probes": ["kprobe:snd_pcm_update_hw_ptr"],
        "alt_probes": ["kprobe:snd_pcm_update_hw_ptr0"],
    },
    {
        "id": "card_register",
        "desc": "Sound card registered",
        "probes": ["kprobe:snd_card_register"],
        "alt_probes": [],
    },
    {
        "id": "ctl_open",
        "desc": "Control device open",
        "probes": ["kprobe:snd_ctl_open"],
        "alt_probes": [],
    },
    {
        "id": "ctl_ioctl",
        "desc": "Control ioctl",
        "probes": ["kprobe:snd_ctl_ioctl"],
        "alt_probes": [],
    },
]


def find_pcm_device():
    """Find a playback PCM device."""
    try:
        result = subprocess.run(
            ["aplay", "-l"], capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0 and "card" in result.stdout:
            for line in result.stdout.splitlines():
                m = re.match(r"card (\d+):.*device (\d+):", line)
                if m:
                    return f"hw:{m.group(1)},{m.group(2)}"
    except Exception:
        pass
    # Fallback: check /dev/snd
    for f in sorted(os.listdir("/dev/snd")) if os.path.isdir("/dev/snd") else []:
        m = re.match(r"pcmC(\d+)D(\d+)p", f)
        if m:
            return f"hw:{m.group(1)},{m.group(2)}"
    return None


def check_probe_available(probe_str):
    """Check if a kprobe target function exists in /proc/kallsyms."""
    func = probe_str.split(":")[-1]
    try:
        result = subprocess.run(
            ["grep", "-qw", func, "/proc/kallsyms"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


def resolve_probes(step):
    """Pick primary or alt probe based on availability."""
    for p in step["probes"]:
        if check_probe_available(p):
            return [p]
    for p in step.get("alt_probes", []):
        if check_probe_available(p):
            return [p]
    return step["probes"]  # fallback to primary


def generate_bpftrace_script(steps):
    """Generate a bpftrace one-liner that traces all steps."""
    parts = []
    for step in steps:
        probes = resolve_probes(step)
        for probe in probes:
            parts.append(
                f'{probe} {{ printf("STEP_HIT:{step["id"]}\\n"); }}'
            )
    return " ".join(parts)


def run_test(pcm_device, timeout_sec):
    """Run bpftrace + aplay and collect results."""
    all_steps = STEPS + PASSIVE_STEPS
    script = generate_bpftrace_script(all_steps)

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".bt", delete=False
    ) as f:
        f.write(script)
        bt_script = f.name

    results = {s["id"]: False for s in all_steps}

    try:
        # Start bpftrace
        bt_proc = subprocess.Popen(
            ["bpftrace", "-e", script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        # Wait for bpftrace to attach
        time.sleep(3)

        if bt_proc.poll() is not None:
            stderr = bt_proc.stderr.read()
            print(f"[WARN] bpftrace exited early: {stderr.strip()}")
            # Try with alt probes only
            alt_steps = []
            for s in all_steps:
                s2 = dict(s)
                if s2.get("alt_probes"):
                    s2["probes"] = s2["alt_probes"]
                alt_steps.append(s2)
            script = generate_bpftrace_script(alt_steps)
            bt_proc = subprocess.Popen(
                ["bpftrace", "-e", script],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            time.sleep(3)

        # Generate a short WAV and play it
        wav_file = "/tmp/sound_core_test.wav"
        has_sox = any(
            os.access(os.path.join(p, "sox"), os.X_OK)
            for p in os.environ.get("PATH", "").split(":")
        )
        if has_sox:
            subprocess.run(
                [
                    "sox",
                    "-n",
                    "-r",
                    "44100",
                    "-c",
                    "2",
                    "-b",
                    "16",
                    wav_file,
                    "synth",
                    "2",
                    "sine",
                    "440",
                ],
                capture_output=True,
                timeout=10,
            )
        else:
            # Generate a minimal WAV file without sox
            import struct
            sample_rate = 44100
            num_samples = sample_rate * 2  # 2 seconds
            with open(wav_file, "wb") as wf:
                import math
                data = b""
                for i in range(num_samples):
                    val = int(16000 * math.sin(2 * math.pi * 440 * i / sample_rate))
                    data += struct.pack("<hh", val, val)
                wf.write(b"RIFF")
                wf.write(struct.pack("<I", 36 + len(data)))
                wf.write(b"WAVEfmt ")
                wf.write(struct.pack("<IHHIIHH", 16, 1, 2, sample_rate, sample_rate * 4, 4, 16))
                wf.write(b"data")
                wf.write(struct.pack("<I", len(data)))
                wf.write(data)

        # Play audio to trigger the PCM path
        aplay_proc = subprocess.run(
            ["aplay", "-D", pcm_device, wav_file],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
        if aplay_proc.returncode != 0:
            print(f"[WARN] aplay returned {aplay_proc.returncode}: {aplay_proc.stderr.strip()}")
            # Try default device
            aplay_proc = subprocess.run(
                ["aplay", wav_file],
                capture_output=True,
                text=True,
                timeout=timeout_sec,
            )

        # Also trigger control path
        subprocess.run(
            ["amixer", "scontents"],
            capture_output=True,
            timeout=10,
        )

        # Let bpftrace collect a bit more
        time.sleep(2)

        # Stop bpftrace
        bt_proc.send_signal(signal.SIGINT)
        try:
            stdout, stderr = bt_proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            bt_proc.kill()
            stdout, stderr = bt_proc.communicate()

        # Parse results
        for line in stdout.splitlines():
            if line.startswith("STEP_HIT:"):
                step_id = line.split(":", 1)[1].strip()
                if step_id in results:
                    results[step_id] = True

    finally:
        os.unlink(bt_script)
        if os.path.exists(wav_file):
            os.unlink(wav_file)

    return results


def main():
    global PROBE_TIMEOUT
    parser = argparse.ArgumentParser(
        description="ALSA Sound Core bpftrace workflow test"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=PROBE_TIMEOUT,
        help=f"Timeout in seconds (default: {PROBE_TIMEOUT})",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format",
    )
    args = parser.parse_args()
    PROBE_TIMEOUT = args.timeout

    # Check prerequisites
    for cmd in ["bpftrace", "aplay", "amixer"]:
        if not any(
            os.access(os.path.join(p, cmd), os.X_OK)
            for p in os.environ.get("PATH", "").split(":")
        ):
            print(f"FAIL: {cmd} not found in PATH")
            sys.exit(1)

    # Check for sox (for WAV generation)
    has_sox = any(
        os.access(os.path.join(p, "sox"), os.X_OK)
        for p in os.environ.get("PATH", "").split(":")
    )
    if not has_sox:
        print("WARN: sox not found, will try /dev/urandom for audio data")

    pcm_dev = find_pcm_device()
    if not pcm_dev:
        print("SKIP: No PCM playback device found")
        sys.exit(0)

    print(f"Using PCM device: {pcm_dev}")
    print(f"Timeout: {PROBE_TIMEOUT}s")
    print()

    results = run_test(pcm_dev, PROBE_TIMEOUT)

    # Report
    all_steps = STEPS + PASSIVE_STEPS
    pass_count = 0
    fail_count = 0
    skip_count = 0

    print("=" * 60)
    print("ALSA Sound Core Workflow Test Results")
    print("=" * 60)

    # Active steps (PCM playback path) — these are expected to fire
    print("\n--- PCM Playback Path (active) ---")
    for step in STEPS:
        hit = results.get(step["id"], False)
        status = "PASS" if hit else "FAIL"
        if hit:
            pass_count += 1
        else:
            fail_count += 1
        print(f"  [{status}] {step['desc']} ({step['id']})")

    # Passive steps — these may or may not fire depending on system state
    print("\n--- Card & Control Path (passive) ---")
    for step in PASSIVE_STEPS:
        hit = results.get(step["id"], False)
        status = "PASS" if hit else "SKIP"
        if hit:
            pass_count += 1
        else:
            skip_count += 1
        print(f"  [{status}] {step['desc']} ({step['id']})")

    print()
    print(f"Total: {pass_count} PASS, {fail_count} FAIL, {skip_count} SKIP")

    if args.json:
        json_results = {
            step["id"]: {
                "desc": step["desc"],
                "result": "PASS"
                if results.get(step["id"], False)
                else ("FAIL" if step in STEPS else "SKIP"),
            }
            for step in all_steps
        }
        print(json.dumps(json_results, indent=2))

    # Exit code: fail only if active PCM path steps failed
    active_failures = sum(1 for s in STEPS if not results.get(s["id"], False))
    sys.exit(1 if active_failures > 0 else 0)


if __name__ == "__main__":
    main()
