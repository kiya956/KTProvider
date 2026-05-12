#!/usr/bin/env python3
"""
HDA (HD-Audio) Subsystem – bpftrace workflow verification test

Traces the HDA codec initialization and PCM stream setup:
  azx_probe_work → snd_hda_codec_new → snd_hda_codec_configure
  → snd_hda_codec_build_pcms → snd_hda_codec_build_controls
  → snd_hda_codec_setup_stream

Requires: HDA sound card (snd_hda_intel module loaded), bpftrace, aplay
Source:   sound/hda/ in noble-linux-oem
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
        "id": "codec_setup_stream",
        "desc": "HDA codec stream setup (triggered by playback)",
        "probes": ["kprobe:snd_hda_codec_setup_stream"],
        "alt_probes": ["kprobe:__snd_hda_codec_cleanup_stream"],
        "trigger": None,
    },
]

PASSIVE_STEPS = [
    {
        "id": "azx_probe_work",
        "desc": "Intel HDA controller probe work",
        "probes": ["kprobe:azx_probe_work"],
        "alt_probes": ["kprobe:azx_probe"],
    },
    {
        "id": "codec_new",
        "desc": "HDA codec created",
        "probes": ["kprobe:snd_hda_codec_new"],
        "alt_probes": ["kprobe:snd_hda_codec_device_new"],
    },
    {
        "id": "codec_configure",
        "desc": "HDA codec configured",
        "probes": ["kprobe:snd_hda_codec_configure"],
        "alt_probes": [],
    },
    {
        "id": "codec_build_pcms",
        "desc": "HDA codec PCMs built",
        "probes": ["kprobe:snd_hda_codec_build_pcms"],
        "alt_probes": [],
    },
    {
        "id": "codec_build_controls",
        "desc": "HDA codec controls built",
        "probes": ["kprobe:snd_hda_codec_build_controls"],
        "alt_probes": [],
    },
]


def find_hda_pcm_device():
    """Find an HDA playback PCM device."""
    try:
        result = subprocess.run(
            ["aplay", "-l"], capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if "HDA" in line.upper() and ("HDA-Intel" in line or "Analog" in line):
                    m = re.match(r"card (\d+):.*device (\d+):", line)
                    if m:
                        return f"hw:{m.group(1)},{m.group(2)}"
    except Exception:
        pass
    # Fallback: skip — only HDA devices should be used
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
    return step["probes"]


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

    results = {s["id"]: False for s in all_steps}

    wav_file = "/tmp/hda_test.wav"
    try:
        bt_proc = subprocess.Popen(
            ["bpftrace", "-e", script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        time.sleep(3)

        if bt_proc.poll() is not None:
            stderr = bt_proc.stderr.read()
            print(f"[WARN] bpftrace exited early: {stderr.strip()}")
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

        # Generate test audio
        has_sox = any(
            os.access(os.path.join(p, "sox"), os.X_OK)
            for p in os.environ.get("PATH", "").split(":")
        )
        if has_sox:
            subprocess.run(
                [
                    "sox", "-n", "-r", "44100", "-c", "2", "-b", "16",
                    wav_file, "synth", "2", "sine", "440",
                ],
                capture_output=True,
                timeout=10,
            )
        else:
            import struct
            import math
            sample_rate = 44100
            num_samples = sample_rate * 2
            data = b""
            for i in range(num_samples):
                val = int(16000 * math.sin(2 * math.pi * 440 * i / sample_rate))
                data += struct.pack("<hh", val, val)
            with open(wav_file, "wb") as wf:
                wf.write(b"RIFF")
                wf.write(struct.pack("<I", 36 + len(data)))
                wf.write(b"WAVEfmt ")
                wf.write(struct.pack("<IHHIIHH", 16, 1, 2, sample_rate, sample_rate * 4, 4, 16))
                wf.write(b"data")
                wf.write(struct.pack("<I", len(data)))
                wf.write(data)

        # Play to trigger HDA codec stream setup
        aplay_proc = subprocess.run(
            ["aplay", "-D", pcm_device, wav_file],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
        if aplay_proc.returncode != 0:
            print(f"[WARN] aplay returned {aplay_proc.returncode}: {aplay_proc.stderr.strip()}")
            subprocess.run(
                ["aplay", wav_file],
                capture_output=True,
                text=True,
                timeout=timeout_sec,
            )

        time.sleep(2)

        bt_proc.send_signal(signal.SIGINT)
        try:
            stdout, stderr = bt_proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            bt_proc.kill()
            stdout, stderr = bt_proc.communicate()

        for line in stdout.splitlines():
            if line.startswith("STEP_HIT:"):
                step_id = line.split(":", 1)[1].strip()
                if step_id in results:
                    results[step_id] = True

    finally:
        if os.path.exists(wav_file):
            os.unlink(wav_file)

    return results


def main():
    global PROBE_TIMEOUT
    parser = argparse.ArgumentParser(
        description="HDA subsystem bpftrace workflow test"
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

    # Check HDA module loaded
    try:
        with open("/proc/modules") as f:
            modules = f.read()
        if "snd_hda" not in modules:
            print("SKIP: snd_hda module not loaded — no HDA hardware")
            sys.exit(0)
    except Exception:
        pass

    for cmd in ["bpftrace", "aplay"]:
        if not any(
            os.access(os.path.join(p, cmd), os.X_OK)
            for p in os.environ.get("PATH", "").split(":")
        ):
            print(f"FAIL: {cmd} not found in PATH")
            sys.exit(1)

    pcm_dev = find_hda_pcm_device()
    if not pcm_dev:
        print("SKIP: No HDA PCM playback device found")
        sys.exit(0)

    print(f"Using HDA PCM device: {pcm_dev}")
    print(f"Timeout: {PROBE_TIMEOUT}s")
    print()

    results = run_test(pcm_dev, PROBE_TIMEOUT)

    all_steps = STEPS + PASSIVE_STEPS
    pass_count = 0
    fail_count = 0
    skip_count = 0

    print("=" * 60)
    print("HDA Subsystem Workflow Test Results")
    print("=" * 60)

    print("\n--- HDA Stream Path (active) ---")
    for step in STEPS:
        hit = results.get(step["id"], False)
        status = "PASS" if hit else "FAIL"
        if hit:
            pass_count += 1
        else:
            fail_count += 1
        print(f"  [{status}] {step['desc']} ({step['id']})")

    print("\n--- HDA Probe & Init (passive — fires at module load) ---")
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

    active_failures = sum(1 for s in STEPS if not results.get(s["id"], False))
    sys.exit(1 if active_failures > 0 else 0)


if __name__ == "__main__":
    main()
