#!/usr/bin/env python3
"""
drm_stimulate.py — Background display activity generator for trace tests.

Generates GPU/display activity to trigger drm_handle_vblank and
dma_fence_signal bpftrace probes.

Backends (tried in order of detected session type):
  1. glxgears  — X11 GL rendering (triggers vblank + fence)
  2. pygame    — SDL color cycling on X11 or Wayland
  3. DRM node  — open/close DRM device in a loop (minimal, last resort)

Usage: sudo python3 drm_stimulate.py
       Run in background; send SIGTERM to stop.
"""
import glob
import os
import shutil
import signal
import subprocess
import sys
import time

# ── Signal handling ───────────────────────────────────────────────────────────
_running = True
def _on_sig(*_):
    global _running
    _running = False
signal.signal(signal.SIGTERM, _on_sig)
signal.signal(signal.SIGINT,  _on_sig)


# ── Session discovery ─────────────────────────────────────────────────────────

def _detect_session():
    """Detect the active display session (X11 or Wayland).

    Returns a dict with keys: type ("x11"|"wayland"|None),
    display, xauthority, xdg_runtime_dir, wayland_display.
    """
    info = {
        "type": None,
        "display": os.environ.get("DISPLAY"),
        "xauthority": os.environ.get("XAUTHORITY"),
        "xdg_runtime_dir": os.environ.get("XDG_RUNTIME_DIR"),
        "wayland_display": os.environ.get("WAYLAND_DISPLAY"),
    }

    # If env vars are already set, use them
    if info["display"] and info["xauthority"]:
        info["type"] = "x11"
        return info
    if info["wayland_display"] and info["xdg_runtime_dir"]:
        info["type"] = "wayland"
        return info

    # Auto-detect: check for X11 sockets first
    x11_socks = sorted(glob.glob("/tmp/.X11-unix/X*"))
    if x11_socks:
        display_num = os.path.basename(x11_socks[0]).lstrip("X")
        info["display"] = f":{display_num}"

        # Find XAUTHORITY — check common locations
        xauth_candidates = []
        for user_dir in sorted(glob.glob("/run/user/*")):
            xauth_candidates.extend([
                os.path.join(user_dir, "gdm", "Xauthority"),
                os.path.join(user_dir, ".mutter-Xwaylandauth.*"),
            ])
        # Also check home dirs
        for home in sorted(glob.glob("/home/*")):
            xauth_candidates.append(os.path.join(home, ".Xauthority"))
        xauth_candidates.append("/root/.Xauthority")

        for candidate in xauth_candidates:
            matches = glob.glob(candidate) if "*" in candidate else [candidate]
            for m in matches:
                if os.path.isfile(m):
                    info["xauthority"] = m
                    break
            if info["xauthority"]:
                break

        if info["xauthority"]:
            info["type"] = "x11"
            print(f"[stimulate] Detected X11 session: DISPLAY={info['display']} "
                  f"XAUTHORITY={info['xauthority']}", flush=True)
            return info

    # Check for Wayland sockets
    wayland_candidates = []
    for user_dir in sorted(glob.glob("/run/user/*")):
        wayland_candidates.extend(
            s for s in sorted(glob.glob(os.path.join(user_dir, "wayland-*")))
            if not s.endswith(".lock")
        )
    if wayland_candidates:
        sock = wayland_candidates[0]
        info["xdg_runtime_dir"] = os.path.dirname(sock)
        info["wayland_display"] = os.path.basename(sock)
        info["type"] = "wayland"
        print(f"[stimulate] Detected Wayland session: "
              f"WAYLAND_DISPLAY={info['wayland_display']}", flush=True)
        return info

    print("[stimulate] No active display session detected", flush=True)
    return info


def _make_env(session):
    """Build environment dict for subprocess based on session info."""
    env = os.environ.copy()
    if session.get("display"):
        env["DISPLAY"] = session["display"]
    if session.get("xauthority"):
        env["XAUTHORITY"] = session["xauthority"]
    if session.get("xdg_runtime_dir"):
        env["XDG_RUNTIME_DIR"] = session["xdg_runtime_dir"]
    if session.get("wayland_display"):
        env["WAYLAND_DISPLAY"] = session["wayland_display"]
    return env


# ── Backend: glxgears (X11) ──────────────────────────────────────────────────

def _try_glxgears(session):
    """Run glxgears on the detected X11 display. Returns True on success."""
    if session.get("type") != "x11":
        return False
    glxgears = shutil.which("glxgears")
    if not glxgears:
        print("[stimulate] glxgears not found — skipping", flush=True)
        return False

    env = _make_env(session)
    try:
        proc = subprocess.Popen(
            [glxgears, "-display", session["display"]],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env,
        )
        # Give it a moment to start rendering
        time.sleep(2)
        if proc.poll() is not None:
            out = proc.stdout.read().decode(errors="replace").strip()
            print(f"[stimulate] glxgears exited early: {out[:200]}", flush=True)
            return False

        print(f"[stimulate] glxgears started (PID {proc.pid}) on "
              f"{session['display']}", flush=True)

        # Keep running until signaled
        while _running:
            if proc.poll() is not None:
                break
            time.sleep(0.5)

        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
        print("[stimulate] glxgears stopped", flush=True)
        return True
    except Exception as e:
        print(f"[stimulate] glxgears failed: {e}", flush=True)
        return False


# ── Backend: pygame (X11 or Wayland) ─────────────────────────────────────────

def _try_pygame(session):
    """Run pygame color cycling on X11 or Wayland. Returns True on success."""
    if session.get("type") not in ("x11", "wayland"):
        return False

    try:
        import pygame
    except ImportError:
        print("[stimulate] pygame not installed — skipping", flush=True)
        return False

    env = _make_env(session)
    for k, v in env.items():
        os.environ[k] = v

    if session["type"] == "wayland":
        os.environ.setdefault("SDL_VIDEODRIVER", "wayland")
    else:
        os.environ.setdefault("SDL_VIDEODRIVER", "x11")

    try:
        pygame.init()
    except Exception as e:
        print(f"[stimulate] pygame init failed: {e}", flush=True)
        return False

    try:
        info = pygame.display.Info()
        w, h = info.current_w, info.current_h
        if not w or not h:
            w, h = 1920, 1080
    except Exception:
        w, h = 1920, 1080

    try:
        screen = pygame.display.set_mode((w, h), pygame.SCALED)
    except Exception as e:
        print(f"[stimulate] pygame display failed: {e}", flush=True)
        pygame.quit()
        return False

    colors = [(255, 0, 0), (0, 255, 0), (0, 0, 255),
              (255, 255, 255), (0, 0, 0)]
    print(f"[stimulate] pygame started ({w}×{h}) via {session['type']}",
          flush=True)

    idx = 0
    clock = pygame.time.Clock()
    while _running:
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                break
        screen.fill(colors[idx % len(colors)])
        pygame.display.flip()
        idx += 1
        clock.tick(2)

    pygame.quit()
    print("[stimulate] pygame stopped", flush=True)
    return True


# ── Backend: DRM node open/close (last resort) ───────────────────────────────

def _try_drm_loop():
    """Open and close DRM device nodes in a loop. Minimal activity."""
    cards = sorted(glob.glob("/dev/dri/card[0-9]*"))
    if not cards:
        print("[stimulate] No DRM devices found", flush=True)
        return False

    card = cards[0]
    print(f"[stimulate] DRM node loop on {card} (low-confidence fallback)",
          flush=True)

    while _running:
        try:
            fd = os.open(card, os.O_RDWR)
            os.close(fd)
        except OSError:
            pass
        time.sleep(0.1)

    print("[stimulate] DRM node loop stopped", flush=True)
    return True


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    session = _detect_session()
    backend = session.get("type") or "none"
    print(f"[stimulate] Session type: {backend}", flush=True)

    # Try backends in order of effectiveness
    if session.get("type") == "x11":
        if _try_glxgears(session):
            return
        if _try_pygame(session):
            return
    elif session.get("type") == "wayland":
        if _try_pygame(session):
            return

    # Last resort
    _try_drm_loop()


if __name__ == "__main__":
    main()
