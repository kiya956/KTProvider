#!/usr/bin/env python3
"""
drm_stimulate.py — Background display activity generator for trace tests.

Forces compositor page flips via pygame color cycling, triggering
drm_handle_vblank and scanout-related bpftrace probes on any GPU.

Usage: sudo python3 drm_stimulate.py
       Run in background; send SIGTERM to stop.

Requires: python3-pygame (sudo apt install python3-pygame)
"""
import glob
import os
import signal
import sys
import time

# ── Signal handling ───────────────────────────────────────────────────────────
_running = True
def _on_sig(*_):
    global _running
    _running = False
signal.signal(signal.SIGTERM, _on_sig)
signal.signal(signal.SIGINT,  _on_sig)

# ── Display flash loop (triggers vblank via compositor scanout) ────────────────
def flash_screen_loop():
    """Cycle colors via pygame/SDL on Wayland — forces compositor page flips."""
    # Find Wayland socket
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    if xdg:
        socks = sorted(glob.glob(os.path.join(xdg, "wayland-*")))
        if not socks:
            socks = []
    else:
        socks = []

    if not socks:
        candidates = sorted(glob.glob("/run/user/*/wayland-*"))
        candidates = [c for c in candidates if not c.endswith(".lock")]
        if not candidates:
            print("[stimulate] No Wayland socket found — display flash skipped",
                  flush=True)
            return
        xdg = os.path.dirname(candidates[0])
        socks = [candidates[0]]

    wayland_display = os.path.basename(socks[0])
    os.environ["XDG_RUNTIME_DIR"] = xdg
    os.environ["WAYLAND_DISPLAY"] = wayland_display
    os.environ.setdefault("SDL_VIDEODRIVER", "wayland")

    try:
        import pygame
    except ImportError:
        print("[stimulate] pygame not installed — display flash skipped\n"
              "  Install with: sudo apt install python3-pygame", flush=True)
        return

    pygame.init()
    try:
        info = pygame.display.Info()
        w, h = info.current_w, info.current_h
        if not w or not h:
            w, h = 1920, 1080
    except Exception:
        w, h = 1920, 1080

    screen = pygame.display.set_mode((w, h), pygame.SCALED)
    colors = [(255, 0, 0), (0, 255, 0), (0, 0, 255),
              (255, 255, 255), (0, 0, 0)]
    print(f"[stimulate] Display flash started ({w}×{h})", flush=True)

    idx = 0
    clock = pygame.time.Clock()
    while _running:
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                pygame.quit()
                print("[stimulate] Display flash stopped", flush=True)
                return
        screen.fill(colors[idx % len(colors)])
        pygame.display.flip()
        idx += 1
        clock.tick(2)   # ~2 fps, enough to keep scanout busy

    pygame.quit()
    print("[stimulate] Display flash stopped", flush=True)

# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    flash_screen_loop()

if __name__ == "__main__":
    main()
