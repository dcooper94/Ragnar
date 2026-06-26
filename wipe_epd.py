#!/usr/bin/env python3
"""Utility to clear the Waveshare E-Paper display when Ragnar restarts."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

try:
    from shared import DEFAULT_EPD_TYPE  # type: ignore
except Exception:
    DEFAULT_EPD_TYPE = "epd2in13_V4"

from epd_helper import EPDHelper

REPO_ROOT = Path(__file__).resolve().parent
CONFIG_PATH = REPO_ROOT / "config" / "shared_config.json"

# How many times to retry if GPIO is busy (e.g. pwnagotchi/old process releasing slowly)
_GPIO_RETRY_ATTEMPTS = 5
_GPIO_RETRY_DELAY = 1.5  # seconds between retries


def _read_epd_type_from_config() -> str | None:
    """Return the epd_type persisted in shared_config.json, if available."""
    try:
        with CONFIG_PATH.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        return None
    except json.JSONDecodeError:
        return None
    return data.get("epd_type")


def resolve_epd_type() -> str | None:
    """Determine which EPD profile to use when clearing the screen."""
    if env_override := os.getenv("EPD_TYPE"):
        return env_override
    config_value = _read_epd_type_from_config()
    if config_value:
        return config_value
    return DEFAULT_EPD_TYPE


def wipe_display(epd_type: str) -> None:
    """Perform a full refresh + clear on the requested display profile."""
    helper = EPDHelper(epd_type)
    helper.init_full_update()
    helper.clear()
    helper.sleep()


def main() -> int:
    epd_type = resolve_epd_type()
    if not epd_type:
        print("wipe_epd: no EPD type configured, skipping", file=sys.stderr)
        return 0
    # Non-EPD displays are managed by display.py — no wipe needed on restart
    _NON_EPD_TYPES = ("max7219_4panel", "max7219_8panel", "ssd1306", "gc9a01", "lcd1602")
    if epd_type in _NON_EPD_TYPES:
        print(f"wipe_epd: {epd_type} is not an e-paper display, skipping wipe")
        return 0

    last_exc: Exception | None = None
    for attempt in range(1, _GPIO_RETRY_ATTEMPTS + 1):
        try:
            EPDHelper._release_epdconfig_gpio()
            wipe_display(epd_type)
            print(f"wipe_epd: cleared display using {epd_type}")
            return 0
        except Exception as exc:
            last_exc = exc
            busy = "busy" in str(exc).lower() or "in use" in str(exc).lower()
            if busy and attempt < _GPIO_RETRY_ATTEMPTS:
                print(
                    f"wipe_epd: GPIO busy (attempt {attempt}/{_GPIO_RETRY_ATTEMPTS}), "
                    f"retrying in {_GPIO_RETRY_DELAY}s...",
                    file=sys.stderr,
                )
                EPDHelper._release_epdconfig_gpio()
                time.sleep(_GPIO_RETRY_DELAY)
            else:
                break

    print(f"wipe_epd: failed to clear display ({last_exc})", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
