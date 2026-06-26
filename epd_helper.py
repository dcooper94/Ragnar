# epd_helper.py

import importlib
import logging
import time
import concurrent.futures

logger = logging.getLogger(__name__)

# Known EPD types to try during auto-detection (most common first).
# V3 is listed before V4 so that a V3 display is detected as V3 rather than V4
# (the V4 init sequence can succeed on V3 hardware, which would give the wrong driver).
KNOWN_EPD_TYPES = [
    "epd2in13_V3",
    "epd2in13_V4",
    "epd2in13_V2",
    "epd2in7_V2",
    "epd2in7",
    "epd2in13",
    "epd2in9_V2",
    "epd3in7",
    "epd4in26",
    "gc9a01",
    "ssd1306",
    "max7219_4panel",
    "max7219_8panel",
]

# Seconds to wait for a single driver's init() before considering it hung.
# e-paper BUSY pin can stay high for up to ~2s during reset; 8s gives a comfortable margin.
_AUTO_DETECT_INIT_TIMEOUT = 8.0

class EPDHelper:
    def __init__(self, epd_type):
        self.epd_type = epd_type
        self.epd = self._load_epd_module()
        # Tracks whether both RAM banks have been initialized for partial updates.
        # Drivers like V3/V4 require displayPartBaseImage() before displayPartial()
        # so the controller has a valid background image in RAM26 for pixel comparison.
        self._base_image_set = False

    def _load_epd_module(self):
        try:
            epd_module_name = f'resources.waveshare_epd.{self.epd_type}'
            epd_module = importlib.import_module(epd_module_name)
            return epd_module.EPD()
        except ImportError as e:
            logger.error(f"EPD module {self.epd_type} not found: {e}")
            raise
        except Exception as e:
            logger.error(f"Error loading EPD module {self.epd_type}: {e}")
            raise

    def init_full_update(self):
        try:
            if hasattr(self.epd, 'FULL_UPDATE'):
                self.epd.init(self.epd.FULL_UPDATE)
            elif hasattr(self.epd, 'lut_full_update'):
                self.epd.init(self.epd.lut_full_update)
            else:
                self.epd.init()
            logger.info("EPD full update initialization complete.")
        except Exception as e:
            logger.error(f"Error initializing EPD for full update: {e}")
            raise

    def init_partial_update(self):
        try:
            if hasattr(self.epd, 'PART_UPDATE'):
                self.epd.init(self.epd.PART_UPDATE)
            elif hasattr(self.epd, 'lut_partial_update'):
                self.epd.init(self.epd.lut_partial_update)
            else:
                self.epd.init()
            logger.info("EPD partial update initialization complete.")
        except Exception as e:
            logger.error(f"Error initializing EPD for partial update: {e}")
            raise

    def display_partial(self, image):
        try:
            imw, imh = image.size
            epd_w, epd_h = self.epd.width, self.epd.height

            # Ensure image matches EPD dimensions before sending to driver
            # Allow swapped dimensions (90°/270° rotation) — getbuffer handles both orientations
            if (imw != epd_w or imh != epd_h) and (imw != epd_h or imh != epd_w):
                logger.warning(f"Image size {imw}x{imh} != EPD size {epd_w}x{epd_h}, resizing")
                image = image.resize((epd_w, epd_h))

            buf = self.epd.getbuffer(image)

            # V3/V4 e-paper controllers require both RAM banks (RAM24 + RAM26) to be
            # loaded before partial updates can work correctly. RAM26 holds the
            # "background" image the controller uses to compute pixel changes. After a
            # clear or cold start RAM26 has stale/undefined content, which makes partial
            # updates produce a white or garbled display.
            # Fix: use displayPartBaseImage() on the first call to fill both banks,
            # then switch to displayPartial() for all subsequent fast updates.
            if not self._base_image_set and hasattr(self.epd, 'displayPartBaseImage'):
                self.epd.displayPartBaseImage(buf)
                self._base_image_set = True
                logger.info("Partial display base image initialized (full refresh to seed RAM26).")
                return

            if hasattr(self.epd, 'displayPartial'):
                self.epd.displayPartial(buf)
            elif hasattr(self.epd, 'display_Partial'):
                import inspect
                sig = inspect.signature(self.epd.display_Partial)
                if len(sig.parameters) >= 5:
                    # V2-style: display_Partial(image, Xstart, Ystart, Xend, Yend)
                    self.epd.display_Partial(buf, 0, 0, epd_w, epd_h)
                else:
                    self.epd.display_Partial(buf)
            else:
                self.epd.display(buf)
            logger.info("Partial display update complete.")
        except Exception as e:
            logger.error(f"Error during partial display update: {e} (image={image.size if hasattr(image,'size') else '?'}, epd={self.epd.width}x{self.epd.height}, buf_len={len(buf) if 'buf' in dir() else '?'})")
            raise

    def clear(self):
        try:
            self.epd.Clear()
            logger.info("EPD cleared.")
        except Exception as e:
            logger.error(f"Error clearing EPD: {e}")
            raise

    def display_full(self, image):
        """Display image on EPD using full update."""
        try:
            self.epd.display(self.epd.getbuffer(image))
            logger.info("Full display update complete.")
        except Exception as e:
            logger.error(f"Error during full display update: {e}")
            raise

    def sleep(self):
        """Put EPD to sleep mode."""
        try:
            self.epd.sleep()
            logger.info("EPD sleep mode activated.")
        except Exception as e:
            logger.error(f"Error putting EPD to sleep: {e}")
            raise

    @staticmethod
    def _release_epdconfig_gpio():
        """Force-release any GPIO pins held by epdconfig.implementation.

        Called between auto-detect attempts so that a failed probe doesn't
        leave zombie gpiozero objects that block the next driver from
        claiming the same pins.
        """
        try:
            from resources.waveshare_epd import epdconfig
            impl = getattr(epdconfig, 'implementation', None)
            if impl and hasattr(impl, '_release_gpio'):
                impl._release_gpio()
            if impl and hasattr(impl, 'SPI'):
                try:
                    impl.SPI.close()
                except Exception:
                    pass
        except Exception:
            pass

    @staticmethod
    def auto_detect(known_types=None, init_timeout=_AUTO_DETECT_INIT_TIMEOUT):
        """Try each known EPD driver and return the first that initializes successfully.

        Each driver's init() is run in a thread with a timeout to avoid hanging
        on a BUSY pin that never goes LOW (which happens when the wrong driver
        is probed against real hardware).

        Uses init_full_update() instead of raw epd.init() so that drivers like
        V1/V2 that require a LUT argument are handled correctly.

        Returns:
            tuple: (epd_type_string, width, height) on success, or None if no display detected.
        """
        if known_types is None:
            known_types = KNOWN_EPD_TYPES

        for epd_type in known_types:
            helper = None
            try:
                logger.info(f"Auto-detect: trying {epd_type}...")
                helper = EPDHelper(epd_type)

                # Run init in a thread with timeout so BUSY-pin hangs don't block forever
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(helper.init_full_update)
                    try:
                        future.result(timeout=init_timeout)
                    except concurrent.futures.TimeoutError:
                        logger.debug(f"Auto-detect: {epd_type} init timed out after {init_timeout}s (BUSY pin stuck?)")
                        try:
                            helper.epd.sleep()
                        except Exception:
                            pass
                        EPDHelper._release_epdconfig_gpio()
                        time.sleep(0.3)
                        continue

                w, h = helper.epd.width, helper.epd.height
                try:
                    helper.epd.sleep()
                except Exception:
                    pass
                time.sleep(0.3)
                logger.info(f"Auto-detect: found {epd_type} ({w}x{h})")
                return (epd_type, w, h)
            except Exception as e:
                logger.debug(f"Auto-detect: {epd_type} failed: {e}")
                if helper is not None:
                    try:
                        helper.epd.sleep()
                    except Exception:
                        pass
                EPDHelper._release_epdconfig_gpio()
                time.sleep(0.3)
        logger.warning("Auto-detect: no e-paper display detected")
        return None
