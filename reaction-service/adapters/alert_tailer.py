"""Yield new Snort alerts while following log rotation."""

import os
import time
import logging

logger = logging.getLogger(__name__)


class AlertTailer:
    def __init__(self, path: str, poll_interval: float = 0.5):
        self._path = path
        self._poll_interval = poll_interval

    def tail(self):
        """Yield alert lines added after startup."""
        fh = None
        position = None

        while True:
            try:
                if fh is None:
                    if not os.path.exists(self._path):
                        logger.debug("Waiting for %s to appear...", self._path)
                        time.sleep(self._poll_interval)
                        continue

                    fh = open(self._path, "r")
                    # Ignore alerts present at startup.
                    fh.seek(0, 2)
                    position = fh.tell()
                    logger.info("Tailing %s from position %d", self._path, position)

                line = fh.readline()

                if line:
                    yield line.strip()
                else:
                    # Reopen after truncation or removal.
                    try:
                        current_size = os.path.getsize(self._path)
                    except FileNotFoundError:
                        current_size = 0

                    if current_size < position:
                        logger.info("Log rotation detected, reopening %s", self._path)
                        fh.close()
                        fh = None
                        position = None
                    else:
                        position = fh.tell()
                        time.sleep(self._poll_interval)

            except OSError as exc:
                logger.warning("File error (%s), retrying: %s", self._path, exc)
                if fh:
                    fh.close()
                    fh = None
                time.sleep(self._poll_interval)
