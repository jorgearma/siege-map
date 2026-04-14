import asyncio
import logging
import os
from pathlib import Path
from typing import AsyncGenerator

logger = logging.getLogger(__name__)


async def tail_log(path: str) -> AsyncGenerator[str, None]:
    """
    Async generator that yields new lines from a log file.
    Uses tail -F which follows the file by name (handles log rotation).
    Falls back to polling if tail is not available.
    """
    log_path = Path(path)

    if not log_path.exists():
        logger.error(f"Log file not found: {path}")
        logger.info("Waiting for log file to appear...")
        while not log_path.exists():
            await asyncio.sleep(5)
        logger.info(f"Log file found: {path}")

    # Check if we can read the file
    if not os.access(path, os.R_OK):
        logger.error(f"Cannot read log file: {path} (permission denied)")
        logger.info("Make sure the container has read access to the log file")
        return

    logger.info(f"Starting tail on {path}")

    while True:
        try:
            proc = await asyncio.create_subprocess_exec(
                "tail", "-F", "-n", "0", path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )

            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                yield line.decode("utf-8", errors="replace")

        except Exception as e:
            logger.error(f"tail error: {e}")

        logger.info("tail process ended, restarting in 2s...")
        await asyncio.sleep(2)
