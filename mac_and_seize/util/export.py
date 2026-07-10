"""Archive log files into a compressed zip on demand (e.g. on exit)."""

from __future__ import annotations

import logging
import os
import zipfile
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


def _readable_size(num_bytes: int) -> str:
    units = [" B", " KB", " MB", " GB", " TB"]
    if num_bytes <= 0:
        return "0 B"
    magnitude = (num_bytes.bit_length() - 1) // 10
    magnitude = min(magnitude, len(units) - 1)
    return f"{num_bytes >> (magnitude * 10)}{units[magnitude]}"


def archive(files: list[Path], archive_path: Path) -> Path | None:
    """Zip ``files`` into ``archive_path``. Returns the archive path or None."""
    existing = [f for f in files if f.exists() and f.is_file()]
    if not existing:
        logger.warning("No files available for archiving, skipping")
        return None

    archive_path.parent.mkdir(parents=True, exist_ok=True)
    raw_size = 0
    with zipfile.ZipFile(
        archive_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as zf:
        for file in existing:
            raw_size += os.path.getsize(file)
            zf.write(file, arcname=file.name)

    logger.info(
        "Archive created at %s (%s -> %s)",
        archive_path,
        _readable_size(raw_size),
        _readable_size(os.path.getsize(archive_path)),
    )
    return archive_path


def export_logs(
    log_directory: Path,
    export_directory: Path,
    *,
    archive_name: str | None = None,
    remove_original: bool = False,
) -> Path | None:
    """Archive every file in ``log_directory`` into ``export_directory``.

    Returns the path to the created archive, or ``None`` if there was nothing
    to archive.
    """
    log_directory = Path(log_directory)
    export_directory = Path(export_directory)
    if not log_directory.exists():
        return None

    if archive_name is None:
        archive_name = f"mac-and-seize-logs_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}"

    files = [log_directory / name for name in os.listdir(log_directory)]
    archive_path = archive(files, export_directory / f"{archive_name}.zip")

    if remove_original and archive_path is not None:
        for file in files:
            try:
                if file.is_file():
                    os.remove(file)
            except OSError as exc:
                logger.warning("Failed to remove log file %s: %s", file, exc)

    return archive_path
