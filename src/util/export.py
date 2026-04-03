from pathlib import Path
import zipfile
from src.util.config import get_config, get_timer
from src.util.logging import LogMessage, TerminalMessage
import os
from datetime import datetime

config = get_config()
timer = get_timer()

# Set up export directory
config.setup.export_directory.mkdir(parents = True, exist_ok = True)

readable_size = lambda v : str(v >> ((max(v.bit_length()-1, 0)//10)*10)) +[" B", " KB", " MB", " GB", " TB"][max(v.bit_length()-1, 0)//10]
    
def archive(files: list[Path], archive_name: str = config.logging.filename) -> Path | None:
    if not files or len(files) == 0:
        LogMessage("No files provided for archiving, skipping", level = "WARNING")
        return None
    archive_path = config.setup.export_directory / Path(f"{archive_name}.zip")

    start_time = timer.start_measure()
    with zipfile.ZipFile(archive_path, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        raw_size = 0
        for i, file in enumerate(files, start=1):
            if not file.exists():
                LogMessage(f"File {file} does not exist, skipping", level = "WARNING")
                TerminalMessage(f"File {file} was selected but does not exist and will not be included in the archive", padding_char=" ", color = "yellow")
                continue
            if file.name == config.logging.filename:
                new_log_file = config.logging.directory / Path(datetime.now().strftime("%Y-%m-%d_%H:%M:%S.log"))
                LogMessage(f"About to archive active log file - app is still running despite this being penultimate log entry. Further logs will be saved to a new file: {new_log_file} (not included in this archive)", level = "WARNING")
                config.logging.filename = new_log_file.name
                (config.logging.directory / config.logging.filename).touch(exist_ok = True)
            size = os.path.getsize(file)
            raw_size += size
            TerminalMessage(f"Adding file {file.name} ({readable_size(size)}) to archive ({i}/{len(files)})", padding_char=" ", end="\r")
            zf.write(file, arcname=file.name)
    LogMessage(f"Archive created at {archive_path} in {timer.runtime(reference = start_time)}s (original: {readable_size(raw_size)} > deflated: {readable_size(os.path.getsize(archive_path))})\nIncluded files: {', '.join([str(file) for file in files if file.exists()])}")
    TerminalMessage(f"Archive created at {archive_path} ({readable_size(raw_size)} > {readable_size(os.path.getsize(archive_path))})", padding_char=" ", color = "green")
    return archive_path

def export_logs(remove_original = False) -> Path | None:
    files = [config.logging.directory / file for file in os.listdir(config.logging.directory)]
    archive_path = archive(files, archive_name = f"mac-and-seize-logs_{datetime.now().strftime('%Y-%m-%d_%H:%M:%S')}")
    if remove_original and archive_path is not None:
        for file in files:
            try:
                os.remove(file)
            except Exception as e:
                LogMessage(f"Failed to remove log file {file} after archiving: {e}", level = "WARNING")
                TerminalMessage(f"Failed to remove log file {file.name} after archiving", color = "yellow")
    return archive_path