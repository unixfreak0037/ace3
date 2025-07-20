import logging
import os
import subprocess

import saq

from saq.analysis import Observable
from saq.database import release_lock
from saq.gui import GUIAlert


def rsync(alert: GUIAlert, remote_host: str, remote_path: str, file_observable: Observable = None, lock_uuid: str = None):
    """
    Uses rsync to copy an entire alert or a single file inside of an alert to the remote_path on the remote_host.

    Args:
        alert: The alert that will be copied (or that contains the file that will be copied)
        file_observable: (Optional) The file observable inside of the given alert that will be copied. If this is not
            specified, then the entire alert will be copied
        lock_uuid: (Optional) The lock UUID obtained on the given alert. If provided, it will be released when the
            rsync command finishes. This is optional since in some cases the caller will release the lock itself.
        remote_host: Hostname/IP of the remote host to receive the file or directory
        remote_path: Path on the remote host where the file or directory should be copied

    Raises:
        CalledProcessError: If the rsync command has a non-zero exit code
    """

    alert_path = os.path.join(saq.SAQ_HOME, alert.storage_dir)
    if not os.path.exists(alert_path):
        raise FileNotFoundError(f"{alert_path} does not exist")

    if file_observable:
        file_path = os.path.join(alert_path, file_observable.value)
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"{file_path} does not exist")

        logging.info(f"attempting to send file {file_path} to {remote_host}:{remote_path}")
    else:
        logging.info(f"attempting to send alert {alert_path} to {remote_host}:{remote_path}")

    try:
        args = [
            "rsync",
            "--archive",
            "--prune-empty-dirs",
            "--compress",

            # The --rsync-path option can be (ab)used to ensure the remote directory is created prior to rsync running.
            f"--rsync-path=mkdir -p {remote_path} && rsync",

            # These include/exclude options are added if a file_observable was specified. This makes rsync only copy the
            # given file instead of everything in the alert.
            "--include=*/" if file_observable else "",
            f"--include={file_observable.value}" if file_observable else "",
            "--exclude=*" if file_observable else "",
            
            alert_path,
            f"{remote_host}:{remote_path}",
        ]

        # If a file observable was not given, there will be 3 sets of "" in the args that need to be removed, or else
        # they will mess up the rsync command and will transfer the entire current directory instead of the alert.
        args = [a for a in args if a]

        _ = subprocess.run(
            args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
    except:
        raise
    finally:
        if lock_uuid:
            release_lock(alert.uuid, lock_uuid)
