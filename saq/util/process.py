import os
import signal

import psutil


def kill_process_tree(pid, sig=signal.SIGTERM, include_parent=True,
                      timeout=None, on_terminate=None):
    """Kill a process tree (including grandchildren) with signal
    "sig" and return a (gone, still_alive) tuple.
    "on_terminate", if specified, is a callabck function which is
    called as soon as a child terminates.
    """

    if pid == os.getpid():
        raise RuntimeError("I refuse to kill myself")

    parent = psutil.Process(pid)
    children = parent.children(recursive=True)
    if include_parent:
        children.append(parent)

    for p in children:
        p.send_signal(sig)

    gone, alive = psutil.wait_procs(children, timeout=timeout,
                                    callback=on_terminate)
    return (gone, alive)