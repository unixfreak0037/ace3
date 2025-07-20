##############################################################################
#
# I/O tracking
# this is used with unit testing
#

# if this is True then bytes_written and write_count get updated
import atexit
import sys


_track_io = False

_io_tracker_manager = None
_io_tracker_sync = None

# total number of write counts
_write_count = None
# total number fo reads
_read_count = None

def _enable_io_tracker():
    if _track_io:
        return

    _start_io_tracker()

def _disable_io_tracker():
    if not _track_io:
        return

    _stop_io_tracker()

def _start_io_tracker():
    import multiprocessing

    global _track_io
    global _io_tracker_manager
    global _io_tracker_sync
    global _write_count
    global _read_count

    _io_tracker_manager = multiprocessing.Manager()
    _io_tracker_sync = multiprocessing.RLock()
    _write_count = _io_tracker_manager.Value('I', 0, lock=False)
    _read_count = _io_tracker_manager.Value('I', 0, lock=False)
    _track_io = True

def _stop_io_tracker():
    global _track_io
    global _io_tracker_manager
    global _io_tracker_sync
    global _write_count
    global _read_count

    if _track_io:
        try:
            _io_tracker_manager.shutdown()
        except Exception as e:
            sys.stderr.write("\n\nunable to shut down io tracker manager: {}\n\n".format(e))

        _io_tracker_manager = None
        _io_tracker_sync = None
        _write_count = None
        _read_count = None
        _track_io = False

atexit.register(_stop_io_tracker)

def _track_writes():
    if not _track_io:
        return

    with _io_tracker_sync:
        _write_count.value += 1

    #sys.stderr.write('\n')
    #sys.stderr.write('#' * 79 + '\n')
    #import traceback
    #traceback.print_stack()
    #sys.stderr.write('\n')

def _get_io_write_count():
    with _io_tracker_sync:
        return _write_count.value

def _track_reads():
    if not _track_io:
        return

    with _io_tracker_sync:
        _read_count.value += 1

def _get_io_read_count():
    with _io_tracker_sync:
        return _read_count.value

#
# end I/O tracking
# 
##############################################################################