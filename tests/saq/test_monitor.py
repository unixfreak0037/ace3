from io import StringIO
import pytest
import re

from saq.monitor import MonitorEmitter, emit_monitor, enable_monitor_cache, enable_monitor_logging, enable_monitor_stderr, enable_monitor_stdout, get_emitter
from saq.monitor_definitions import MONITOR_TEST
from tests.saq.helpers import log_count

LOG_TEST = "log test"
LOG_TEST_2 = "log test 2"

@pytest.mark.unit
def test_get_emitter():
    assert isinstance(get_emitter(), MonitorEmitter)

@pytest.mark.unit
def test_emit_monitor_logging():
    emit_monitor(MONITOR_TEST, LOG_TEST)
    assert log_count(LOG_TEST) == 0
    enable_monitor_logging()
    emit_monitor(MONITOR_TEST, LOG_TEST)
    assert log_count(LOG_TEST) == 1

@pytest.mark.unit
def test_emit_monitor_logging_with_identifier():
    emit_monitor(MONITOR_TEST, LOG_TEST, "id")
    assert log_count(LOG_TEST) == 0
    enable_monitor_logging()
    emit_monitor(MONITOR_TEST, LOG_TEST, "id")
    assert log_count(LOG_TEST) == 1

@pytest.mark.unit
def test_emit_monitor_stdout(capsys):
    emit_monitor(MONITOR_TEST, LOG_TEST)
    captured = capsys.readouterr()
    assert LOG_TEST not in captured.out
    enable_monitor_stdout()
    emit_monitor(MONITOR_TEST, LOG_TEST)
    captured = capsys.readouterr()
    assert LOG_TEST in captured.out

@pytest.mark.unit
def test_emit_monitor_stderr(capsys):
    emit_monitor(MONITOR_TEST, LOG_TEST)
    captured = capsys.readouterr()
    assert LOG_TEST not in captured.err
    enable_monitor_stderr()
    emit_monitor(MONITOR_TEST, LOG_TEST)
    captured = capsys.readouterr()
    assert LOG_TEST in captured.err

@pytest.mark.unit
def test_emit_monitor_cache():
    emit_monitor(MONITOR_TEST, LOG_TEST)
    assert not get_emitter().cache
    enable_monitor_cache()
    emit_monitor(MONITOR_TEST, LOG_TEST)
    assert get_emitter().cache
    cache_entry = get_emitter().cache[MONITOR_TEST.category][MONITOR_TEST.name]
    assert cache_entry.value == LOG_TEST
    assert not cache_entry.identifier

    # emit the same message and get a different cache entry
    emit_monitor(MONITOR_TEST, LOG_TEST)
    new_cache_entry= get_emitter().cache[MONITOR_TEST.category][MONITOR_TEST.name]
    assert not (cache_entry is new_cache_entry)
    assert cache_entry.value == LOG_TEST
    assert not cache_entry.identifier
    cache_entry = new_cache_entry

    # emit a new message and get a new cache entry with a different value
    emit_monitor(MONITOR_TEST, LOG_TEST_2)
    new_cache_entry= get_emitter().cache[MONITOR_TEST.category][MONITOR_TEST.name]
    assert not (cache_entry is new_cache_entry)
    assert new_cache_entry.value == LOG_TEST_2
    assert not new_cache_entry.identifier

    # dump the cache
    _buffer = StringIO()
    get_emitter().dump_cache(_buffer)
    # [test] (test): log test 2 @ 2025-04-09 12:43:11.524041
    assert re.match(r"^\[test\] \(test\): log test 2 @ [0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}$", _buffer.getvalue().strip())

    # emit a new message with an identifier
    emit_monitor(MONITOR_TEST, LOG_TEST, "id")
    new_cache_entry= get_emitter().cache[MONITOR_TEST.category][MONITOR_TEST.name]
    assert not (cache_entry is new_cache_entry)
    assert new_cache_entry.value == LOG_TEST
    assert new_cache_entry.identifier == "id"

    # dump the cache
    _buffer = StringIO()
    get_emitter().dump_cache(_buffer)
    # [test] (test): log test 2 @ 2025-04-09 12:43:11.524041
    assert re.match(r"^\[test\] \(test:id\): log test @ [0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}$", _buffer.getvalue().strip())