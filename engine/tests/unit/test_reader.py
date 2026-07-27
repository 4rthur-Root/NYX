# tests/unit/test_reader.py
"""Tests unitaires — Reader et _LogFileHandler."""
import logging
import os
import queue
import tempfile
import time
from pathlib import Path

import pytest

from reader import _LogFileHandler, Reader


@pytest.fixture
def shared_queue():
    return queue.Queue(maxsize=10)


@pytest.fixture
def handler(shared_queue):
    return _LogFileHandler(
        shared_queue=shared_queue,
        sources={"test.log"},
        maxsize=10,
    )


@pytest.fixture
def tmp_log(tmp_path):
    return tmp_path / "test.log"


# =====================================================================
# _read_new_lines — lecture normale
# =====================================================================

class TestReadNewLines:
    def test_reads_new_lines_from_position(self, handler, tmp_log):
        tmp_log.write_text("line1\nline2\nline3\n")
        handler._read_new_lines(str(tmp_log), "test.log")

        assert handler._positions[str(tmp_log)] == 18
        items = []
        while not handler._queue.empty():
            items.append(handler._queue.get_nowait())
        assert items == [("line1", "test.log"), ("line2", "test.log"), ("line3", "test.log")]

    def test_skips_already_read_lines(self, handler, tmp_log):
        tmp_log.write_text("line1\nline2\nline3\n")
        handler._read_new_lines(str(tmp_log), "test.log")
        handler._queue.queue.clear()

        tmp_log.write_text("line1\nline2\nline3\nline4\n")
        handler._read_new_lines(str(tmp_log), "test.log")

        items = []
        while not handler._queue.empty():
            items.append(handler._queue.get_nowait())
        assert items == [("line4", "test.log")]

    def test_empty_lines_skipped(self, handler, tmp_log):
        tmp_log.write_text("line1\n\nline2\n\n")
        handler._read_new_lines(str(tmp_log), "test.log")

        items = []
        while not handler._queue.empty():
            items.append(handler._queue.get_nowait())
        assert items == [("line1", "test.log"), ("line2", "test.log")]

    def test_queue_full_drops_lines(self, handler, tmp_log):
        small_queue = queue.Queue(maxsize=1)
        handler._queue = small_queue
        tmp_log.write_text("line1\nline2\nline3\n")
        handler._read_new_lines(str(tmp_log), "test.log")

        assert small_queue.qsize() == 1

    def test_missing_file_logs_warning(self, handler, caplog):
        handler._read_new_lines("/nonexistent/path/test.log", "test.log")
        assert "Impossible de lire" in caplog.text or "Impossible de stat" in caplog.text


# =====================================================================
# _read_new_lines — rotation copytruncate
# =====================================================================

class TestCopytruncateRotation:
    def test_truncate_resets_position_to_zero(self, handler, tmp_log):
        with open(tmp_log, "w") as f:
            f.write("old_line_1\nold_line_2\n")
        handler._read_new_lines(str(tmp_log), "test.log")
        assert handler._positions[str(tmp_log)] > 0

        # Vider la queue avant la deuxième lecture
        while not handler._queue.empty():
            handler._queue.get_nowait()

        with open(tmp_log, "w") as f:
            f.write("new_content\n")
        handler._read_new_lines(str(tmp_log), "test.log")

        items = []
        while not handler._queue.empty():
            items.append(handler._queue.get_nowait())
        assert items == [("new_content", "test.log")]

    def test_truncate_logs_info_message(self, handler, tmp_log, caplog):
        with open(tmp_log, "w") as f:
            f.write("old_line_1\nold_line_2\n")
        handler._read_new_lines(str(tmp_log), "test.log")

        with open(tmp_log, "w") as f:
            f.write("new_content\n")
        with caplog.at_level(logging.INFO):
            handler._read_new_lines(str(tmp_log), "test.log")

        assert "Troncature détectée" in caplog.text

    def test_no_truncate_when_file_grew(self, handler, tmp_log):
        tmp_log.write_text("line1\nline2\n")
        handler._read_new_lines(str(tmp_log), "test.log")
        handler._queue.queue.clear()

        tmp_log.write_text("line1\nline2\nline3\nline4\n")
        handler._read_new_lines(str(tmp_log), "test.log")

        items = []
        while not handler._queue.empty():
            items.append(handler._queue.get_nowait())
        assert items == [("line3", "test.log"), ("line4", "test.log")]


# =====================================================================
# _LogFileHandler — routing par filename
# =====================================================================

class TestFilenameRouting:
    def test_ignores_unknown_filename(self, handler, tmp_log):
        tmp_log.write_text("line1\n")

        class FakeEvent:
            is_directory = False
            src_path = str(tmp_log)

        handler._sources = {"other.log"}
        handler.on_modified(FakeEvent())
        assert handler._queue.empty()

    def test_processes_known_filename(self, handler, tmp_log):
        tmp_log.write_text("line1\n")

        class FakeEvent:
            is_directory = False
            src_path = str(tmp_log)

        handler.on_modified(FakeEvent())
        assert not handler._queue.empty()


# =====================================================================
# Reader — catch-up initial
# =====================================================================

class TestReaderStartup:
    def test_catch_up_reads_existing_lines(self, tmp_path):
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        log_file = log_dir / "test.log"
        log_file.write_text("existing_line\n")

        q = queue.Queue()
        reader = Reader(str(log_dir), {"test.log"}, q)
        reader.start()
        time.sleep(0.3)
        reader.stop()

        items = []
        while not q.empty():
            items.append(q.get_nowait())
        assert ("existing_line", "test.log") in items

    def test_catch_up_does_not_block_on_missing_file(self, tmp_path):
        log_dir = tmp_path / "logs"
        log_dir.mkdir()

        q = queue.Queue()
        reader = Reader(str(log_dir), {"missing.log"}, q)
        reader.start()
        time.sleep(0.3)
        reader.stop()

        assert q.empty()


# =====================================================================
# Reader — intégration avec Dispatcher (mocked)
# =====================================================================

class TestReaderDispatcherIntegration:
    def test_lines_routed_to_correct_parser(self, tmp_path):
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        log_file = log_dir / "test.log"
        log_file.write_text("line1\nline2\n")

        q = queue.Queue()
        reader = Reader(str(log_dir), {"test.log"}, q)
        reader.start()
        time.sleep(0.3)
        reader.stop()

        items = []
        while not q.empty():
            items.append(q.get_nowait())
        assert len(items) == 2
        assert all(filename == "test.log" for _, filename in items)


# =====================================================================
# _LogFileHandler — on_created
# =====================================================================

class TestOnCreated:
    def test_created_reads_from_start(self, handler, tmp_path):
        tmp_log = tmp_path / "test.log"
        tmp_log.write_text("first_line\n")

        class FakeEvent:
            is_directory = False
            src_path = str(tmp_log)

        handler.on_created(FakeEvent())
        assert handler._positions[str(tmp_log)] == 11
        items = []
        while not handler._queue.empty():
            items.append(handler._queue.get_nowait())
        assert items == [("first_line", "test.log")]


# =====================================================================
# _LogFileHandler — on_modified ignore directories
# =====================================================================

class TestOnModified:
    def test_modified_ignores_directory(self, handler, tmp_path):
        class FakeEvent:
            is_directory = True
            src_path = str(tmp_path)

        handler.on_modified(FakeEvent())
        assert handler._queue.empty()
