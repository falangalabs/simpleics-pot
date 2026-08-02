from __future__ import annotations

import logging
import unittest

from simpleics_pot.runtime import BoundedLibraryLogFilter, MAX_PYMODBUS_LOG_CHARS


class BoundedLibraryLogFilterTests(unittest.TestCase):
    def test_truncates_only_pymodbus_records(self) -> None:
        wire_record = logging.LogRecord(
            "pymodbus.logging",
            logging.ERROR,
            __file__,
            1,
            "payload=%s",
            ("x" * 4096,),
            None,
        )
        event_record = logging.LogRecord(
            "simpleics_pot.event",
            logging.INFO,
            __file__,
            1,
            "x" * 4096,
            (),
            None,
        )
        log_filter = BoundedLibraryLogFilter()

        self.assertTrue(log_filter.filter(wire_record))
        self.assertLessEqual(
            len(wire_record.getMessage()),
            MAX_PYMODBUS_LOG_CHARS + len("...[truncated]"),
        )
        self.assertTrue(wire_record.getMessage().endswith("...[truncated]"))

        self.assertTrue(log_filter.filter(event_record))
        self.assertEqual(4096, len(event_record.getMessage()))


if __name__ == "__main__":
    unittest.main()
