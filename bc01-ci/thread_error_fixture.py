"""Real ordinary-thread body for baseline/corrected recorder controls only."""

import os
import threading
import unittest


class OrdinaryThreadProbe(unittest.TestCase):
    def test_joined_ordinary_thread(self):
        fault = os.environ.get("FR13_THREAD_CONTROL_FAULT") == "1"
        seen = []

        def work():
            seen.append("started")
            if fault:
                raise RuntimeError("release unlocked lock")
            seen.append("finished")

        thread = threading.Thread(target=work, name="ordinary-thread-error-control")
        thread.start()
        thread.join(5)
        self.assertFalse(thread.is_alive(), "This control owns and joins its actual thread")
        self.assertEqual(seen, ["started"] if fault else ["started", "finished"])
