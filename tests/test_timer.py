from pathlib import Path
import unittest


class TimerTest(unittest.TestCase):
    def test_daily_timer_restarts_running_client(self):
        units = Path(__file__).resolve().parents[1] / 'usr/lib/systemd/system'
        self.assertIn('Unit=h3c-campus-daily-refresh.service',
                      (units / 'h3c-campus-daily.timer').read_text())
        self.assertIn('ExecStart=/usr/bin/systemctl restart h3c-campus-daily.service',
                      (units / 'h3c-campus-daily-refresh.service').read_text())


if __name__ == '__main__':
    unittest.main()
