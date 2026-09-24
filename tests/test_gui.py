"""Guard password passing and autostart ownership."""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "usr/lib/h3c-campus"))
import h3c_gui


class GuiTest(unittest.TestCase):
    def setUp(self):
        self.devices = patch("h3c_gui.interfaces", return_value=[
            {"name": "eth0", "physical": True, "state": "up"}
        ])
        self.devices.start()
        self.window = h3c_gui.CampusWindow()

    def tearDown(self):
        self.window.tray.set_visible(False)
        self.window.window.destroy()
        self.devices.stop()

    def test_password_uses_stdin_only(self):
        with patch("h3c_gui.shutil.which", return_value="/usr/bin/run0"), \
                patch("h3c_gui.subprocess.Popen") as popen, \
                patch("h3c_gui.threading.Thread"):
            process = Mock()
            popen.return_value = process
            self.window.username.set_text("student@example")
            self.window.password.set_text("sample-secret")
            self.window.connect()
            self.assertNotIn("sample-secret", popen.call_args.args[0])
            self.assertIn("--password-stdin", popen.call_args.args[0])
            process.stdin.write.assert_called_once_with("sample-secret\n")
            self.assertEqual(self.window.password.get_text(), "")

    def test_autostart_only_removes_its_own_file(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(h3c_gui, "AUTOSTART", Path(directory) / "autostart.desktop"):
            self.window.autostart.set_active(False)
            self.window.autostart.set_active(True)
            self.assertTrue(h3c_gui.CampusWindow.autostart_enabled())
            self.window.autostart.set_active(False)
            self.assertFalse(h3c_gui.AUTOSTART.exists())

    def test_daily_service_disables_manual_login(self):
        with patch.object(self.window, "daily_service_active", return_value=True):
            self.window.check_daily_service()
        self.assertFalse(self.window.connect_button.get_sensitive())
        self.assertTrue(self.window.disconnect_button.get_sensitive())
        self.assertEqual(self.window.status.get_text(), "定时服务运行中")


if __name__ == "__main__":
    unittest.main()
