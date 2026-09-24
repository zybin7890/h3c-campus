"""Guard password passing and autostart ownership."""

import sys
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "usr/lib/h3c-campus"))
import h3c_gui
import h3c_campus


class GuiTest(unittest.TestCase):
    def setUp(self):
        self.devices = patch("h3c_gui.interfaces", return_value=[
            {"name": "eth0", "physical": True, "state": "up"}
        ])
        self.devices.start()
        self.notifications = patch.object(h3c_gui.CampusWindow, "notify_connected")
        self.notifications.start()
        self.window = h3c_gui.CampusWindow()
        self.window.notify_connected.reset_mock()

    def tearDown(self):
        self.window.tray.set_visible(False)
        self.window.window.destroy()
        self.devices.stop()
        self.notifications.stop()

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

    def test_manual_success_notifies(self):
        self.window.show_line("2026-09-24 12:27:34 IPV4_PRESENT 10.38.0.17")
        self.window.notify_connected.assert_called_once()

    def test_systemd_ready_only_after_auth_success(self):
        with patch.dict(os.environ, {"NOTIFY_SOCKET": "@test"}), \
                patch("h3c_campus.socket.socket") as sock, \
                patch("builtins.print"):
            h3c_campus.log("AUTH_REJECTED")
            sock.assert_not_called()
            h3c_campus.log("AUTH_SUCCESS")
            sock.return_value.__enter__.return_value.sendto.assert_called_once_with(
                b"READY=1", "\0test")


if __name__ == "__main__":
    unittest.main()
