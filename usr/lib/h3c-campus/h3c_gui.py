#!/usr/bin/env python3
"""GTK desktop front end; authentication stays in the existing CLI."""

import os
import shutil
import subprocess
import sys
import threading
from pathlib import Path

import gi

gi.require_version("Gtk", "3.0")
gi.require_version("Gdk", "3.0")
gi.require_version("GdkPixbuf", "2.0")
from gi.repository import Gdk, GdkPixbuf, Gio, GLib, Gtk

from h3c_campus import interfaces

AUTOSTART = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "autostart/h3c-campus.desktop"
ICON = str(Path(__file__).resolve().parents[2] / "share/pixmaps/h3c-campus.png")
TRAY_ICON = str(Path(__file__).resolve().parents[2] / "share/pixmaps/h3c-campus-tray.png")
AUTOSTART_CONTENT = """[Desktop Entry]
Type=Application
Name=H3C Campus Network
Name[zh_CN]=至诚校园网
Exec=/usr/bin/h3c-campus-gui --minimized
Terminal=false
Icon=h3c-campus
Categories=Network;
X-H3C-Campus=true
"""


class CampusWindow:
    def __init__(self, minimized=False):
        self.process = None
        self.stopping = False
        self.daily_notified = False
        self.updating_autostart = False
        self.window = Gtk.Window(title="至诚校园网")
        self.window.set_icon_from_file(ICON)
        self.window.set_default_size(560, 390)
        self.window.connect("delete-event", self.on_delete)
        self.window.connect("window-state-event", self.on_window_state)

        grid = Gtk.Grid(column_spacing=10, row_spacing=8, margin=16)
        grid.set_column_homogeneous(False)
        self.window.add(grid)

        grid.attach(Gtk.Label(label="有线网卡", xalign=0), 0, 0, 1, 1)
        self.interface = Gtk.ComboBoxText()
        devices = interfaces()
        for item in devices:
            self.interface.append_text(item["name"])
        preferred = next((i for i, item in enumerate(devices)
                          if item["physical"] and item["state"] == "up"), 0)
        if devices:
            self.interface.set_active(preferred)
        self.interface.set_hexpand(True)
        grid.attach(self.interface, 1, 0, 1, 1)

        grid.attach(Gtk.Label(label="校园网账号", xalign=0), 0, 1, 1, 1)
        self.username = Gtk.Entry()
        self.username.set_hexpand(True)
        grid.attach(self.username, 1, 1, 1, 1)

        grid.attach(Gtk.Label(label="密码", xalign=0), 0, 2, 1, 1)
        self.password = Gtk.Entry()
        self.password.set_visibility(False)
        grid.attach(self.password, 1, 2, 1, 1)

        actions = Gtk.Box(spacing=8)
        self.connect_button = Gtk.Button(label="连接")
        self.connect_button.connect("clicked", self.connect)
        actions.pack_start(self.connect_button, False, False, 0)
        self.disconnect_button = Gtk.Button(label="断开")
        self.disconnect_button.set_sensitive(False)
        self.disconnect_button.connect("clicked", self.disconnect)
        actions.pack_start(self.disconnect_button, False, False, 0)
        about_button = Gtk.Button(label="关于")
        about_button.connect("clicked", self.show_about)
        actions.pack_start(about_button, False, False, 0)
        self.status = Gtk.Label(label="未连接")
        actions.pack_end(self.status, False, False, 0)
        grid.attach(actions, 0, 3, 2, 1)

        self.autostart = Gtk.CheckButton(label="登录桌面时启动（最小化到托盘）")
        self.autostart.set_active(self.autostart_enabled())
        self.autostart.connect("toggled", self.on_autostart)
        grid.attach(self.autostart, 0, 4, 2, 1)

        self.output = Gtk.TextView(editable=False, cursor_visible=False, wrap_mode=Gtk.WrapMode.WORD)
        scroll = Gtk.ScrolledWindow()
        scroll.set_vexpand(True)
        scroll.add(self.output)
        grid.attach(scroll, 0, 5, 2, 1)

        # ponytail: GTK StatusIcon uses KDE's XEmbed bridge; use StatusNotifier
        # if support for Wayland desktops without a bridge becomes necessary.
        tray_pixbuf = GdkPixbuf.Pixbuf.new_from_file_at_scale(TRAY_ICON, 24, 24, True)
        self.tray = Gtk.StatusIcon.new_from_pixbuf(tray_pixbuf)
        self.tray.set_tooltip_text("至诚校园网")
        self.tray.set_visible(True)
        self.tray.connect("activate", lambda *_: self.show())
        self.tray.connect("popup-menu", self.show_tray_menu)
        self.window.show_all()
        self.check_daily_service()
        GLib.timeout_add_seconds(3, self.check_daily_service)
        if minimized:
            self.hide_attempts = 0
            GLib.timeout_add_seconds(1, self.hide_on_start)

    def hide_on_start(self):
        if self.tray.is_embedded():
            self.window.hide()
            return False
        self.hide_attempts += 1
        return self.hide_attempts < 5

    @staticmethod
    def autostart_enabled():
        try:
            return "X-H3C-Campus=true" in AUTOSTART.read_text(encoding="utf-8")
        except OSError:
            return False

    def on_autostart(self, button):
        if self.updating_autostart:
            return
        previous = self.autostart_enabled()
        try:
            if button.get_active():
                if AUTOSTART.exists() and not previous:
                    raise FileExistsError("已有同名自启动项，未覆盖。")
                AUTOSTART.parent.mkdir(parents=True, exist_ok=True)
                AUTOSTART.write_text(AUTOSTART_CONTENT, encoding="utf-8")
            elif previous:
                AUTOSTART.unlink()
        except OSError as exc:
            self.updating_autostart = True
            button.set_active(previous)
            self.updating_autostart = False
            self.error(str(exc))

    def error(self, message):
        dialog = Gtk.MessageDialog(transient_for=self.window, modal=True,
                                   message_type=Gtk.MessageType.ERROR,
                                   buttons=Gtk.ButtonsType.CLOSE, text=message)
        dialog.run()
        dialog.destroy()

    def daily_service_active(self):
        try:
            return subprocess.run(["systemctl", "is-active", "--quiet", "h3c-campus-daily.service"],
                                  timeout=2).returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False

    def notify_connected(self):
        try:
            bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
            bus.call("org.freedesktop.Notifications", "/org/freedesktop/Notifications",
                     "org.freedesktop.Notifications", "Notify",
                     GLib.Variant("(susssasa{sv}i)",
                                  ("H3C Campus", 0, "h3c-campus", "至诚校园网",
                                   "校园网认证成功", [], {}, 5000)),
                     None, Gio.DBusCallFlags.NONE, 2000, None, None)
        except GLib.Error:
            pass

    def check_daily_service(self):
        if self.process is None:
            active = self.daily_service_active()
            self.connect_button.set_sensitive(not active)
            self.disconnect_button.set_sensitive(active)
            if active:
                self.status.set_text("定时服务运行中")
                if not self.daily_notified:
                    self.notify_connected()
                    self.daily_notified = True
            elif self.status.get_text() == "定时服务运行中":
                self.status.set_text("未连接")
            if not active:
                self.daily_notified = False
        return True

    def connect(self, *_):
        interface = self.interface.get_active_text()
        username = self.username.get_text().strip()
        password = self.password.get_text()
        if not interface or not username or not password:
            self.error("请选择有线网卡并填写账号、密码。")
            return
        helper = next((path for name in ("run0", "pkexec")
                       if (path := shutil.which(name))), None)
        if os.geteuid() != 0 and helper is None:
            self.error("请安装 run0 或 pkexec 以授权原始网卡访问。")
            return
        command = ([helper] if os.geteuid() != 0 else []) + [
            "/usr/bin/h3c-campus", "--interface", interface, "--username", username,
            "--password-stdin", "--renew-dhcp"]
        try:
            self.process = subprocess.Popen(command, stdin=subprocess.PIPE,
                                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                            text=True, bufsize=1)
            self.process.stdin.write(password + "\n")
            self.process.stdin.close()
        except (OSError, BrokenPipeError) as exc:
            if self.process is not None:
                self.process.terminate()
                self.process = None
            self.error(str(exc))
            return
        finally:
            self.password.set_text("")
            del password
        self.stopping = False
        self.status.set_text("认证中")
        self.connect_button.set_sensitive(False)
        self.disconnect_button.set_sensitive(True)
        threading.Thread(target=self.read_output, args=(self.process,), daemon=True).start()

    def read_output(self, process):
        for line in process.stdout:
            GLib.idle_add(self.show_line, line.rstrip())
        GLib.idle_add(self.finished, process, process.wait())

    def show_line(self, line):
        buffer = self.output.get_buffer()
        buffer.insert(buffer.get_end_iter(), line + "\n")
        self.output.scroll_to_iter(buffer.get_end_iter(), 0, False, 0, 0)
        parts = line.split(maxsplit=3)
        event = parts[2] if len(parts) >= 3 else ""
        if event == "AUTH_SUCCESS":
            self.status.set_text("认证成功，等待 IPv4")
        elif event == "IPV4_PRESENT":
            self.status.set_text("已连接")
            self.notify_connected()
        elif event in {"AUTH_REJECTED", "AUTH_TIMEOUT", "NO_EAPOL_REPLY", "ERROR"}:
            self.status.set_text("连接失败")
        return False

    def finished(self, process, code):
        if process is self.process:
            self.process = None
            self.connect_button.set_sensitive(True)
            self.disconnect_button.set_sensitive(False)
            self.status.set_text("已断开" if self.stopping else f"已退出（{code}）")
        return False

    def disconnect(self, *_):
        if self.process is not None and self.process.poll() is None:
            self.stopping = True
            self.status.set_text("正在断开")
            self.process.terminate()
        elif self.daily_service_active():
            helper = next((path for name in ("run0", "pkexec")
                           if (path := shutil.which(name))), None)
            if os.geteuid() != 0 and helper is None:
                self.error("请安装 run0 或 pkexec 以断开定时服务。")
                return
            subprocess.Popen(([helper] if os.geteuid() != 0 else []) +
                             ["systemctl", "stop", "h3c-campus-daily.service"])
            self.status.set_text("正在断开")

    def on_window_state(self, _window, event):
        if event.new_window_state & Gdk.WindowState.ICONIFIED and self.tray.is_embedded():
            GLib.idle_add(self.window.hide)
        return False

    def on_delete(self, *_):
        if self.tray.is_embedded():
            self.window.hide()
        else:
            self.quit()
        return True

    def show(self):
        self.window.deiconify()
        self.window.present()

    def show_about(self, *_):
        dialog = Gtk.AboutDialog(transient_for=self.window, modal=True)
        dialog.set_program_name("H3C Campus Network")
        dialog.set_version("0.2.5")
        dialog.set_comments("非官方软件；无担保。源码可依 AGPL-3.0 再分发。")
        dialog.set_license_type(Gtk.License.AGPL_3_0)
        dialog.set_website("https://github.com/zybin7890/h3c-campus")
        dialog.run()
        dialog.destroy()

    def show_tray_menu(self, _icon, button, time):
        menu = Gtk.Menu()
        for label, action in (("显示", self.show), ("断开", self.disconnect),
                              ("关于", self.show_about), ("退出", self.quit)):
            item = Gtk.MenuItem(label=label)
            item.connect("activate", lambda _item, callback=action: callback())
            menu.append(item)
        menu.show_all()
        menu.popup(None, None, Gtk.StatusIcon.position_menu, self.tray, button, time)

    def quit(self):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
        self.tray.set_visible(False)
        Gtk.main_quit()


def main():
    window = CampusWindow(minimized="--minimized" in sys.argv[1:])
    window.username.grab_focus()
    Gtk.main()


if __name__ == "__main__":
    main()
