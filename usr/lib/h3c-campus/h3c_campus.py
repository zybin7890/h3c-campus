#!/usr/bin/env python3
"""Linux wired H3C EAP-MD5 client. No passwords are stored or logged."""
from __future__ import annotations

import argparse
import getpass
import ipaddress
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import time

from h3c_protocol import (identity_data, make_frame, make_response,
                          md5_data, parse_frame)

CLIENT_VERSION = '0.2.7'
# Decoded from a successful E0645 Identity frame; this is a version descriptor,
# not a captured authentication response, account, or password.
SITE_VERSION = bytes.fromhex('43481156372e33302d30363435000000')
BROADCAST = b'\xff' * 6
PAE_GROUP = bytes.fromhex('0180c2000003')


def log(event: str, message: str = '') -> None:
    print(time.strftime('%Y-%m-%d %H:%M:%S'), event, message, flush=True)
    if event == 'AUTH_SUCCESS' and (address := os.environ.get('NOTIFY_SOCKET')):
        if address.startswith('@'):
            address = '\0' + address[1:]
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notifier:
                notifier.sendto(b'READY=1', address)
        except OSError:
            pass


class RecoveryBudget:
    """Never retry an initially rejected credential; bound recovery after login."""
    def __init__(self):
        self.had_online_session = False
        self.attempts = 0

    def authenticated(self):
        self.had_online_session = True
        self.attempts = 0

    def retry(self):
        if not self.had_online_session or self.attempts >= 3:
            return False
        self.attempts += 1
        return True


class Session:
    """Protocol state independent of sockets, clocks and DHCP management."""
    def __init__(self, mac: bytes, username: bytes, password: bytes,
                 version: bytes = SITE_VERSION, emit=log):
        if len(mac) != 6 or len(version) != 16:
            raise ValueError('Invalid MAC or client version length')
        if not username or len(username) > 253 or b'\x00' in username:
            raise ValueError('Username must contain 1..253 bytes without NUL')
        if not password or len(password) > 1024:
            raise ValueError('Password must contain 1..1024 bytes')
        self.mac, self.username, self.password = mac, username, password
        self.version, self.emit = version, emit
        self.reset()

    def reset(self):
        self.peer = None
        self.state = 'starting'
        self.request_id = None
        self.cached_request = None
        self.cached_response = None
        self.vendor_seen = False
        self.secure_heartbeat_unsupported = False

    def start(self, destination=BROADCAST):
        return make_frame(self.mac, destination, 1)

    def logoff(self):
        return make_frame(self.mac, self.peer or BROADCAST, 2)

    def process(self, packet: dict, ipv4: bytes = b'\x00' * 4) -> bytes | None:
        if (packet['eapol_type'] != 0 or packet['src'] == self.mac or
                packet['dst'] not in (self.mac, BROADCAST, PAE_GROUP)):
            return None
        if self.peer is not None and packet['src'] != self.peer:
            return None
        code, ident = packet['eap_code'], packet['eap_id']
        if code == 1:
            method, data = packet['eap_type'], packet['eap_data']
            key = (packet['src'], ident, method, data)
            if key == self.cached_request:
                return self.cached_response
            # Validate all method-specific input before updating the state.
            if method == 1:
                reply_type = 1
                reply_data = identity_data(self.username, self.version)
                event = 'IDENTITY_REQUEST'
            elif method == 4:
                if not data or not 1 <= data[0] <= 255 or len(data) < 1 + data[0]:
                    self.emit('MALFORMED_MD5', 'Ignored truncated challenge')
                    return None
                reply_type = 4
                reply_data = md5_data(ident, self.password, data[1:1+data[0]], self.username)
                event = 'MD5_CHALLENGE'
            elif method == 2:
                reply_type, reply_data, event = 2, b'', 'EAP_NOTIFICATION'
            elif method == 20:
                # H3C AVAILABLE request. The IPv4 extension is requested here,
                # while this site's ordinary Identity carries no IPv4 field.
                if len(ipv4) != 4:
                    raise ValueError('IPv4 must have four bytes')
                reply_type = 20
                reply_data = b'\x00\x15\x04' + ipv4 + identity_data(self.username, self.version)
                event = 'H3C_AVAILABLE_REQUEST'
            else:
                reply_type, reply_data, event = 3, b'\x04', 'UNSUPPORTED_EAP_METHOD'
            self.peer = packet['src']
            self.request_id = ident
            if method in (1, 4, 20):
                self.state = 'authenticating'
            response = make_frame(self.mac, self.peer, 0,
                                  make_response(ident, reply_type, reply_data),
                                  version=packet['version'])
            self.cached_request, self.cached_response = key, response
            self.emit(event, f'id={ident}, method={method}')
            return response
        if self.peer is None:
            return None
        if code in (3, 4) and ident == self.request_id:
            new_state = 'online' if code == 3 else 'failed'
            if self.state != new_state:
                self.state = new_state
                self.emit('AUTH_SUCCESS' if code == 3 else 'AUTH_REJECTED',
                          '802.1X accepted; IP connectivity is checked separately.'
                          if code == 3 else 'Server rejected this authentication attempt.')
        elif code == 10:
            if packet['eap_data'].startswith(bytes.fromhex('192b442b32')):
                self.secure_heartbeat_unsupported = True
                self.emit('UNSUPPORTED_SECURE_HEARTBEAT',
                          'This legacy private handshake needs a separate implementation.')
            elif not self.vendor_seen:
                self.emit('VENDOR_NOTICE', 'Received H3C server notification; payload omitted.')
                self.vendor_seen = True
        return None


def interfaces():
    result = []
    for entry in sorted(Path('/sys/class/net').glob('*')):
        try:
            if entry.name == 'lo' or (entry/'type').read_text().strip() != '1':
                continue
            if (entry/'wireless').exists():
                continue
            result.append({'name': entry.name,
                           'state': (entry/'operstate').read_text().strip(),
                           'physical': (entry/'device').exists(),
                           'mac': bytes.fromhex((entry/'address').read_text().strip().replace(':',''))})
        except (OSError, ValueError):
            continue
    return result


def choose_interface(name):
    candidates = interfaces()
    if name:
        match = [item for item in candidates if item['name'] == name]
        if not match:
            raise ValueError('Interface is missing or is not a wired Ethernet interface')
        return match[0]
    physical = [item for item in candidates if item['physical'] and item['state'] == 'up']
    preferred = physical or [item for item in candidates if item['state'] == 'up']
    if len(preferred) == 1:
        return preferred[0]
    for item in candidates:
        print(f"  {item['name']}: {item['state']}, physical={item['physical']}")
    raise ValueError('Select an interface with --interface NAME')


def link_up(iface):
    try:
        return (Path('/sys/class/net')/iface/'carrier').read_text().strip() == '1'
    except OSError:
        return False


def ipv4_status(iface):
    try:
        p = subprocess.run(['ip', '-j', '-4', 'address', 'show', 'dev', iface],
                           capture_output=True, text=True, timeout=2, check=True)
        for dev in json.loads(p.stdout):
            for addr in dev.get('addr_info', []):
                ip = ipaddress.ip_address(addr['local'])
                if addr.get('scope') == 'global' and not ip.is_link_local:
                    return ip.packed, str(ip)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        pass
    return b'\x00'*4, None


def request_dhcp_renew(iface):
    """Ask an existing manager to reapply/renew; never replace its configuration."""
    import shutil
    if shutil.which('nmcli'):
        p = subprocess.run(['nmcli', '-g', 'GENERAL.STATE', 'device', 'show', iface],
                           capture_output=True, text=True, timeout=3)
        if p.returncode == 0 and p.stdout.lstrip().startswith('100'):
            p = subprocess.run(['nmcli', 'device', 'reapply', iface],
                               capture_output=True, timeout=5)
            if p.returncode == 0:
                log('NETWORK_MANAGER_REAPPLIED', 'Existing connection configuration retained.')
                return
    if shutil.which('networkctl'):
        p = subprocess.run(['networkctl', 'renew', iface], capture_output=True, timeout=5)
        if p.returncode == 0:
            log('DHCP_RENEW_REQUESTED', 'Existing systemd-networkd configuration retained.')
            return
    log('DHCP_MANAGER', 'Waiting for the existing network manager; configure this NIC for automatic IPv4 if no address appears.')


def run(args):
    if not sys.platform.startswith('linux') or not hasattr(socket, 'AF_PACKET'):
        raise RuntimeError('Raw EAPOL authentication requires Linux, not Windows Python.')
    selected = choose_interface(args.interface)
    iface, mac = selected['name'], selected['mac']
    if 'microsoft' in Path('/proc/sys/kernel/osrelease').read_text().lower():
        log('WSL_DETECTED', 'A virtual NIC may not reach the campus switch. An EAPOL reply is required to prove access.')
    log('INTERFACE', f'{iface}, physical={selected["physical"]}')
    # Open the socket before asking for a password, so permission errors cannot
    # cause an unnecessary credential prompt.
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x888e))
    except PermissionError as exc:
        raise RuntimeError('CAP_NET_RAW is required. Run this client with sudo.') from exc
    session = None
    try:
        sock.bind((iface, 0))
        sock.setblocking(False)
        if not args.probe:
            username = (args.username or input('Campus username (include operator suffix): ')).encode('utf-8')
            password = (sys.stdin.readline().rstrip('\r\n') if args.password_stdin
                        else getpass.getpass('Campus password: ')).encode('utf-8')
            session = Session(mac, username, password)
            del password
        destination = PAE_GROUP if args.multicast else BROADCAST
        starts = 0
        recovery = RecoveryBudget()
        next_start = time.monotonic()
        progress_deadline = None
        online_since = None
        next_ip_check = 0
        ipv4, ip_text = b'\x00'*4, None
        address_reported = False
        reported_ip = None
        previous_link = link_up(iface)
        link_wait_started = time.monotonic()

        def recover(reason):
            nonlocal starts, online_since, progress_deadline, next_start
            nonlocal ipv4, ip_text, address_reported, reported_ip
            if session is None or not recovery.retry():
                return False
            log('RECONNECT', f'{reason}; retry in 15 seconds ({recovery.attempts}/3).')
            session.reset()
            starts, online_since, progress_deadline = 0, None, None
            ipv4, ip_text, reported_ip = b'\x00'*4, None, None
            address_reported = False
            next_start = time.monotonic() + 15
            return True

        while True:
            now = time.monotonic()
            carrier = link_up(iface)
            if not carrier:
                if previous_link:
                    log('LINK_DOWN', 'Waiting for cable/link restoration.')
                    if session:
                        session.reset()
                    starts, online_since = 0, None
                    progress_deadline = None
                    address_reported = False
                    reported_ip = None
                    ipv4, ip_text = b'\x00'*4, None
                    link_wait_started = now
                previous_link = False
                if args.probe and now - link_wait_started > 15:
                    log('NO_LINK', 'The interface has no physical carrier.')
                    return 4
                time.sleep(0.5)
                continue
            if not previous_link:
                log('LINK_UP', 'Starting a new authentication exchange.')
                next_start = now
                previous_link = True
            if (session is None or session.state == 'starting') and now >= next_start:
                if starts >= 4:
                    if recover('No EAPOL reply during recovery'):
                        continue
                    log('NO_EAPOL_REPLY', 'Four Start frames received no usable Identity request. Check physical L2 access; credentials were not rejected.')
                    return 4
                frame = session.start(destination) if session else make_frame(mac, destination, 1)
                sock.send(frame)
                starts += 1
                next_start = now + 3
                log('EAPOL_START', f'attempt={starts}')
            if progress_deadline is not None and now >= progress_deadline:
                if recover('Reauthentication timed out'):
                    continue
                log('AUTH_TIMEOUT', 'The server stopped responding during authentication.')
                return 4
            if session and session.state == 'failed':
                if recover('Previously authenticated session was rejected'):
                    continue
                # Initial rejection exits immediately; recovery is bounded.
                return 3
            if session and session.state == 'online' and now >= next_ip_check:
                ipv4, ip_text = ipv4_status(iface)
                next_ip_check = now + 3
                if ip_text and ip_text != reported_ip:
                    log('IPV4_PRESENT', ip_text + ' (address presence alone does not prove Internet access)')
                    reported_ip = ip_text
                elif not ip_text and not address_reported and online_since is not None and now - online_since >= 30:
                    log('NO_IPV4_AFTER_AUTH', '802.1X succeeded, but DHCP has not supplied a usable IPv4 address.')
                    address_reported = True
            ready, _, _ = select.select([sock], [], [], 0.5)
            if not ready:
                continue
            frame, address = sock.recvfrom(65535)
            if len(address) > 2 and address[2] == getattr(socket, 'PACKET_OUTGOING', 4):
                continue
            try:
                packet = parse_frame(frame)
            except (ValueError, IndexError):
                continue
            if packet is None:
                continue
            if args.probe:
                if (packet['eapol_type'] == 0 and packet['eap_code'] == 1 and
                        packet['eap_type'] == 1 and packet['src'] != mac and
                        packet['dst'] in (mac, BROADCAST, PAE_GROUP)):
                    log('EAPOL_REACHABLE', 'Received switch Identity request. No username or password was sent.')
                    return 0
                continue
            before = session.state
            if packet['eap_code'] == 1 and packet['eap_type'] == 20:
                ipv4, ip_text = ipv4_status(iface)
            response = session.process(packet, ipv4)
            if response:
                sock.send(response)
                progress_deadline = time.monotonic() + 20
            if session.state == 'online':
                progress_deadline = None
                if before != 'online':
                    recovery.authenticated()
                    online_since = time.monotonic()
                    next_ip_check = 0
                    address_reported = False
                    if args.renew_dhcp:
                        try:
                            request_dhcp_renew(iface)
                        except (OSError, subprocess.SubprocessError):
                            log('DHCP_RENEW_FAILED', 'Authentication stays active; inspect your network manager.')
    finally:
        if session and session.peer is not None:
            try:
                sock.send(session.logoff())
                log('EAPOL_LOGOFF', 'Session closed.')
            except OSError:
                pass
        sock.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description='H3C campus 802.1X client for native Linux. Passwords are never saved.')
    parser.add_argument('--version', action='version', version=CLIENT_VERSION)
    parser.add_argument('-i', '--interface', help='Wired Ethernet interface (e.g. enp4s0)')
    parser.add_argument('-u', '--username', help='Optional; otherwise prompted interactively')
    parser.add_argument('--password-stdin', action='store_true', help='Read one password line from stdin, never from argv')
    parser.add_argument('--probe', action='store_true', help='Only test EAPOL reachability; send no credentials')
    parser.add_argument('--list-interfaces', action='store_true')
    parser.add_argument('--multicast', action='store_true', help='Use standard PAE multicast instead of site-observed broadcast')
    parser.add_argument('--renew-dhcp', action='store_true', help='After authentication, ask an existing manager to renew/reapply')
    args = parser.parse_args(argv)
    if args.list_interfaces:
        for item in interfaces():
            print(f"{item['name']}\t{item['state']}\tphysical={item['physical']}")
        return 0
    def stop(_signal, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop)
    try:
        return run(args)
    except (KeyboardInterrupt, EOFError):
        log('STOPPED')
        return 130
    except (OSError, ValueError, RuntimeError) as exc:
        log('ERROR', str(exc))
        return 2


if __name__ == '__main__':
    sys.exit(main())
