"""Private, authenticated credential storage for unattended campus login."""
import json
import os
import stat
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class CredentialStore:
    def __init__(self, home=None):
        home = Path(home or Path.home())
        self.home = home.absolute()
        self.directory = self.home / '.config/h3c-campus'
        self.key_directory = self.home / '.local/share/h3c-campus'
        self.secret = self.directory / 'credentials.enc'
        self.key = self.key_directory / 'credential.key'

    def check_directory(self, path, create=False):
        current = self.home
        for component in (None, *path.relative_to(self.home).parts):
            if component is not None:
                current = current / component
            try:
                info = current.lstat()
            except FileNotFoundError:
                if not create:
                    raise
                current.mkdir(mode=0o700)
                info = current.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_mode & 0o022):
                raise PermissionError('校园网凭证目录归属或权限异常。')
        if create:
            path.chmod(0o700)
        elif path.stat().st_mode & 0o077:
            raise PermissionError('校园网凭证目录权限异常。')

    def private_directory(self, path):
        self.check_directory(path, create=True)

    @staticmethod
    def read_private(path):
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise PermissionError('校园网凭证文件权限异常。')
            return stream.read()

    @staticmethod
    def write_private(path, data):
        descriptor, temporary = tempfile.mkstemp(prefix='.credential-', dir=path.parent)
        try:
            with os.fdopen(descriptor, 'wb') as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def save(self, username, password):
        self.private_directory(self.directory)
        self.private_directory(self.key_directory)
        try:
            key = self.read_private(self.key)
        except FileNotFoundError:
            key = AESGCM.generate_key(bit_length=256)
            self.write_private(self.key, key)
        nonce = os.urandom(12)
        payload = json.dumps({'username': username, 'password': password}, ensure_ascii=False).encode()
        self.write_private(self.secret, b'H3C1' + nonce + AESGCM(key).encrypt(nonce, payload, b'h3c-campus'))

    def load(self):
        try:
            self.check_directory(self.directory)
            data = self.read_private(self.secret)
        except FileNotFoundError:
            return None
        self.check_directory(self.key_directory)
        if len(data) < 32 or data[:4] != b'H3C1':
            raise ValueError('校园网凭证格式无效，请重新保存。')
        value = json.loads(AESGCM(self.read_private(self.key)).decrypt(data[4:16], data[16:], b'h3c-campus'))
        if not isinstance(value.get('username'), str) or not isinstance(value.get('password'), str):
            raise ValueError('校园网凭证格式无效，请重新保存。')
        return value

    def clear(self):
        # Explicitly opting out of remembering credentials revokes this app's secret.
        for path in (self.secret, self.key):
            try:
                self.check_directory(path.parent)
                path.unlink()
            except FileNotFoundError:
                pass
