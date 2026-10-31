"""Verify a converted ssl.cert with real MIS in an isolated Linux namespace.

The caller prepares an offline synthetic A49 fixture, its converter-generated
ssl.cert and a matching leaf/CA PEM. No account authentication or file transfer
is attempted. Fixture preparation must never use production keys or DAT files.
"""
import argparse
import fcntl
import hashlib
import os
from pathlib import Path
import pty
import socket
import ssl
import struct
import subprocess
import termios
import threading
import time

parser = argparse.ArgumentParser()
parser.add_argument('--fixture', required=True, type=Path)
parser.add_argument('--library', required=True, type=Path)
parser.add_argument('--leaf', required=True, type=Path)
parser.add_argument('--ca', required=True, type=Path)
parser.add_argument('--port', type=int, default=24553)
args = parser.parse_args()
root = args.fixture.resolve()
library = args.library.resolve()
assert (root / '.mpemtrans-handshake-fixture').read_text().strip() == 'Synthetic offline mpemtrans fixture'
assert {name for _, name in socket.if_nameindex()} == {'lo'}, 'Use a loopback-only network namespace'
subprocess.run(['/usr/sbin/ip', 'link', 'set', 'lo', 'up'], check=True)
keyset = root / 'data/ssl.cert'
before = hashlib.sha256(keyset.read_bytes()).digest()
expected = ssl.PEM_cert_to_DER_cert(args.leaf.read_text())
env = dict(os.environ, LD_LIBRARY_PATH=str(library.parent), TERM='xterm')
master, slave = pty.openpty()
fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 25, 80, 0, 0))
process = subprocess.Popen([str(root / 'mis'), 'server'], cwd=root, env=env,
                           stdin=slave, stdout=slave, stderr=slave)
os.close(slave)


def drain():
    while True:
        try:
            if not os.read(master, 4096):
                break
        except OSError:
            break


threading.Thread(target=drain, daemon=True).start()
try:
    deadline = time.monotonic() + 60
    while True:
        assert process.poll() is None, 'MIS exited before TLS handshake'
        try:
            connection = socket.create_connection(('127.0.0.1', args.port), timeout=5)
            break
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(.1)
    with connection:
        context = ssl.create_default_context(cafile=str(args.ca))
        with context.wrap_socket(connection, server_hostname='localhost') as secure:
            assert secure.getpeercert(binary_form=True) == expected, 'MIS served a different certificate'
            assert secure.version() == 'TLSv1.2'

            def exact(length):
                result = b''
                while len(result) < length:
                    chunk = secure.recv(length - len(result))
                    assert chunk, 'Truncated BinkP frame'
                    result += chunk
                return result

            # BinkP command frames: two-byte network-order length with bit 15
            # set; first payload byte is the command. M_NUL (0) carries text.
            header = int.from_bytes(exact(2), 'big')
            assert header & 0x8000
            payload = exact(header & 0x7fff)
            assert payload[0] == 0, 'Expected BinkP M_NUL greeting'
            message = b'\x00SYS mpemtrans isolated certificate test'
            secure.sendall((0x8000 | len(message)).to_bytes(2, 'big') + message)
    assert str(library) in Path(f'/proc/{process.pid}/maps').read_text(), 'Wrong cryptlib mapping'
    assert hashlib.sha256(keyset.read_bytes()).digest() == before, 'MIS replaced the converted keyset'
    print('PASS native MIS BinkP TLS 1.2: exact converted certificate, CA/hostname verification, encrypted framing, actual library mapping and unchanged keyset')
finally:
    subprocess.run([str(root / 'mis'), 'shutdown'], cwd=root, env=env,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.terminate()
        process.wait(timeout=5)
    os.close(master)
