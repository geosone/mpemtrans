"""Start only the setup-owned synthetic fixture in a loopback-only namespace."""
import argparse
import fcntl
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
parser.add_argument('--fixture', type=Path, required=True)
parser.add_argument('--library', type=Path, required=True)
parser.add_argument('--capture', type=Path, required=True)
parser.add_argument('--port', type=int, required=True)
args = parser.parse_args()
root = args.fixture.resolve()
assert (root / '.mpemtrans-setup-fixture').read_text() == 'Fresh vendor fixture'
assert {name for _, name in socket.if_nameindex()} == {'lo'}
subprocess.run(['/usr/sbin/ip', 'link', 'set', 'lo', 'up'], check=True)
env = dict(os.environ, LD_LIBRARY_PATH=str(root), TERM='xterm',
           MPEMTRANS_REAL_LIBRARY=str(args.library.resolve()),
           MPEMTRANS_CAPTURE_DIRECTORY=str(args.capture.resolve()))
master, slave = pty.openpty()
fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 25, 80, 0, 0))
process = subprocess.Popen([str(root / 'mis'), 'server'], cwd=root, env=env,
                           stdin=slave, stdout=slave, stderr=slave)
os.close(slave)


def discard():
    while True:
        try:
            if not os.read(master, 4096):
                break
        except OSError:
            break


threading.Thread(target=discard, daemon=True).start()
try:
    deadline = time.monotonic() + 60
    while True:
        assert process.poll() is None, 'Synthetic MIS exited'
        try:
            connection = socket.create_connection(('127.0.0.1', args.port), timeout=3)
            break
        except OSError:
            if time.monotonic() >= deadline:
                raise RuntimeError('Synthetic MIS did not open TLS') from None
            time.sleep(.1)
    with connection:
        # The only peer in this namespace is the newly created synthetic MIS.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with context.wrap_socket(connection, server_hostname='localhost') as secure:
            assert secure.getpeercert(binary_form=True)
            assert secure.recv(2048), 'No encrypted BinkP greeting'
    assert all((args.capture / name).is_file() for name in ['label.capture', 'password.capture'])
    print('PASS isolated synthetic capture; profile values are not displayed')
finally:
    subprocess.run([str(root / 'mis'), 'shutdown'], cwd=root, env=env,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.terminate()
        process.wait(timeout=5)
    os.close(master)
