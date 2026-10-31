"""Synthetic certificates only; caller supplies isolated test libraries."""
import os
import pathlib
import secrets
import subprocess
import sys
import tempfile

exe = pathlib.Path(sys.argv[1]).resolve()
libraries = [str(pathlib.Path(p).resolve()) for p in sys.argv[2:]]
if not libraries:
    raise SystemExit('Supply one or more test cryptlib library paths.')


def openssl(*args):
    subprocess.run(['openssl', *args], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


with tempfile.TemporaryDirectory(prefix='mpemtrans-test-') as directory:
    root = pathlib.Path(directory)
    password = root / 'password'
    password.write_text(secrets.token_hex(20))
    password.chmod(0o600)
    key = root / 'key.pem'
    cert = root / 'cert.pem'
    openssl('req', '-new', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(cert), '-subj', '/CN=localhost', '-days', '1', '-addext', 'keyUsage=digitalSignature,keyEncipherment')
    wrong_key = root / 'wrong-key.pem'
    wrong_cert = root / 'wrong-cert.pem'
    openssl('req', '-new', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(wrong_key), '-out', str(wrong_cert), '-subj', '/CN=unrelated', '-days', '1')
    for index, library in enumerate(libraries):
        output = root / ('result-' + str(index) + '.p15')
        command = [str(exe), '--library', library, '--key', str(key), '--cert', str(cert), '--out', str(output), '--label', 'ssl_cert', '--password-file', str(password)]
        subprocess.run(command, check=True)
        assert output.stat().st_size > 0
        if os.name != 'nt':
            assert output.stat().st_mode & 0o077 == 0
        before = output.read_bytes()
        result = subprocess.run(command, capture_output=True)
        assert result.returncode != 0 and output.read_bytes() == before
        mismatch = root / ('mismatch-' + str(index) + '.p15')
        bad = command.copy()
        bad[bad.index('--cert') + 1] = str(wrong_cert)
        bad[bad.index('--out') + 1] = str(mismatch)
        result = subprocess.run(bad, capture_output=True)
        assert result.returncode != 0 and not mismatch.exists()
        assert password.read_bytes() not in result.stdout + result.stderr
        assert not list(root.glob('.mpemtrans-*'))
print('PASS synthetic RSA conversion/reopen, owner-only output, overwrite refusal, key mismatch and staging cleanup for all supplied libraries.')
