"""Synthetic certificates only; caller supplies isolated test libraries."""
import os
import pathlib
import shutil
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
        if os.name != 'nt':
            auto = command.copy()
            del auto[1:3]
            auto[auto.index('--out') + 1] = str(root / ('auto-' + str(index) + '.p15'))
            loader_dir = root / ('loader-' + str(index))
            loader_dir.mkdir()
            (loader_dir / 'libcl.so').symlink_to(library)
            env = dict(os.environ, LD_LIBRARY_PATH=str(loader_dir))
            subprocess.run(auto, check=True, env=env)
            local_dir = root / ('local-' + str(index))
            local_dir.mkdir()
            local_exe = local_dir / 'mpemtrans'
            shutil.copy2(exe, local_exe)
            (local_dir / 'libcl.so').symlink_to(library)
            # A located non-cryptlib in the loader path would fail API checks.
            # Success proves the executable-local library was preferred.
            invalid_loader = root / ('invalid-loader-' + str(index))
            invalid_loader.mkdir()
            libc = pathlib.Path('/lib/x86_64-linux-gnu/libc.so.6')
            if libc.exists():
                (invalid_loader / 'libcl.so').symlink_to(libc)
            local = auto.copy()
            local[0] = str(local_exe)
            local[local.index('--out') + 1] = str(root / ('local-result-' + str(index) + '.p15'))
            subprocess.run(local, check=True, cwd=root, env=dict(os.environ, LD_LIBRARY_PATH=str(invalid_loader)))
            relative = command.copy()
            relative[relative.index('--library') + 1] = 'libcl.so'
            result = subprocess.run(relative, capture_output=True)
            assert result.returncode != 0 and b'absolute path' in result.stderr
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
