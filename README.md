# mpemtrans

Mystic PEM certificate conversion, based on
[amenonsen/pemtrans](https://github.com/amenonsen/pemtrans). The original explicit
permission is retained in the C header and LICENSE.

Status: development prototype. The Linux converter has created and reopened
synthetic RSA keysets with cryptlib 3.4.5 and the tested generic 3.4.9.6 build.
Native Windows qualification and native Mystic handshake tests
are tracked separately in each release report. Isolated Linux Mystic A48/A49
BinkP TLS 1.2 testing has verified the exact converted certificate, CA/hostname
validation and encrypted BinkP framing with cryptlib 3.4.5. Synthetic single-certificate,
fullchain and encrypted PKCS#8 conversion tests are included in the test suite. Published preview archives are not production-qualified releases.

## What it does

The converter reads a PEM private key and a matching certificate/full chain,
imports them through the explicitly selected cryptlib and creates a new PKCS#15
keyset. It reopens that keyset and retrieves the private key before publishing
it. Existing output files are never replaced. The tool does not install or
restart Mystic, obtain certificates, or change server configuration.

Current key scope: RSA, 2048–4096 bits; PKCS#1 or PKCS#8 private-key input.
ECDSA private keys are rejected in this prototype. An RSA private key and its
matching certificate are required. Issuer relationships and certificate dates
are checked; this is not a substitute for validating public CA trust.

The 3.4.5 and 3.4.9.6 public headers were compared for the used API constants and
RSA structure layout. Session attributes are not used. A newer cryptlib being
usable by this converter does not prove it is compatible with an old Mystic
binary. Always select the intended library explicitly.

## Linux

The Linux tar.gz contains only `mpemtrans` and `README.txt`. Extract beside
Mystic, normally `/opt/mystic`, or another chosen location. No DEB installation,
PATH update or separate manpage is needed. The target cryptlib is an external
prerequisite; it is not bundled or replaced by this tool.

Prepare a nonempty output-password file. Use a strong password for general
keysets; cryptlib enforces its supported password constraints. Mystic A49's
native keyset interface expects a fixed legacy label/password, so an arbitrary
label or password produces a keyset Mystic cannot open. Use the matching Mystic
profile when preparing `data/ssl.cert`; no vendor password is printed here.
Protect it so only its owner can read it (`chmod 600 output-password.txt`). Do
not put the password directly on the command line.

```sh
./mpemtrans \
  --library /absolute/path/to/libcl.so.3.4.5 \
  --key privkey.pem \
  --cert fullchain.pem \
  --out server-new.p15 \
  --label ssl_cert \
  --password-file output-password.txt
```

On Linux, `--library` is optional. Without it, the directory of the actual executable
(resolved through `/proc/self/exe`, including when invoked through a symlink)
is searched first for `libcl.so`, `libcl.so.3`, `libcl.so.3.4.5`, then
`libcl.so.3.4.9`. Only after those local names are absent does discovery use
the same names through the system loader's configured library paths.
The first located library must pass the API/version checks; an incompatible
installation does not trigger silent switching. The working directory is not
scanned. Normal loader configuration, including an explicitly configured
`LD_LIBRARY_PATH`, applies. If loading fails, the error asks for an explicit
`--library /absolute/path/to/library`. Windows discovery is described below.

An explicit library path must be absolute. Select a tested newer cryptlib with the same
option when preparing a keyset for that version. If an input PEM is encrypted,
provide its separate protected file with `--input-password-file FILE`; otherwise
no interactive prompt is issued.

## Windows

The Windows ZIP contains only `mpemtrans.exe` and `README.txt`. Extract into a
chosen short ASCII path, normally `C:\Mystic`. There is no MSI or global PATH
change. Use the cryptlib DLL matching the executable architecture; existing
Mystic x86/x64 builds conventionally use `cl32.dll` / `cl64.dll` respectively.
Without `--library`, Windows searches for `cl32.dll` (x86) or `cl64.dll`
(x64) beside `mpemtrans.exe`, then in the Windows system directory returned by
`GetSystemDirectory`. It does not search the working directory or PATH. The
first located library must pass qualification; `--library` selects an explicit
absolute path instead. If loading fails, the error asks for that option.
Do not copy a different DLL over a working Mystic library to test this tool.

Example from PowerShell:

```powershell
./mpemtrans.exe --library 'C:\Mystic\cl64.dll' --key 'privkey.pem' --cert 'fullchain.pem' --out 'server-new.p15' --label 'ssl_cert' --password-file 'output-password.txt'
```

Create the password file through your preferred secure editor and restrict its
ACL to the intended account, SYSTEM and administrators. Passwords are read from
files, not printed or included in process arguments. The prototype uses Windows
ANSI file APIs, so short ASCII file paths are required for now.

## Output and checks

A private temporary directory is created beside the destination, and the new
keyset is written there. Linux uses owner-only permissions; Windows uses an
explicit protected directory ACL. The completed keyset is reopened through the
selected cryptlib before publication under the requested name without replacing
an existing file. Source keys and certificates are not changed.

A successful conversion exits with 0. Failure exits nonzero and reports the
operation stage without printing private key material or passwords. Keep the
current server certificate until a separate native Mystic test succeeds. Do
not infer a usable TLS configuration merely from a .p15 filename.

## Source and distribution

`make CRYPTLIB_INCLUDE=/path/to/headers` builds a Linux development executable.
Linux builds link the distribution's OpenSSL 3 libcrypto dynamically. Build on
the oldest supported distribution and test the identical executable on all
supported targets; the OpenSSL major version alone does not qualify glibc or
symbol requirements.

Windows builds link OpenSSL 3 libcrypto and the MSVC runtime statically. No
separate OpenSSL installation or OpenSSL DLL is required. The Windows workflow
uses vcpkg's x86-windows-static / x64-windows-static triplets, inspects executable
imports and assembles the applicable dependency notices into README.txt.
Bundled OpenSSL security fixes require rebuilding and redistributing the EXE.
The external cryptlib DLL is still required. This build arrangement does not
replace native conversion and Mystic handshake qualification.
The selected cryptlib is loaded at runtime, not linked into the program.

The old Unix manpage has been retired from the active root. Its content is
retained only as a source reference under `docs/upstream-manpage-reference.txt`;
this README replaces it for both platforms. The maintained implementation stays in the original `pemtrans.c` file.
Its upstream version and subsequent changes remain available through Git history;
the executable is named `mpemtrans`.

Tool code, builds and tests belong here. Mystic installation/configuration is
maintained in mysticd; theme artwork belongs to mystic-theme. Release archives
must contain exactly one executable and README.txt, with checksums and source
published separately. Windows support is not claimed until native tests pass.
