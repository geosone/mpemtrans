# Mystic A49 BinkP TLS qualification

An isolated Linux amd64 Mystic 1.12 A49 instance successfully loaded a keyset
created by mpemtrans and completed a BinkP TLS 1.2 connection with cryptlib 3.4.5.

The synthetic input was an encrypted PKCS#8 RSA private key and an ordered PEM
fullchain (leaf plus test CA). The test client trusted only that test CA and
verified `localhost`. The received leaf DER had to equal the original leaf
exactly, preventing a pass based on Mystic silently generating another key.

After the handshake, the client parsed an encrypted BinkP M_NUL greeting and
sent an encrypted M_NUL command. The test checked the mapped cryptlib file and
that the converted `data/ssl.cert` bytes were unchanged. This was a real MIS
process with the actual cryptlib, without an interception shim during the final
test. No node authentication or mail/file transfer was attempted.

## Native keyset interface

A49 uses a fixed legacy key label and short internal keyset password. A converter
keyset using arbitrary values can reopen successfully in cryptlib but fail in
Mystic. The synthetic fixture's native interface parameters were measured and
kept in private owner-only files; their password contents are not published.
Preview 1 incorrectly imposed a minimum of eight password bytes. Preview 2
accepts nonempty protected password files and lets cryptlib enforce its keyset
constraints. Encrypted PEM input passwords are likewise not subject to an
unrelated output-keyset length requirement.

## Repeating the protocol test

Prepare a separate offline installation with loopback BinkP enabled and its TLS
port set to 24553. Use the matching A49 developer records and tested configuration
helpers; never patch an unknown DAT layout. Convert synthetic PEM input with the
native keyset label/password and place the result at that fixture's
`data/ssl.cert`, preserving its previous file as a backup. Do not use production
configuration, certificates or passwords.

Create `.mpemtrans-handshake-fixture` in the fixture root containing exactly
`Synthetic offline mpemtrans fixture`. Then run the committed test in a new
loopback-only network namespace:

```sh
unshare -Urn python3 tests/test_mystic_binkp.py \
  --fixture /absolute/path/to/synthetic-mystic \
  --library /absolute/path/to/libcl.so.3.4.5 \
  --leaf /absolute/path/to/test-leaf.pem \
  --ca /absolute/path/to/test-ca.pem
```

The test starts and stops only the selected fixture. The fixture marker and
loopback-only namespace are mandatory. A CA/hostname failure, wrong leaf,
missing encrypted frame, different library or changed keyset fails the test.

This result qualifies this BinkP TLS combination. It does not establish native
Mystic compatibility with newer cryptlib releases, HTTP(S), other Mystic
versions or Windows protocol handshakes. The conversion-level Windows tests
are recorded separately in the release build report.
