# Upstream conversion audit

Source: https://github.com/amenonsen/pemtrans (preserved Git history).
The explicit permission in pemtrans.c permits use, modification and distribution
without limitations. Preserve Abhijit Menon-Sen's attribution and warranty notice.
The imported program's original license is not replaced by a generic GPL notice.

The original implementation calls PEM_read_PrivateKey, EVP_PKEY_get1_RSA,
cryptCreateContext, cryptSetAttributeString(KEY_COMPONENTS), cryptImportCert,
cryptKeysetOpen, cryptAddPrivateKey and cryptAddPublicKey.

Required adaptations before a usable release:

- Replace direct RSA structure access (key->n etc.) with supported OpenSSL APIs.
- Initialize handles/pointers and close/free all resources on every error path.
- Remove secrets from process arguments; accept protected password input.
- Check all cryptlib return codes, allocation lengths and bounded input sizes.
- Verify the private key and certificate match and define chain handling.
- Refuse existing output by default; stage protected output and reopen it through
  the chosen target library before publishing it under the requested name.
- Replace the author's hardcoded /home/ams build paths with portable tooling.
- Provide Windows file/permission/loading handling alongside the Linux path.
- Compare the actual public headers and ABI for 3.4.5 and the newer cryptlib;
  test conversion/reopen against both, without assuming enum compatibility.
- Prove native Mystic keyset/handshake behavior separately from tool conversion.

Distribution is one native executable plus README.txt in ZIP / tar.gz archives.
No compiled release is claimed yet. The old source is retained as reference and
must not be run on production keys while these adaptations are outstanding.
