/*
 * Mystic PEM conversion, based on amenonsen/pemtrans.
 * Copyright 2004 Abhijit Menon-Sen <ams@toroid.org>.
 * Adaptations 2026 Disconnected by Peer AT contributors.
 * Use, modification, and distribution are allowed without any limitations.
 * There is no warranty, express or implied.
 */
#define _POSIX_C_SOURCE 200809L
#include <cryptlib.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/pkcs7.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <windows.h>
#include <sddl.h>
#include <io.h>
#include <direct.h>
#define CALL __stdcall
#ifdef _MSC_VER
#define fstat _fstat64
#define stat _stat64
#define fileno _fileno
#define S_ISREG(mode) (((mode) & _S_IFMT) == _S_IFREG)
#endif
#else
#include <dlfcn.h>
#include <unistd.h>
#include <sys/resource.h>
#define CALL
#endif

/* These public ABI values and RSA layout were compared using the actual 3.4.5
 * and 3.4.9.6 headers. Session attributes are deliberately not used here. */
_Static_assert(sizeof(CRYPT_PKCINFO_RSA) == 4132, "Review cryptlib RSA ABI");
_Static_assert(CRYPT_CTXINFO_LABEL == 1016 && CRYPT_CTXINFO_KEY_COMPONENTS == 1013,
               "Review cryptlib context attributes");
#define API_LIST(X) \
 X(init, cryptInit, (void)) \
 X(end, cryptEnd, (void)) \
 X(get_attribute, cryptGetAttribute, (int, int, int *)) \
 X(create_context, cryptCreateContext, (int *, int, int)) \
 X(set_string, cryptSetAttributeString, (int, int, const void *, int)) \
 X(import_cert, cryptImportCert, (const void *, int, int, int *)) \
 X(open_keyset, cryptKeysetOpen, (int *, int, int, const char *, int)) \
 X(add_private, cryptAddPrivateKey, (int, int, const char *)) \
 X(add_public, cryptAddPublicKey, (int, int)) \
 X(close_keyset, cryptKeysetClose, (int)) \
 X(destroy_context, cryptDestroyContext, (int)) \
 X(destroy_cert, cryptDestroyCert, (int)) \
 X(get_private, cryptGetPrivateKey, (int, int *, int, const char *, const char *))
#define DECLARE_API(member, symbol, signature) int (CALL *member) signature;
static struct { API_LIST(DECLARE_API) } api;
#ifdef _WIN32
static HMODULE library;
#else
static void *library;
#endif

static int load_library(const char *path) {
#ifdef _WIN32
    if (!(path[0] && path[1] == ':' && (path[2] == '/' || path[2] == '\\')) && strncmp(path, "\\\\", 2)) return 0;
    library = LoadLibraryExA(path, NULL, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
#define LOAD_API(member, symbol, signature) \
    api.member = (int (CALL *) signature)GetProcAddress(library, #symbol); if (!api.member) return 0;
#else
    library = dlopen(path, RTLD_NOW | RTLD_LOCAL);
#define LOAD_API(member, symbol, signature) \
    *(void **)(&api.member) = dlsym(library, #symbol); if (!api.member) return 0;
#endif
    if (!library) return 0;
    API_LIST(LOAD_API)
#undef LOAD_API
    return 1;
}

#ifdef _WIN32
/* Only inspect the executable directory and the Windows system directory.
 * Avoid the current working directory and PATH for automatic DLL loading. */
static int load_installed_library(void) {
    char path[MAX_PATH];
    char *separator;
    DWORD length;
#ifdef _WIN64
    const char *name = "cl64.dll";
#else
    const char *name = "cl32.dll";
#endif
    length = GetModuleFileNameA(NULL, path, sizeof(path));
    if (length && length < sizeof(path)) {
        separator = strrchr(path, '\\');
        if (separator && (size_t)(separator - path + 1) + strlen(name) < sizeof(path)) {
            strcpy(separator + 1, name);
            if (load_library(path)) return 1;
            if (library) return 0;
        }
    }
    length = GetSystemDirectoryA(path, sizeof(path));
    if (length && length + 1 + strlen(name) < sizeof(path)) {
        strcat(path, "\\");
        strcat(path, name);
        if (load_library(path)) return 1;
    }
    return 0;
}
#else
/* Ask the system loader for installed SONAMEs; never scan the working folder.
 * Prefer the package-selected link. A located but incompatible library is an
 * error rather than permission to silently choose a different implementation.
 * Explicit --library bypasses discovery and must remain an absolute path. */
static int load_installed_library(void) {
    const char *names[] = { "libcl.so", "libcl.so.3", "libcl.so.3.4.5", "libcl.so.3.4.9" };
    size_t index;
    for (index = 0; index < sizeof(names) / sizeof(names[0]); index++) {
        if (load_library(names[index])) return 1;
        if (library) return 0;
    }
    return 0;
}
#endif

static int supported_library(void) {
    int major = 0, minor = 0, step = 0;
    return api.get_attribute(CRYPT_UNUSED, CRYPT_OPTION_INFO_MAJORVERSION, &major) == CRYPT_OK &&
        api.get_attribute(CRYPT_UNUSED, CRYPT_OPTION_INFO_MINORVERSION, &minor) == CRYPT_OK &&
        api.get_attribute(CRYPT_UNUSED, CRYPT_OPTION_INFO_STEPPING, &step) == CRYPT_OK &&
        major == 3 && minor == 4 && (step == 5 || step == 9);
}

static int password_file(const char *path, char output[257]) {
    FILE *file = fopen(path, "rb");
    size_t count;
    struct stat info;
    if (!file) return 0;
    if (fstat(fileno(file), &info) || !S_ISREG(info.st_mode) || info.st_size > 256) {
        fclose(file); return 0;
    }
#ifndef _WIN32
    if (info.st_mode & 0077) { fclose(file); return 0; }
#endif
    count = fread(output, 1, 256, file);
    if (ferror(file)) { fclose(file); return 0; }
    fclose(file);
    if (memchr(output, '\0', count)) return 0;
    while (count && (output[count - 1] == '\n' || output[count - 1] == '\r')) count--;
    if (count < 8 || memchr(output, '\n', count) || memchr(output, '\r', count)) return 0;
    output[count] = 0;
    return 1;
}

static int pem_password(char *buffer, int size, int writing, void *value) {
    const char *password = value;
    size_t length = password ? strlen(password) : 0;
    (void)writing;
    if (!length || length >= (size_t)size) return 0;
    memcpy(buffer, password, length);
    return (int)length;
}

static int put_component(unsigned char *output, size_t capacity, int *bits, const BIGNUM *value) {
    if (!value || BN_is_negative(value) || BN_num_bytes(value) > (int)capacity) return 0;
    *bits = BN_num_bits(value);
    return BN_bn2bin(value, output) > 0;
}

static int rsa_components(EVP_PKEY *key, CRYPT_PKCINFO_RSA *components) {
    const BIGNUM *n, *e, *d, *p, *q, *dmp1, *dmq1, *iqmp;
    const RSA *rsa = EVP_PKEY_get0_RSA(key);
    if (!rsa || EVP_PKEY_bits(key) < 2048) return 0;
    RSA_get0_key(rsa, &n, &e, &d);
    RSA_get0_factors(rsa, &p, &q);
    RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);
    cryptInitComponents(components, CRYPT_KEYTYPE_PRIVATE);
#define PUT(field, value) put_component(components->field, sizeof(components->field), &components->field##Len, value)
    return PUT(n, n) && PUT(e, e) && PUT(d, d) && PUT(p, p) && PUT(q, q) &&
        PUT(u, iqmp) && PUT(e1, dmp1) && PUT(e2, dmq1);
#undef PUT
}

/* Put all supplied certificates in a PKCS#7 certificate bag. cryptlib performs
 * the final chain import; the leaf/key match and adjacent signatures are checked
 * first. This verifies supplied chain relationships, not public trust. */
static unsigned char *certificate_data(const char *path, EVP_PKEY *key, int *length) {
    STACK_OF(X509) *certificates = sk_X509_new_null();
    FILE *file = fopen(path, "rb");
    X509 *certificate = NULL;
    PKCS7 *bag = NULL;
    EVP_PKEY *issuer_key = NULL;
    unsigned char *der = NULL, *position;
    int count, i;
    struct stat info;
    if (!certificates || !file) goto cleanup;
    if (fstat(fileno(file), &info) || !S_ISREG(info.st_mode) || info.st_size > 16 * 1024 * 1024) goto cleanup;
    while ((certificate = PEM_read_X509(file, NULL, NULL, NULL)) != NULL) {
        if (sk_X509_num(certificates) >= 32 || !sk_X509_push(certificates, certificate)) {
            X509_free(certificate); goto cleanup;
        }
    }
    if (ferror(file) || (ERR_peek_last_error() && ERR_GET_REASON(ERR_peek_last_error()) != PEM_R_NO_START_LINE)) goto cleanup;
    ERR_clear_error();
    count = sk_X509_num(certificates);
    if (!count || X509_check_private_key(sk_X509_value(certificates, 0), key) != 1) goto cleanup;
    for (i = 0; i < count; i++) {
        certificate = sk_X509_value(certificates, i);
        if (X509_cmp_current_time(X509_get0_notBefore(certificate)) >= 0 ||
            X509_cmp_current_time(X509_get0_notAfter(certificate)) <= 0) goto cleanup;
        if (i + 1 < count) {
            X509 *issuer = sk_X509_value(certificates, i + 1);
            if (X509_check_issued(issuer, certificate) != X509_V_OK) goto cleanup;
            issuer_key = X509_get_pubkey(issuer);
            if (!issuer_key || X509_verify(certificate, issuer_key) != 1) goto cleanup;
            EVP_PKEY_free(issuer_key); issuer_key = NULL;
        }
    }
    if (count == 1) {
        *length = i2d_X509(sk_X509_value(certificates, 0), NULL);
    } else {
        bag = PKCS7_new();
        if (!bag || !PKCS7_set_type(bag, NID_pkcs7_signed) || !PKCS7_content_new(bag, NID_pkcs7_data)) goto cleanup;
        for (i = 0; i < count; i++) if (!PKCS7_add_certificate(bag, sk_X509_value(certificates, i))) goto cleanup;
        *length = i2d_PKCS7(bag, NULL);
    }
    if (*length <= 0 || *length > 16 * 1024 * 1024) goto cleanup;
    der = OPENSSL_malloc((size_t)*length);
    if (!der) goto cleanup;
    position = der;
    if ((count == 1 ? i2d_X509(sk_X509_value(certificates, 0), &position) : i2d_PKCS7(bag, &position)) != *length) {
        OPENSSL_free(der); der = NULL;
    }
cleanup:
    if (file) fclose(file);
    EVP_PKEY_free(issuer_key);
    PKCS7_free(bag);
    sk_X509_pop_free(certificates, X509_free);
    return der;
}

static int make_private_directory(const char *path) {
#ifdef _WIN32
    PSECURITY_DESCRIPTOR descriptor = NULL;
    SECURITY_ATTRIBUTES attributes = {sizeof(attributes), NULL, FALSE};
    int result;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(
        "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", SDDL_REVISION_1, &descriptor, NULL)) return 0;
    attributes.lpSecurityDescriptor = descriptor;
    result = CreateDirectoryA(path, &attributes) != 0;
    LocalFree(descriptor);
    return result;
#else
    return mkdir(path, 0700) == 0;
#endif
}

static int publish_output(const char *temporary, const char *output) {
#ifdef _WIN32
    return MoveFileExA(temporary, output, MOVEFILE_WRITE_THROUGH) != 0;
#else
    /* Same-filesystem link is atomic and fails if output already exists. */
    if (link(temporary, output)) return 0;
    unlink(temporary);
    return 1;
#endif
}

int main(int argc, char **argv) {
    const char *library_path = NULL, *key_path = NULL, *cert_path = NULL;
    const char *output = NULL, *label = NULL, *password_path = NULL, *input_password_path = NULL;
    char password[257] = {0}, input_password[257] = {0};
    char directory[4096] = {0}, temporary[4096] = {0};
    unsigned char random_bytes[16], *cert_data = NULL;
    CRYPT_PKCINFO_RSA components;
    EVP_PKEY *key = NULL;
    FILE *file = NULL;
    int context = CRYPT_UNUSED, certificate = CRYPT_UNUSED, keyset = CRYPT_UNUSED;
    int restored = CRYPT_UNUSED, initialized = 0, created_directory = 0, status = 2;
    int cert_length = 0, i, result;
    const char *stage = "arguments";
    struct stat existing;
#ifdef _WIN32
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
#else
    /* Key material must not enter a Unix core dump, including on DLL failure. */
    struct rlimit core_limit = {0, 0};
    if (setrlimit(RLIMIT_CORE, &core_limit)) return 2;
    umask(0077);
#endif
    memset(&components, 0, sizeof(components));
    if (argc == 2 && !strcmp(argv[1], "--help")) {
        puts("mpemtrans [--library ABSOLUTE_LIBRARY] --key PEM --cert FULLCHAIN_PEM --out NEW_KEYSET --label NAME --password-file FILE [--input-password-file FILE]");
        puts("Linux: --library is optional; installed libcl is discovered through the system loader. Windows: searches beside the EXE, then the Windows system directory.");
        puts("RSA 2048-4096; PKCS#1/PKCS#8 input; cryptlib 3.4.5 and 3.4.9 profiles. No existing output is replaced.");
        return 0;
    }
    for (i = 1; i < argc; i += 2) {
        if (i + 1 >= argc) goto cleanup;
#define OPTION(name, target) if (!strcmp(argv[i], name)) { if (target) goto cleanup; target = argv[i + 1]; }
        OPTION("--library", library_path)
        else OPTION("--key", key_path)
        else OPTION("--cert", cert_path)
        else OPTION("--out", output)
        else OPTION("--label", label)
        else OPTION("--password-file", password_path)
        else OPTION("--input-password-file", input_password_path)
        else goto cleanup;
#undef OPTION
    }
    if (!key_path || !cert_path || !output || !label || !password_path ||
        !strlen(label) || strlen(label) > 64 || strlen(output) > 3800) goto cleanup;
#ifndef _WIN32
    if (library_path && library_path[0] != '/') {
        fprintf(stderr, "mpemtrans: --library requires an absolute path.\n");
        goto cleanup;
    }
#endif
    stage = "existing output refusal";
    if (!stat(output, &existing)) goto cleanup;
    stage = "protected password input";
    if (!password_file(password_path, password) ||
        (input_password_path && !password_file(input_password_path, input_password))) goto cleanup;
    stage = "private key input (RSA only)";
    file = fopen(key_path, "rb");
    if (!file) goto cleanup;
    if (fstat(fileno(file), &existing) || !S_ISREG(existing.st_mode) || existing.st_size > 16 * 1024 * 1024) goto cleanup;
    key = PEM_read_PrivateKey(file, NULL, pem_password, input_password_path ? input_password : NULL);
    fclose(file); file = NULL;
    if (!key || EVP_PKEY_base_id(key) != EVP_PKEY_RSA || !rsa_components(key, &components)) goto cleanup;
    stage = "certificate/key match, dates and chain";
    cert_data = certificate_data(cert_path, key, &cert_length);
    if (!cert_data) goto cleanup;
    stage = "cryptlib loading/version qualification";
    {
        int loaded;
        loaded = library_path ? load_library(library_path) : load_installed_library();
        if (!loaded) {
            fprintf(stderr, "mpemtrans: cryptlib could not be loaded; specify --library with the absolute path to a compatible library.\n");
            goto cleanup;
        }
    }
    if (api.init() != CRYPT_OK) goto cleanup;
    initialized = 1;
    if (!supported_library()) goto cleanup;
    stage = "RSA context import";
#define CHECK(call) do { result = (call); if (result != CRYPT_OK) goto cleanup; } while (0)
    CHECK(api.create_context(&context, CRYPT_UNUSED, CRYPT_ALGO_RSA));
    CHECK(api.set_string(context, CRYPT_CTXINFO_LABEL, label, (int)strlen(label)));
    CHECK(api.set_string(context, CRYPT_CTXINFO_KEY_COMPONENTS, &components, sizeof(components)));
    OPENSSL_cleanse(&components, sizeof(components));
    stage = "cryptlib certificate import";
    CHECK(api.import_cert(cert_data, cert_length, CRYPT_UNUSED, &certificate));
    stage = "private staging directory";
    if (RAND_bytes(random_bytes, sizeof(random_bytes)) != 1) goto cleanup;
    {
        const char *slash = strrchr(output, '/');
#ifdef _WIN32
        const char *backslash = strrchr(output, '\\');
        if (backslash && (!slash || backslash > slash)) slash = backslash;
#endif
        size_t parent_length = slash ? (size_t)(slash - output + 1) : 0;
        if (parent_length) memcpy(directory, output, parent_length);
        strcat(directory, ".mpemtrans-");
        for (i = 0; i < 16; i++) sprintf(directory + strlen(directory), "%02x", random_bytes[i]);
    }
    if (!make_private_directory(directory)) goto cleanup;
    created_directory = 1;
    snprintf(temporary, sizeof(temporary), "%s/keyset.p15", directory);
    stage = "keyset creation";
    CHECK(api.open_keyset(&keyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE, temporary, CRYPT_KEYOPT_CREATE));
#ifndef _WIN32
    if (chmod(temporary, 0600)) goto cleanup;
#endif
    CHECK(api.add_private(keyset, context, password));
    CHECK(api.add_public(keyset, certificate));
    CHECK(api.close_keyset(keyset)); keyset = CRYPT_UNUSED;
    stage = "keyset reopen and private-key verification";
    CHECK(api.open_keyset(&keyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE, temporary, CRYPT_KEYOPT_READONLY));
    CHECK(api.get_private(keyset, &restored, CRYPT_KEYID_NAME, label, password));
    CHECK(api.destroy_context(restored)); restored = CRYPT_UNUSED;
    CHECK(api.close_keyset(keyset)); keyset = CRYPT_UNUSED;
    stage = "publish new output without replacement";
    if (!publish_output(temporary, output)) goto cleanup;
    status = 0;
    puts("Converted and reopened the new cryptlib keyset. No existing output was replaced.");
cleanup:
    if (status) fprintf(stderr, "mpemtrans: failed during %s; no private data is printed.\n", stage);
    if (file) fclose(file);
    if (initialized) {
        if (restored != CRYPT_UNUSED) api.destroy_context(restored);
        if (keyset != CRYPT_UNUSED) api.close_keyset(keyset);
        if (certificate != CRYPT_UNUSED) api.destroy_cert(certificate);
        if (context != CRYPT_UNUSED) api.destroy_context(context);
        api.end();
    }
    if (created_directory) {
        remove(temporary);
#ifdef _WIN32
        _rmdir(directory);
#else
        rmdir(directory);
#endif
    }
    EVP_PKEY_free(key);
    OPENSSL_free(cert_data);
    OPENSSL_cleanse(&components, sizeof(components));
    OPENSSL_cleanse(password, sizeof(password));
    OPENSSL_cleanse(input_password, sizeof(input_password));
#ifdef _WIN32
    if (library) FreeLibrary(library);
#else
    if (library) dlclose(library);
#endif
    return status;
}
