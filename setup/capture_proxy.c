/* Local setup-only forwarding shim. Never deploy over a production libcl.
 * Forward all API calls to an explicitly selected real cryptlib. Capture only
 * native key-label/password arguments in a fresh private fixture directory.
 * There are deliberately no Mystic label/password constants in this source. */
#define _GNU_SOURCE
#include <limits.h>
#define _CRYPT_DEFINED
#include <cryptlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>
#define PROXY_CALL __stdcall
static HMODULE real_library;
static INIT_ONCE initialized = INIT_ONCE_STATIC_INIT;
static BOOL CALLBACK load_real(PINIT_ONCE once, PVOID value, PVOID *context) {
    const char *path = getenv("MPEMTRANS_REAL_LIBRARY");
    (void)once; (void)value; (void)context;
    if (path && strlen(path) > 3 && path[1] == ':' && (path[2] == '/' || path[2] == '\\'))
        real_library = LoadLibraryExA(path, NULL, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    return TRUE;
}
static void *proxy_symbol(const char *name) {
    InitOnceExecuteOnce(&initialized, load_real, NULL, NULL);
    return real_library ? (void *)GetProcAddress(real_library, name) : NULL;
}
#else
#include <dlfcn.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#define PROXY_CALL
static void *real_library;
static pthread_once_t initialized = PTHREAD_ONCE_INIT;
static void load_real(void) {
    const char *path = getenv("MPEMTRANS_REAL_LIBRARY");
    if (path && path[0] == '/') real_library = dlopen(path, RTLD_NOW | RTLD_LOCAL);
}
static void *proxy_symbol(const char *name) {
    pthread_once(&initialized, load_real);
    return real_library ? dlsym(real_library, name) : NULL;
}
#endif

static int plain_string(const char *text, size_t maximum) {
    size_t i;
    for (i = 0; i <= maximum; i++) {
        unsigned char value = (unsigned char)text[i];
        if (!value) return i > 0;
        if (value < 32 || value > 126) return 0;
    }
    return 0;
}

static int save_exclusive(const char *name, const char *value) {
    const char *directory = getenv("MPEMTRANS_CAPTURE_DIRECTORY");
    char path[4096];
    int fd;
    size_t length = strlen(value);
    if (!directory || snprintf(path, sizeof(path), "%s/%s", directory, name) >= (int)sizeof(path)) return 0;
#ifdef _WIN32
    /* The setup runner creates the directory with an owner-only protected ACL. */
    fd = _open(path, _O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY, _S_IREAD | _S_IWRITE);
    if (fd < 0) return 0;
    if (_write(fd, value, (unsigned)length) != (int)length) { _close(fd); return 0; }
    _close(fd);
#else
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) return 0;
    if (write(fd, value, length) != (ssize_t)length) { close(fd); return 0; }
    close(fd);
#endif
    return 1;
}

static void capture_values(const char *label, const char *password) {
    if (!plain_string(label, 64) || !plain_string(password, 256)) return;
    /* Exclusive creation keeps the first observed pair and refuses overwrites.
     * The caller validates both files after MIS has stopped. */
    if (save_exclusive("label.capture", label)) save_exclusive("password.capture", password);
}
#include "proxy_api.inc"
