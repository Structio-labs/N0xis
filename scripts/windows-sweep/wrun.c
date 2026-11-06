/* The sweep's hands on Windows: one long-lived process over ssh that starts each case the way a person's shell would, at
   below-normal priority, with its standard streams kept apart. Every field on the wire is base64, so nothing between here and
   the other machine (a shell, a code page, a line ending) can change a byte of what a case printed or was given.
   PowerShell is not used for this: it adds a second of start-up per case, and its text is what Defender's script scanner reads.

   In:  id exe cmdline cwd env stdin timeout_ms kill_after_ms close_stdout_after, one line per case, "-" for an empty field.
   Out: R id rc ms timed_out killed low_memory peak_ws start_error, then one line of base64 stdout and one of stderr. */
#define PSAPI_VERSION 2
#include <windows.h>
#include <psapi.h>
#include <fcntl.h>
#include <io.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOW_MEMORY (300ull << 20) /* a case is stopped before it can take the owner's desktop down with it */

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *decode(const char *s, size_t *out_len) {
    size_t n = strlen(s), o = 0;
    unsigned char *r = malloc(n / 4 * 3 + 4);
    unsigned v = 0; int bits = 0;
    for (size_t i = 0; i < n; i++) {
        const char *p = s[i] == '=' ? NULL : strchr(B64, s[i]);
        if (!p) continue;
        v = (v << 6) | (unsigned)(p - B64); bits += 6;
        if (bits >= 8) { bits -= 8; r[o++] = (v >> bits) & 0xff; }
    }
    r[o] = 0;
    if (out_len) *out_len = o;
    return (char *)r;
}

static void put_encoded(const unsigned char *d, size_t n) {
    char q[4];
    for (size_t i = 0; i < n; i += 3) {
        unsigned v = d[i] << 16 | (i + 1 < n ? d[i + 1] << 8 : 0) | (i + 2 < n ? d[i + 2] : 0);
        q[0] = B64[v >> 18]; q[1] = B64[(v >> 12) & 63];
        q[2] = i + 1 < n ? B64[(v >> 6) & 63] : '=';
        q[3] = i + 2 < n ? B64[v & 63] : '=';
        fwrite(q, 1, 4, stdout);
    }
    fputc('\n', stdout);
}

static wchar_t *wide(const char *s) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    wchar_t *w = malloc(sizeof(wchar_t) * (n + 1));
    MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
    return w;
}

struct sink { HANDLE h; unsigned char *d; size_t n, cap; long long close_after; };

static DWORD WINAPI drain(void *arg) {
    struct sink *s = arg;
    for (;;) {
        if (s->n + 65536 > s->cap) { s->cap = s->cap ? s->cap * 2 : 1 << 20; s->d = realloc(s->d, s->cap); }
        DWORD got = 0;
        if (!ReadFile(s->h, s->d + s->n, 65536, &got, NULL) || got == 0) break;
        s->n += got;
        /* the reader that goes away after the first bytes, as `| head -1` does */
        if (s->close_after >= 0 && (long long)s->n >= s->close_after) break;
    }
    CloseHandle(s->h); s->h = NULL;
    return 0;
}

struct feed { HANDLE h; const char *d; size_t n; };

static DWORD WINAPI give(void *arg) {
    struct feed *f = arg;
    DWORD wrote;
    size_t at = 0;
    while (at < f->n && WriteFile(f->h, f->d + at, (DWORD)(f->n - at), &wrote, NULL)) at += wrote;
    CloseHandle(f->h);
    return 0;
}

static void set_env(char *block, int set) {
    for (char *line = strtok(block, "\n"); line; line = strtok(NULL, "\n")) {
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = 0;
        wchar_t *k = wide(line), *v = wide(eq + 1);
        SetEnvironmentVariableW(k, set ? v : NULL);
        free(k); free(v);
        *eq = '=';
    }
}

static void run_case(char **f) {
    char *exe = decode(f[1], NULL), *line = decode(f[2], NULL), *cwd = decode(f[3], NULL), *env = decode(f[4], NULL);
    size_t stdin_len; char *in = decode(f[5], &stdin_len);
    long long timeout = atoll(f[6]), kill_after = atoll(f[7]), close_after = atoll(f[8]);
    SECURITY_ATTRIBUTES sa = {sizeof sa, NULL, TRUE};
    HANDLE in_r, in_w, out_r, out_w, err_r, err_w;
    CreatePipe(&in_r, &in_w, &sa, 0); CreatePipe(&out_r, &out_w, &sa, 0); CreatePipe(&err_r, &err_w, &sa, 0);
    SetHandleInformation(in_w, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(out_r, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(err_r, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOW si; memset(&si, 0, sizeof si); si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES; si.hStdInput = in_r; si.hStdOutput = out_w; si.hStdError = err_w;
    PROCESS_INFORMATION pi; memset(&pi, 0, sizeof pi);
    char *env_copy = _strdup(env);
    set_env(env_copy, 1);
    wchar_t *wexe = wide(exe), *wline = wide(line), *wcwd = wide(cwd);
    ULONGLONG t0 = GetTickCount64();
    BOOL started = CreateProcessW(wexe, wline, NULL, NULL, TRUE, BELOW_NORMAL_PRIORITY_CLASS | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, NULL, wcwd[0] ? wcwd : NULL, &si, &pi);
    DWORD start_error = started ? 0 : GetLastError();
    free(env_copy); env_copy = _strdup(env);
    set_env(env_copy, 0);
    CloseHandle(in_r); CloseHandle(out_w); CloseHandle(err_w);
    struct sink so = {out_r, NULL, 0, 0, close_after}, se = {err_r, NULL, 0, 0, -1};
    struct feed fd = {in_w, in, stdin_len};
    HANDLE ht[2] = {CreateThread(NULL, 0, drain, &so, 0, NULL), CreateThread(NULL, 0, drain, &se, 0, NULL)};
    CloseHandle(CreateThread(NULL, 0, give, &fd, 0, NULL));
    int timed_out = 0, killed = 0, low = 0;
    DWORD rc = 0; SIZE_T peak = 0; int have_rc = 0;
    if (started) {
        for (;;) {
            ULONGLONG el = GetTickCount64() - t0;
            DWORD step = 200;
            if (kill_after >= 0 && !killed && (ULONGLONG)kill_after > el && (ULONGLONG)kill_after - el < step) step = (DWORD)(kill_after - el);
            if (WaitForSingleObject(pi.hProcess, step) == WAIT_OBJECT_0) break;
            el = GetTickCount64() - t0;
            PROCESS_MEMORY_COUNTERS pm; pm.cb = sizeof pm;
            if (GetProcessMemoryInfo(pi.hProcess, &pm, sizeof pm) && pm.PeakWorkingSetSize > peak) peak = pm.PeakWorkingSetSize;
            MEMORYSTATUSEX ms; ms.dwLength = sizeof ms;
            if (GlobalMemoryStatusEx(&ms) && ms.ullAvailPhys < LOW_MEMORY) { low = 1; TerminateProcess(pi.hProcess, 0xDEAD); break; }
            if (kill_after >= 0 && !killed && el >= (ULONGLONG)kill_after) { killed = 1; TerminateProcess(pi.hProcess, 9); }
            if (timeout > 0 && el >= (ULONGLONG)timeout) { timed_out = 1; TerminateProcess(pi.hProcess, 0xDEAD); break; }
        }
        WaitForSingleObject(pi.hProcess, 5000);
        have_rc = GetExitCodeProcess(pi.hProcess, &rc);
        PROCESS_MEMORY_COUNTERS pm; pm.cb = sizeof pm;
        if (GetProcessMemoryInfo(pi.hProcess, &pm, sizeof pm) && pm.PeakWorkingSetSize > peak) peak = pm.PeakWorkingSetSize;
    }
    /* A process the case started can hold the pipe open past the case. */
    if (WaitForMultipleObjects(2, ht, TRUE, 5000) != WAIT_OBJECT_0) {
        CancelIoEx(so.h, NULL); CancelIoEx(se.h, NULL);
        WaitForMultipleObjects(2, ht, TRUE, 2000);
    }
    ULONGLONG ms = GetTickCount64() - t0;
    if (started && have_rc) printf("R %s %lu %llu %d %d %d %llu %lu\n", f[0], rc, ms, timed_out, killed, low, (unsigned long long)peak, start_error);
    else printf("R %s none %llu %d %d %d %llu %lu\n", f[0], ms, timed_out, killed, low, (unsigned long long)peak, start_error);
    put_encoded(so.d, so.n); put_encoded(se.d, se.n);
    fflush(stdout);
    if (pi.hProcess) { CloseHandle(pi.hProcess); CloseHandle(pi.hThread); }
    free(so.d); free(se.d); free(exe); free(line); free(cwd); free(env); free(in); free(env_copy); free(wexe); free(wline); free(wcwd);
}

int main(void) {
    _setmode(_fileno(stdout), _O_BINARY);
    _setmode(_fileno(stdin), _O_BINARY);
    static char line[64 << 20];
    printf("HELLO\n"); fflush(stdout);
    while (fgets(line, sizeof line, stdin)) {
        char *f[9]; int n = 0;
        for (char *t = strtok(line, " \r\n"); t && n < 9; t = strtok(NULL, " \r\n")) f[n++] = strcmp(t, "-") == 0 ? "" : t;
        if (n == 9) run_case(f);
    }
    return 0;
}
