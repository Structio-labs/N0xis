/* ctrlsend <c|break|kill|none> <delay_ms> <exe> [args...]: runs the command on a console of its own, in a new process
   group when it can, and after the delay sends it that console event. Prints the exit code as it saw it. The fix pass's
   way of doing to n0xis what a person at a console does, with no person and no visible window. */
#include <windows.h>
#include <stdio.h>
#include <string.h>
static BOOL WINAPI ignore(DWORD k) { (void)k; return TRUE; }
int main(int argc, char **argv) {
    if (argc < 4) return 64;
    const char *how = argv[1]; int delay = atoi(argv[2]);
    /* the tool's answer goes to a file by way of our own handles: a new console must not take stdout from it */
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE), err = GetStdHandle(STD_ERROR_HANDLE);
    FreeConsole();
    AllocConsole();
    ShowWindow(GetConsoleWindow(), SW_HIDE);
    /* a process started in a new group, as under ssh, has Ctrl-C off, and its children inherit that */
    SetConsoleCtrlHandler(NULL, FALSE);
    SetConsoleCtrlHandler(ignore, TRUE);
    char line[8192] = "";
    for (int i = 3; i < argc; i++) { strcat(line, "\""); strcat(line, argv[i]); strcat(line, "\" "); }
    STARTUPINFOA si; memset(&si, 0, sizeof si); si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES; si.hStdOutput = out; si.hStdError = err;
    si.hStdInput = CreateFileA("CONIN$", GENERIC_READ | GENERIC_WRITE, 3, 0, OPEN_EXISTING, 0, 0);
    SetHandleInformation(out, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    SetHandleInformation(err, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    SECURITY_ATTRIBUTES sa = {sizeof sa, 0, TRUE};
    (void)sa;
    PROCESS_INFORMATION pi;
    /* CTRL_C_EVENT is ignored in a new process group, so only Ctrl-Break gets one */
    DWORD flags = strcmp(how, "break") == 0 ? CREATE_NEW_PROCESS_GROUP : 0;
    if (!CreateProcessA(0, line, 0, 0, TRUE, flags, 0, 0, &si, &pi)) { printf("CreateProcess failed %lu\n", GetLastError()); return 65; }
    Sleep(delay);
    if (strcmp(how, "c") == 0) GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0);
    else if (strcmp(how, "break") == 0) GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pi.dwProcessId);
    else if (strcmp(how, "kill") == 0) TerminateProcess(pi.hProcess, 9);
    DWORD w = WaitForSingleObject(pi.hProcess, 20000);
    DWORD code = 0; GetExitCodeProcess(pi.hProcess, &code);
    fflush(stdout);
    char buf[128]; int n = snprintf(buf, sizeof buf, "\nTOOL_EXIT wait=%lu code=%lu\n", w, code);
    DWORD wrote; WriteFile(out, buf, n, &wrote, 0);
    if (w != WAIT_OBJECT_0) TerminateProcess(pi.hProcess, 9);
    return 0;
}
