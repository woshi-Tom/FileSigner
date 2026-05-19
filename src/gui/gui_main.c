/* gui_main.c — Pure C11 Sciter GUI for FileSigner
 *
 * Registers native functions on the view's expando (SciterGetViewExpando + 
 * ValueNativeFunctorSet), no C++ or sciter::window needed.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define _CRT_SECURE_NO_WARNINGS
#include "sciter-x.h"
#include "resource.h"

#include "batch_signer.h"
#include "cert_gen.h"
#include "timestamp.h"

/* ----------------------------------------------------------------- */
/* Constants                                                         */
/* ----------------------------------------------------------------- */

#define WM_SCITER_EVAL  (WM_APP + 100)
#define MAX_STR         1024

/* ----------------------------------------------------------------- */
/* Globals                                                           */
/* ----------------------------------------------------------------- */

static HWND g_hwnd = NULL;   /* main Sciter window (HWINDOW == HWND) */

/* ----------------------------------------------------------------- */
/* VALUE helpers                                                     */
/* ----------------------------------------------------------------- */

static int
val_to_int(const VALUE *v, int fallback)
{
    INT val = 0;
    return (ValueIntData(v, &val) == HV_OK) ? (int)val : fallback;
}

/* Copy VALUE string into a UTF-8 buffer; returns bytes written. */
static int
val_to_utf8(const VALUE *v, char *buf, int size)
{
    LPCWSTR ws;
    UINT    nchars;

    buf[0] = '\0';
    if (ValueStringData(v, &ws, &nchars) != HV_OK || !ws || nchars == 0)
        return 0;

    int n = WideCharToMultiByte(CP_UTF8, 0, ws, (int)nchars,
                                 buf, size - 1, NULL, NULL);
    if (n > 0) buf[n] = '\0';
    else       buf[0] = '\0';
    return n;
}

/* ----------------------------------------------------------------- */
/* Thread-safe script eval — posts to main thread via custom msg      */
/* ----------------------------------------------------------------- */

static void
ui_eval_async(const char *utf8)
{
    if (!g_hwnd) return;

    int wlen = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, NULL, 0);
    if (wlen <= 0) return;

    LPWSTR ws = (LPWSTR)malloc((size_t)wlen * sizeof(WCHAR));
    if (!ws) return;

    MultiByteToWideChar(CP_UTF8, 0, utf8, -1, ws, wlen);
    PostMessageW(g_hwnd, WM_SCITER_EVAL, 0, (LPARAM)ws);
}

/* Escape a UTF-8 string for embedding in a TIScript double-quoted literal. */
static void
escape_js_string(const char *src, char *dst, size_t dst_size)
{
    size_t j = 0;
    for (size_t i = 0; src[i] && j < dst_size - 6; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '\\')       { dst[j++] = '\\'; dst[j++] = '\\'; }
        else if (c == '"')   { dst[j++] = '\\'; dst[j++] = '"'; }
        else if (c == '\n')  { dst[j++] = '\\'; dst[j++] = 'n'; }
        else if (c == '\r')  { }
        else if (c < 0x20)   { }
        else                 { dst[j++] = (char)c; }
    }
    dst[j] = '\0';
}

/* ----------------------------------------------------------------- */
/* Batch-sign progress callback (worker thread)                      */
/* ----------------------------------------------------------------- */

static void
batch_progress(const char *filename, int current, int total,
               int success, void *user_data)
{
    (void)user_data;
    char buf[2048], esc[1024];

    int pct = (total > 0) ? (current * 100) / total : 0;
    snprintf(buf, sizeof(buf), "onProgress(%d)", pct);
    ui_eval_async(buf);

    escape_js_string(filename, esc, sizeof(esc));
    snprintf(buf, sizeof(buf), "onLog(\"%s\",\"%s\")",
             esc, success ? "ok" : "fail");
    ui_eval_async(buf);
}

/* Parameters passed to the worker thread. */
typedef struct {
    char target[MAX_PATH];
    char pfx[MAX_PATH];
    char password[256];
    char tsa_url[512];
    char outdir[MAX_PATH];
    int  recursive;
    int  force;
    int  debug;
} SignParams;

static DWORD WINAPI
sign_worker(LPVOID param)
{
    SignParams *p = (SignParams *)param;

    int count = batch_sign(p->target, p->pfx,
                           p->password[0] ? p->password : NULL,
                           p->tsa_url[0]  ? p->tsa_url  : NULL,
                           p->outdir[0]   ? p->outdir   : NULL,
                           p->force, p->recursive,
                           batch_progress, NULL);

    char buf[128];
    snprintf(buf, sizeof(buf), "onSignComplete(%d)", count);
    ui_eval_async(buf);

    free(p);
    return 0;
}

/* ----------------------------------------------------------------- */
/* Native functor: start_sign(target, pfx, password, tsa_url,        */
/*                            outdir, recursive, force, debug)        */
/* Spawns a worker thread, returns immediately.                      */
/* ----------------------------------------------------------------- */

static VOID
invoke_start_sign(VOID *tag, UINT argc, const VALUE *argv, VALUE *retval)
{
    (void)tag; (void)retval;

    if (argc < 8) return;

    SignParams *p = (SignParams *)calloc(1, sizeof(SignParams));
    if (!p) return;

    val_to_utf8(&argv[0], p->target,   sizeof(p->target));
    val_to_utf8(&argv[1], p->pfx,      sizeof(p->pfx));
    val_to_utf8(&argv[2], p->password, sizeof(p->password));
    val_to_utf8(&argv[3], p->tsa_url,  sizeof(p->tsa_url));
    val_to_utf8(&argv[4], p->outdir,   sizeof(p->outdir));
    p->recursive = val_to_int(&argv[5], 0);
    p->force     = val_to_int(&argv[6], 0);
    p->debug     = val_to_int(&argv[7], 0);

    HANDLE h = CreateThread(NULL, 0, sign_worker, p, 0, NULL);
    if (h) CloseHandle(h);
    else   free(p);
}

/* ----------------------------------------------------------------- */
/* Native functor: generate_cert(dir, pw, days, cn, email)           */
/* ----------------------------------------------------------------- */

static VOID
invoke_generate_cert(VOID *tag, UINT argc, const VALUE *argv, VALUE *retval)
{
    (void)tag;
    if (argc < 5) return;

    char outdir[MAX_PATH] = {0};
    char pw[256]          = {0};
    char cn[256]          = {0};
    char email[256]       = {0};
    int  days;

    val_to_utf8(&argv[0], outdir, sizeof(outdir));
    val_to_utf8(&argv[1], pw,     sizeof(pw));
    days    = val_to_int(&argv[2], 90);
    val_to_utf8(&argv[3], cn,     sizeof(cn));
    val_to_utf8(&argv[4], email,  sizeof(email));

    /* Ensure output directory exists */
    CreateDirectoryA(outdir, NULL);

    int ok = cert_generate(outdir,
                           NULL,        /* ca_password  — no password for CA key */
                           pw[0] ? pw : NULL,
                           days,
                           cn[0]  ? cn  : NULL,
                           email[0] ? email : NULL);

    ValueIntDataSet(retval, ok ? 1 : 0, T_BOOL, 0);
}

/* ----------------------------------------------------------------- */
/* Native functor: browse_folder() — returns selected folder path    */
/* ----------------------------------------------------------------- */

static VOID
invoke_browse_folder(VOID *tag, UINT argc, const VALUE *argv, VALUE *retval)
{
    (void)tag; (void)argc; (void)argv;

    BROWSEINFOW bi;
    memset(&bi, 0, sizeof(bi));
    bi.hwndOwner = g_hwnd;
    bi.lpszTitle = L"选择目录";
    bi.ulFlags   = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;

    LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
    if (pidl) {
        WCHAR path[MAX_PATH];
        if (SHGetPathFromIDListW(pidl, path)) {
            ValueStringDataSet(retval, path, (UINT)wcslen(path),
                               UT_STRING_STRING);
        }
        CoTaskMemFree(pidl);
    }
    /* If user cancelled, retval stays undefined → TIScript gets undefined */
}

/* ----------------------------------------------------------------- */
/* Native functor: browse_file(filter) — returns selected file path   */
/* The filter string is null-separated like "PFX\0*.pfx;*.p12\0..."  */
/* as constructed in TIScript via String.fromCharCode(0).             */
/* ----------------------------------------------------------------- */

static VOID
invoke_browse_file(VOID *tag, UINT argc, const VALUE *argv, VALUE *retval)
{
    (void)tag;

    LPCWSTR filter_str = NULL;
    UINT    filter_len = 0;
    WCHAR   default_filter[] = L"All Files\0*.*\0";

    if (argc > 0)
        ValueStringData(&argv[0], &filter_str, &filter_len);

    WCHAR file_buf[MAX_PATH] = {0};

    OPENFILENAMEW ofn;
    memset(&ofn, 0, sizeof(ofn));
    ofn.lStructSize  = sizeof(ofn);
    ofn.hwndOwner    = g_hwnd;
    ofn.lpstrFile    = file_buf;
    ofn.nMaxFile     = MAX_PATH;
    ofn.lpstrFilter  = (filter_str && filter_len > 0) ? filter_str : default_filter;
    ofn.nFilterIndex = 1;
    ofn.Flags        = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;

    if (GetOpenFileNameW(&ofn)) {
        ValueStringDataSet(retval, file_buf, (UINT)wcslen(file_buf),
                           UT_STRING_STRING);
    }
}

/* ----------------------------------------------------------------- */
/* Native functor: test_tsa(url) — returns bool                      */
/* ----------------------------------------------------------------- */

static VOID
invoke_test_tsa(VOID *tag, UINT argc, const VALUE *argv, VALUE *retval)
{
    (void)tag;
    if (argc < 1) return;

    char url[512];
    val_to_utf8(&argv[0], url, sizeof(url));

    int ok = timestamp_test_server(url);
    ValueIntDataSet(retval, ok ? 1 : 0, T_BOOL, 0);
}

/* ----------------------------------------------------------------- */
/* Register all native functions on the view's expando as             */
/* view.frame.methodName(...)                                         */
/* ----------------------------------------------------------------- */

static void
register_native_functions(HWINDOW hwnd)
{
    VALUE expando, frame, key, func;

    ValueInit(&expando);
    ValueInit(&frame);
    ValueInit(&key);
    ValueInit(&func);

    /* Get the view's global namespace (accessible as "view" in TIScript) */
    SciterGetViewExpando(hwnd, &expando);

    /* ---- Build the "frame" sub-object ---- */
    /* (so TIScript calls view.frame.start_sign(...) etc.) */

#define REGISTER_METHOD(method_name, handler)                          \
    do {                                                               \
        ValueNativeFunctorSet(&func, handler, NULL, NULL);             \
        WCHAR wname[64];                                               \
        MultiByteToWideChar(CP_UTF8, 0, method_name, -1, wname, 64);  \
        ValueStringDataSet(&key, wname, (UINT)wcslen(wname),           \
                           UT_STRING_STRING);                           \
        ValueSetValueToKey(&frame, &key, &func);                       \
        ValueClear(&key);                                              \
        ValueClear(&func);                                             \
    } while (0)

    REGISTER_METHOD("start_sign",     invoke_start_sign);
    REGISTER_METHOD("generate_cert",  invoke_generate_cert);
    REGISTER_METHOD("browse_folder",  invoke_browse_folder);
    REGISTER_METHOD("browse_file",    invoke_browse_file);
    REGISTER_METHOD("test_tsa",       invoke_test_tsa);

    /* ---- Set frame on view expando ---- */
    ValueStringDataSet(&key, L"frame", 5, UT_STRING_STRING);
    ValueSetValueToKey(&expando, &key, &frame);

    ValueClear(&key);
    ValueClear(&frame);
    ValueClear(&expando);

#undef REGISTER_METHOD
}

/* ----------------------------------------------------------------- */
/* Populate TSA server dropdown via TIScript setTSAServers()          */
/* ----------------------------------------------------------------- */

static void
populate_tsa_servers(HWINDOW hwnd)
{
    WCHAR script[4096];
    wcscpy(script, L"setTSAServers([");
    int first = 1;

    for (int i = 0; i < TSA_SERVER_COUNT; i++) {
        if (!first) wcscat(script, L",");
        first = 0;

        WCHAR wlabel[128], wurl[512];
        MultiByteToWideChar(CP_UTF8, 0, g_tsa_servers[i].label, -1,
                             wlabel, 128);
        MultiByteToWideChar(CP_UTF8, 0, g_tsa_servers[i].url, -1,
                             wurl, 512);

        wcscat(script, L"{label:'");
        wcscat(script, wlabel);
        wcscat(script, L"',url:'");
        wcscat(script, wurl);
        wcscat(script, L"'}");
    }
    wcscat(script, L"]);");

    SciterEval(hwnd, script, (UINT)wcslen(script), NULL);
}

/* ----------------------------------------------------------------- */
/* Sciter host callback — resource loading, engine lifecycle          */
/* ----------------------------------------------------------------- */

static UINT SC_CALLBACK
host_callback(LPSCITER_CALLBACK_NOTIFICATION pns, LPVOID param)
{
    (void)param;

    switch (pns->code) {
    case SC_ENGINE_DESTROYED:
        PostQuitMessage(0);
        return 0;
    case SC_LOAD_DATA:
        /* Let Sciter handle resource loading via built-in file loader */
        return LOAD_OK;
    default:
        return 0;
    }
}

/* ----------------------------------------------------------------- */
/* Sciter window delegate — receives Win32 messages forwarded by      */
/* Sciter's internal WndProc.                                         */
/* ----------------------------------------------------------------- */

static LRESULT SC_CALLBACK
wnd_delegate(HWINDOW hwnd, UINT msg, WPARAM wParam,
             LPARAM lParam, LPVOID pParam, SBOOL *handled)
{
    (void)pParam;

    switch (msg) {
    case WM_DESTROY:
        PostQuitMessage(0);
        *handled = TRUE;
        return 0;

    case WM_SCITER_EVAL: {
        /* Execute a script string that was posted from a worker thread */
        LPCWSTR script = (LPCWSTR)lParam;
        if (script) {
            SciterEval(hwnd, script, (UINT)wcslen(script), NULL);
            free((void *)script);
        }
        *handled = TRUE;
        return 0;
    }
    }

    *handled = FALSE;
    return 0;
}

/* ----------------------------------------------------------------- */
/* Entry point — called from main.c :: WinMain                       */
/* ----------------------------------------------------------------- */

int
gui_main(HINSTANCE hInstance, HINSTANCE hPrevInstance,
         LPSTR lpCmdLine, int nCmdShow)
{
    (void)hPrevInstance;
    (void)lpCmdLine;

    /* Needed for COM-based dialogs (SHBrowseForFolder) and drag-n-drop */
    OleInitialize(NULL);

    /* --- Create the Sciter window --- */
    RECT frame = { 100, 100, 700, 600 };
    HWINDOW hwnd = SciterCreateWindow(
        SW_TITLEBAR | SW_RESIZEABLE | SW_CONTROLS | SW_MAIN,
        &frame,
        wnd_delegate,
        NULL,
        NULL
    );

    if (!hwnd) {
        MessageBoxA(NULL, "Failed to create Sciter window.",
                     "FileSigner", MB_ICONERROR);
        OleUninitialize();
        return 1;
    }

    g_hwnd = (HWND)hwnd;

    /* Window title */
    SetWindowTextW(g_hwnd, L"FileSigner");

    /* --- Set host callback (resource loading, engine destroyed) --- */
    SciterSetCallback(hwnd, host_callback, NULL);

    /* --- Enable "unisex" UX theming --- */
    SciterSetOption(hwnd, SCITER_SET_UX_THEMING, TRUE);

    /* --- Load the UI file --- */
    /* Try exe-directory/ui/main.html first, then source tree fallback */

    {   WCHAR path[MAX_PATH];
        GetModuleFileNameW(NULL, path, MAX_PATH);
        WCHAR *slash = wcsrchr(path, L'\\');
        if (slash) *slash = L'\0';
        wcscat_s(path, MAX_PATH, L"\\ui\\main.html");

        if (!SciterLoadFile(hwnd, path)) {
            /* Fallback: running from build directory */
            SciterLoadFile(hwnd, L"src/gui/ui/main.html");
        }
    }

    /* --- Register native functions --- */
    register_native_functions(hwnd);

    /* --- Populate TSA server dropdown --- */
    populate_tsa_servers(hwnd);

    /* --- Show window --- */
    ShowWindow(g_hwnd, nCmdShow);
    UpdateWindow(g_hwnd);

    /* --- Message loop --- */
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    /* Cancel any remaining eval messages in the queue */
    MSG dummy;
    while (PeekMessage(&dummy, NULL, WM_SCITER_EVAL, WM_SCITER_EVAL, PM_REMOVE)) {
        free((void *)dummy.lParam);
    }

    OleUninitialize();
    return (int)msg.wParam;
}
