#define WIN32_LEAN_AND_MEAN
#define UNICODE
#include <windows.h>
#include <dwmapi.h>
#ifndef DWMWA_USE_IMMERSIVE_DARK_MODE
#define DWMWA_USE_IMMERSIVE_DARK_MODE 20
#endif
#include <commdlg.h>
#include <shlobj.h>
#include <commctrl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#include "authenticode.h"
#include "batch_signer.h"
#include "cert_gen.h"
#include "timestamp.h"
#include "resource.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "ole32.lib")

/* Control IDs */
#define IDC_TAB             100

#define IDC_EDIT_TARGET     201
#define IDC_BTN_BROWSE_TGT  202
#define IDC_EDIT_PFX        203
#define IDC_BTN_BROWSE_PFX  204
#define IDC_EDIT_PASSWORD   205
#define IDC_COMBO_TSA       206
#define IDC_BTN_TEST_TSA    207
#define IDC_CHK_RECURSIVE   208
#define IDC_CHK_FORCE       209
#define IDC_EDIT_OUTDIR     210
#define IDC_BTN_BROWSE_OUT  211
#define IDC_BTN_SIGN        212
#define IDC_PROGRESS        213
#define IDC_LIST_LOG        214
#define IDC_LBL_LOG_TITLE   215
#define IDC_SEP_SIGN        216
#define IDC_CHK_DEBUG       217

#define IDC_EDIT_CERT_DIR   301
#define IDC_BTN_BROWSE_CD   302
#define IDC_EDIT_CERT_DAYS  303
#define IDC_BTN_GENERATE    304
#define IDC_LBL_CERT_STATUS 305
#define IDC_EDIT_CERT_PW    306
#define IDC_EDIT_CERT_CN    307
#define IDC_EDIT_CERT_EMAIL 308
#define IDC_LBL_CERT_TITLE  309
#define IDC_SEP_CERT        310

#define WM_APP_LOG          (WM_APP + 1)
#define WM_APP_PROGRESS     (WM_APP + 2)
#define WM_APP_SIGN_DONE    (WM_APP + 3)

#define GUI_PATH_LEN    4096

/* Layout */
#define PAD             16
#define LH              18
#define EH              28
#define W_CLIENT        800
#define W_EDIT           560
#define W_BROWSE         86
#define PAGE_H          660

#define LOG_COLOR_INFO  0
#define LOG_COLOR_OK    1
#define LOG_COLOR_FAIL  2
#define LOG_COLOR_SKIP  3

typedef struct {
    HWND hwnd;
    char target[GUI_PATH_LEN];
    char pfx[GUI_PATH_LEN];
    char password[256];
    char ts_url[512];
    char outdir[GUI_PATH_LEN];
    int recursive;
    int force;
} SignTask;

static HINSTANCE g_hInst;
static HFONT g_hFont;
static HFONT g_hFontSection;
static HFONT g_hMonoFont;
static HBRUSH g_hbrBg, g_hbrLogBg, g_hbrEditBg, g_hbrBtnFace, g_hbrAccent;

static COLORREF g_clrBg       = RGB(244, 245, 248);
static COLORREF g_clrLogBg    = RGB(34, 35, 38);
static COLORREF g_clrLogText  = RGB(232, 233, 237);
static COLORREF g_clrAccent   = RGB(94, 106, 210);
static COLORREF g_clrText     = RGB(43, 43, 47);
static COLORREF g_clrLabel    = RGB(100, 104, 112);
static COLORREF g_clrEditBg   = RGB(255, 255, 255);
static COLORREF g_clrBorder   = RGB(208, 214, 224);

static HWND g_hwndMain, g_hTab, g_hPageSign, g_hPageCert, g_hProgress, g_hLog;
static HANDLE g_hThread;
static const COLORREF g_log_colors[] = {
    RGB(232, 233, 237),
    RGB(74, 222, 128),
    RGB(248, 113, 113),
    RGB(155, 155, 173),
};

/* ---------------------------------------------------------------- */
/* Helpers                                                          */
/* ---------------------------------------------------------------- */

static void
wide_from_utf8(const char *src, wchar_t *dst, int dst_chars)
{
    if (!src || !dst || dst_chars <= 0) { if (dst && dst_chars > 0) dst[0] = L'\0'; return; }
    if (!src[0]) { dst[0] = L'\0'; return; }
    MultiByteToWideChar(CP_UTF8, 0, src, -1, dst, dst_chars);
}

static void
wide_to_utf8(const wchar_t *src, char *dst, int dst_chars)
{
    if (!src || !src[0]) { dst[0] = '\0'; return; }
    WideCharToMultiByte(CP_UTF8, 0, src, -1, dst, dst_chars, NULL, NULL);
}

static void
log_scroll_bottom(void)
{
    int count = (int)SendMessageW(g_hLog, LB_GETCOUNT, 0, 0);
    if (count <= 0) return;
    RECT rc;
    GetClientRect(g_hLog, &rc);
    int itemH = (int)SendMessageW(g_hLog, LB_GETITEMHEIGHT, 0, 0);
    if (itemH <= 0) itemH = 16;
    int visible = rc.bottom / itemH;
    if (visible <= 0) visible = 1;
    int top = count - visible;
    if (top < 0) top = 0;
    SendMessageW(g_hLog, LB_SETTOPINDEX, top, 0);
}

static void
log_message(int color, const wchar_t *fmt, ...)
{
    wchar_t buf[2048];
    va_list args;
    va_start(args, fmt);
    vswprintf(buf, sizeof(buf) / sizeof(wchar_t), fmt, args);
    va_end(args);
    int idx = (int)SendMessageW(g_hLog, LB_ADDSTRING, 0, (LPARAM)buf);
    SendMessageW(g_hLog, LB_SETITEMDATA, (WPARAM)idx, (LPARAM)color);
    log_scroll_bottom();
}

static HWND
make_ctrl(HWND parent, const wchar_t *cls, const wchar_t *text,
          DWORD style, int x, int y, int w, int ht, int id)
{
    HWND hw = CreateWindowExW(0, cls, text,
                               WS_CHILD | WS_VISIBLE | style,
                               x, y, w, ht,
                               parent, (HMENU)(INT_PTR)id, g_hInst, NULL);
    SendMessageW(hw, WM_SETFONT, (WPARAM)g_hFont, TRUE);
    return hw;
}

static HWND
make_edit(HWND parent, const wchar_t *text, int x, int y, int w, int id)
{
    return make_ctrl(parent, L"EDIT", text,
                     WS_BORDER | ES_AUTOHSCROLL, x, y, w, EH, id);
}

static BOOL CALLBACK
set_font_cb(HWND child, LPARAM lp)
{
    (void)lp;
    SendMessageW(child, WM_SETFONT, (WPARAM)g_hFont, TRUE);
    return TRUE;
}

static void
apply_font(HWND parent)
{
    EnumChildWindows(parent, (WNDENUMPROC)set_font_cb, 0);
}

static int g_debug;

/* ---------------------------------------------------------------- */
/* Sign page                                                        */
/* ---------------------------------------------------------------- */

static void
create_sign_page(HWND parent)
{
    int edit_x = W_CLIENT - 2*PAD - W_BROWSE - 6;

    g_hPageSign = CreateWindowExW(0, L"STATIC", L"",
                                   WS_CHILD | WS_VISIBLE,
                                   PAD, 40, W_CLIENT - 2*PAD, PAGE_H,
                                   parent, NULL, g_hInst, NULL);

    int y = 8;

    make_ctrl(g_hPageSign, L"STATIC", L"  \u7B7E\u540D\u8BBE\u7F6E",
              SS_LEFT, 0, y, 300, LH + 2, 0);
    y += LH + 8;

    make_ctrl(g_hPageSign, L"STATIC", L"\u76EE\u6807 (\u6587\u4EF6\u6216\u76EE\u5F55):",
              0, 8, y, edit_x, LH, 0);
    y += LH + 3;
    make_edit(g_hPageSign, L"", 0, y, W_EDIT, IDC_EDIT_TARGET);
    make_ctrl(g_hPageSign, L"BUTTON", L"\u6D4F\u89C8...",
              BS_TEXT, W_EDIT + 6, y, W_BROWSE, EH, IDC_BTN_BROWSE_TGT);
    y += EH + 6;

    make_ctrl(g_hPageSign, L"STATIC", L"PFX \u8BC1\u4E66\u6587\u4EF6:",
              0, 8, y, edit_x, LH, 0);
    y += LH + 3;
    make_edit(g_hPageSign, L"", 0, y, W_EDIT, IDC_EDIT_PFX);
    make_ctrl(g_hPageSign, L"BUTTON", L"\u6D4F\u89C8...",
              BS_TEXT, W_EDIT + 6, y, W_BROWSE, EH, IDC_BTN_BROWSE_PFX);
    y += EH + 6;

    make_ctrl(g_hPageSign, L"STATIC", L"PFX \u5BC6\u7801:", 0, 8, y, edit_x, LH, 0);
    y += LH + 3;
    make_ctrl(g_hPageSign, L"EDIT", L"",
              WS_BORDER | ES_AUTOHSCROLL | ES_PASSWORD,
              0, y, 280, EH, IDC_EDIT_PASSWORD);
    y += EH + 6;

    make_ctrl(g_hPageSign, L"STATIC", L"\u65F6\u95F4\u6233\u670D\u52A1\u5668:",
              0, 8, y, edit_x, LH, 0);
    y += LH + 3;
    {
        HWND hCombo = CreateWindowExW(0, L"COMBOBOX", NULL,
            WS_BORDER | WS_CHILD | WS_VISIBLE | CBS_DROPDOWN | CBS_HASSTRINGS | WS_VSCROLL,
            0, y, W_EDIT - 90, 250,
            g_hPageSign, (HMENU)(INT_PTR)IDC_COMBO_TSA, g_hInst, NULL);
        SendMessageW(hCombo, WM_SETFONT, (WPARAM)g_hFont, TRUE);
        for (int i = 0; i < TSA_SERVER_COUNT; i++) {
            wchar_t wlabel[256];
            MultiByteToWideChar(CP_UTF8, 0, g_tsa_servers[i].label, -1, wlabel, 256);
            int idx = (int)SendMessageW(hCombo, CB_ADDSTRING, 0, (LPARAM)wlabel);
            SendMessageW(hCombo, CB_SETITEMDATA, (WPARAM)idx, (LPARAM)i);
        }
        SendMessageW(hCombo, CB_SETCURSEL, 0, 0);
    }
    make_ctrl(g_hPageSign, L"BUTTON", L"\u6D4B\u901F",
              BS_TEXT, W_EDIT - 86, y, 80, EH, IDC_BTN_TEST_TSA);
    y += EH + 6;

    make_ctrl(g_hPageSign, L"STATIC",
              L"\u8F93\u51FA\u76EE\u5F55 (\u53EF\u9009, \u7559\u7A7A = \u8986\u76D6\u539F\u6587\u4EF6):",
              0, 8, y, edit_x, LH, 0);
    y += LH + 3;
    make_edit(g_hPageSign, L"", 0, y, W_EDIT, IDC_EDIT_OUTDIR);
    make_ctrl(g_hPageSign, L"BUTTON", L"\u6D4F\u89C8...",
              BS_TEXT, W_EDIT + 6, y, W_BROWSE, EH, IDC_BTN_BROWSE_OUT);
    y += EH + 8;

    make_ctrl(g_hPageSign, L"BUTTON", L"\u5305\u542B\u5B50\u76EE\u5F55",
              BS_AUTOCHECKBOX, 4, y, 150, LH, IDC_CHK_RECURSIVE);
    make_ctrl(g_hPageSign, L"BUTTON", L"\u5F3A\u5236\u91CD\u65B0\u7B7E\u540D",
              BS_AUTOCHECKBOX, 170, y, 180, LH, IDC_CHK_FORCE);
    make_ctrl(g_hPageSign, L"BUTTON", L"\u8C03\u8BD5\u65E5\u5FD7",
              BS_AUTOCHECKBOX, 360, y, 120, LH, IDC_CHK_DEBUG);
    y += LH + 12;

    make_ctrl(g_hPageSign, L"STATIC", L"", SS_ETCHEDHORZ,
              0, y, W_CLIENT - 2*PAD, 2, IDC_SEP_SIGN);
    y += 10;

    make_ctrl(g_hPageSign, L"BUTTON", L"\u5F00\u59CB\u7B7E\u540D",
              BS_DEFPUSHBUTTON, 0, y, 130, EH + 4, IDC_BTN_SIGN);
    y += EH + 4 + 10;

    g_hProgress = make_ctrl(g_hPageSign, PROGRESS_CLASSW, L"",
                             0, 0, y, W_CLIENT - 2*PAD, 24, IDC_PROGRESS);
    SendMessageW(g_hProgress, PBM_SETRANGE32, 0, 100);
    SendMessageW(g_hProgress, PBM_SETBARCOLOR, 0, g_clrAccent);
    SendMessageW(g_hProgress, PBM_SETBKCOLOR, 0, g_clrBorder);
    y += 28;

    make_ctrl(g_hPageSign, L"STATIC", L"  \u65E5\u5FD7\u8F93\u51FA",
              SS_LEFT, 0, y, 300, LH + 2, IDC_LBL_LOG_TITLE);
    y += LH + 4;

    g_hLog = make_ctrl(g_hPageSign, L"LISTBOX", L"",
                        WS_BORDER | WS_VSCROLL | LBS_NOINTEGRALHEIGHT,
                        0, y, W_CLIENT - 2*PAD, 200, IDC_LIST_LOG);

    g_hMonoFont = CreateFontW(-14, 0, 0, 0, FW_NORMAL, 0, 0, 0,
                               DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY,
                               0, L"Consolas");
    if (!g_hMonoFont)
        g_hMonoFont = CreateFontW(-14, 0, 0, 0, FW_NORMAL, 0, 0, 0,
                                   DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY,
                                   0, L"Segoe UI");
    SendMessageW(g_hLog, WM_SETFONT, (WPARAM)g_hMonoFont, TRUE);
}

/* ---------------------------------------------------------------- */
/* Certificate page                                                 */
/* ---------------------------------------------------------------- */

static void
create_cert_page(HWND parent)
{
    g_hPageCert = CreateWindowExW(0, L"STATIC", L"",
                                   WS_CHILD | WS_VISIBLE,
                                   PAD, 40, W_CLIENT - 2*PAD, PAGE_H,
                                   parent, NULL, g_hInst, NULL);

    int y = 8;

    make_ctrl(g_hPageCert, L"STATIC", L"  \u8BC1\u4E66\u751F\u6210",
              SS_LEFT, 0, y, 300, LH + 2, IDC_LBL_CERT_TITLE);
    y += LH + 8;

    make_ctrl(g_hPageCert, L"STATIC",
              L"\u751F\u6210\u81EA\u7B7E\u540D\u6839 CA + \u4EE3\u7801\u7B7E\u540D\u8BC1\u4E66\u3002\n"
              L"\u5C06\u6839 CA \u5BFC\u5165 Windows \u53D7\u4FE1\u4EFB\u6839\u5B58\u50A8\u5373\u53EF\u4FE1\u4EFB\u7B7E\u540D\u3002",
              SS_LEFT, 8, y, W_CLIENT - 2*PAD - 16, 36, 0);
    y += 44;

    make_ctrl(g_hPageCert, L"STATIC", L"\u8F93\u51FA\u76EE\u5F55:",
              0, 8, y, W_CLIENT - 2*PAD, LH, 0);
    y += LH + 3;
    make_ctrl(g_hPageCert, L"EDIT", L"./certs",
              WS_BORDER | ES_AUTOHSCROLL,
              0, y, W_EDIT, EH, IDC_EDIT_CERT_DIR);
    make_ctrl(g_hPageCert, L"BUTTON", L"\u6D4F\u89C8...",
              BS_TEXT, W_EDIT + 6, y, W_BROWSE, EH, IDC_BTN_BROWSE_CD);
    y += EH + 8;

    make_ctrl(g_hPageCert, L"STATIC", L"\u7B7E\u540D\u8BC1\u4E66\u6709\u6548\u671F (\u5929):",
              0, 8, y, 180, LH, 0);
    y += LH + 3;
    make_ctrl(g_hPageCert, L"EDIT", L"90",
              WS_BORDER | ES_AUTOHSCROLL | ES_NUMBER,
              0, y, 80, EH, IDC_EDIT_CERT_DAYS);
    y += EH + 8;

    make_ctrl(g_hPageCert, L"STATIC", L"PFX \u5BC6\u7801 (\u7B7E\u540D\u65F6\u9700\u586B\u5199\u6B64\u5BC6\u7801):",
              0, 8, y, W_CLIENT - 2*PAD, LH, 0);
    y += LH + 3;
    make_edit(g_hPageCert, L"", 0, y, 280, IDC_EDIT_CERT_PW);
    y += EH + 8;

    make_ctrl(g_hPageCert, L"STATIC",
              L"\u7B7E\u540D\u8005\u59D3\u540D (CN, \u53EF\u9009, \u9ED8\u8BA4: FileSigner Code Signing):",
              0, 8, y, W_CLIENT - 2*PAD, LH, 0);
    y += LH + 3;
    make_edit(g_hPageCert, L"", 0, y, 280, IDC_EDIT_CERT_CN);
    y += EH + 8;

    make_ctrl(g_hPageCert, L"STATIC", L"\u7B7E\u540D\u8005\u90AE\u7BB1 (\u53EF\u9009):",
              0, 8, y, W_CLIENT - 2*PAD, LH, 0);
    y += LH + 3;
    make_edit(g_hPageCert, L"", 0, y, 280, IDC_EDIT_CERT_EMAIL);
    y += EH + 10;

    make_ctrl(g_hPageCert, L"STATIC", L"", SS_ETCHEDHORZ,
              0, y, W_CLIENT - 2*PAD, 2, IDC_SEP_CERT);
    y += 8;

    make_ctrl(g_hPageCert, L"BUTTON", L"\u751F\u6210\u8BC1\u4E66",
              BS_DEFPUSHBUTTON, 0, y, 160, EH + 4, IDC_BTN_GENERATE);
    y += EH + 10;

    make_ctrl(g_hPageCert, L"STATIC", L"",
              SS_LEFT, 8, y, W_CLIENT - 2*PAD - 16, 140, IDC_LBL_CERT_STATUS);
}

/* ---------------------------------------------------------------- */
/* Tab switching                                                    */
/* ---------------------------------------------------------------- */

static void
switch_tab(int idx)
{
    ShowWindow(g_hPageSign, idx == 0 ? SW_SHOW : SW_HIDE);
    ShowWindow(g_hPageCert, idx == 1 ? SW_SHOW : SW_HIDE);
}

/* ---------------------------------------------------------------- */
/* Worker thread                                                    */
/* ---------------------------------------------------------------- */

static void
post_log_utf8(int color, const char *fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    wchar_t wbuf[1024];
    wide_from_utf8(buf, wbuf, 1024);
    size_t len = wcslen(wbuf) + 1;
    wchar_t *copy = malloc(len * sizeof(wchar_t));
    if (!copy) return;
    wcscpy(copy, wbuf);
    if (!PostMessageW(g_hwndMain, WM_APP_LOG, (WPARAM)color, (LPARAM)copy))
        free(copy);
}

static void
log_debug_utf8(const char *fmt, ...)
{
    if (!g_debug) return;
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    wchar_t wbuf[1024];
    wide_from_utf8(buf, wbuf, 1024);
    size_t len = wcslen(wbuf) + 1;
    wchar_t *copy = malloc(len * sizeof(wchar_t));
    if (!copy) return;
    wcscpy(copy, wbuf);
    if (!PostMessageW(g_hwndMain, WM_APP_LOG, (WPARAM)LOG_COLOR_INFO, (LPARAM)copy))
        free(copy);
}

static void
post_progress(int percent)
{
    PostMessageW(g_hwndMain, WM_APP_PROGRESS, (WPARAM)percent, 0);
}

static void
thread_progress_cb(const char *filename, int current, int total,
                   int success, void *user_data)
{
    (void)user_data;
    if (!filename) return;
    if (total > 0)
        post_progress((int)(current * 100 / total));

    wchar_t wfile[GUI_PATH_LEN];
    wide_from_utf8(filename, wfile, GUI_PATH_LEN);

    if (success == 1)
        post_log_utf8(LOG_COLOR_OK, "[OK] %s", filename);
    else if (success == -2)
        post_log_utf8(LOG_COLOR_SKIP, "[\u8DF3\u8FC7] %s", filename);
    else if (success == -3)
        post_log_utf8(LOG_COLOR_INFO, "%s", filename);
    else if (success == -4)
        post_log_utf8(LOG_COLOR_INFO, "  %s", filename);
    else if (success == 0)
        post_log_utf8(LOG_COLOR_FAIL, "[\u5931\u8D25] %s", filename);

    log_debug_utf8("  [\u8C03\u8BD5] \u8FDB\u5EA6: %d/%d, \u7ED3\u679C: %d",
                   current, total, success);
}

static DWORD WINAPI
sign_thread_proc(LPVOID param)
{
    SignTask *task = (SignTask *)param;
    if (!task) return 0;

    HWND hwnd = task->hwnd;
    log_debug_utf8("[\u8C03\u8BD5] \u76EE\u6807: %s", task->target);
    log_debug_utf8("[\u8C03\u8BD5] PFX: %s", task->pfx);
    log_debug_utf8("[\u8C03\u8BD5] TSA: %s", task->ts_url[0] ? task->ts_url : "(\u65E0)");
    log_debug_utf8("[\u8C03\u8BD5] \u5F3A\u5236=%d \u5B50\u76EE\u5F55=%d", task->force, task->recursive);

    int count = batch_sign(task->target, task->pfx,
                           task->password[0] ? task->password : NULL,
                           task->ts_url[0]   ? task->ts_url : NULL,
                           task->outdir[0]   ? task->outdir : NULL,
                           task->force, task->recursive,
                           thread_progress_cb, task);

    wchar_t wtarget[GUI_PATH_LEN];
    wide_from_utf8(task->target, wtarget, GUI_PATH_LEN);

    post_log_utf8(LOG_COLOR_INFO, "\u5B8C\u6210 - \u5DF2\u7B7E\u540D %d \u4E2A\u6587\u4EF6", count);
    PostMessageW(hwnd, WM_APP_SIGN_DONE, (WPARAM)count, 0);
    return 0;
}

/* ---------------------------------------------------------------- */
/* WndProc                                                          */
/* ---------------------------------------------------------------- */

static LRESULT CALLBACK
page_subclass(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp,
              UINT_PTR uIdSubclass, DWORD_PTR dwRefData)
{
    (void)uIdSubclass; (void)dwRefData;
    if (msg == WM_COMMAND || msg == WM_CTLCOLORSTATIC || msg == WM_CTLCOLORLISTBOX
        || msg == WM_DRAWITEM || msg == WM_MEASUREITEM)
        return SendMessageW(GetParent(hwnd), msg, wp, lp);
    return DefSubclassProc(hwnd, msg, wp, lp);
}

static LRESULT CALLBACK
WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_APP_LOG: {
        wchar_t *wmsg = (wchar_t *)lParam;
        if (wmsg) {
            int idx = (int)SendMessageW(g_hLog, LB_ADDSTRING, 0, (LPARAM)wmsg);
            SendMessageW(g_hLog, LB_SETITEMDATA, (WPARAM)idx, wParam);
            log_scroll_bottom();
            UpdateWindow(g_hLog);
            free(wmsg);
        }
        return 0;
    }
    case WM_APP_PROGRESS:
        SendMessageW(g_hProgress, PBM_SETPOS, wParam, 0);
        return 0;
    case WM_APP_SIGN_DONE: {
        if (g_hThread) {
            WaitForSingleObject(g_hThread, INFINITE);
            CloseHandle(g_hThread);
            g_hThread = NULL;
        }
        EnableWindow(GetDlgItem(g_hPageSign, IDC_BTN_SIGN), TRUE);
        return 0;
    }
    case WM_CREATE: {
        InitCommonControls();
        g_hbrBg     = CreateSolidBrush(g_clrBg);
        g_hbrLogBg  = CreateSolidBrush(g_clrLogBg);
        g_hbrEditBg = CreateSolidBrush(g_clrEditBg);
        g_hbrAccent = CreateSolidBrush(g_clrAccent);
        g_hbrBtnFace = GetSysColorBrush(COLOR_BTNFACE);

        g_hFont = CreateFontW(-13, 0, 0, 0, FW_NORMAL, 0, 0, 0,
                               DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY,
                               0, L"Segoe UI");
        g_hFontSection = CreateFontW(-14, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0,
                                     DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY,
                                     0, L"Segoe UI");

        g_hTab = CreateWindowExW(0, WC_TABCONTROLW, L"",
                                  WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | TCS_FLATBUTTONS,
                                  0, 0, W_CLIENT, 38,
                                  hwnd, (HMENU)IDC_TAB, g_hInst, NULL);
        SendMessageW(g_hTab, WM_SETFONT, (WPARAM)g_hFont, TRUE);

        TCITEMW tie;
        tie.mask = TCIF_TEXT;
        tie.pszText = L"  \u7B7E\u540D  ";
        SendMessageW(g_hTab, TCM_INSERTITEMW, 0, (LPARAM)&tie);
        tie.pszText = L"  \u751F\u6210\u8BC1\u4E66  ";
        SendMessageW(g_hTab, TCM_INSERTITEMW, 1, (LPARAM)&tie);

        create_sign_page(hwnd);
        create_cert_page(hwnd);
        apply_font(g_hPageSign);
        apply_font(g_hPageCert);
        SetWindowSubclass(g_hPageSign, page_subclass, 0, 0);
        SetWindowSubclass(g_hPageCert, page_subclass, 0, 0);
        switch_tab(0);

        /* Enable dark title bar (Win10 20H1+) */
        BOOL dark = TRUE;
        DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &dark, sizeof(dark));

        return 0;
    }
    case WM_GETMINMAXINFO: {
        MINMAXINFO *mmi = (MINMAXINFO *)lParam;
        mmi->ptMinTrackSize.x = 800;
        mmi->ptMinTrackSize.y = 720;
        return 0;
    }
    case WM_SIZE: {
        int cw = LOWORD(lParam), ch = HIWORD(lParam);
        if (g_hTab)
            SetWindowPos(g_hTab, NULL, 0, 0, cw, 38, SWP_NOZORDER);
        int pw = cw - 2 * PAD;
        int ph = ch - 50;
        if (g_hPageSign)
            SetWindowPos(g_hPageSign, NULL, PAD, 40, pw, ph, SWP_NOZORDER);
        if (g_hPageCert)
            SetWindowPos(g_hPageCert, NULL, PAD, 40, pw, ph, SWP_NOZORDER);
        HWND hSep;
        hSep = GetDlgItem(g_hPageSign, IDC_SEP_SIGN);
        if (hSep) {
            RECT r; GetWindowRect(hSep, &r);
            MapWindowPoints(NULL, g_hPageSign, (POINT *)&r, 2);
            SetWindowPos(hSep, NULL, 0, r.top, pw, 2, SWP_NOZORDER);
        }
        hSep = GetDlgItem(g_hPageCert, IDC_SEP_CERT);
        if (hSep) {
            RECT r; GetWindowRect(hSep, &r);
            MapWindowPoints(NULL, g_hPageCert, (POINT *)&r, 2);
            SetWindowPos(hSep, NULL, 0, r.top, pw, 2, SWP_NOZORDER);
        }
        if (g_hPageSign) {
            HWND hProg = GetDlgItem(g_hPageSign, IDC_PROGRESS);
            HWND hLst  = GetDlgItem(g_hPageSign, IDC_LIST_LOG);
            if (hProg) {
                RECT r; GetWindowRect(hProg, &r);
                MapWindowPoints(NULL, g_hPageSign, (POINT *)&r, 2);
                SetWindowPos(hProg, NULL, 0, r.top, pw, 24, SWP_NOZORDER);
            }
            if (hLst) {
                RECT r; GetWindowRect(hLst, &r);
                MapWindowPoints(NULL, g_hPageSign, (POINT *)&r, 2);
                int lh = ph - r.top - 8;
                if (lh < 50) lh = 50;
                SetWindowPos(hLst, NULL, 0, r.top, pw, lh, SWP_NOZORDER);
            }
        }
        InvalidateRect(hwnd, NULL, TRUE);
        return 0;
    }
    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)wParam;
        HWND hCtrl = (HWND)lParam;
        if (hCtrl == g_hPageSign || hCtrl == g_hPageCert) {
            SetTextColor(hdc, g_clrText);
            SetBkColor(hdc, g_clrEditBg);
            return (LRESULT)g_hbrEditBg;
        }
        if (hCtrl == g_hLog) {
            SetTextColor(hdc, g_clrLogText);
            SetBkColor(hdc, g_clrLogBg);
            return (LRESULT)g_hbrLogBg;
        }
        int id = GetDlgCtrlID(hCtrl);
        HWND hParent = GetParent(hCtrl);
        if (hParent == g_hPageSign || hParent == g_hPageCert) {
            if (id == IDC_LBL_LOG_TITLE || id == IDC_LBL_CERT_TITLE) {
                SetTextColor(hdc, g_clrAccent);
                SetBkColor(hdc, g_clrEditBg);
                SelectObject(hdc, g_hFontSection);
                return (LRESULT)g_hbrEditBg;
            }
            SetTextColor(hdc, g_clrText);
            SetBkColor(hdc, g_clrEditBg);
            return (LRESULT)g_hbrEditBg;
        }
        SetTextColor(hdc, g_clrText);
        SetBkColor(hdc, g_clrBg);
        return (LRESULT)g_hbrBg;
    }
    case WM_CTLCOLOREDIT: {
        HDC hdc = (HDC)wParam;
        SetBkColor(hdc, g_clrEditBg);
        return (LRESULT)g_hbrEditBg;
    }
    case WM_CTLCOLORBTN: {
        HDC hdc = (HDC)wParam;
        HWND hCtrl = (HWND)lParam;
        int id = GetDlgCtrlID(hCtrl);
        if (id == IDC_BTN_SIGN || id == IDC_BTN_GENERATE) {
            SetTextColor(hdc, RGB(255, 255, 255));
            SetBkColor(hdc, g_clrAccent);
            return (LRESULT)g_hbrAccent;
        }
        SetTextColor(hdc, g_clrText);
        SetBkColor(hdc, g_clrBg);
        return (LRESULT)g_hbrBg;
    }
    case WM_CTLCOLORLISTBOX: {
        HDC hdc = (HDC)wParam;
        HWND hCtrl = (HWND)lParam;
        if (hCtrl == g_hLog) {
            SetTextColor(hdc, g_clrLogText);
            SetBkColor(hdc, g_clrLogBg);
            return (LRESULT)g_hbrLogBg;
        }
        SetTextColor(hdc, g_clrText);
        SetBkColor(hdc, g_clrBg);
        return (LRESULT)g_hbrBg;
    }
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc;
        GetClientRect(hwnd, &rc);
        FillRect(hdc, &rc, g_hbrBg);
        RECT hdr = { 0, 0, rc.right, 3 };
        HBRUSH hbrHdr = CreateSolidBrush(g_clrAccent);
        FillRect(hdc, &hdr, hbrHdr);
        DeleteObject(hbrHdr);
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_ERASEBKGND: {
        RECT rc;
        GetClientRect(hwnd, &rc);
        FillRect((HDC)wParam, &rc, g_hbrBg);
        return 1;
    }
    case WM_MEASUREITEM:
        return FALSE;
    case WM_DRAWITEM:
        return FALSE;
    case WM_NOTIFY: {
        NMHDR *nmh = (NMHDR *)lParam;
        if (nmh->idFrom == IDC_TAB && nmh->code == TCN_SELCHANGE) {
            switch_tab(TabCtrl_GetCurSel(g_hTab));
            InvalidateRect(hwnd, NULL, TRUE);
        }
        if (nmh->idFrom == IDC_TAB && nmh->code == NM_CUSTOMDRAW) {
            NMTTCUSTOMDRAW *nmc = (NMTTCUSTOMDRAW *)lParam;
            if (nmc->nmcd.dwDrawStage == CDDS_PREPAINT)
                return CDRF_NOTIFYITEMDRAW;
            if (nmc->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
                int sel = TabCtrl_GetCurSel(g_hTab);
                BOOL isSel = ((int)nmc->nmcd.dwItemSpec == sel);
                RECT rc = nmc->nmcd.rc;
                COLORREF bg = isSel ? g_clrEditBg : RGB(234, 235, 240);
                HBRUSH hbr = CreateSolidBrush(bg);
                FillRect(nmc->nmcd.hdc, &rc, hbr);
                DeleteObject(hbr);
                if (isSel) {
                    RECT bar = { rc.left + 8, rc.bottom - 3, rc.right - 8, rc.bottom };
                    HBRUSH hbrBar = CreateSolidBrush(g_clrAccent);
                    FillRect(nmc->nmcd.hdc, &bar, hbrBar);
                    DeleteObject(hbrBar);
                }
                TCITEMW tci;
                memset(&tci, 0, sizeof(tci));
                tci.mask = TCIF_TEXT;
                wchar_t tabText[64] = {0};
                tci.pszText = tabText;
                tci.cchTextMax = 64;
                SendMessageW(g_hTab, TCM_GETITEMW, nmc->nmcd.dwItemSpec, (LPARAM)&tci);
                SetBkMode(nmc->nmcd.hdc, TRANSPARENT);
                SetTextColor(nmc->nmcd.hdc, isSel ? g_clrAccent : g_clrLabel);
                SelectObject(nmc->nmcd.hdc, g_hFont);
                DrawTextW(nmc->nmcd.hdc, tabText, -1, &rc,
                          DT_CENTER | DT_VCENTER | DT_SINGLELINE);
                return CDRF_SKIPDEFAULT;
            }
        }
        return 0;
    }
    case WM_COMMAND: {
        int id = LOWORD(wParam);

        if (id == IDC_BTN_BROWSE_TGT) {
            wchar_t path[GUI_PATH_LEN] = {0};
            BROWSEINFOW bi = {0};
            bi.hwndOwner = hwnd;
            bi.lpszTitle = L"\u9009\u62E9\u76EE\u6807\u76EE\u5F55";
            bi.ulFlags   = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
            LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
            if (pidl) {
                if (SHGetPathFromIDListW(pidl, path))
                    SetDlgItemTextW(g_hPageSign, IDC_EDIT_TARGET, path);
                CoTaskMemFree(pidl);
            }
        }
        else if (id == IDC_BTN_BROWSE_PFX) {
            wchar_t path[GUI_PATH_LEN] = {0};
            OPENFILENAMEW ofn = {0};
            ofn.lStructSize  = sizeof(ofn);
            ofn.hwndOwner    = hwnd;
            ofn.lpstrFile    = path;
            ofn.nMaxFile     = GUI_PATH_LEN;
            ofn.lpstrFilter  = L"PFX/P12 Files\0*.pfx;*.p12\0All Files\0*.*\0";
            ofn.nFilterIndex = 1;
            ofn.Flags        = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
            if (GetOpenFileNameW(&ofn))
                SetDlgItemTextW(g_hPageSign, IDC_EDIT_PFX, path);
        }
        else if (id == IDC_BTN_BROWSE_OUT) {
            wchar_t path[GUI_PATH_LEN] = {0};
            BROWSEINFOW bi = {0};
            bi.hwndOwner = hwnd;
            bi.lpszTitle = L"\u9009\u62E9\u8F93\u51FA\u76EE\u5F55";
            bi.ulFlags   = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
            LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
            if (pidl) {
                if (SHGetPathFromIDListW(pidl, path))
                    SetDlgItemTextW(g_hPageSign, IDC_EDIT_OUTDIR, path);
                CoTaskMemFree(pidl);
            }
        }
        else if (id == IDC_BTN_SIGN) {
            wchar_t wtarget[GUI_PATH_LEN], wpfx[GUI_PATH_LEN], wpassword[256];
            wchar_t wts_url[512], woutdir[GUI_PATH_LEN];

            GetDlgItemTextW(g_hPageSign, IDC_EDIT_TARGET, wtarget, GUI_PATH_LEN);
            GetDlgItemTextW(g_hPageSign, IDC_EDIT_PFX,    wpfx,    GUI_PATH_LEN);
            GetDlgItemTextW(g_hPageSign, IDC_EDIT_PASSWORD, wpassword, 256);
            {
                HWND hC = GetDlgItem(g_hPageSign, IDC_COMBO_TSA);
                int sel = (int)SendMessageW(hC, CB_GETCURSEL, 0, 0);
                if (sel >= 0) {
                    int si = (int)SendMessageW(hC, CB_GETITEMDATA, (WPARAM)sel, 0);
                    if (si >= 0 && si < TSA_SERVER_COUNT) {
                        MultiByteToWideChar(CP_UTF8, 0, g_tsa_servers[si].url, -1, wts_url, 512);
                    } else {
                        GetDlgItemTextW(g_hPageSign, IDC_COMBO_TSA, wts_url, 512);
                    }
                } else {
                    GetDlgItemTextW(g_hPageSign, IDC_COMBO_TSA, wts_url, 512);
                }
            }
            GetDlgItemTextW(g_hPageSign, IDC_EDIT_OUTDIR, woutdir, GUI_PATH_LEN);

            if (wcslen(wtarget) == 0 || wcslen(wpfx) == 0) {
                MessageBoxW(hwnd, L"\u8BF7\u586B\u5199\u76EE\u6807\u548C PFX \u6587\u4EF6\u3002",
                            L"\u9519\u8BEF", MB_OK | MB_ICONERROR);
                break;
            }

            if (g_hThread) {
                MessageBoxW(hwnd, L"\u7B7E\u540D\u64CD\u4F5C\u6B63\u5728\u8FDB\u884C\u4E2D\uFF0C\u8BF7\u7B49\u5F85\u5B8C\u6210\u3002",
                            L"\u63D0\u793A", MB_OK | MB_ICONINFORMATION);
                break;
            }

            int recursive = IsDlgButtonChecked(g_hPageSign, IDC_CHK_RECURSIVE) == BST_CHECKED;
            int force     = IsDlgButtonChecked(g_hPageSign, IDC_CHK_FORCE) == BST_CHECKED;
            g_debug       = IsDlgButtonChecked(g_hPageSign, IDC_CHK_DEBUG) == BST_CHECKED;

            SignTask *task = calloc(1, sizeof(SignTask));
            if (!task) break;
            task->hwnd = hwnd;
            wide_to_utf8(wtarget,   task->target,   GUI_PATH_LEN);
            wide_to_utf8(wpfx,      task->pfx,      GUI_PATH_LEN);
            wide_to_utf8(wpassword, task->password, 256);
            wide_to_utf8(wts_url,   task->ts_url,   512);
            wide_to_utf8(woutdir,   task->outdir,    GUI_PATH_LEN);
            task->recursive = recursive;
            task->force     = force;

            EnableWindow(GetDlgItem(g_hPageSign, IDC_BTN_SIGN), FALSE);
            SendMessageW(g_hProgress, PBM_SETPOS, 0, 0);
            log_message(LOG_COLOR_INFO, L"\u2500\u2500\u2500 \u65B0\u7B7E\u540D %s \u2500\u2500\u2500", wtarget);
            if (g_debug)
                log_message(LOG_COLOR_INFO, L"\u8C03\u8BD5\u65E5\u5FD7\u5DF2\u5F00\u542F");

            g_hThread = CreateThread(NULL, 0, sign_thread_proc, task, 0, NULL);
            if (!g_hThread) {
                free(task);
                EnableWindow(GetDlgItem(g_hPageSign, IDC_BTN_SIGN), TRUE);
                MessageBoxW(hwnd, L"\u65E0\u6CD5\u521B\u5EFA\u7B7E\u540D\u7EBF\u7A0B\u3002",
                            L"\u9519\u8BEF", MB_OK | MB_ICONERROR);
            }
        }
        else if (id == IDC_BTN_TEST_TSA) {
            EnableWindow(GetDlgItem(hwnd, IDC_BTN_TEST_TSA), FALSE);
            SetDlgItemTextW(hwnd, IDC_BTN_TEST_TSA, L"\u6D4B\u8BD5\u4E2D...");

            log_message(LOG_COLOR_INFO, L"\u5F00\u59CB\u6D4B\u8BD5 %d \u4E2A\u65F6\u95F4\u6233\u670D\u52A1\u5668...", TSA_SERVER_COUNT);
            UpdateWindow(g_hLog);

            int best_idx = -1, best_latency = 0;

            for (int i = 0; i < TSA_SERVER_COUNT; i++) {
                wchar_t wlabel[256];
                MultiByteToWideChar(CP_UTF8, 0, g_tsa_servers[i].label, -1, wlabel, 256);

                DWORD t0 = GetTickCount();
                int ok = timestamp_test_server(g_tsa_servers[i].url);
                DWORD elapsed = GetTickCount() - t0;

                if (ok) {
                    log_message(LOG_COLOR_OK, L"\u6765\u81EA %s: \u5EF6\u8FDF = %lu ms", wlabel, elapsed);
                    if (best_idx < 0 || (int)elapsed < best_latency) {
                        best_idx = i;
                        best_latency = (int)elapsed;
                    }
                } else {
                    log_message(LOG_COLOR_FAIL, L"\u6765\u81EA %s: \u8BF7\u6C42\u8D85\u65F6", wlabel);
                }
                UpdateWindow(g_hLog);
            }

            if (best_idx >= 0) {
                wchar_t wlabel[256];
                MultiByteToWideChar(CP_UTF8, 0, g_tsa_servers[best_idx].label, -1, wlabel, 256);
                log_message(LOG_COLOR_OK, L"\u6700\u5FEB\u670D\u52A1\u5668: %s (%d ms)", wlabel, best_latency);

                HWND hCombo = GetDlgItem(g_hPageSign, IDC_COMBO_TSA);
                SendMessageW(hCombo, CB_SETCURSEL, best_idx, 0);

                wchar_t msg[128];
                swprintf(msg, 128, L"\u6700\u5FEB: %s (%d ms)", wlabel, best_latency);
                MessageBoxW(hwnd, msg, L"\u6D4B\u901F\u5B8C\u6210", MB_OK | MB_ICONINFORMATION);
            } else {
                log_message(LOG_COLOR_FAIL, L"\u6240\u6709\u65F6\u95F4\u6233\u670D\u52A1\u5668\u5747\u4E0D\u53EF\u8FBE");
                MessageBoxW(hwnd, L"\u6240\u6709\u65F6\u95F4\u6233\u670D\u52A1\u5668\u5747\u4E0D\u53EF\u8FBE\u3002\n\u8BF7\u68C0\u67E5\u7F51\u7EDC\u8FDE\u63A5\u3002",
                            L"\u6D4B\u901F\u5931\u8D25", MB_OK | MB_ICONERROR);
            }

            SetDlgItemTextW(hwnd, IDC_BTN_TEST_TSA, L"\u6D4B\u901F");
            EnableWindow(GetDlgItem(hwnd, IDC_BTN_TEST_TSA), TRUE);
        }
        else if (id == IDC_BTN_BROWSE_CD) {
            wchar_t path[GUI_PATH_LEN] = {0};
            BROWSEINFOW bi = {0};
            bi.hwndOwner = hwnd;
            bi.lpszTitle = L"\u9009\u62E9\u8F93\u51FA\u76EE\u5F55";
            bi.ulFlags   = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
            LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
            if (pidl) {
                if (SHGetPathFromIDListW(pidl, path))
                    SetDlgItemTextW(g_hPageCert, IDC_EDIT_CERT_DIR, path);
                CoTaskMemFree(pidl);
            }
        }
        else if (id == IDC_BTN_GENERATE) {
            wchar_t wdir[GUI_PATH_LEN], wdays_str[16], wpw[256];
            wchar_t wcn[256], wemail[256];

            GetDlgItemTextW(g_hPageCert, IDC_EDIT_CERT_DIR,   wdir,  GUI_PATH_LEN);
            GetDlgItemTextW(g_hPageCert, IDC_EDIT_CERT_DAYS,  wdays_str, 16);
            GetDlgItemTextW(g_hPageCert, IDC_EDIT_CERT_PW,    wpw,   256);
            GetDlgItemTextW(g_hPageCert, IDC_EDIT_CERT_CN,    wcn,   256);
            GetDlgItemTextW(g_hPageCert, IDC_EDIT_CERT_EMAIL, wemail, 256);

            if (wcslen(wdir) == 0) {
                MessageBoxW(hwnd, L"\u8BF7\u9009\u62E9\u8F93\u51FA\u76EE\u5F55\u3002",
                            L"\u9519\u8BEF", MB_OK | MB_ICONERROR);
                break;
            }

            int days = _wtoi(wdays_str);
            if (days <= 0) days = CERT_SIGNER_DEFAULT_DAYS;

            char dir[GUI_PATH_LEN], pw[256], cn[256], email[256];
            wide_to_utf8(wdir,   dir,   GUI_PATH_LEN);
            wide_to_utf8(wpw,    pw,    256);
            wide_to_utf8(wcn,    cn,    256);
            wide_to_utf8(wemail, email, 256);

            CreateDirectoryA(dir, NULL);

            EnableWindow(GetDlgItem(g_hPageCert, IDC_BTN_GENERATE), FALSE);
            SetDlgItemTextW(g_hPageCert, IDC_LBL_CERT_STATUS,
                            L"\u6B63\u5728\u751F\u6210...");

            int ok = cert_generate(dir, NULL,
                                   pw[0] ? pw : NULL,
                                   days,
                                   cn[0]  ? cn  : NULL,
                                   email[0] ? email : NULL);

            if (ok) {
                wchar_t msg[512];
                swprintf(msg, 512,
                         L"\u8BC1\u4E66\u751F\u6210\u6210\u529F!\n\n"
                         L"\u751F\u6210\u6587\u4EF6\u4F4D\u4E8E: %s\n\n"
                         L"%s"
                         L"\u8BF7\u5C06 FileSigner_RootCA.cer \u5BFC\u5165\n"
                         L"Windows \u53D7\u4FE1\u4EFB\u7684\u6839\u8BC1\u4E66\u9881\u53D1\u673A\u6784",
                         wdir,
                         wpw[0] ? L"PFX \u5BC6\u7801\u5DF2\u8BBE\u7F6E\uFF0C\u7B7E\u540D\u65F6\u8BF7\u4F7F\u7528\u76F8\u540C\u5BC6\u7801\u3002\n\n"
                                 : L"PFX \u65E0\u5BC6\u7801\uFF0C\u7B7E\u540D\u65F6\u5BC6\u7801\u7559\u7A7A\u5373\u53EF\u3002\n\n");
                SetDlgItemTextW(g_hPageCert, IDC_LBL_CERT_STATUS, msg);
                MessageBoxW(hwnd, msg, L"\u6210\u529F", MB_OK | MB_ICONINFORMATION);
            } else {
                SetDlgItemTextW(g_hPageCert, IDC_LBL_CERT_STATUS,
                                L"\u751F\u6210\u5931\u8D25! \u8BF7\u68C0\u67E5\u8F93\u51FA\u76EE\u5F55\u548C\u53C2\u6570\u3002");
                MessageBoxW(hwnd, L"\u8BC1\u4E66\u751F\u6210\u5931\u8D25\u3002",
                            L"\u9519\u8BEF", MB_OK | MB_ICONERROR);
            }

            EnableWindow(GetDlgItem(g_hPageCert, IDC_BTN_GENERATE), TRUE);
        }

        return 0;
    }
    case WM_CLOSE: {
        if (g_hThread) {
            if (IDYES != MessageBoxW(hwnd,
                    L"\u7B7E\u540D\u64CD\u4F5C\u5C1A\u672A\u5B8C\u6210\uFF0C\u786E\u5B9A\u8981\u5173\u95ED\u5417\uFF1F",
                    L"FileSigner", MB_YESNO | MB_ICONWARNING))
                return 0;
        }
        DestroyWindow(hwnd);
        return 0;
    }
    case WM_DESTROY:
        if (g_hThread) {
            WaitForSingleObject(g_hThread, INFINITE);
            CloseHandle(g_hThread);
            g_hThread = NULL;
        }
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

/* ---------------------------------------------------------------- */
/* Entry point                                                      */
/* ---------------------------------------------------------------- */

int
gui_main(HINSTANCE hInstance, HINSTANCE hPrevInstance,
         LPSTR lpCmdLine, int nCmdShow)
{
    (void)hPrevInstance;
    (void)lpCmdLine;

    g_hInst = hInstance;

    OleInitialize(NULL);

    WNDCLASSEXW wc = {0};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInstance;
    wc.hIcon         = LoadIconW(hInstance, MAKEINTRESOURCEW(IDI_MAIN_ICON));
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = NULL;
    wc.lpszClassName = L"FileSignerClass";

    if (!RegisterClassExW(&wc)) return 1;

    RECT rc = { 0, 0, W_CLIENT, 720 };
    AdjustWindowRect(&rc, WS_OVERLAPPEDWINDOW, FALSE);
    int w = rc.right - rc.left;
    int h = rc.bottom - rc.top;

    g_hwndMain = CreateWindowExW(0, L"FileSignerClass", L"FileSigner",
                                 WS_OVERLAPPEDWINDOW,
                                 CW_USEDEFAULT, CW_USEDEFAULT,
                                 w, h, NULL, NULL, hInstance, NULL);
    if (!g_hwndMain) { OleUninitialize(); return 1; }

    ShowWindow(g_hwndMain, nCmdShow ? nCmdShow : SW_SHOWDEFAULT);
    UpdateWindow(g_hwndMain);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    if (g_hFont)       DeleteObject(g_hFont);
    if (g_hFontSection) DeleteObject(g_hFontSection);
    if (g_hMonoFont)    DeleteObject(g_hMonoFont);
    if (g_hbrBg)        DeleteObject(g_hbrBg);
    if (g_hbrLogBg)     DeleteObject(g_hbrLogBg);
    if (g_hbrEditBg)    DeleteObject(g_hbrEditBg);
    if (g_hbrAccent)    DeleteObject(g_hbrAccent);

    OleUninitialize();
    return (int)msg.wParam;
}
