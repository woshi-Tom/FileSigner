#ifdef _WIN32

#include <windows.h>
#include <commdlg.h>
#include <shlobj.h>
#include <commctrl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "cert_gen.h"
#include "authenticode.h"
#include "batch_signer.h"
#include "file_utils.h"
#include "resource.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "ole32.lib")

/* ------------------------------------------------------------------ */
/* Control IDs                                                         */
/* ------------------------------------------------------------------ */

#define IDC_TAB             100
#define IDC_EDIT_TARGET     201
#define IDC_BTN_BROWSE_TGT  202
#define IDC_EDIT_PFX        203
#define IDC_BTN_BROWSE_PFX  204
#define IDC_EDIT_PASSWORD   205
#define IDC_EDIT_TIMESTAMP  206
#define IDC_CHK_RECURSIVE   207
#define IDC_CHK_FORCE       208
#define IDC_EDIT_OUTDIR     209
#define IDC_BTN_BROWSE_OUT  210
#define IDC_BTN_SIGN        211
#define IDC_PROGRESS        212
#define IDC_LIST_LOG        213

#define IDC_EDIT_CERT_DIR   301
#define IDC_BTN_BROWSE_CD   302
#define IDC_EDIT_CERT_DAYS  303
#define IDC_BTN_GENERATE    304
#define IDC_LBL_CERT_STATUS 305

/* ------------------------------------------------------------------ */
/* Globals                                                             */
/* ------------------------------------------------------------------ */

static HINSTANCE g_hInst;
static HWND g_hTab;
static HWND g_hPageSign, g_hPageCert;
static HWND g_hProgress, g_hLog;

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

/* Convert system-codepage char* → wide string for display */
static void wide_from_acp(const char *src, wchar_t *dst, int dst_chars)
{
    if (!src || !src[0]) { dst[0] = L'\0'; return; }
    MultiByteToWideChar(CP_ACP, 0, src, -1, dst, dst_chars);
}

/* Convert wide string → system-codepage char* for core API calls */
static void wide_to_acp(const wchar_t *src, char *dst, int dst_chars)
{
    if (!src || !src[0]) { dst[0] = '\0'; return; }
    WideCharToMultiByte(CP_ACP, 0, src, -1, dst, dst_chars, NULL, NULL);
}

static void log_message(HWND hList, const wchar_t *fmt, ...)
{
    wchar_t buf[2048];
    va_list args;
    va_start(args, fmt);
    vswprintf(buf, sizeof(buf) / sizeof(wchar_t), fmt, args);
    va_end(args);

    int idx = (int)SendMessageW(hList, LB_ADDSTRING, 0, (LPARAM)buf);
    SendMessageW(hList, LB_SETTOPINDEX, idx, 0);
}

static BOOL browse_file(HWND hwnd, const wchar_t *filter, const wchar_t *title,
                         wchar_t *outpath, DWORD outsize)
{
    OPENFILENAMEW ofn;
    memset(&ofn, 0, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = filter;
    ofn.lpstrFile = outpath;
    ofn.nMaxFile = outsize;
    ofn.lpstrTitle = title;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    outpath[0] = L'\0';
    return GetOpenFileNameW(&ofn);
}

static BOOL browse_folder(HWND hwnd, const wchar_t *title, wchar_t *outpath)
{
    BROWSEINFOW bi;
    memset(&bi, 0, sizeof(bi));
    bi.hwndOwner = hwnd;
    bi.lpszTitle = title;
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;

    LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
    if (!pidl) return FALSE;

    BOOL ret = SHGetPathFromIDListW(pidl, outpath);
    CoTaskMemFree(pidl);
    return ret;
}

static HWND make_ctrl(HWND parent, const wchar_t *cls, const wchar_t *text,
                       DWORD style, int x, int y, int w, int h, int id)
{
    return CreateWindowExW(0, cls, text,
                            WS_CHILD | WS_VISIBLE | style,
                            x, y, w, h,
                            parent, (HMENU)(INT_PTR)id, g_hInst, NULL);
}

/* ------------------------------------------------------------------ */
/* Sign page                                                           */
/* ------------------------------------------------------------------ */

static void create_sign_page(HWND parent)
{
    g_hPageSign = CreateWindowExW(0, L"STATIC", L"",
                                   WS_CHILD | WS_VISIBLE,
                                   10, 35, 570, 430, parent, NULL, g_hInst, NULL);

    int y = 10;

    make_ctrl(g_hPageSign, L"STATIC", L"目标 (文件或目录):", 0, 0, y, 160, 20, 0);
    y += 20;
    make_ctrl(g_hPageSign, L"EDIT", L"", WS_BORDER | ES_AUTOHSCROLL, 0, y, 450, 24, IDC_EDIT_TARGET);
    make_ctrl(g_hPageSign, L"BUTTON", L"浏览...", 0, 460, y, 90, 24, IDC_BTN_BROWSE_TGT);
    y += 32;

    make_ctrl(g_hPageSign, L"STATIC", L"PFX 证书文件:", 0, 0, y, 160, 20, 0);
    y += 20;
    make_ctrl(g_hPageSign, L"EDIT", L"", WS_BORDER | ES_AUTOHSCROLL, 0, y, 450, 24, IDC_EDIT_PFX);
    make_ctrl(g_hPageSign, L"BUTTON", L"浏览...", 0, 460, y, 90, 24, IDC_BTN_BROWSE_PFX);
    y += 32;

    make_ctrl(g_hPageSign, L"STATIC", L"PFX 密码:", 0, 0, y, 160, 20, 0);
    y += 20;
    make_ctrl(g_hPageSign, L"EDIT", L"", WS_BORDER | ES_AUTOHSCROLL | ES_PASSWORD, 0, y, 300, 24, IDC_EDIT_PASSWORD);
    y += 32;

    make_ctrl(g_hPageSign, L"STATIC", L"时间戳服务器 URL (可选):", 0, 0, y, 250, 20, 0);
    y += 20;
    make_ctrl(g_hPageSign, L"EDIT", L"http://timestamp.digicert.com",
              WS_BORDER | ES_AUTOHSCROLL, 0, y, 450, 24, IDC_EDIT_TIMESTAMP);
    y += 32;

    make_ctrl(g_hPageSign, L"STATIC", L"输出目录 (可选, 留空 = 覆盖原文件):", 0, 0, y, 320, 20, 0);
    y += 20;
    make_ctrl(g_hPageSign, L"EDIT", L"", WS_BORDER | ES_AUTOHSCROLL, 0, y, 450, 24, IDC_EDIT_OUTDIR);
    make_ctrl(g_hPageSign, L"BUTTON", L"浏览...", 0, 460, y, 90, 24, IDC_BTN_BROWSE_OUT);
    y += 32;

    make_ctrl(g_hPageSign, L"BUTTON", L"包含子目录",
              BS_AUTOCHECKBOX, 0, y, 300, 20, IDC_CHK_RECURSIVE);
    y += 24;
    make_ctrl(g_hPageSign, L"BUTTON", L"强制重新签名已签名的文件",
              BS_AUTOCHECKBOX, 0, y, 300, 20, IDC_CHK_FORCE);
    y += 32;

    make_ctrl(g_hPageSign, L"BUTTON", L"开始签名",
              BS_DEFPUSHBUTTON, 0, y, 120, 32, IDC_BTN_SIGN);
    y += 40;

    g_hProgress = make_ctrl(g_hPageSign, PROGRESS_CLASSW, L"",
                             0, 0, y, 550, 20, IDC_PROGRESS);
    y += 28;

    g_hLog = make_ctrl(g_hPageSign, L"LISTBOX", L"",
                        WS_BORDER | WS_VSCROLL | LBS_NOTIFY | LBS_NOINTEGRALHEIGHT,
                        0, y, 550, 180, IDC_LIST_LOG);
}

/* ------------------------------------------------------------------ */
/* Certificate generation page                                          */
/* ------------------------------------------------------------------ */

static void create_cert_page(HWND parent)
{
    g_hPageCert = CreateWindowExW(0, L"STATIC", L"",
                                   WS_CHILD,
                                   10, 35, 570, 430, parent, NULL, g_hInst, NULL);

    int y = 10;

    make_ctrl(g_hPageCert, L"STATIC",
              L"生成 FileSigner 证书 (根 CA + 代码签名证书)。\n"
              L"将根 CA 导入 Windows 受信任根存储即可信任签名后的文件。",
              0, 0, y, 550, 40, 0);
    y += 50;

    make_ctrl(g_hPageCert, L"STATIC", L"输出目录:", 0, 0, y, 160, 20, 0);
    y += 20;
    make_ctrl(g_hPageCert, L"EDIT", L"./certs", WS_BORDER | ES_AUTOHSCROLL,
              0, y, 450, 24, IDC_EDIT_CERT_DIR);
    make_ctrl(g_hPageCert, L"BUTTON", L"浏览...", 0, 460, y, 90, 24, IDC_BTN_BROWSE_CD);
    y += 32;

    make_ctrl(g_hPageCert, L"STATIC", L"签名证书有效期 (天):", 0, 0, y, 200, 20, 0);
    y += 20;
    make_ctrl(g_hPageCert, L"EDIT", L"90", WS_BORDER | ES_AUTOHSCROLL | ES_NUMBER,
              0, y, 100, 24, IDC_EDIT_CERT_DAYS);
    y += 32;

    make_ctrl(g_hPageCert, L"BUTTON", L"生成证书",
              BS_DEFPUSHBUTTON, 0, y, 180, 32, IDC_BTN_GENERATE);
    y += 40;

    make_ctrl(g_hPageCert, L"STATIC", L"", 0, 0, y, 550, 120, IDC_LBL_CERT_STATUS);
}

/* ------------------------------------------------------------------ */
/* Tab switching                                                       */
/* ------------------------------------------------------------------ */

static void switch_tab(int idx)
{
    ShowWindow(g_hPageSign, idx == 0 ? SW_SHOW : SW_HIDE);
    ShowWindow(g_hPageCert, idx == 1 ? SW_SHOW : SW_HIDE);
}

/* ------------------------------------------------------------------ */
/* Signing progress callback                                           */
/* ------------------------------------------------------------------ */

typedef struct {
    HWND hProgress;
    HWND hLog;
    HWND hBtnSign;
} SignProgressCtx;

static void sign_progress_cb(const char *filename, int current, int total,
                              int success, void *user_data)
{
    SignProgressCtx *ctx = (SignProgressCtx *)user_data;
    SendMessageW(ctx->hProgress, PBM_SETPOS, (WPARAM)(current * 100 / total), 0);

    wchar_t wfilename[MAX_PATH];
    wide_from_acp(filename, wfilename, MAX_PATH);

    if (success == 1)
        log_message(ctx->hLog, L"[成功] %s", wfilename);
    else if (success == 0)
        log_message(ctx->hLog, L"[跳过/失败] %s", wfilename);

    MSG msg;
    while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
}

/* ------------------------------------------------------------------ */
/* Window procedure                                                    */
/* ------------------------------------------------------------------ */

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_CREATE:
    {
        g_hTab = CreateWindowExW(0, WC_TABCONTROLW, L"",
                                  WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
                                  0, 0, 590, 28, hwnd, (HMENU)IDC_TAB, g_hInst, NULL);

        TCITEMW tie;
        tie.mask = TCIF_TEXT;
        tie.pszText = L"签名";
        TabCtrl_InsertItemW(g_hTab, 0, &tie);
        tie.pszText = L"生成证书";
        TabCtrl_InsertItemW(g_hTab, 1, &tie);

        create_sign_page(hwnd);
        create_cert_page(hwnd);
        switch_tab(0);

        SendMessageW(g_hProgress, PBM_SETRANGE32, 0, 100);

        return 0;
    }

    case WM_NOTIFY:
    {
        NMHDR *nmh = (NMHDR *)lParam;
        if (nmh->idFrom == IDC_TAB && nmh->code == TCN_SELCHANGE) {
            switch_tab(TabCtrl_GetCurSel(g_hTab));
        }
        return 0;
    }

    case WM_COMMAND:
    {
        int id = LOWORD(wParam);

        /* --- Sign page --- */
        if (id == IDC_BTN_BROWSE_TGT) {
            wchar_t path[MAX_PATH] = {0};
            if (browse_folder(hwnd, L"选择目标目录", path))
                SetDlgItemTextW(hwnd, IDC_EDIT_TARGET, path);
        }
        else if (id == IDC_BTN_BROWSE_PFX) {
            wchar_t path[MAX_PATH] = {0};
            if (browse_file(hwnd,
                            L"PFX 文件\0*.pfx;*.p12\0所有文件\0*.*\0",
                            L"选择 PFX 文件", path, MAX_PATH))
                SetDlgItemTextW(hwnd, IDC_EDIT_PFX, path);
        }
        else if (id == IDC_BTN_BROWSE_OUT) {
            wchar_t path[MAX_PATH] = {0};
            if (browse_folder(hwnd, L"选择输出目录", path))
                SetDlgItemTextW(hwnd, IDC_EDIT_OUTDIR, path);
        }
        else if (id == IDC_BTN_SIGN) {
            wchar_t wtarget[MAX_PATH], wpfx[MAX_PATH], wpassword[256];
            wchar_t wts_url[512], woutdir[MAX_PATH];

            GetDlgItemTextW(hwnd, IDC_EDIT_TARGET, wtarget, MAX_PATH);
            GetDlgItemTextW(hwnd, IDC_EDIT_PFX, wpfx, MAX_PATH);
            GetDlgItemTextW(hwnd, IDC_EDIT_PASSWORD, wpassword, 256);
            GetDlgItemTextW(hwnd, IDC_EDIT_TIMESTAMP, wts_url, 512);
            GetDlgItemTextW(hwnd, IDC_EDIT_OUTDIR, woutdir, MAX_PATH);

            if (wcslen(wtarget) == 0) {
                MessageBoxW(hwnd, L"请选择目标文件或目录。",
                            L"错误", MB_OK | MB_ICONERROR);
                break;
            }
            if (wcslen(wpfx) == 0) {
                MessageBoxW(hwnd, L"请选择 PFX 文件。",
                            L"错误", MB_OK | MB_ICONERROR);
                break;
            }

            int recursive = IsDlgButtonChecked(hwnd, IDC_CHK_RECURSIVE) == BST_CHECKED;
            int force = IsDlgButtonChecked(hwnd, IDC_CHK_FORCE) == BST_CHECKED;

            /* Convert wide strings to ACP for C library API */
            char target[MAX_PATH], pfx[MAX_PATH], password[256];
            char ts_url[512], outdir[MAX_PATH];
            wide_to_acp(wtarget, target, MAX_PATH);
            wide_to_acp(wpfx, pfx, MAX_PATH);
            wide_to_acp(wpassword, password, 256);
            wide_to_acp(wts_url, ts_url, 512);
            wide_to_acp(woutdir, outdir, MAX_PATH);

            const char *ts = (ts_url[0]) ? ts_url : NULL;
            const char *out = (outdir[0]) ? outdir : NULL;

            HWND hBtn = GetDlgItem(hwnd, IDC_BTN_SIGN);
            EnableWindow(hBtn, FALSE);
            SendMessageW(g_hProgress, PBM_SETPOS, 0, 0);
            SendMessageW(g_hLog, LB_RESETCONTENT, 0, 0);
            log_message(g_hLog, L"正在开始签名...");

            SignProgressCtx ctx = { g_hProgress, g_hLog, hBtn };
            int count;

            if (directory_exists(target)) {
                if (out && !directory_exists(out)) create_directory(out);
                count = batch_sign(target, pfx, password[0] ? password : NULL,
                                    ts, out, force, recursive,
                                    sign_progress_cb, &ctx);
            } else if (file_exists(target)) {
                log_message(g_hLog, L"正在签名: %s", wtarget);
                if (authenticode_sign(target, pfx, password[0] ? password : NULL,
                                       ts, out ? out : target)) {
                    count = 1;
                    log_message(g_hLog, L"[成功] 签名完成");
                } else {
                    count = 0;
                    log_message(g_hLog, L"[失败] 签名失败");
                }
                SendMessageW(g_hProgress, PBM_SETPOS, 100, 0);
            } else {
                log_message(g_hLog, L"错误: 目标不存在: %s", wtarget);
                count = 0;
            }

            log_message(g_hLog, L"完成。已签名 %d 个文件。", count);

            EnableWindow(hBtn, TRUE);
        }

        /* --- Cert page --- */
        else if (id == IDC_BTN_BROWSE_CD) {
            wchar_t path[MAX_PATH] = {0};
            if (browse_folder(hwnd, L"选择输出目录", path))
                SetDlgItemTextW(hwnd, IDC_EDIT_CERT_DIR, path);
        }
        else if (id == IDC_BTN_GENERATE) {
            wchar_t wdir[MAX_PATH], wdays_str[16];
            GetDlgItemTextW(hwnd, IDC_EDIT_CERT_DIR, wdir, MAX_PATH);
            GetDlgItemTextW(hwnd, IDC_EDIT_CERT_DAYS, wdays_str, 16);

            if (wcslen(wdir) == 0) {
                MessageBoxW(hwnd, L"请选择输出目录。",
                            L"错误", MB_OK | MB_ICONERROR);
                break;
            }

            int days = _wtoi(wdays_str);
            if (days <= 0) days = 90;

            char dir[MAX_PATH];
            wide_to_acp(wdir, dir, MAX_PATH);
            if (!directory_exists(dir)) create_directory(dir);

            HWND hBtn = GetDlgItem(hwnd, IDC_BTN_GENERATE);
            EnableWindow(hBtn, FALSE);
            SetDlgItemTextW(hwnd, IDC_LBL_CERT_STATUS,
                            L"正在生成...");

            if (cert_generate(dir, NULL, "FileSigner", days)) {
                wchar_t msg[512];
                wsprintfW(msg,
                         L"证书生成成功!\n\n"
                         L"生成文件位于: %s\n\n"
                         L"重要: 请将 FileSigner_RootCA.cer 导入\n"
                         L"Windows “受信任的根证书颁发机构”\n"
                         L"存储，以信任签名后的可执行文件。",
                         wdir);
                SetDlgItemTextW(hwnd, IDC_LBL_CERT_STATUS, msg);
                MessageBoxW(hwnd, msg, L"成功", MB_OK | MB_ICONINFORMATION);
            } else {
                SetDlgItemTextW(hwnd, IDC_LBL_CERT_STATUS,
                                L"生成失败! 请查看控制台输出。");
                MessageBoxW(hwnd, L"证书生成失败。",
                            L"错误", MB_OK | MB_ICONERROR);
            }

            EnableWindow(hBtn, TRUE);
        }

        return 0;
    }

    case WM_SIZE:
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

/* ------------------------------------------------------------------ */
/* GUI entry point                                                     */
/* ------------------------------------------------------------------ */

int gui_main(HINSTANCE hInstance, HINSTANCE hPrevInstance,
             LPSTR lpCmdLine, int nCmdShow)
{
    WNDCLASSW wc;
    HWND hwnd;
    MSG msg;

    INITCOMMONCONTROLSEX icc;
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_TAB_CLASSES | ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    CoInitialize(NULL);

    g_hInst = hInstance;
    (void)hPrevInstance; (void)lpCmdLine; (void)nCmdShow;

    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc = WndProc;
    wc.hInstance = g_hInst;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"FileSignerGUI";
    wc.hIcon = LoadIconW(hInstance, MAKEINTRESOURCEW(IDI_MAIN_ICON));
    RegisterClassW(&wc);

    hwnd = CreateWindowExW(0, L"FileSignerGUI",
                            L"FileSigner - Authenticode PE 签名工具",
                            WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX,
                            CW_USEDEFAULT, CW_USEDEFAULT,
                            600, 520,
                            NULL, NULL, g_hInst, NULL);

    if (!hwnd) return 1;

    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    while (GetMessageW(&msg, NULL, 0, 0)) {
        if (!IsDialogMessageW(hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    CoUninitialize();
    return (int)msg.wParam;
}

#endif /* _WIN32 */
