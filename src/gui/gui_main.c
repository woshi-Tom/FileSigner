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

/* Subclass procedure for page panels (STATIC) — forward WM_COMMAND to main window */
#include <commctrl.h>
static LRESULT CALLBACK page_subclass(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp,
                                      UINT_PTR uIdSubclass, DWORD_PTR dwRefData)
{
    (void)uIdSubclass; (void)dwRefData;
    /* Forward messages that need custom handling to main window */
    if (msg == WM_COMMAND || msg == WM_CTLCOLORSTATIC || msg == WM_CTLCOLORLISTBOX) {
        return SendMessageW(GetParent(hwnd), msg, wp, lp);
    }
    return DefSubclassProc(hwnd, msg, wp, lp);
}

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
#define IDC_EDIT_CERT_PW    306

/* Layout constants */
#define PAD             14      /* outer padding */
#define GAP             10      /* vertical gap between groups */
#define LH              18      /* label height */
#define EH              28      /* edit/button height */
#define W_CLIENT        600     /* client width */
#define W_EDIT          460     /* edit box width */
#define W_BROWSE        84      /* browse button width */
#define W_BTN_SIGN      130     /* sign button width */
#define W_BTN_GEN       160     /* generate button width */
#define PAGE_TOP        42      /* top offset for page content */
#define TAB_H           32      /* tab control height */

/* ------------------------------------------------------------------ */
/* Globals                                                             */
/* ------------------------------------------------------------------ */

static HINSTANCE g_hInst;
static HFONT g_hFont;
static HFONT g_hMonoFont;
static HWND g_hTab;
static HWND g_hPageSign, g_hPageCert;
static HWND g_hProgress, g_hLog;

/* Color scheme */
static HBRUSH g_hbrBg;             /* main background */
static HBRUSH g_hbrLogBg;          /* log area dark background */
static HBRUSH g_hbrEditBg;         /* edit control background */
static HBRUSH g_hbrBtnFace;        /* button/checkbox background */
static COLORREF g_clrBg            = RGB(245, 247, 250);  /* light blue-gray */
static COLORREF g_clrLogBg         = RGB(30, 30, 40);     /* dark background */
static COLORREF g_clrLogText       = RGB(200, 220, 255);  /* light blue text */
static COLORREF g_clrAccent        = RGB(0, 120, 215);    /* Windows blue */
static COLORREF g_clrAccentHover   = RGB(0, 140, 240);    /* lighter blue hover */
static COLORREF g_clrText          = RGB(30, 30, 30);     /* dark text */
static COLORREF g_clrLabel         = RGB(60, 60, 70);     /* label text */
static COLORREF g_clrEditBg        = RGB(255, 255, 255);  /* white */
static COLORREF g_clrLogOK         = RGB(80, 200, 120);   /* green for [OK] */
static COLORREF g_clrLogFail       = RGB(240, 80, 80);    /* red for [FAIL] */
static COLORREF g_clrLogSkip       = RGB(180, 180, 190);  /* gray for [SKIP] */

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static void wide_from_utf8(const char *src, wchar_t *dst, int dst_chars)
{
    if (!src || !src[0]) { dst[0] = L'\0'; return; }
    MultiByteToWideChar(CP_UTF8, 0, src, -1, dst, dst_chars);
}

static void wide_to_utf8(const wchar_t *src, char *dst, int dst_chars)
{
    if (!src || !src[0]) { dst[0] = '\0'; return; }
    WideCharToMultiByte(CP_UTF8, 0, src, -1, dst, dst_chars, NULL, NULL);
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

/* Set font on a window and all its children */
static void set_font_callback(HWND child)
{
    SendMessageW(child, WM_SETFONT, (WPARAM)g_hFont, TRUE);
}

static void apply_font(HWND parent)
{
    EnumChildWindows(parent, (WNDENUMPROC)set_font_callback, 0);
}

static HWND make_ctrl(HWND parent, const wchar_t *cls, const wchar_t *text,
                       DWORD style, int x, int y, int w, int ht, int id)
{
    HWND hw = CreateWindowExW(0, cls, text,
                               WS_CHILD | WS_VISIBLE | style,
                               x, y, w, ht,
                               parent, (HMENU)(INT_PTR)id, g_hInst, NULL);
    SendMessageW(hw, WM_SETFONT, (WPARAM)g_hFont, TRUE);
    return hw;
}

/* ------------------------------------------------------------------ */
/* Sign page                                                           */
/* ------------------------------------------------------------------ */

static void create_sign_page(HWND parent)
{
    g_hPageSign = CreateWindowExW(0, L"STATIC", L"",
                                   WS_CHILD | WS_VISIBLE,
                                   PAD, PAGE_TOP,
                                   W_CLIENT - 2*PAD, 500,
                                   parent, NULL, g_hInst, NULL);

    int y = 8;
    int edit_x = W_CLIENT - 2*PAD - W_BROWSE - 6;

    /* Section header */
    make_ctrl(g_hPageSign, L"STATIC", L"  签名设置",
              SS_LEFT, 0, y, 300, LH + 2, 0);
    y += LH + 6;

    /* Target */
    make_ctrl(g_hPageSign, L"STATIC", L"目标 (文件或目录):", 0, 8, y, edit_x, LH, 0);
    y += LH + 3;
    make_ctrl(g_hPageSign, L"EDIT", L"", WS_BORDER | ES_AUTOHSCROLL,
              0, y, W_EDIT, EH, IDC_EDIT_TARGET);
    make_ctrl(g_hPageSign, L"BUTTON", L"浏览...",
              BS_FLAT, W_EDIT + 6, y, W_BROWSE, EH, IDC_BTN_BROWSE_TGT);
    y += EH + 6;

    /* PFX */
    make_ctrl(g_hPageSign, L"STATIC", L"PFX 证书文件:", 0, 8, y, edit_x, LH, 0);
    y += LH + 3;
    make_ctrl(g_hPageSign, L"EDIT", L"", WS_BORDER | ES_AUTOHSCROLL,
              0, y, W_EDIT, EH, IDC_EDIT_PFX);
    make_ctrl(g_hPageSign, L"BUTTON", L"浏览...",
              BS_FLAT, W_EDIT + 6, y, W_BROWSE, EH, IDC_BTN_BROWSE_PFX);
    y += EH + 6;

    /* Password */
    make_ctrl(g_hPageSign, L"STATIC", L"PFX 密码:", 0, 8, y, edit_x, LH, 0);
    y += LH + 3;
    make_ctrl(g_hPageSign, L"EDIT", L"",
              WS_BORDER | ES_AUTOHSCROLL | ES_PASSWORD,
              0, y, 280, EH, IDC_EDIT_PASSWORD);
    y += EH + 6;

    /* Timestamp */
    make_ctrl(g_hPageSign, L"STATIC", L"时间戳服务器 URL (可选):", 0, 8, y, edit_x, LH, 0);
    y += LH + 3;
    make_ctrl(g_hPageSign, L"EDIT", L"http://timestamp.digicert.com",
              WS_BORDER | ES_AUTOHSCROLL,
              0, y, W_EDIT + W_BROWSE + 6, EH, IDC_EDIT_TIMESTAMP);
    y += EH + 6;

    /* Output dir */
    make_ctrl(g_hPageSign, L"STATIC", L"输出目录 (可选, 留空 = 覆盖原文件):", 0, 8, y, edit_x, LH, 0);
    y += LH + 3;
    make_ctrl(g_hPageSign, L"EDIT", L"", WS_BORDER | ES_AUTOHSCROLL,
              0, y, W_EDIT, EH, IDC_EDIT_OUTDIR);
    make_ctrl(g_hPageSign, L"BUTTON", L"浏览...",
              BS_FLAT, W_EDIT + 6, y, W_BROWSE, EH, IDC_BTN_BROWSE_OUT);
    y += EH + 8;

    /* Checkboxes */
    make_ctrl(g_hPageSign, L"BUTTON", L"包含子目录",
              BS_AUTOCHECKBOX, 4, y, 200, LH, IDC_CHK_RECURSIVE);
    make_ctrl(g_hPageSign, L"BUTTON", L"强制重新签名",
              BS_AUTOCHECKBOX, 220, y, 180, LH, IDC_CHK_FORCE);
    y += LH + 10;

    /* Separator line */
    HWND hSep = make_ctrl(g_hPageSign, L"STATIC", L"",
                           SS_ETCHEDHORZ, 0, y, W_CLIENT - 2*PAD, 2, 0);
    (void)hSep;
    y += 8;

    /* Sign button */
    make_ctrl(g_hPageSign, L"BUTTON", L"开始签名",
              BS_DEFPUSHBUTTON, 0, y, W_BTN_SIGN, EH + 4, IDC_BTN_SIGN);
    y += EH + 4 + 8;

    /* Progress bar */
    g_hProgress = make_ctrl(g_hPageSign, PROGRESS_CLASSW, L"",
                             0, 0, y, W_CLIENT - 2*PAD, 22, IDC_PROGRESS);
    y += 22 + 8;

    /* Log section title */
    make_ctrl(g_hPageSign, L"STATIC", L"  日志输出",
              SS_LEFT, 0, y, 300, LH + 2, 0);
    y += LH + 3;

    /* Log listbox */
    g_hLog = make_ctrl(g_hPageSign, L"LISTBOX", L"",
                        WS_BORDER | WS_VSCROLL | LBS_NOTIFY | LBS_NOINTEGRALHEIGHT,
                        0, y, W_CLIENT - 2*PAD, 170, IDC_LIST_LOG);

    /* Log listbox font (monospace feel) */
    g_hMonoFont = CreateFontW(-14, 0, 0, 0, FW_NORMAL, 0, 0, 0,
                                    GB2312_CHARSET, 0, 0, CLEARTYPE_QUALITY,
                                    FIXED_PITCH | FF_MODERN,
                                    L"Microsoft YaHei UI");
    if (!g_hMonoFont)
        g_hMonoFont = CreateFontW(-14, 0, 0, 0, FW_NORMAL, 0, 0, 0,
                                  DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY,
                                  0, L"Segoe UI");
    SendMessageW(g_hLog, WM_SETFONT, (WPARAM)g_hMonoFont, TRUE);

    /* Set dark background for log listbox */
    SendMessageW(g_hLog, LB_SETITEMHEIGHT, 0, 18);
}

/* ------------------------------------------------------------------ */
/* Certificate generation page                                          */
/* ------------------------------------------------------------------ */

static void create_cert_page(HWND parent)
{
    g_hPageCert = CreateWindowExW(0, L"STATIC", L"",
                                   WS_CHILD,
                                   PAD, PAGE_TOP,
                                   W_CLIENT - 2*PAD, 500,
                                   parent, NULL, g_hInst, NULL);

    int y = 8;

    /* Section header */
    make_ctrl(g_hPageCert, L"STATIC", L"  证书生成",
              SS_LEFT, 0, y, 300, LH + 2, 0);
    y += LH + 8;

    /* Description */
    make_ctrl(g_hPageCert, L"STATIC",
              L"生成自签名根 CA + 代码签名证书。\n"
              L"将根 CA 导入 Windows 受信任根存储即可信任签名。",
              SS_LEFT, 8, y, W_CLIENT - 2*PAD - 16, 36, 0);
    y += 44;

    /* Output directory */
    make_ctrl(g_hPageCert, L"STATIC", L"输出目录:", 0, 8, y, W_CLIENT - 2*PAD, LH, 0);
    y += LH + 3;
    make_ctrl(g_hPageCert, L"EDIT", L"./certs",
              WS_BORDER | ES_AUTOHSCROLL,
              0, y, W_EDIT, EH, IDC_EDIT_CERT_DIR);
    make_ctrl(g_hPageCert, L"BUTTON", L"浏览...",
              BS_FLAT, W_EDIT + 6, y, W_BROWSE, EH, IDC_BTN_BROWSE_CD);
    y += EH + 8;

    /* Validity days */
    make_ctrl(g_hPageCert, L"STATIC", L"签名证书有效期 (天):", 0, 8, y, 180, LH, 0);
    y += LH + 3;
    make_ctrl(g_hPageCert, L"EDIT", L"90",
              WS_BORDER | ES_AUTOHSCROLL | ES_NUMBER,
              0, y, 80, EH, IDC_EDIT_CERT_DAYS);
    y += EH + 8;

    /* PFX password */
    make_ctrl(g_hPageCert, L"STATIC", L"PFX 密码 (签名时需填写此密码):", 0, 8, y, W_CLIENT - 2*PAD, LH, 0);
    y += LH + 3;
    make_ctrl(g_hPageCert, L"EDIT", L"",
              WS_BORDER | ES_AUTOHSCROLL,
              0, y, 280, EH, IDC_EDIT_CERT_PW);
    y += EH + 10;

    /* Separator line */
    make_ctrl(g_hPageCert, L"STATIC", L"",
              SS_ETCHEDHORZ, 0, y, W_CLIENT - 2*PAD, 2, 0);
    y += 8;

    /* Generate button */
    make_ctrl(g_hPageCert, L"BUTTON", L"生成证书",
              BS_DEFPUSHBUTTON, 0, y, W_BTN_GEN, EH + 4, IDC_BTN_GENERATE);
    y += EH + 4 + 10;

    /* Status label */
    make_ctrl(g_hPageCert, L"STATIC", L"",
              SS_LEFT, 8, y, W_CLIENT - 2*PAD - 16, 140, IDC_LBL_CERT_STATUS);
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
    wide_from_utf8(filename, wfilename, MAX_PATH);

    if (success == 1)
        log_message(ctx->hLog, L"[OK] %s", wfilename);
    else if (success == -2)
        log_message(ctx->hLog, L"[跳过] %s (已签名，请勾选\"强制重新签名\")", wfilename);
    else if (success == 0)
        log_message(ctx->hLog, L"[失败] %s", wfilename);

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
        /* Tab control */
        g_hTab = CreateWindowExW(0, WC_TABCONTROLW, L"",
                                  WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS
                                  | TCS_FLATBUTTONS,
                                  0, 0, W_CLIENT, TAB_H + 4,
                                  hwnd, (HMENU)IDC_TAB, g_hInst, NULL);
        SendMessageW(g_hTab, WM_SETFONT, (WPARAM)g_hFont, TRUE);

        TCITEMW tie;
        tie.mask = TCIF_TEXT;
        tie.pszText = L"  签名  ";
        SendMessageW(g_hTab, TCM_INSERTITEMW, 0, (LPARAM)&tie);
        tie.pszText = L"  生成证书  ";
        SendMessageW(g_hTab, TCM_INSERTITEMW, 1, (LPARAM)&tie);

        create_sign_page(hwnd);
        create_cert_page(hwnd);
        apply_font(g_hPageSign);
        apply_font(g_hPageCert);
        /* Subclass page panels to forward WM_COMMAND to main window */
        SetWindowSubclass(g_hPageSign, page_subclass, 0, 0);
        SetWindowSubclass(g_hPageCert, page_subclass, 0, 0);
        switch_tab(0);

        SendMessageW(g_hProgress, PBM_SETRANGE32, 0, 100);
        SendMessageW(g_hProgress, PBM_SETBARCOLOR, 0, (LPARAM)g_clrAccent);
        SendMessageW(g_hProgress, PBM_SETBKCOLOR, 0, (LPARAM)RGB(220, 225, 232));

        return 0;
    }

    case WM_CTLCOLORSTATIC:
    {
        HDC hdc = (HDC)wParam;
        HWND hCtrl = (HWND)lParam;
        /* Dark bg for log listbox (it sends CTLCOLORSTATIC too) */
        if (hCtrl == g_hLog) {
            SetTextColor(hdc, g_clrLogText);
            SetBkColor(hdc, g_clrLogBg);
            return (LRESULT)g_hbrLogBg;
        }
        /* Light background for all other static controls */
        SetTextColor(hdc, g_clrText);
        SetBkColor(hdc, g_clrBg);
        return (LRESULT)g_hbrBg;
    }

    case WM_CTLCOLOREDIT:
    {
        HDC hdc = (HDC)wParam;
        SetBkColor(hdc, g_clrEditBg);
        return (LRESULT)g_hbrEditBg;
    }

    case WM_CTLCOLORLISTBOX:
    {
        HDC hdc = (HDC)wParam;
        SetTextColor(hdc, g_clrLogText);
        SetBkColor(hdc, g_clrLogBg);
        return (LRESULT)g_hbrLogBg;
    }

    case WM_PAINT:
    {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc;
        GetClientRect(hwnd, &rc);

        /* Fill background */
        FillRect(hdc, &rc, g_hbrBg);

        /* Accent header bar */
        RECT hdr = { 0, 0, rc.right, 3 };
        HBRUSH hbrHdr = CreateSolidBrush(g_clrAccent);
        FillRect(hdc, &hdr, hbrHdr);
        DeleteObject(hbrHdr);

        /* Thin line below tab area */
        RECT line = { PAD, PAGE_TOP - 2, rc.right - PAD, PAGE_TOP - 1 };
        HBRUSH hbrLine = CreateSolidBrush(RGB(210, 215, 222));
        FillRect(hdc, &line, hbrLine);
        DeleteObject(hbrLine);

        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_ERASEBKGND:
    {
        RECT rc;
        GetClientRect(hwnd, &rc);
        FillRect((HDC)wParam, &rc, g_hbrBg);
        return 1;
    }

    case WM_NOTIFY:
    {
        NMHDR *nmh = (NMHDR *)lParam;
        if (nmh->idFrom == IDC_TAB && nmh->code == TCN_SELCHANGE) {
            switch_tab(TabCtrl_GetCurSel(g_hTab));
            InvalidateRect(hwnd, NULL, TRUE);
        }
        /* Custom draw tab control for modern look */
        if (nmh->idFrom == IDC_TAB && nmh->code == NM_CUSTOMDRAW) {
            NMTTCUSTOMDRAW *nmc = (NMTTCUSTOMDRAW *)lParam;
            if (nmc->nmcd.dwDrawStage == CDDS_PREPAINT)
                return CDRF_NOTIFYITEMDRAW;
            if (nmc->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
                int sel = TabCtrl_GetCurSel(g_hTab);
                BOOL isSel = ((int)nmc->nmcd.dwItemSpec == sel);
                RECT rc = nmc->nmcd.rc;

                /* Fill background */
                COLORREF bg = isSel ? g_clrBg : RGB(230, 234, 240);
                HBRUSH hbr = CreateSolidBrush(bg);
                FillRect(nmc->nmcd.hdc, &rc, hbr);
                DeleteObject(hbr);

                /* Draw accent bar on selected tab */
                if (isSel) {
                    RECT bar = { rc.left + 8, rc.bottom - 3, rc.right - 8, rc.bottom };
                    HBRUSH hbrBar = CreateSolidBrush(g_clrAccent);
                    FillRect(nmc->nmcd.hdc, &bar, hbrBar);
                    DeleteObject(hbrBar);
                }

                /* Draw text */
                TCITEMW tci;
                memset(&tci, 0, sizeof(tci));
                tci.mask = TCIF_TEXT;
                wchar_t tabText[64] = {0};
                tci.pszText = tabText;
                tci.cchTextMax = 64;
                SendMessageW(g_hTab, TCM_GETITEMW, nmc->nmcd.dwItemSpec, (LPARAM)&tci);

                SetBkMode(nmc->nmcd.hdc, TRANSPARENT);
                SetTextColor(nmc->nmcd.hdc, isSel ? g_clrAccent : RGB(100, 100, 110));
                SelectObject(nmc->nmcd.hdc, g_hFont);
                DrawTextW(nmc->nmcd.hdc, tabText, -1, &rc,
                          DT_CENTER | DT_VCENTER | DT_SINGLELINE);
                return CDRF_SKIPDEFAULT;
            }
        }
        return 0;
    }

    case WM_COMMAND:
    {
        int id = LOWORD(wParam);

        if (id == IDC_BTN_BROWSE_TGT) {
            wchar_t path[MAX_PATH] = {0};
            if (browse_folder(hwnd, L"选择目标目录", path))
                SetDlgItemTextW(g_hPageSign, IDC_EDIT_TARGET, path);
        }
        else if (id == IDC_BTN_BROWSE_PFX) {
            wchar_t path[MAX_PATH] = {0};
            if (browse_file(hwnd,
                            L"PFX 文件\0*.pfx;*.p12\所有文件\0*.*\0",
                            L"选择 PFX 文件", path, MAX_PATH))
                SetDlgItemTextW(g_hPageSign, IDC_EDIT_PFX, path);
        }
        else if (id == IDC_BTN_BROWSE_OUT) {
            wchar_t path[MAX_PATH] = {0};
            if (browse_folder(hwnd, L"选择输出目录", path))
                SetDlgItemTextW(g_hPageSign, IDC_EDIT_OUTDIR, path);
        }
        else if (id == IDC_BTN_SIGN) {
            wchar_t wtarget[MAX_PATH], wpfx[MAX_PATH], wpassword[256];
            wchar_t wts_url[512], woutdir[MAX_PATH];

            GetDlgItemTextW(g_hPageSign, IDC_EDIT_TARGET, wtarget, MAX_PATH);
            GetDlgItemTextW(g_hPageSign, IDC_EDIT_PFX, wpfx, MAX_PATH);
            GetDlgItemTextW(g_hPageSign, IDC_EDIT_PASSWORD, wpassword, 256);
            GetDlgItemTextW(g_hPageSign, IDC_EDIT_TIMESTAMP, wts_url, 512);
            GetDlgItemTextW(g_hPageSign, IDC_EDIT_OUTDIR, woutdir, MAX_PATH);

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

            int recursive = IsDlgButtonChecked(g_hPageSign, IDC_CHK_RECURSIVE) == BST_CHECKED;
            int force = IsDlgButtonChecked(g_hPageSign, IDC_CHK_FORCE) == BST_CHECKED;

            char target[MAX_PATH], pfx[MAX_PATH], password[256];
            char ts_url[512], outdir[MAX_PATH];
            wide_to_utf8(wtarget, target, MAX_PATH);
            wide_to_utf8(wpfx, pfx, MAX_PATH);
            wide_to_utf8(wpassword, password, 256);
            wide_to_utf8(wts_url, ts_url, 512);
            wide_to_utf8(woutdir, outdir, MAX_PATH);

            const char *ts = (ts_url[0]) ? ts_url : NULL;
            const char *out = (outdir[0]) ? outdir : NULL;

            HWND hBtn = GetDlgItem(g_hPageSign, IDC_BTN_SIGN);
            EnableWindow(hBtn, FALSE);
            SendMessageW(g_hProgress, PBM_SETPOS, 0, 0);
            SendMessageW(g_hLog, LB_RESETCONTENT, 0, 0);
            log_message(g_hLog, L"开始签名...");
            log_message(g_hLog, L"目标: %s", wtarget);
            log_message(g_hLog, L"PFX: %s", wpfx);
            log_message(g_hLog, L"密码: %ls", wpassword[0] ? L"***" : L"(空)");
            log_message(g_hLog, L"输出: %s", woutdir[0] ? woutdir : L"(覆盖原文件)");
            log_message(g_hLog, L"强制: %s  递归: %s",
                        force ? L"是" : L"否", recursive ? L"是" : L"否");

            SignProgressCtx ctx = { g_hProgress, g_hLog, hBtn };
            int count = 0;

            __try {
                if (directory_exists(target)) {
                    log_message(g_hLog, L"[调试] 检测为目录");
                    if (out && !directory_exists(out)) create_directory(out);
                    count = batch_sign(target, pfx, password[0] ? password : NULL,
                                        ts, out, force, recursive,
                                        sign_progress_cb, &ctx);
                } else if (file_exists(target)) {
                    log_message(g_hLog, L"[调试] 检测为文件");
                    log_message(g_hLog, L"正在签名: %s", wtarget);
                    if (authenticode_sign(target, pfx, password[0] ? password : NULL,
                                           ts, out ? out : target)) {
                        count = 1;
                        log_message(g_hLog, L"[OK] 签名完成");
                    } else {
                        log_message(g_hLog, L"[FAIL] 签名失败");
                    }
                    SendMessageW(g_hProgress, PBM_SETPOS, 100, 0);
                } else {
                    log_message(g_hLog, L"错误: 目标不存在: %s", wtarget);
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                log_message(g_hLog, L"[严重错误] 签名过程崩溃! 异常代码: 0x%08X",
                            GetExceptionCode());
            }

            log_message(g_hLog, L"完成 - 已签名 %d 个文件", count);
            EnableWindow(hBtn, TRUE);
        }

        else if (id == IDC_BTN_BROWSE_CD) {
            wchar_t path[MAX_PATH] = {0};
            if (browse_folder(hwnd, L"选择输出目录", path))
                SetDlgItemTextW(g_hPageCert, IDC_EDIT_CERT_DIR, path);
        }
        else if (id == IDC_BTN_GENERATE) {
            wchar_t wdir[MAX_PATH], wdays_str[16], wpw[256];
            GetDlgItemTextW(g_hPageCert, IDC_EDIT_CERT_DIR, wdir, MAX_PATH);
            GetDlgItemTextW(g_hPageCert, IDC_EDIT_CERT_DAYS, wdays_str, 16);
            GetDlgItemTextW(g_hPageCert, IDC_EDIT_CERT_PW, wpw, 256);

            if (wcslen(wdir) == 0) {
                MessageBoxW(hwnd, L"请选择输出目录。",
                            L"错误", MB_OK | MB_ICONERROR);
                break;
            }

            int days = _wtoi(wdays_str);
            if (days <= 0) days = 90;

            char dir[MAX_PATH], pw[256];
            wide_to_utf8(wdir, dir, MAX_PATH);
            wide_to_utf8(wpw, pw, 256);
            if (!directory_exists(dir)) create_directory(dir);

            HWND hBtn = GetDlgItem(g_hPageCert, IDC_BTN_GENERATE);
            EnableWindow(hBtn, FALSE);
            SetDlgItemTextW(g_hPageCert, IDC_LBL_CERT_STATUS, L"正在生成...");

            const char *pfx_pw = pw[0] ? pw : NULL;
            if (cert_generate(dir, NULL, pfx_pw, days)) {
                wchar_t msg[512];
                if (wpw[0])
                    wsprintfW(msg,
                             L"证书生成成功!\n\n"
                             L"生成文件位于: %s\n\n"
                             L"PFX 密码已设置，签名时请使用相同密码。\n"
                             L"请将 FileSigner_RootCA.cer 导入\n"
                             L"Windows 受信任的根证书颁发机构",
                             wdir);
                else
                    wsprintfW(msg,
                             L"证书生成成功!\n\n"
                             L"生成文件位于: %s\n\n"
                             L"PFX 无密码，签名时密码留空即可。\n"
                             L"请将 FileSigner_RootCA.cer 导入\n"
                             L"Windows 受信任的根证书颁发机构",
                             wdir);
                SetDlgItemTextW(g_hPageCert, IDC_LBL_CERT_STATUS, msg);
                MessageBoxW(hwnd, msg, L"成功", MB_OK | MB_ICONINFORMATION);
            } else {
                SetDlgItemTextW(g_hPageCert, IDC_LBL_CERT_STATUS,
                                L"生成失败! 请查看控制台输出。");
                MessageBoxW(hwnd, L"证书生成失败。",
                            L"错误", MB_OK | MB_ICONERROR);
            }

            EnableWindow(hBtn, TRUE);
        }

        return 0;
    }

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

    /* DPI awareness */
    HMODULE hUser = GetModuleHandleW(L"user32.dll");
    typedef BOOL (WINAPI *SetDpiAwarenessCtx_t)(HANDLE);
    SetDpiAwarenessCtx_t pSetDpiAware =
        (SetDpiAwarenessCtx_t)(hUser ?
            GetProcAddress(hUser, "SetProcessDpiAwarenessContext") : NULL);
    if (pSetDpiAware)
        pSetDpiAware((HANDLE)-4); /* DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 */
    else
        SetProcessDPIAware();

    /* Init common controls */
    INITCOMMONCONTROLSEX icc;
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_TAB_CLASSES | ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    CoInitialize(NULL);
    g_hInst = hInstance;
    (void)hPrevInstance; (void)lpCmdLine; (void)nCmdShow;

    /* Create font */
    g_hFont = CreateFontW(-14, 0, 0, 0, FW_NORMAL, 0, 0, 0,
                            GB2312_CHARSET, 0, 0, CLEARTYPE_QUALITY,
                            0, L"Microsoft YaHei UI");
    if (!g_hFont)
        g_hFont = CreateFontW(-14, 0, 0, 0, FW_NORMAL, 0, 0, 0,
                              DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY,
                              0, L"Segoe UI");

    /* Create brushes for custom colors */
    g_hbrBg     = CreateSolidBrush(g_clrBg);
    g_hbrLogBg  = CreateSolidBrush(g_clrLogBg);
    g_hbrEditBg = CreateSolidBrush(g_clrEditBg);
    g_hbrBtnFace = CreateSolidBrush(g_clrBg);

    /* Register window class */
    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc = WndProc;
    wc.hInstance = g_hInst;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = g_hbrBg;
    wc.lpszClassName = L"FileSignerGUI";
    wc.hIcon = LoadIconW(hInstance, MAKEINTRESOURCEW(IDI_MAIN_ICON));
    RegisterClassW(&wc);

    /* Create window, centered on screen */
    int win_w = W_CLIENT + 2 * GetSystemMetrics(SM_CXSIZEFRAME);
    int win_h = 560 + 2 * GetSystemMetrics(SM_CYSIZEFRAME) + GetSystemMetrics(SM_CYCAPTION);
    int scr_w = GetSystemMetrics(SM_CXSCREEN);
    int scr_h = GetSystemMetrics(SM_CYSCREEN);
    int win_x = (scr_w - win_w) / 2;
    int win_y = (scr_h - win_h) / 2;

    hwnd = CreateWindowExW(0, L"FileSignerGUI",
                            L"FileSigner  Authenticode PE 签名工具",
                            WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX,
                            win_x, win_y, win_w, win_h,
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

    /* Cleanup */
    DeleteObject(g_hFont);
    if (g_hMonoFont) DeleteObject(g_hMonoFont);
    DeleteObject(g_hbrBg);
    DeleteObject(g_hbrLogBg);
    DeleteObject(g_hbrEditBg);
    DeleteObject(g_hbrBtnFace);
    CoUninitialize();
    return (int)msg.wParam;
}

#endif /* _WIN32 */
