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
#include <uxtheme.h>
#include <winhttp.h>
#include <windowsx.h>

#include "authenticode.h"
#include "batch_signer.h"
#include "cert_gen.h"
#include "timestamp.h"
#include "resource.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "uxtheme.lib")

/* ── Control IDs ─────────────────────────────────────────────── */

#define IDC_TAB_SIGN_BTN    101
#define IDC_TAB_CERT_BTN    102
#define IDC_TAB_VERIFY_BTN  103

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

#define IDC_EDIT_VERIFY_PE   501
#define IDC_BTN_BROWSE_VPE   502
#define IDC_EDIT_VERIFY_CA   503
#define IDC_BTN_BROWSE_VCA   504
#define IDC_BTN_VERIFY       505
#define IDC_LBL_VERIFY_STATUS 506
#define IDC_SEP_VERIFY       507
#define IDC_CHK_VERIFY_RECURSIVE 508

#define IDC_BTN_ABOUT       401
#define IDC_BTN_UPDATE      402
#define IDC_BTN_EXPORT_LOG  403

#define IDM_COPY_SELECTED   5001
#define IDM_SELECT_ALL      5002

#define WM_APP_LOG          (WM_APP + 1)
#define WM_APP_PROGRESS     (WM_APP + 2)
#define WM_APP_SIGN_DONE    (WM_APP + 3)
#define WM_APP_CERT_DONE    (WM_APP + 4)
#define WM_APP_TSA_DONE     (WM_APP + 5)
#define WM_APP_UPDATE_DONE  (WM_APP + 6)
#define WM_APP_VERIFY_DONE  (WM_APP + 7)

#define GUI_PATH_LEN    4096

/* ── Layout ──────────────────────────────────────────────────── */

#define PAD             16
#define LH              18
#define EH              28
#define BTN_H           34
#define W_CLIENT        800
#define W_EDIT           624
#define W_BROWSE         86
#define LOG_H           200
#define PAGE_H          660
#define TAB_H           40
#define TAB_BTN_W       120

#define LOG_COLOR_INFO  0
#define LOG_COLOR_OK    1
#define LOG_COLOR_FAIL  2
#define LOG_COLOR_SKIP  3

/* ── Breeze Palette ──────────────────────────────────────────── */

static COLORREF g_clrBg         = RGB(255, 255, 255);  /* #FFFFFF */
static COLORREF g_clrPanelBg    = RGB(245, 247, 250);  /* #F5F7FA */
static COLORREF g_clrText       = RGB(35, 38, 41);     /* #232629 */
static COLORREF g_clrLabel      = RGB(127, 140, 141);  /* #7F8C8D */
static COLORREF g_clrAccent     = RGB(61, 174, 233);   /* #3DAEE9 */
static COLORREF g_clrAccentHov  = RGB(45, 158, 211);   /* #2D9ED3 */
static COLORREF g_clrAccentDown = RGB(37, 136, 186);   /* #2588BA */
static COLORREF g_clrBorder     = RGB(224, 224, 224);  /* #E0E0E0 */
static COLORREF g_clrEditBg     = RGB(255, 255, 255);
static COLORREF g_clrBtnBg      = RGB(240, 241, 244);  /* #F0F1F4 */
static COLORREF g_clrBtnHov     = RGB(228, 230, 234);  /* #E4E6EA */
static COLORREF g_clrBtnBorder  = RGB(208, 214, 224);  /* #D0D6E0 */
static COLORREF g_clrTabBg      = RGB(245, 247, 250);  /* #F5F7FA */

/* Log terminal palette (Catppuccin-inspired) */
static COLORREF g_clrLogBg      = RGB(30, 30, 46);    /* #1E1E2E */
static COLORREF g_clrLogText    = RGB(205, 214, 244);  /* #CDD6F4 */
static COLORREF g_clrLogOk      = RGB(166, 227, 161);  /* #A6E3A1 */
static COLORREF g_clrLogFail    = RGB(243, 139, 168);  /* #F38BA8 */
static COLORREF g_clrLogSkip    = RGB(108, 112, 134);  /* #6C7086 */

/* ── Structures ──────────────────────────────────────────────── */

/* Failed file entry for summary */
typedef struct FailEntry {
    char filename[256];
    char reason[256];
    struct FailEntry *next;
} FailEntry;

typedef struct {
    HWND hwnd;
    char target[GUI_PATH_LEN];
    char pfx[GUI_PATH_LEN];
    char password[256];
    char ts_url[512];
    char outdir[GUI_PATH_LEN];
    int recursive;
    int force;
    volatile LONG ok_count;
    volatile LONG fail_count;
    volatile LONG skip_count;
    FailEntry *fail_list;
} SignTask;

typedef struct {
    wchar_t wdir[GUI_PATH_LEN];
    wchar_t wpw[256];
    HWND hwnd;
    char dir[GUI_PATH_LEN];
    char pw[256];
    char cn[256];
    char email[256];
    int days;
} CertTask;

typedef struct {
    HWND hwnd;
    char pe_path[GUI_PATH_LEN];
    char ca_path[GUI_PATH_LEN];
    int recursive;
    int is_dir;
    int result;
} VerifyTask;

/* ── Globals ─────────────────────────────────────────────────── */

static HINSTANCE g_hInst;
static HFONT g_hFont;
static HFONT g_hFontBold;
static HFONT g_hFontTab;
static HFONT g_hMonoFont;
static HBRUSH g_hbrBg, g_hbrPanel, g_hbrLogBg, g_hbrEditBg, g_hbrAccent;

static HWND g_hwndMain;
static HWND g_hBtnSign, g_hBtnCert, g_hBtnVerify;  /* tab buttons */
static HWND g_hPageSign, g_hPageCert, g_hPageVerify;
static HWND g_hProgress, g_hLog;
static HANDLE g_hThread;
static HANDLE g_hCertThread;
static HANDLE g_hVerifyThread;

static int g_curTab = 0;                   /* 0 = sign, 1 = cert */
static int g_debug;
static HWND g_hHoverBtn = NULL;            /* currently hovered button */
static HANDLE g_hTSAThread = NULL;         /* TSA test thread */
static volatile LONG g_tsaCancel = 0;      /* cancel flag for TSA test */

static const COLORREF g_log_colors[] = {
    RGB(205, 214, 244),   /* INFO  #CDD6F4 */
    RGB(166, 227, 161),   /* OK    #A6E3A1 */
    RGB(243, 139, 168),   /* FAIL  #F38BA8 */
    RGB(108, 112, 134),   /* SKIP  #6C7086 */
};

/* ══════════════════════════════════════════════════════════════ */
/*  Helpers                                                       */
/* ══════════════════════════════════════════════════════════════ */

/* Semantic version comparison: returns >0 if a > b, <0 if a < b, 0 if equal */
static int version_cmp(const wchar_t *a, const wchar_t *b)
{
    while (*a || *b) {
        unsigned long na = 0, nb = 0;
        while (*a >= L'0' && *a <= L'9') { na = na * 10 + (*a - L'0'); a++; }
        while (*b >= L'0' && *b <= L'9') { nb = nb * 10 + (*b - L'0'); b++; }
        if (na != nb) return (na > nb) ? 1 : -1;
        if (*a == L'.') a++;
        if (*b == L'.') b++;
    }
    return 0;
}

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
    if (!dst) return;
    if (!src || !src[0]) { dst[0] = '\0'; return; }
    WideCharToMultiByte(CP_UTF8, 0, src, -1, dst, dst_chars, NULL, NULL);
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

/* ── Log scroll helper ──────────────────────────────────────── */

static void
log_scroll_bottom(void)
{
    int count = (int)SendMessageW(g_hLog, LB_GETCOUNT, 0, 0);
    if (count <= 0) return;
    RECT rc;
    GetClientRect(g_hLog, &rc);
    int itemH = (int)SendMessageW(g_hLog, LB_GETITEMHEIGHT, 0, 0);
    if (itemH <= 0) itemH = 18;
    int visible = rc.bottom / itemH;
    if (visible <= 0) visible = 1;
    int top = count - visible;
    if (top < 0) top = 0;
    SendMessageW(g_hLog, LB_SETTOPINDEX, top, 0);
}

/* ══════════════════════════════════════════════════════════════ */
/*  Custom-draw helpers                                           */
/* ══════════════════════════════════════════════════════════════ */

/* ── Progress bar (custom paint) ────────────────────────────── */

static void
draw_progress_custom(HWND hwnd, HDC hdc)
{
    RECT rc;
    GetClientRect(hwnd, &rc);

    int pos  = (int)SendMessageW(hwnd, PBM_GETPOS, 0, 0);
    int lo   = (int)SendMessageW(hwnd, PBM_GETRANGE, TRUE, 0);
    int hi   = (int)SendMessageW(hwnd, PBM_GETRANGE, FALSE, 0);
    int range = hi - lo;
    if (range <= 0) range = 100;

    /* background */
    HBRUSH hbrBg = CreateSolidBrush(g_clrBorder);
    HPEN   hPen  = CreatePen(PS_SOLID, 1, g_clrBorder);
    HGDIOBJ oB   = SelectObject(hdc, hbrBg);
    HGDIOBJ oP   = SelectObject(hdc, hPen);
    RoundRect(hdc, rc.left, rc.top, rc.right, rc.bottom, 4, 4);

    /* fill */
    int fw = 0;
    if (pos > lo)
        fw = (int)((__int64)(rc.right - rc.left) * (pos - lo) / range);
    if (fw > 0) {
        HBRUSH hbrFill = CreateSolidBrush(g_clrAccent);
        HPEN   hPenF   = CreatePen(PS_SOLID, 1, g_clrAccent);
        SelectObject(hdc, hbrFill);
        SelectObject(hdc, hPenF);
        RoundRect(hdc, rc.left, rc.top, rc.left + fw, rc.bottom, 4, 4);
        DeleteObject(hbrFill);
        DeleteObject(hPenF);
    }
    SelectObject(hdc, oB);
    SelectObject(hdc, oP);
    DeleteObject(hbrBg);
    DeleteObject(hPen);
}

/* ── Button subclass (hover tracking) ──────────────────────── */

static LRESULT CALLBACK
button_subclass(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp,
                UINT_PTR uIdSub, DWORD_PTR dwRef)
{
    (void)uIdSub; (void)dwRef;
    if (msg == WM_MOUSEMOVE) {
        if (g_hHoverBtn != hwnd) {
            HWND hOld = g_hHoverBtn;
            g_hHoverBtn = hwnd;
            InvalidateRect(hwnd, NULL, TRUE);
            if (hOld) InvalidateRect(hOld, NULL, TRUE);
            TRACKMOUSEEVENT tme = { sizeof(tme), TME_LEAVE, hwnd, 0 };
            TrackMouseEvent(&tme);
        }
        return 0;
    }
    if (msg == WM_MOUSELEAVE) {
        if (g_hHoverBtn == hwnd) {
            g_hHoverBtn = NULL;
            InvalidateRect(hwnd, NULL, TRUE);
        }
        return 0;
    }
    return DefSubclassProc(hwnd, msg, wp, lp);
}

static LRESULT CALLBACK
progress_subclass(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp,
                  UINT_PTR uIdSub, DWORD_PTR dwRef)
{
    (void)uIdSub; (void)dwRef;
    if (msg == WM_PAINT) {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        draw_progress_custom(hwnd, hdc);
        EndPaint(hwnd, &ps);
        return 0;
    }
    return DefSubclassProc(hwnd, msg, wp, lp);
}

/* ── Log listbox subclass (Ctrl+C/A shortcuts) ──────────────── */

static LRESULT CALLBACK
log_subclass(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp,
             UINT_PTR uIdSub, DWORD_PTR dwRef)
{
    (void)uIdSub; (void)dwRef;
    if (msg == WM_KEYDOWN) {
        if (wp == 'C' && GetKeyState(VK_CONTROL) < 0) {
            SendMessageW(GetParent(hwnd), WM_COMMAND, IDM_COPY_SELECTED, 0);
            return 0;
        }
        if (wp == 'A' && GetKeyState(VK_CONTROL) < 0) {
            int count = (int)SendMessageW(hwnd, LB_GETCOUNT, 0, 0);
            for (int i = 0; i < count; i++)
                SendMessageW(hwnd, LB_SETSEL, TRUE, (LPARAM)i);
            return 0;
        }
    }
    return DefSubclassProc(hwnd, msg, wp, lp);
}

/* ── Section header (blue left bar) ─────────────────────────── */

static LRESULT CALLBACK
header_subclass(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp,
                UINT_PTR uIdSub, DWORD_PTR dwRef)
{
    (void)uIdSub; (void)dwRef;
    if (msg == WM_PAINT) {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc;
        GetClientRect(hwnd, &rc);
        FillRect(hdc, &rc, g_hbrEditBg);

        /* blue indicator bar */
        HBRUSH hbrBar = CreateSolidBrush(g_clrAccent);
        RECT bar = { 0, 2, 3, rc.bottom - 2 };
        FillRect(hdc, &bar, hbrBar);
        DeleteObject(hbrBar);

        /* text */
        wchar_t txt[128];
        GetWindowTextW(hwnd, txt, 128);
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, g_clrText);
        SelectObject(hdc, g_hFontBold);
        RECT tr = { 10, 0, rc.right - 4, rc.bottom };
        DrawTextW(hdc, txt, -1, &tr, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        EndPaint(hwnd, &ps);
        return 0;
    }
    if (msg == WM_ERASEBKGND) return 1;
    return DefSubclassProc(hwnd, msg, wp, lp);
}

/* ── Edit control (flat 1px border, Breeze style) ──────────── */

static LRESULT CALLBACK
edit_subclass(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp,
              UINT_PTR uIdSub, DWORD_PTR dwRef)
{
    (void)uIdSub; (void)dwRef;
    if (msg == WM_NCPAINT) {
        HDC hdc = GetWindowDC(hwnd);
        if (hdc) {
            RECT wr;
            GetWindowRect(hwnd, &wr);
            int w = wr.right - wr.left, h = wr.bottom - wr.top;

            /* Fill NC area with background to kill 3D border */
            HBRUSH hbrBg = CreateSolidBrush(RGB(240, 240, 240));
            RECT ncR = { 0, 0, w, h };
            FillRect(hdc, &ncR, hbrBg);
            DeleteObject(hbrBg);

            /* Draw flat 1px border */
            COLORREF bc = (GetFocus() == hwnd) ? g_clrAccent : g_clrBorder;
            HPEN hPen = CreatePen(PS_SOLID, 1, bc);
            HGDIOBJ oP = SelectObject(hdc, hPen);
            HBRUSH hBr = (HBRUSH)GetStockObject(NULL_BRUSH);
            HGDIOBJ oB = SelectObject(hdc, hBr);
            Rectangle(hdc, 0, 0, w, h);
            SelectObject(hdc, oP);
            SelectObject(hdc, oB);
            DeleteObject(hPen);
            ReleaseDC(hwnd, hdc);
        }
        return 0;
    }
    if (msg == WM_SETFOCUS || msg == WM_KILLFOCUS) {
        LRESULT r = DefSubclassProc(hwnd, msg, wp, lp);
        RedrawWindow(hwnd, NULL, NULL, RDW_FRAME | RDW_INVALIDATE);
        return r;
    }
    return DefSubclassProc(hwnd, msg, wp, lp);
}

/* ── Tab button (KDE Breeze flat style) ─────────────────────── */

static void
draw_tab_button(DRAWITEMSTRUCT *di)
{
    HWND btn = di->hwndItem;
    int isSel = (di->itemState & ODS_SELECTED) ||
                (btn == g_hBtnSign && g_curTab == 0) ||
                (btn == g_hBtnCert && g_curTab == 1) ||
                (btn == g_hBtnVerify && g_curTab == 2);
    int isHov = (btn == g_hHoverBtn);
    RECT rc = di->rcItem;
    HDC hdc = di->hDC;

    /* rounded background (6px, matching breeze buttons) */
    COLORREF bg = isSel ? g_clrBtnBg :
                  isHov  ? g_clrBtnHov : g_clrTabBg;
    COLORREF bc = isSel ? g_clrAccent : g_clrBtnBorder;
    HPEN   hPen = CreatePen(PS_SOLID, 1, bc);
    HBRUSH hBr  = CreateSolidBrush(bg);
    HGDIOBJ oP  = SelectObject(hdc, hPen);
    HGDIOBJ oB  = SelectObject(hdc, hBr);
    RoundRect(hdc, rc.left, rc.top, rc.right, rc.bottom, 6, 6);
    SelectObject(hdc, oP);
    SelectObject(hdc, oB);
    DeleteObject(hPen);
    DeleteObject(hBr);

    /* text */
    COLORREF tc = isSel ? g_clrAccent :
                  isHov  ? g_clrAccent : g_clrText;
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, tc);
    SelectObject(hdc, g_hFontTab);

    wchar_t txt[64];
    GetWindowTextW(btn, txt, 64);
    DrawTextW(hdc, txt, -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
}

/* ── Generic button draw ────────────────────────────────────── */

static void
draw_breeze_button(DRAWITEMSTRUCT *di, int isPrimary)
{
    HDC hdc = di->hDC;
    RECT rc = di->rcItem;
    int pressed = (di->itemState & ODS_SELECTED) != 0;
    int isHov  = (di->hwndItem == g_hHoverBtn);
    int disabled = (di->itemState & ODS_DISABLED) != 0;

    COLORREF bg, tc, border;
    if (isPrimary) {
        bg = disabled ? g_clrBorder :
             pressed  ? g_clrAccentDown :
             isHov    ? g_clrAccentHov : g_clrAccent;
        tc = disabled ? g_clrLabel : RGB(255, 255, 255);
        border = bg;
    } else {
        bg = disabled ? g_clrPanelBg :
             pressed  ? g_clrBtnBorder :
             isHov    ? g_clrBtnHov : g_clrBtnBg;
        tc = disabled ? g_clrLabel :
             isHov    ? g_clrAccent : g_clrText;
        border = disabled ? g_clrBorder : g_clrBtnBorder;
    }

    HPEN   hPen = CreatePen(PS_SOLID, 1, border);
    HBRUSH hBr  = CreateSolidBrush(bg);
    HGDIOBJ oP  = SelectObject(hdc, hPen);
    HGDIOBJ oB  = SelectObject(hdc, hBr);
    RoundRect(hdc, rc.left, rc.top, rc.right, rc.bottom, 6, 6);
    SelectObject(hdc, oP);
    SelectObject(hdc, oB);
    DeleteObject(hPen);
    DeleteObject(hBr);

    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, tc);
    /* Tab-bar buttons use smaller font */
    UINT id = GetDlgCtrlID(di->hwndItem);
    int isTabBtn = (id == IDC_BTN_ABOUT || id == IDC_BTN_UPDATE);
    SelectObject(hdc, isPrimary ? g_hFontBold : isTabBtn ? g_hFontTab : g_hFont);
    wchar_t txt[128];
    GetWindowTextW(di->hwndItem, txt, 128);
    DrawTextW(hdc, txt, -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
}

/* ══════════════════════════════════════════════════════════════ */
/*  Tab bar                                                       */
/* ══════════════════════════════════════════════════════════════ */

static void
create_tab_buttons(HWND parent)
{
    g_hBtnSign = CreateWindowExW(0, L"BUTTON",
        L"签名",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
        0, 0, 80, TAB_H,
        parent, (HMENU)(INT_PTR)IDC_TAB_SIGN_BTN, g_hInst, NULL);

    g_hBtnCert = CreateWindowExW(0, L"BUTTON",
        L"生成证书",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
        86, 0, 100, TAB_H,
        parent, (HMENU)(INT_PTR)IDC_TAB_CERT_BTN, g_hInst, NULL);

    g_hBtnVerify = CreateWindowExW(0, L"BUTTON",
        L"验证",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
        186, 0, 80, TAB_H,
        parent, (HMENU)(INT_PTR)IDC_TAB_VERIFY_BTN, g_hInst, NULL);
}

static void
switch_tab(int idx)
{
    g_curTab = idx;
    ShowWindow(g_hPageSign, idx == 0 ? SW_SHOW : SW_HIDE);
    ShowWindow(g_hPageCert, idx == 1 ? SW_SHOW : SW_HIDE);
    ShowWindow(g_hPageVerify, idx == 2 ? SW_SHOW : SW_HIDE);
    InvalidateRect(g_hBtnSign, NULL, TRUE);
    InvalidateRect(g_hBtnCert, NULL, TRUE);
    InvalidateRect(g_hBtnVerify, NULL, TRUE);
}

/* ══════════════════════════════════════════════════════════════ */
/*  Sign page                                                     */
/* ══════════════════════════════════════════════════════════════ */

static void
create_sign_page(HWND parent)
{
    int pw = W_CLIENT - 2 * PAD;

    g_hPageSign = CreateWindowExW(0, L"STATIC", L"",
                                   WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
                                   PAD, TAB_H + 4, pw, PAGE_H,
                                   parent, NULL, g_hInst, NULL);

    int y = 4;

    /* Section: 签名设置 */
    HWND hHdr = make_ctrl(g_hPageSign, L"STATIC", L"签名设置",
                  SS_OWNERDRAW, 0, y, 300, LH + 4, IDC_LBL_LOG_TITLE);
    SetWindowSubclass(hHdr, header_subclass, 0, 0);
    y += LH + 12;

    /* 目标 */
    make_ctrl(g_hPageSign, L"STATIC", L"目标 (文件或目录):",
              0, 8, y, W_EDIT, LH, 0);
    y += LH + 4;

    CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        0, y, W_EDIT, EH,
        g_hPageSign, (HMENU)(INT_PTR)IDC_EDIT_TARGET, g_hInst, NULL);
    make_ctrl(g_hPageSign, L"BUTTON", L"浏览...",
              BS_OWNERDRAW, W_EDIT + 6, y, W_BROWSE, EH, IDC_BTN_BROWSE_TGT);
    y += EH + 8;

    /* PFX */
    make_ctrl(g_hPageSign, L"STATIC", L"PFX 证书文件:",
              0, 8, y, W_EDIT, LH, 0);
    y += LH + 4;

    CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        0, y, W_EDIT, EH,
        g_hPageSign, (HMENU)(INT_PTR)IDC_EDIT_PFX, g_hInst, NULL);
    make_ctrl(g_hPageSign, L"BUTTON", L"浏览...",
              BS_OWNERDRAW, W_EDIT + 6, y, W_BROWSE, EH, IDC_BTN_BROWSE_PFX);
    y += EH + 8;

    /* PFX 密码 */
    make_ctrl(g_hPageSign, L"STATIC", L"PFX 密码:",
              0, 8, y, 280, LH, 0);
    y += LH + 4;

    CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | ES_PASSWORD,
        0, y, 280, EH,
        g_hPageSign, (HMENU)(INT_PTR)IDC_EDIT_PASSWORD, g_hInst, NULL);
    y += EH + 8;

    /* 时间戳服务器 */
    make_ctrl(g_hPageSign, L"STATIC", L"时间戳服务器:",
              0, 8, y, W_EDIT, LH, 0);
    y += LH + 4;
    {
        HWND hCombo = CreateWindowExW(0, L"COMBOBOX", NULL,
            WS_CHILD | WS_VISIBLE | CBS_DROPDOWN | CBS_HASSTRINGS | WS_VSCROLL,
            0, y, W_EDIT - 96, 250,
            g_hPageSign, (HMENU)(INT_PTR)IDC_COMBO_TSA, g_hInst, NULL);
        SendMessageW(hCombo, WM_SETFONT, (WPARAM)g_hFont, TRUE);
        SetWindowTheme(hCombo, L"", L"");
        for (int i = 0; i < TSA_SERVER_COUNT; i++) {
            wchar_t wlabel[256];
            MultiByteToWideChar(CP_UTF8, 0, g_tsa_servers[i].label, -1, wlabel, 256);
            int idx = (int)SendMessageW(hCombo, CB_ADDSTRING, 0, (LPARAM)wlabel);
            SendMessageW(hCombo, CB_SETITEMDATA, (WPARAM)idx, (LPARAM)i);
        }
        SendMessageW(hCombo, CB_SETCURSEL, 0, 0);
    }
    make_ctrl(g_hPageSign, L"BUTTON", L"测速",
              BS_OWNERDRAW, W_EDIT - 90, y, 84, EH, IDC_BTN_TEST_TSA);
    y += EH + 8;

    /* 输出目录 */
    make_ctrl(g_hPageSign, L"STATIC",
              L"输出目录 (可选, 留空 = 覆盖原文件):",
              0, 8, y, W_EDIT, LH, 0);
    y += LH + 4;

    CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        0, y, W_EDIT, EH,
        g_hPageSign, (HMENU)(INT_PTR)IDC_EDIT_OUTDIR, g_hInst, NULL);
    make_ctrl(g_hPageSign, L"BUTTON", L"浏览...",
              BS_OWNERDRAW, W_EDIT + 6, y, W_BROWSE, EH, IDC_BTN_BROWSE_OUT);
    y += EH + 10;

    /* Checkboxes */
    {
        HWND hChk;
        hChk = make_ctrl(g_hPageSign, L"BUTTON", L"包含子目录",
                  BS_AUTOCHECKBOX, 4, y, 140, LH, IDC_CHK_RECURSIVE);
        SetWindowTheme(hChk, L"", L"");
        hChk = make_ctrl(g_hPageSign, L"BUTTON", L"强制重新签名",
                  BS_AUTOCHECKBOX, 160, y, 160, LH, IDC_CHK_FORCE);
        SetWindowTheme(hChk, L"", L"");
        hChk = make_ctrl(g_hPageSign, L"BUTTON", L"调试日志",
                  BS_AUTOCHECKBOX, 340, y, 120, LH, IDC_CHK_DEBUG);
        SetWindowTheme(hChk, L"", L"");
    }
    y += LH + 14;

    /* Thin separator */
    make_ctrl(g_hPageSign, L"STATIC", L"", SS_ETCHEDHORZ,
              0, y, pw, 1, IDC_SEP_SIGN);
    y += 10;

    /* Sign button (primary) */
    make_ctrl(g_hPageSign, L"BUTTON", L"开始签名",
              BS_OWNERDRAW, 0, y, 140, BTN_H, IDC_BTN_SIGN);
}

/* ══════════════════════════════════════════════════════════════ */
/*  Certificate page                                              */
/* ══════════════════════════════════════════════════════════════ */

static void
create_cert_page(HWND parent)
{
    int pw = W_CLIENT - 2 * PAD;

    g_hPageCert = CreateWindowExW(0, L"STATIC", L"",
                                   WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
                                   PAD, TAB_H + 4, pw, PAGE_H,
                                   parent, NULL, g_hInst, NULL);

    int y = 4;

    /* Section: 证书生成 */
    HWND hHdr = make_ctrl(g_hPageCert, L"STATIC", L"证书生成",
                  SS_OWNERDRAW, 0, y, 300, LH + 4, IDC_LBL_CERT_TITLE);
    SetWindowSubclass(hHdr, header_subclass, 0, 0);
    y += LH + 12;

    /* Description */
    make_ctrl(g_hPageCert, L"STATIC",
              L"生成自签名根 CA + 代码签名证书。\n"
              L"将根 CA 导入 Windows 受信任根存储即可信任签名。",
              SS_LEFT, 8, y, pw - 16, 36, 0);
    y += 44;

    /* 输出目录 */
    make_ctrl(g_hPageCert, L"STATIC", L"输出目录:",
              0, 8, y, pw, LH, 0);
    y += LH + 4;

    CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"./certs",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        0, y, W_EDIT, EH,
        g_hPageCert, (HMENU)(INT_PTR)IDC_EDIT_CERT_DIR, g_hInst, NULL);
    make_ctrl(g_hPageCert, L"BUTTON", L"浏览...",
              BS_OWNERDRAW, W_EDIT + 6, y, W_BROWSE, EH, IDC_BTN_BROWSE_CD);
    y += EH + 10;

    /* 有效期 */
    make_ctrl(g_hPageCert, L"STATIC", L"签名证书有效期 (天):",
              0, 8, y, 200, LH, 0);
    y += LH + 4;

    CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"90",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | ES_NUMBER,
        0, y, 80, EH,
        g_hPageCert, (HMENU)(INT_PTR)IDC_EDIT_CERT_DAYS, g_hInst, NULL);
    y += EH + 10;

    /* PFX 密码 */
    make_ctrl(g_hPageCert, L"STATIC",
              L"PFX 密码 (签名时需填写此密码):",
              0, 8, y, pw, LH, 0);
    y += LH + 4;

    CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | ES_PASSWORD,
        0, y, 280, EH,
        g_hPageCert, (HMENU)(INT_PTR)IDC_EDIT_CERT_PW, g_hInst, NULL);
    y += EH + 10;

    /* 签名者姓名 */
    make_ctrl(g_hPageCert, L"STATIC",
              L"签名者姓名 (CN, 可选, 默认: FileSigner Code Signing):",
              0, 8, y, pw, LH, 0);
    y += LH + 4;

    CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        0, y, W_EDIT, EH,
        g_hPageCert, (HMENU)(INT_PTR)IDC_EDIT_CERT_CN, g_hInst, NULL);
    y += EH + 10;

    /* 签名者邮箱 */
    make_ctrl(g_hPageCert, L"STATIC", L"签名者邮箱 (可选):",
              0, 8, y, pw, LH, 0);
    y += LH + 4;

    CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        0, y, W_EDIT, EH,
        g_hPageCert, (HMENU)(INT_PTR)IDC_EDIT_CERT_EMAIL, g_hInst, NULL);
    y += EH + 12;

    /* Thin separator */
    make_ctrl(g_hPageCert, L"STATIC", L"", SS_ETCHEDHORZ,
              0, y, pw, 1, IDC_SEP_CERT);
    y += 10;

    /* Generate button (primary) */
    make_ctrl(g_hPageCert, L"BUTTON", L"生成证书",
              BS_OWNERDRAW, 0, y, 160, BTN_H, IDC_BTN_GENERATE);
}

/* ══════════════════════════════════════════════════════════════ */
/*  Verify page                                                   */
/* ══════════════════════════════════════════════════════════════ */

static void
create_verify_page(HWND parent)
{
    int pw = W_CLIENT - 2 * PAD;

    g_hPageVerify = CreateWindowExW(0, L"STATIC", L"",
                                    WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
                                    PAD, TAB_H + 4, pw, PAGE_H,
                                    parent, NULL, g_hInst, NULL);

    int y = 4;

    /* Section: 签名验证 */
    HWND hHdr = make_ctrl(g_hPageVerify, L"STATIC", L"签名验证",
                  SS_OWNERDRAW, 0, y, 300, LH + 4, 0);
    SetWindowSubclass(hHdr, header_subclass, 0, 0);
    y += LH + 12;

    /* Description */
    make_ctrl(g_hPageVerify, L"STATIC",
              L"验证 PE 文件的 Authenticode 签名有效性。\n"
              L"支持选择单个文件或目录（批量验证），可选 CA 证书验证证书链。",
              SS_LEFT, 8, y, pw - 16, 36, 0);
    y += 44;

    /* PE 文件 */
    make_ctrl(g_hPageVerify, L"STATIC", L"PE 文件:",
              0, 8, y, W_EDIT, LH, 0);
    y += LH + 4;

    CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        0, y, W_EDIT, EH,
        g_hPageVerify, (HMENU)(INT_PTR)IDC_EDIT_VERIFY_PE, g_hInst, NULL);
    make_ctrl(g_hPageVerify, L"BUTTON", L"浏览...",
              BS_OWNERDRAW, W_EDIT + 6, y, W_BROWSE, EH, IDC_BTN_BROWSE_VPE);
    y += EH + 10;

    /* CA 证书 (可选) */
    make_ctrl(g_hPageVerify, L"STATIC",
              L"CA 证书 (可选, 用于验证证书链):",
              0, 8, y, pw, LH, 0);
    y += LH + 4;

    CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        0, y, W_EDIT, EH,
        g_hPageVerify, (HMENU)(INT_PTR)IDC_EDIT_VERIFY_CA, g_hInst, NULL);
    make_ctrl(g_hPageVerify, L"BUTTON", L"浏览...",
              BS_OWNERDRAW, W_EDIT + 6, y, W_BROWSE, EH, IDC_BTN_BROWSE_VCA);
    y += EH + 10;

    /* Checkbox: recursive */
    {
        HWND hChk = make_ctrl(g_hPageVerify, L"BUTTON", L"包含子目录",
                      BS_AUTOCHECKBOX, 4, y, 140, LH, IDC_CHK_VERIFY_RECURSIVE);
        SetWindowTheme(hChk, L"", L"");
    }
    y += LH + 12;

    /* Thin separator */
    make_ctrl(g_hPageVerify, L"STATIC", L"", SS_ETCHEDHORZ,
              0, y, pw, 1, IDC_SEP_VERIFY);
    y += 10;

    /* Verify button (primary) */
    make_ctrl(g_hPageVerify, L"BUTTON", L"开始验证",
              BS_OWNERDRAW, 0, y, 140, BTN_H, IDC_BTN_VERIFY);
}

/* ══════════════════════════════════════════════════════════════ */
/*  Logging                                                       */
/* ══════════════════════════════════════════════════════════════ */

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

/* ══════════════════════════════════════════════════════════════ */
/*  Worker threads                                                */
/* ══════════════════════════════════════════════════════════════ */

static void
thread_progress_cb(const char *filename, int current, int total,
                   int success, void *user_data)
{
    SignTask *task = (SignTask *)user_data;
    if (!filename) return;
    if (total > 0)
        post_progress((int)(current * 100 / total));

    if (success == 1) {
        post_log_utf8(LOG_COLOR_OK, "[%d/%d] %s → [OK]", current, total, filename);
        if (task) InterlockedIncrement(&task->ok_count);
    } else if (success == -2) {
        post_log_utf8(LOG_COLOR_SKIP, "[%d/%d] %s → [跳过]", current, total, filename);
        if (task) InterlockedIncrement(&task->skip_count);
    } else if (success == -3)
        post_log_utf8(LOG_COLOR_INFO, "%s", filename);
    else if (success == -4)
        post_log_utf8(LOG_COLOR_INFO, "  %s", filename);
    else if (success == 0) {
        post_log_utf8(LOG_COLOR_FAIL, "[%d/%d] %s → [失败]", current, total, filename);
        if (task) {
            InterlockedIncrement(&task->fail_count);
            FailEntry *entry = calloc(1, sizeof(FailEntry));
            if (entry) {
                snprintf(entry->filename, sizeof(entry->filename), "%s", filename);
                snprintf(entry->reason, sizeof(entry->reason), "签名失败");
                entry->next = task->fail_list;
                task->fail_list = entry;
            }
        }
    }

    log_debug_utf8("  [调试] 进度: %d/%d, 结果: %d",
                   current, total, success);
}

static DWORD WINAPI
sign_thread_proc(LPVOID param)
{
    SignTask *task = (SignTask *)param;
    if (!task) return 0;

    HWND hwnd = task->hwnd;
    log_debug_utf8("[调试] 目标: %s", task->target);
    log_debug_utf8("[调试] PFX: %s", task->pfx);
    log_debug_utf8("[调试] TSA: %s", task->ts_url[0] ? task->ts_url : "(无)");
    log_debug_utf8("[调试] 强制=%d 子目录=%d", task->force, task->recursive);

    int count = batch_sign(task->target, task->pfx,
                           task->password[0] ? task->password : NULL,
                           task->ts_url[0]   ? task->ts_url : NULL,
                           task->outdir[0]   ? task->outdir : NULL,
                           task->force, task->recursive,
                           thread_progress_cb, task);

    post_log_utf8(LOG_COLOR_INFO, "完成: 成功 %d / 跳过 %d / 失败 %d",
                  task->ok_count, task->skip_count, task->fail_count);

    /* List failed files */
    if (task->fail_list) {
        post_log_utf8(LOG_COLOR_FAIL, "失败文件:");
        for (FailEntry *e = task->fail_list; e; e = e->next)
            post_log_utf8(LOG_COLOR_FAIL, "  - %s (%s)", e->filename, e->reason);
    }
    PostMessageW(hwnd, WM_APP_SIGN_DONE, (WPARAM)count, (LPARAM)task);
    return 0;
}

static void cert_status_callback(const char *status, void *user_data)
{
    (void)user_data;
    post_log_utf8(LOG_COLOR_INFO, "%s", status);
}

static DWORD WINAPI
cert_thread_proc(LPVOID param)
{
    CertTask *task = (CertTask *)param;
    if (!task) return 0;

    post_log_utf8(LOG_COLOR_INFO, "─── 开始生成证书 ───");

    int ok = cert_generate_ex(task->dir, NULL,
                              task->pw[0] ? task->pw : NULL,
                              task->days,
                              task->cn[0] ? task->cn : NULL,
                              task->email[0] ? task->email : NULL,
                              cert_status_callback, NULL);

    if (ok)
        post_log_utf8(LOG_COLOR_OK, "完成: 证书生成成功");
    else
        post_log_utf8(LOG_COLOR_FAIL, "完成: 证书生成失败");

    PostMessageW(task->hwnd, WM_APP_CERT_DONE, (WPARAM)ok, (LPARAM)task);
    return 0;
}

static void verify_status_callback(const char *status, void *user_data)
{
    (void)user_data;
    post_log_utf8(LOG_COLOR_INFO, "%s", status);
}

static void
verify_progress_cb(const char *filename, int current, int total,
                   int success, void *user_data)
{
    (void)user_data;
    if (!filename) return;

    if (success == 1)
        post_log_utf8(LOG_COLOR_OK, "[%d/%d] %s → [有效]", current, total, filename);
    else if (success == -1)
        post_log_utf8(LOG_COLOR_SKIP, "[%d/%d] %s → [未签名]", current, total, filename);
    else if (success == 0)
        post_log_utf8(LOG_COLOR_FAIL, "[%d/%d] %s → [无效]", current, total, filename);
    else if (success == -3)
        post_log_utf8(LOG_COLOR_INFO, "%s", filename);
}

static DWORD WINAPI
verify_thread_proc(LPVOID param)
{
    VerifyTask *task = (VerifyTask *)param;
    if (!task) return 0;

    if (task->is_dir) {
        /* Batch verify */
        post_log_utf8(LOG_COLOR_INFO, "─── 批量验证 %s ───", task->pe_path);

        int valid = batch_verify(task->pe_path,
                                 task->ca_path[0] ? task->ca_path : NULL,
                                 task->recursive,
                                 verify_progress_cb, NULL);

        if (valid < 0) {
            post_log_utf8(LOG_COLOR_FAIL, "未找到 PE 文件");
            task->result = 0;
        } else {
            post_log_utf8(LOG_COLOR_INFO, "完成: 有效 %d 个", valid);
            task->result = (valid > 0) ? 1 : 0;
        }
    } else {
        /* Single file verify */
        const char *fname = strrchr(task->pe_path, '/');
        if (!fname) fname = strrchr(task->pe_path, '\\');
        fname = fname ? fname + 1 : task->pe_path;

        post_log_utf8(LOG_COLOR_INFO, "─── 验证 %s ───", fname);

        task->result = authenticode_verify_ex(task->pe_path,
                                              task->ca_path[0] ? task->ca_path : NULL,
                                              verify_status_callback, NULL);

        if (task->result)
            post_log_utf8(LOG_COLOR_OK, "签名验证通过");
        else
            post_log_utf8(LOG_COLOR_FAIL, "签名验证失败");
    }

    PostMessageW(task->hwnd, WM_APP_VERIFY_DONE, (WPARAM)task->result, (LPARAM)task);
    return 0;
}

/* ── TSA test thread ──────────────────────────────────────── */

typedef struct {
    HWND hwnd;
    int best_idx;
    int best_latency;
    int completed;          /* 1 = all done, -1 = cancelled */
} TSATask;

static DWORD WINAPI
tsa_test_thread(LPVOID param)
{
    TSATask *task = (TSATask *)param;
    task->best_idx = -1;
    task->best_latency = 0;
    task->completed = 0;

    post_log_utf8(LOG_COLOR_INFO, "开始测试 %d 个时间戳服务器...", TSA_SERVER_COUNT);

    for (int i = 0; i < TSA_SERVER_COUNT; i++) {
        if (InterlockedCompareExchange(&g_tsaCancel, 0, 0))
            break;

        wchar_t wlabel[256];
        MultiByteToWideChar(CP_UTF8, 0, g_tsa_servers[i].label, -1, wlabel, 256);

        DWORD t0 = GetTickCount();
        int ok = timestamp_test_server(g_tsa_servers[i].url);
        DWORD elapsed = GetTickCount() - t0;

        if (ok) {
            post_log_utf8(LOG_COLOR_OK, "[OK] %s: %lu ms", g_tsa_servers[i].label, elapsed);
            if (task->best_idx < 0 || (int)elapsed < task->best_latency) {
                task->best_idx = i;
                task->best_latency = (int)elapsed;
            }
        } else {
            post_log_utf8(LOG_COLOR_FAIL, "[超时] %s", g_tsa_servers[i].label);
        }
    }

    task->completed = InterlockedCompareExchange(&g_tsaCancel, 0, 0) ? -1 : 1;
    PostMessageW(task->hwnd, WM_APP_TSA_DONE, 0, (LPARAM)task);
    return 0;
}

/* ══════════════════════════════════════════════════════════════ */
/*  About dialog & Update check                                   */
/* ══════════════════════════════════════════════════════════════ */

#define FILESIGNER_VERSION L"4.1.0"
#define UPDATE_CHECK_URL   L"https://api.github.com/repos/woshi-Tom/FileSigner/releases/latest"

static HANDLE g_hUpdateThread = NULL;

static void
show_about_dialog(HWND parent)
{
    wchar_t msg[1024];
    swprintf(msg, 1024,
        L"FileSigner\n"
        L"版本 %s\n\n"
        L"Authenticode PE 签名工具\n"
        L"基于 OpenSSL 3.x 的自签名代码签名方案\n\n"
        L"功能:\n"
        L"  - PE 文件批量 Authenticode 签名\n"
        L"  - 自签名根 CA + 代码签名证书生成\n"
        L"  - RFC 3161 时间戳支持\n"
        L"  - 命令行 & 图形界面双模式\n\n"
        L"(C) 2024-2026 FileSigner",
        FILESIGNER_VERSION);
    MessageBoxW(parent, msg, L"关于 FileSigner",
                MB_OK | MB_ICONINFORMATION);
}

static DWORD WINAPI
update_check_thread(LPVOID param)
{
    HWND hwnd = (HWND)param;
    int has_update = 0;
    wchar_t latest_ver[64] = L"";
    wchar_t download_url[1024] = L"";

#ifdef _WIN32
    HINTERNET hSession = WinHttpOpen(L"FileSigner/2.1",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) { PostMessageW(hwnd, WM_APP_UPDATE_DONE, 0, 0); return 0; }

    WinHttpSetTimeouts(hSession, 5000, 5000, 8000, 8000);

    HINTERNET hConnect = WinHttpConnect(hSession,
        L"api.github.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); PostMessageW(hwnd, WM_APP_UPDATE_DONE, 0, 0); return 0; }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET",
        L"/repos/woshi-Tom/FileSigner/releases/latest",
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); PostMessageW(hwnd, WM_APP_UPDATE_DONE, 0, 0); return 0; }

    WinHttpAddRequestHeaders(hRequest, L"User-Agent: FileSigner", -1L, WINHTTP_ADDREQ_FLAG_ADD);

    if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                           WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
        WinHttpReceiveResponse(hRequest, NULL)) {

        DWORD status = 0, sz = sizeof(status);
        WinHttpQueryHeaders(hRequest,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz,
            WINHTTP_NO_HEADER_INDEX);

        if (status == 200) {
            char buf[4096] = {0};
            DWORD read = 0, total = 0;
            while (WinHttpReadData(hRequest, buf + total, sizeof(buf) - 1 - total, &read) && read > 0) {
                total += read;
                read = 0;
                if (total >= sizeof(buf) - 1) break;
            }
            buf[total] = '\0';

            /* Simple JSON parse: find "tag_name" */
            const char *p = strstr(buf, "\"tag_name\"");
            if (p) {
                p = strchr(p, ':');
                if (p) {
                    p++;
                    while (*p == ' ' || *p == '"') p++;
                    const char *end = strchr(p, '"');
                    if (end && end - p < 60) {
                        char ver_ascii[64] = {0};
                        memcpy(ver_ascii, p, end - p);
                        MultiByteToWideChar(CP_UTF8, 0, ver_ascii, -1, latest_ver, 64);

                        /* Compare versions (simple string compare, strip 'v' prefix) */
                        wchar_t *v = latest_ver;
                        if (*v == L'v' || *v == L'V') v++;
                        if (version_cmp(v, FILESIGNER_VERSION) > 0)
                            has_update = 1;
                    }
                }
            }

            /* Find "html_url" for download link */
            if (has_update) {
                p = strstr(buf, "\"html_url\"");
                if (p) {
                    p = strchr(p, ':');
                    if (p) {
                        p++;
                        while (*p == ' ' || *p == '"') p++;
                        const char *end = strchr(p, '"');
                        if (end && end - p < 1020) {
                            char url_ascii[1024] = {0};
                            memcpy(url_ascii, p, end - p);
                            MultiByteToWideChar(CP_UTF8, 0, url_ascii, -1, download_url, 1024);
                        }
                    }
                }
            }
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
#endif

    if (has_update && download_url[0]) {
        /* Store URL in a heap copy for the UI thread */
        size_t len = wcslen(download_url) + 1;
        wchar_t *url_copy = malloc(len * sizeof(wchar_t));
        if (url_copy) {
            wcscpy(url_copy, download_url);
            PostMessageW(hwnd, WM_APP_UPDATE_DONE, 1, (LPARAM)url_copy);
        } else {
            PostMessageW(hwnd, WM_APP_UPDATE_DONE, 0, 0);
        }
    } else {
        PostMessageW(hwnd, WM_APP_UPDATE_DONE, 0, 0);
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════ */
/*  WndProc                                                       */
/* ══════════════════════════════════════════════════════════════ */

/* ── Page subclass: forward messages to parent ──────────────── */

static LRESULT CALLBACK
page_subclass(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp,
              UINT_PTR uIdSubclass, DWORD_PTR dwRefData)
{
    (void)uIdSubclass; (void)dwRefData;
    if (msg == WM_COMMAND || msg == WM_CTLCOLORSTATIC || msg == WM_CTLCOLORLISTBOX
        || msg == WM_CTLCOLOREDIT || msg == WM_CTLCOLORBTN
        || msg == WM_DRAWITEM || msg == WM_MEASUREITEM)
        return SendMessageW(GetParent(hwnd), msg, wp, lp);
    return DefSubclassProc(hwnd, msg, wp, lp);
}

static LRESULT CALLBACK
WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {

    /* ── Thread messages ──────────────────────────────────── */

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
        SignTask *task = (SignTask *)lParam;
        if (g_hThread) {
            WaitForSingleObject(g_hThread, INFINITE);
            CloseHandle(g_hThread);
            g_hThread = NULL;
        }
        EnableWindow(GetDlgItem(g_hPageSign, IDC_BTN_SIGN), TRUE);
        ShowWindow(g_hProgress, SW_HIDE);
        /* Free failure list */
        {
            FailEntry *e = task->fail_list;
            while (e) { FailEntry *next = e->next; free(e); e = next; }
        }
        free(task);
        return 0;
    }
    case WM_APP_CERT_DONE: {
        CertTask *task = (CertTask *)lParam;
        int ok = (int)wParam;
        if (g_hCertThread) {
            WaitForSingleObject(g_hCertThread, INFINITE);
            CloseHandle(g_hCertThread);
            g_hCertThread = NULL;
        }
        if (ok) {
            wchar_t msg[512];
            swprintf(msg, 512,
                     L"证书生成成功!\n\n"
                     L"生成文件位于: %s\n\n"
                     L"%s"
                     L"请将 FileSigner_RootCA.cer 导入\n"
                     L"Windows 受信任的根证书颁发机构",
                     task->wdir,
                     task->wpw[0] ? L"PFX 密码已设置，签名时请使用相同密码。\n\n"
                                   : L"PFX 无密码，签名时密码留空即可。\n\n");
            MessageBoxW(task->hwnd, msg, L"成功", MB_OK | MB_ICONINFORMATION);
        } else {
            MessageBoxW(task->hwnd, L"证书生成失败。",
                        L"错误", MB_OK | MB_ICONERROR);
        }
        EnableWindow(GetDlgItem(g_hPageCert, IDC_BTN_GENERATE), TRUE);
        free(task);
        return 0;
    }
    case WM_APP_VERIFY_DONE: {
        VerifyTask *task = (VerifyTask *)lParam;
        if (g_hVerifyThread) {
            WaitForSingleObject(g_hVerifyThread, INFINITE);
            CloseHandle(g_hVerifyThread);
            g_hVerifyThread = NULL;
        }
        EnableWindow(GetDlgItem(g_hPageVerify, IDC_BTN_VERIFY), TRUE);
        free(task);
        return 0;
    }
    case WM_APP_TSA_DONE: {
        TSATask *task = (TSATask *)lParam;
        if (g_hTSAThread) {
            WaitForSingleObject(g_hTSAThread, INFINITE);
            CloseHandle(g_hTSAThread);
            g_hTSAThread = NULL;
        }
        InterlockedExchange(&g_tsaCancel, 0);

        if (task->completed == -1) {
            log_message(LOG_COLOR_SKIP, L"测速已取消");
        } else if (task->best_idx >= 0) {
            wchar_t wlabel[256];
            MultiByteToWideChar(CP_UTF8, 0, g_tsa_servers[task->best_idx].label, -1, wlabel, 256);
            log_message(LOG_COLOR_OK, L"最快服务器: %s (%d ms)", wlabel, task->best_latency);
            HWND hCombo = GetDlgItem(g_hPageSign, IDC_COMBO_TSA);
            SendMessageW(hCombo, CB_SETCURSEL, task->best_idx, 0);
        } else {
            log_message(LOG_COLOR_FAIL, L"所有时间戳服务器均不可达");
        }

        SetDlgItemTextW(g_hPageSign, IDC_BTN_TEST_TSA, L"测速");
        EnableWindow(GetDlgItem(g_hPageSign, IDC_BTN_TEST_TSA), TRUE);
        free(task);
        return 0;
    }
    case WM_APP_UPDATE_DONE: {
        if (g_hUpdateThread) {
            WaitForSingleObject(g_hUpdateThread, INFINITE);
            CloseHandle(g_hUpdateThread);
            g_hUpdateThread = NULL;
        }
        if (wParam == 1 && lParam) {
            wchar_t *url = (wchar_t *)lParam;
            int ret = MessageBoxW(hwnd,
                L"发现新版本！是否前往下载页面？",
                L"更新可用", MB_YESNO | MB_ICONINFORMATION);
            if (ret == IDYES)
                ShellExecuteW(NULL, L"open", url, NULL, NULL, SW_SHOWNORMAL);
            free(url);
        } else {
            MessageBoxW(hwnd,
                L"当前已是最新版本。",
                L"检查更新", MB_OK | MB_ICONINFORMATION);
        }
        return 0;
    }

    /* ── WM_CREATE ────────────────────────────────────────── */

    case WM_CREATE: {
        InitCommonControls();

        g_hbrBg     = CreateSolidBrush(g_clrBg);
        g_hbrPanel  = CreateSolidBrush(g_clrPanelBg);
        g_hbrLogBg  = CreateSolidBrush(g_clrLogBg);
        g_hbrEditBg = CreateSolidBrush(g_clrEditBg);
        g_hbrAccent = CreateSolidBrush(g_clrAccent);

        g_hFont = CreateFontW(-13, 0, 0, 0, FW_NORMAL, 0, 0, 0,
                               DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY,
                               0, L"Segoe UI");
        g_hFontBold = CreateFontW(-13, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0,
                                   DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY,
                                   0, L"Segoe UI");
        g_hFontTab = CreateFontW(-12, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0,
                                  DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY,
                                  0, L"Segoe UI");

        /* Tab buttons */
        create_tab_buttons(hwnd);
        SendMessageW(g_hBtnSign, WM_SETFONT, (WPARAM)g_hFontTab, TRUE);
        SendMessageW(g_hBtnCert, WM_SETFONT, (WPARAM)g_hFontTab, TRUE);
        SendMessageW(g_hBtnVerify, WM_SETFONT, (WPARAM)g_hFontTab, TRUE);

        /* About button (right side of tab bar) */
        {
            HWND hAbout = CreateWindowExW(0, L"BUTTON", L"关于",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
                0, 0, 60, TAB_H,
                hwnd, (HMENU)(INT_PTR)IDC_BTN_ABOUT, g_hInst, NULL);
            SendMessageW(hAbout, WM_SETFONT, (WPARAM)g_hFontTab, TRUE);
            SetWindowSubclass(hAbout, button_subclass, 0, 0);
        }
        {
            HWND hUpd = CreateWindowExW(0, L"BUTTON", L"检查更新",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
                0, 0, 80, TAB_H,
                hwnd, (HMENU)(INT_PTR)IDC_BTN_UPDATE, g_hInst, NULL);
            SendMessageW(hUpd, WM_SETFONT, (WPARAM)g_hFontTab, TRUE);
            SetWindowSubclass(hUpd, button_subclass, 0, 0);
        }

        /* Pages */
        create_sign_page(hwnd);
        create_cert_page(hwnd);
        create_verify_page(hwnd);
        apply_font(g_hPageSign);
        apply_font(g_hPageCert);
        apply_font(g_hPageVerify);

        /* Subclass pages for message forwarding */
        SetWindowSubclass(g_hPageSign, page_subclass, 0, 0);
        SetWindowSubclass(g_hPageCert, page_subclass, 0, 0);
        SetWindowSubclass(g_hPageVerify, page_subclass, 0, 0);

        /* Subclass edit controls for focus border */
        {
            HWND hEd;
            hEd = GetDlgItem(g_hPageSign, IDC_EDIT_TARGET);
            if (hEd) SetWindowSubclass(hEd, edit_subclass, 0, 0);
            hEd = GetDlgItem(g_hPageSign, IDC_EDIT_PFX);
            if (hEd) SetWindowSubclass(hEd, edit_subclass, 0, 0);
            hEd = GetDlgItem(g_hPageSign, IDC_EDIT_PASSWORD);
            if (hEd) SetWindowSubclass(hEd, edit_subclass, 0, 0);
            hEd = GetDlgItem(g_hPageSign, IDC_EDIT_OUTDIR);
            if (hEd) SetWindowSubclass(hEd, edit_subclass, 0, 0);
            hEd = GetDlgItem(g_hPageCert, IDC_EDIT_CERT_DIR);
            if (hEd) SetWindowSubclass(hEd, edit_subclass, 0, 0);
            hEd = GetDlgItem(g_hPageCert, IDC_EDIT_CERT_DAYS);
            if (hEd) SetWindowSubclass(hEd, edit_subclass, 0, 0);
            hEd = GetDlgItem(g_hPageCert, IDC_EDIT_CERT_PW);
            if (hEd) SetWindowSubclass(hEd, edit_subclass, 0, 0);
            hEd = GetDlgItem(g_hPageCert, IDC_EDIT_CERT_CN);
            if (hEd) SetWindowSubclass(hEd, edit_subclass, 0, 0);
            hEd = GetDlgItem(g_hPageCert, IDC_EDIT_CERT_EMAIL);
            if (hEd) SetWindowSubclass(hEd, edit_subclass, 0, 0);
            hEd = GetDlgItem(g_hPageVerify, IDC_EDIT_VERIFY_PE);
            if (hEd) SetWindowSubclass(hEd, edit_subclass, 0, 0);
            hEd = GetDlgItem(g_hPageVerify, IDC_EDIT_VERIFY_CA);
            if (hEd) SetWindowSubclass(hEd, edit_subclass, 0, 0);
        }

        /* Subclass all buttons for hover tracking */
        {
            HWND hBtns[] = {
                g_hBtnSign, g_hBtnCert, g_hBtnVerify,
                GetDlgItem(g_hPageSign, IDC_BTN_BROWSE_TGT),
                GetDlgItem(g_hPageSign, IDC_BTN_BROWSE_PFX),
                GetDlgItem(g_hPageSign, IDC_BTN_BROWSE_OUT),
                GetDlgItem(g_hPageSign, IDC_BTN_TEST_TSA),
                GetDlgItem(g_hPageSign, IDC_BTN_SIGN),
                GetDlgItem(g_hPageCert, IDC_BTN_BROWSE_CD),
                GetDlgItem(g_hPageCert, IDC_BTN_GENERATE),
                GetDlgItem(g_hPageVerify, IDC_BTN_BROWSE_VPE),
                GetDlgItem(g_hPageVerify, IDC_BTN_BROWSE_VCA),
                GetDlgItem(g_hPageVerify, IDC_BTN_VERIFY),
            };
            for (int i = 0; i < (int)(sizeof(hBtns)/sizeof(hBtns[0])); i++)
                if (hBtns[i]) SetWindowSubclass(hBtns[i], button_subclass, 0, 0);
        }

        /* Global log area (shared across all tabs) */
        g_hMonoFont = CreateFontW(-14, 0, 0, 0, FW_NORMAL, 0, 0, 0,
                                   DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY,
                                   0, L"Consolas");
        if (!g_hMonoFont)
            g_hMonoFont = CreateFontW(-14, 0, 0, 0, FW_NORMAL, 0, 0, 0,
                                       DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY,
                                       0, L"Segoe UI");

        /* Progress bar (global, initially hidden) */
        g_hProgress = CreateWindowExW(0, PROGRESS_CLASSW, L"",
                        WS_CHILD,
                        0, 0, 0, 0,
                        hwnd, (HMENU)(INT_PTR)IDC_PROGRESS, g_hInst, NULL);
        SendMessageW(g_hProgress, PBM_SETRANGE32, 0, 100);
        SetWindowSubclass(g_hProgress, progress_subclass, 0, 0);

        /* Log section header */
        {
            HWND hLogHdr = CreateWindowExW(0, L"STATIC", L"日志输出",
                             WS_CHILD | WS_VISIBLE | SS_OWNERDRAW,
                             0, 0, 300, LH + 4,
                             hwnd, (HMENU)(INT_PTR)IDC_LBL_LOG_TITLE, g_hInst, NULL);
            SetWindowSubclass(hLogHdr, header_subclass, 0, 0);
        }

        /* Log listbox (global) */
        g_hLog = CreateWindowExW(0, L"LISTBOX", L"",
                   WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_BORDER |
                   LBS_NOINTEGRALHEIGHT | LBS_EXTENDEDSEL,
                   0, 0, 0, 0,
                   hwnd, (HMENU)(INT_PTR)IDC_LIST_LOG, g_hInst, NULL);
        SendMessageW(g_hLog, WM_SETFONT, (WPARAM)g_hMonoFont, TRUE);
        SetWindowSubclass(g_hLog, log_subclass, 0, 0);

        /* Export log button */
        {
            HWND hExp = CreateWindowExW(0, L"BUTTON", L"导出日志",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
                0, 0, 80, TAB_H,
                hwnd, (HMENU)(INT_PTR)IDC_BTN_EXPORT_LOG, g_hInst, NULL);
            SendMessageW(hExp, WM_SETFONT, (WPARAM)g_hFontTab, TRUE);
            SetWindowSubclass(hExp, button_subclass, 0, 0);
        }

        switch_tab(0);

        /* Dark title bar (Win10 20H1+) */
        BOOL dark = TRUE;
        DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &dark, sizeof(dark));

        return 0;
    }

    /* ── Constraints ──────────────────────────────────────── */

    case WM_GETMINMAXINFO: {
        MINMAXINFO *mmi = (MINMAXINFO *)lParam;
        mmi->ptMinTrackSize.x = 800;
        mmi->ptMinTrackSize.y = 720;
        return 0;
    }

    /* ── Resize ───────────────────────────────────────────── */

    case WM_SIZE: {
        int cw = LOWORD(lParam), ch = HIWORD(lParam);
        int pw = cw - 2 * PAD;
        int log_top = ch - LOG_H - 8;
        int ph = log_top - TAB_H - 12;

        /* About + Update + Tab buttons: auto-size tabs, right-align extras */
        {
            /* Measure tab text widths to auto-size buttons */
            HDC hdc = GetDC(hwnd);
            HGDIOBJ oF = SelectObject(hdc, g_hFontTab);
            wchar_t tSign[32], tCert[32], tVerify[32];
            GetWindowTextW(g_hBtnSign, tSign, 32);
            GetWindowTextW(g_hBtnCert, tCert, 32);
            GetWindowTextW(g_hBtnVerify, tVerify, 32);
            SIZE szSign, szCert, szVerify;
            GetTextExtentPoint32W(hdc, tSign, (int)wcslen(tSign), &szSign);
            GetTextExtentPoint32W(hdc, tCert, (int)wcslen(tCert), &szCert);
            GetTextExtentPoint32W(hdc, tVerify, (int)wcslen(tVerify), &szVerify);

            /* Measure About/Update text too */
            HWND hAbout = GetDlgItem(hwnd, IDC_BTN_ABOUT);
            HWND hUpd   = GetDlgItem(hwnd, IDC_BTN_UPDATE);
            wchar_t tAbout[32], tUpd[32];
            GetWindowTextW(hAbout, tAbout, 32);
            GetWindowTextW(hUpd, tUpd, 32);
            SIZE szAbout, szUpd;
            GetTextExtentPoint32W(hdc, tAbout, (int)wcslen(tAbout), &szAbout);
            GetTextExtentPoint32W(hdc, tUpd, (int)wcslen(tUpd), &szUpd);
            SelectObject(hdc, oF);
            ReleaseDC(hwnd, hdc);

            int tabSignW  = szSign.cx + 28;
            int tabCertW  = szCert.cx + 28;
            int tabVerifyW = szVerify.cx + 28;
            int aboutW    = szAbout.cx + 28;
            int updW      = szUpd.cx + 28;
            int btnGap    = 6;

            /* All buttons left-aligned as a group */
            int x = 0;
            SetWindowPos(g_hBtnSign, NULL, x, 0, tabSignW, TAB_H, SWP_NOZORDER);
            x += tabSignW + btnGap;
            SetWindowPos(g_hBtnCert, NULL, x, 0, tabCertW, TAB_H, SWP_NOZORDER);
            x += tabCertW + btnGap;
            SetWindowPos(g_hBtnVerify, NULL, x, 0, tabVerifyW, TAB_H, SWP_NOZORDER);
            x += tabVerifyW + btnGap;
            if (hAbout)
                SetWindowPos(hAbout, NULL, x, 0, aboutW, TAB_H, SWP_NOZORDER);
            x += aboutW + btnGap;
            if (hUpd)
                SetWindowPos(hUpd, NULL, x, 0, updW, TAB_H, SWP_NOZORDER);
        }

        if (g_hPageSign)
            SetWindowPos(g_hPageSign, NULL, PAD, TAB_H + 4, pw, ph, SWP_NOZORDER);
        if (g_hPageCert)
            SetWindowPos(g_hPageCert, NULL, PAD, TAB_H + 4, pw, ph, SWP_NOZORDER);
        if (g_hPageVerify)
            SetWindowPos(g_hPageVerify, NULL, PAD, TAB_H + 4, pw, ph, SWP_NOZORDER);

        /* Separators */
        HWND hSep;
        hSep = GetDlgItem(g_hPageSign, IDC_SEP_SIGN);
        if (hSep) {
            RECT r; GetWindowRect(hSep, &r);
            MapWindowPoints(NULL, g_hPageSign, (POINT *)&r, 2);
            SetWindowPos(hSep, NULL, 0, r.top, pw, 1, SWP_NOZORDER);
        }
        hSep = GetDlgItem(g_hPageCert, IDC_SEP_CERT);
        if (hSep) {
            RECT r; GetWindowRect(hSep, &r);
            MapWindowPoints(NULL, g_hPageCert, (POINT *)&r, 2);
            SetWindowPos(hSep, NULL, 0, r.top, pw, 1, SWP_NOZORDER);
        }
        hSep = GetDlgItem(g_hPageVerify, IDC_SEP_VERIFY);
        if (hSep) {
            RECT r; GetWindowRect(hSep, &r);
            MapWindowPoints(NULL, g_hPageVerify, (POINT *)&r, 2);
            SetWindowPos(hSep, NULL, 0, r.top, pw, 1, SWP_NOZORDER);
        }

        /* Global progress bar + log area at bottom */
        {
            int log_y = log_top;

            /* Section header + export button */
            HWND hLogHdr = GetDlgItem(hwnd, IDC_LBL_LOG_TITLE);
            if (hLogHdr)
                SetWindowPos(hLogHdr, NULL, PAD, log_y, 300, LH + 4, SWP_NOZORDER);
            HWND hExpBtn = GetDlgItem(hwnd, IDC_BTN_EXPORT_LOG);
            if (hExpBtn)
                SetWindowPos(hExpBtn, NULL, pw - 80 + PAD, log_y - 2, 80, LH + 6, SWP_NOZORDER);
            log_y += LH + 6;

            /* Progress bar (always reserve space) */
            if (g_hProgress) {
                SetWindowPos(g_hProgress, NULL, PAD, log_y, pw, 8, SWP_NOZORDER);
            }
            log_y += 14;

            /* Log listbox */
            if (g_hLog) {
                int log_h = ch - log_y - 8;
                if (log_h < 50) log_h = 50;
                SetWindowPos(g_hLog, NULL, PAD, log_y, pw, log_h, SWP_NOZORDER);
            }
        }
        return 0;
    }

    /* ── Hover fallback (clear if mouse leaves window) ──────── */

    case WM_MOUSELEAVE:
        if (g_hHoverBtn) {
            HWND hOld = g_hHoverBtn;
            g_hHoverBtn = NULL;
            InvalidateRect(hOld, NULL, TRUE);
        }
        return 0;

    /* ── Color messages ───────────────────────────────────── */

    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)wParam;
        HWND hCtrl = (HWND)lParam;
        if (hCtrl == g_hPageSign || hCtrl == g_hPageCert || hCtrl == g_hPageVerify) {
            SetTextColor(hdc, g_clrText);
            SetBkColor(hdc, g_clrEditBg);
            return (LRESULT)g_hbrEditBg;
        }
        int id = GetDlgCtrlID(hCtrl);
        HWND hParent = GetParent(hCtrl);
        if (hParent == g_hPageSign || hParent == g_hPageCert || hParent == g_hPageVerify) {
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
        SetTextColor(hdc, g_clrText);
        return (LRESULT)g_hbrEditBg;
    }
    case WM_CTLCOLORBTN: {
        HDC hdc = (HDC)wParam;
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

    /* ── Paint (accent bar + tab separator) ────────────────── */

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc;
        GetClientRect(hwnd, &rc);

        /* 3px top accent bar (brand indicator) */
        RECT hdr = { 0, 0, rc.right, 3 };
        HBRUSH hbrHdr = CreateSolidBrush(g_clrAccent);
        FillRect(hdc, &hdr, hbrHdr);
        DeleteObject(hbrHdr);

        /* Thin line under tab area */
        RECT sep = { 0, TAB_H, rc.right, TAB_H + 1 };
        HBRUSH hbrSep = CreateSolidBrush(g_clrBorder);
        FillRect(hdc, &sep, hbrSep);
        DeleteObject(hbrSep);

        /* Tab bar border (left + right lines) */
        HBRUSH hbrBorder = CreateSolidBrush(g_clrBorder);
        RECT lft = { 0, 3, 1, TAB_H };
        RECT rgt = { rc.right - 1, 3, rc.right, TAB_H };
        FillRect(hdc, &lft, hbrBorder);
        FillRect(hdc, &rgt, hbrBorder);
        DeleteObject(hbrBorder);

        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_ERASEBKGND: {
        RECT rc;
        GetClientRect(hwnd, &rc);
        /* WS_CLIPCHILDREN prevents erasing child areas, no flicker */
        FillRect((HDC)wParam, &rc, g_hbrBg);
        return 1;
    }

    /* ── Owner-draw: draw ──────────────────────────────────── */
    case WM_DRAWITEM: {
        DRAWITEMSTRUCT *di = (DRAWITEMSTRUCT *)lParam;

        /* Tab buttons */
        if (di->CtlID == IDC_TAB_SIGN_BTN || di->CtlID == IDC_TAB_CERT_BTN ||
            di->CtlID == IDC_TAB_VERIFY_BTN) {
            draw_tab_button(di);
            return TRUE;
        }
        /* Primary action buttons */
        if (di->CtlID == IDC_BTN_SIGN || di->CtlID == IDC_BTN_GENERATE ||
            di->CtlID == IDC_BTN_VERIFY) {
            draw_breeze_button(di, 1);
            return TRUE;
        }
        /* Secondary buttons (browse, test, about) */
        if (di->CtlID == IDC_BTN_BROWSE_TGT || di->CtlID == IDC_BTN_BROWSE_PFX ||
            di->CtlID == IDC_BTN_BROWSE_OUT || di->CtlID == IDC_BTN_BROWSE_CD ||
            di->CtlID == IDC_BTN_BROWSE_VPE || di->CtlID == IDC_BTN_BROWSE_VCA ||
            di->CtlID == IDC_BTN_TEST_TSA || di->CtlID == IDC_BTN_ABOUT ||
            di->CtlID == IDC_BTN_UPDATE || di->CtlID == IDC_BTN_EXPORT_LOG) {
            draw_breeze_button(di, 0);
            return TRUE;
        }
        return FALSE;
    }

    /* ── Notifications ────────────────────────────────────── */

    case WM_NOTIFY: {
        return 0;
    }

    /* ── Commands ─────────────────────────────────────────── */

    case WM_COMMAND: {
        int id = LOWORD(wParam);

        /* Tab switching */
        if (id == IDC_TAB_SIGN_BTN) { switch_tab(0); return 0; }
        if (id == IDC_TAB_CERT_BTN) { switch_tab(1); return 0; }
        if (id == IDC_TAB_VERIFY_BTN) { switch_tab(2); return 0; }

        /* About */
        if (id == IDC_BTN_ABOUT) {
            show_about_dialog(hwnd);
            return 0;
        }
        /* Check for updates */
        if (id == IDC_BTN_UPDATE) {
            if (!g_hUpdateThread) {
                g_hUpdateThread = CreateThread(NULL, 0, update_check_thread, hwnd, 0, NULL);
            }
            return 0;
        }

        if (id == IDC_BTN_BROWSE_TGT) {
            wchar_t path[GUI_PATH_LEN] = {0};
            BROWSEINFOW bi = {0};
            bi.hwndOwner = hwnd;
            bi.lpszTitle = L"选择目标目录（批量签名）";
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
            bi.lpszTitle = L"选择输出目录";
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
                MessageBoxW(hwnd, L"请填写目标和 PFX 文件。",
                            L"错误", MB_OK | MB_ICONERROR);
                break;
            }
            {
                DWORD attr = GetFileAttributesW(wtarget);
                if (attr == INVALID_FILE_ATTRIBUTES) {
                    MessageBoxW(hwnd, L"目标文件或目录不存在。",
                                L"错误", MB_OK | MB_ICONERROR);
                    break;
                }
                attr = GetFileAttributesW(wpfx);
                if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY)) {
                    MessageBoxW(hwnd, L"PFX 证书文件不存在。",
                                L"错误", MB_OK | MB_ICONERROR);
                    break;
                }
            }
            if (g_hThread) {
                MessageBoxW(hwnd, L"签名操作正在进行中，请等待完成。",
                            L"提示", MB_OK | MB_ICONINFORMATION);
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
            ShowWindow(g_hProgress, SW_SHOW);
            SendMessageW(g_hProgress, PBM_SETPOS, 0, 0);
            log_message(LOG_COLOR_INFO, L"─── 新签名 %s ───", wtarget);
            if (g_debug)
                log_message(LOG_COLOR_INFO, L"调试日志已开启");

            g_hThread = CreateThread(NULL, 0, sign_thread_proc, task, 0, NULL);
            if (!g_hThread) {
                free(task);
                EnableWindow(GetDlgItem(g_hPageSign, IDC_BTN_SIGN), TRUE);
                MessageBoxW(hwnd, L"无法创建签名线程。",
                            L"错误", MB_OK | MB_ICONERROR);
            }
        }
        else if (id == IDC_BTN_TEST_TSA) {
            if (g_hTSAThread) break; /* already running */

            EnableWindow(GetDlgItem(g_hPageSign, IDC_BTN_TEST_TSA), FALSE);
            SetDlgItemTextW(g_hPageSign, IDC_BTN_TEST_TSA, L"测试中...");

            InterlockedExchange(&g_tsaCancel, 0);
            TSATask *task = calloc(1, sizeof(TSATask));
            if (!task) break;
            task->hwnd = hwnd;

            g_hTSAThread = CreateThread(NULL, 0, tsa_test_thread, task, 0, NULL);
            if (!g_hTSAThread) {
                free(task);
                SetDlgItemTextW(g_hPageSign, IDC_BTN_TEST_TSA, L"测速");
                EnableWindow(GetDlgItem(g_hPageSign, IDC_BTN_TEST_TSA), TRUE);
            }
        }
        else if (id == IDC_BTN_BROWSE_CD) {
            wchar_t path[GUI_PATH_LEN] = {0};
            BROWSEINFOW bi = {0};
            bi.hwndOwner = hwnd;
            bi.lpszTitle = L"选择输出目录";
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
                MessageBoxW(hwnd, L"请选择输出目录。",
                            L"错误", MB_OK | MB_ICONERROR);
                break;
            }

            int days = _wtoi(wdays_str);
            if (days <= 0) days = CERT_SIGNER_DEFAULT_DAYS;

            CertTask *task = calloc(1, sizeof(CertTask));
            if (!task) break;
            task->hwnd = hwnd;
            wcscpy(task->wdir, wdir);
            wcscpy(task->wpw, wpw);
            wide_to_utf8(wdir,   task->dir,   GUI_PATH_LEN);
            wide_to_utf8(wpw,    task->pw,    256);
            wide_to_utf8(wcn,    task->cn,    256);
            wide_to_utf8(wemail, task->email, 256);
            task->days = days;

            CreateDirectoryW(task->wdir, NULL);

            EnableWindow(GetDlgItem(g_hPageCert, IDC_BTN_GENERATE), FALSE);

            HANDLE hThread = CreateThread(NULL, 0, cert_thread_proc, task, 0, NULL);
            if (!hThread) {
                free(task);
                EnableWindow(GetDlgItem(g_hPageCert, IDC_BTN_GENERATE), TRUE);
                MessageBoxW(hwnd, L"无法创建证书生成线程。",
                            L"错误", MB_OK | MB_ICONERROR);
            } else {
                g_hCertThread = hThread;
            }
        }
        else if (id == IDC_BTN_BROWSE_VPE) {
            wchar_t path[GUI_PATH_LEN] = {0};
            OPENFILENAMEW ofn = {0};
            ofn.lStructSize  = sizeof(ofn);
            ofn.hwndOwner    = hwnd;
            ofn.lpstrFile    = path;
            ofn.nMaxFile     = GUI_PATH_LEN;
            ofn.lpstrFilter  = L"PE Files\0*.exe;*.dll;*.sys;*.ocx;*.scr;*.cpl;*.efi\0All Files\0*.*\0";
            ofn.nFilterIndex = 1;
            ofn.Flags        = OFN_PATHMUSTEXIST | OFN_HIDEREADONLY;
            if (GetOpenFileNameW(&ofn))
                SetDlgItemTextW(g_hPageVerify, IDC_EDIT_VERIFY_PE, path);
        }
        else if (id == IDC_BTN_BROWSE_VCA) {
            wchar_t path[GUI_PATH_LEN] = {0};
            OPENFILENAMEW ofn = {0};
            ofn.lStructSize  = sizeof(ofn);
            ofn.hwndOwner    = hwnd;
            ofn.lpstrFile    = path;
            ofn.nMaxFile     = GUI_PATH_LEN;
            ofn.lpstrFilter  = L"Certificate Files\0*.cer;*.crt;*.pem;*.der\0All Files\0*.*\0";
            ofn.nFilterIndex = 1;
            ofn.Flags        = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
            if (GetOpenFileNameW(&ofn))
                SetDlgItemTextW(g_hPageVerify, IDC_EDIT_VERIFY_CA, path);
        }
        else if (id == IDC_BTN_VERIFY) {
            wchar_t wpe[GUI_PATH_LEN], wca[GUI_PATH_LEN];
            GetDlgItemTextW(g_hPageVerify, IDC_EDIT_VERIFY_PE, wpe, GUI_PATH_LEN);
            GetDlgItemTextW(g_hPageVerify, IDC_EDIT_VERIFY_CA, wca, GUI_PATH_LEN);

            if (wcslen(wpe) == 0) {
                MessageBoxW(hwnd, L"请选择要验证的 PE 文件或目录。",
                            L"错误", MB_OK | MB_ICONERROR);
                break;
            }

            DWORD attr = GetFileAttributesW(wpe);
            if (attr == INVALID_FILE_ATTRIBUTES) {
                MessageBoxW(hwnd, L"目标不存在。",
                            L"错误", MB_OK | MB_ICONERROR);
                break;
            }

            int is_dir = (attr & FILE_ATTRIBUTE_DIRECTORY) ? 1 : 0;

            if (!is_dir && wcslen(wca) > 0) {
                DWORD ca_attr = GetFileAttributesW(wca);
                if (ca_attr == INVALID_FILE_ATTRIBUTES || (ca_attr & FILE_ATTRIBUTE_DIRECTORY)) {
                    MessageBoxW(hwnd, L"CA 证书文件不存在。",
                                L"错误", MB_OK | MB_ICONERROR);
                    break;
                }
            }

            if (g_hVerifyThread) {
                MessageBoxW(hwnd, L"验证操作正在进行中，请等待完成。",
                            L"提示", MB_OK | MB_ICONINFORMATION);
                break;
            }

            int recursive = IsDlgButtonChecked(g_hPageVerify, IDC_CHK_VERIFY_RECURSIVE) == BST_CHECKED;

            VerifyTask *task = calloc(1, sizeof(VerifyTask));
            if (!task) break;
            task->hwnd = hwnd;
            task->is_dir = is_dir;
            task->recursive = recursive;
            wide_to_utf8(wpe, task->pe_path, GUI_PATH_LEN);
            wide_to_utf8(wca, task->ca_path, GUI_PATH_LEN);

            EnableWindow(GetDlgItem(g_hPageVerify, IDC_BTN_VERIFY), FALSE);

            g_hVerifyThread = CreateThread(NULL, 0, verify_thread_proc, task, 0, NULL);
            if (!g_hVerifyThread) {
                free(task);
                EnableWindow(GetDlgItem(g_hPageVerify, IDC_BTN_VERIFY), TRUE);
                MessageBoxW(hwnd, L"无法创建验证线程。",
                            L"错误", MB_OK | MB_ICONERROR);
            }
        }
        else if (id == IDC_BTN_EXPORT_LOG) {
            wchar_t path[GUI_PATH_LEN] = {0};
            OPENFILENAMEW ofn = {0};
            ofn.lStructSize  = sizeof(ofn);
            ofn.hwndOwner    = hwnd;
            ofn.lpstrFile    = path;
            ofn.nMaxFile     = GUI_PATH_LEN;
            ofn.lpstrFilter  = L"Text Files\0*.txt\0All Files\0*.*\0";
            ofn.nFilterIndex = 1;
            ofn.lpstrDefExt  = L"txt";
            ofn.Flags        = OFN_OVERWRITEPROMPT | OFN_HIDEREADONLY;
            if (GetSaveFileNameW(&ofn)) {
                FILE *fp = _wfopen(path, L"w, ccs=UTF-8");
                if (fp) {
                    int count = (int)SendMessageW(g_hLog, LB_GETCOUNT, 0, 0);
                    for (int i = 0; i < count; i++) {
                        wchar_t buf[2048];
                        int len = (int)SendMessageW(g_hLog, LB_GETTEXT, (WPARAM)i, (LPARAM)buf);
                        if (len > 0) fwprintf(fp, L"%s\n", buf);
                    }
                    fclose(fp);
                    MessageBoxW(hwnd, L"日志已导出。", L"导出成功", MB_OK | MB_ICONINFORMATION);
                } else {
                    MessageBoxW(hwnd, L"无法创建文件。", L"导出失败", MB_OK | MB_ICONERROR);
                }
            }
        }
        else if (id == IDM_COPY_SELECTED) {
            int sel_count = (int)SendMessageW(g_hLog, LB_GETSELCOUNT, 0, 0);
            if (sel_count > 0) {
                int *sel = malloc(sel_count * sizeof(int));
                if (sel) {
                    SendMessageW(g_hLog, LB_GETSELITEMS, (WPARAM)sel_count, (LPARAM)sel);
                    size_t total = 0;
                    for (int i = 0; i < sel_count; i++) {
                        int len = (int)SendMessageW(g_hLog, LB_GETTEXTLEN, (WPARAM)sel[i], 0);
                        total += len + 2; /* +2 for \r\n */
                    }
                    wchar_t *clip = malloc((total + 1) * sizeof(wchar_t));
                    if (clip) {
                        clip[0] = L'\0';
                        for (int i = 0; i < sel_count; i++) {
                            wchar_t buf[2048];
                            SendMessageW(g_hLog, LB_GETTEXT, (WPARAM)sel[i], (LPARAM)buf);
                            wcscat(clip, buf);
                            wcscat(clip, L"\r\n");
                        }
                        if (OpenClipboard(hwnd)) {
                            EmptyClipboard();
                            HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, (total + 1) * sizeof(wchar_t));
                            if (hMem) {
                                wchar_t *p = GlobalLock(hMem);
                                wcscpy(p, clip);
                                GlobalUnlock(hMem);
                                SetClipboardData(CF_UNICODETEXT, hMem);
                            }
                            CloseClipboard();
                        }
                        free(clip);
                    }
                    free(sel);
                }
            }
        }
        else if (id == IDM_SELECT_ALL) {
            int count = (int)SendMessageW(g_hLog, LB_GETCOUNT, 0, 0);
            for (int i = 0; i < count; i++)
                SendMessageW(g_hLog, LB_SETSEL, TRUE, (LPARAM)i);
        }

        return 0;
    }

    /* ── Right-click context menu on log ──────────────────────── */

    case WM_CONTEXTMENU: {
        if ((HWND)wParam == g_hLog) {
            HMENU hMenu = CreatePopupMenu();
            AppendMenuW(hMenu, MF_STRING, IDM_COPY_SELECTED, L"复制选中\tCtrl+C");
            AppendMenuW(hMenu, MF_STRING, IDM_SELECT_ALL, L"全选\tCtrl+A");
            int x = GET_X_LPARAM(lParam);
            int y = GET_Y_LPARAM(lParam);
            TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, x, y, 0, hwnd, NULL);
            DestroyMenu(hMenu);
            return 0;
        }
        break;
    }

    /* ── Close / Destroy ──────────────────────────────────── */

    case WM_CLOSE: {
        if (g_hThread || g_hCertThread || g_hTSAThread || g_hVerifyThread) {
            if (IDYES != MessageBoxW(hwnd,
                    L"操作尚未完成，确定要关闭吗？",
                    L"FileSigner", MB_YESNO | MB_ICONWARNING))
                return 0;
        }
        /* Signal TSA thread to stop */
        InterlockedExchange(&g_tsaCancel, 1);
        DestroyWindow(hwnd);
        return 0;
    }
    case WM_DESTROY:
        InterlockedExchange(&g_tsaCancel, 1);
        if (g_hThread) {
            WaitForSingleObject(g_hThread, INFINITE);
            CloseHandle(g_hThread);
            g_hThread = NULL;
        }
        if (g_hCertThread) {
            WaitForSingleObject(g_hCertThread, INFINITE);
            CloseHandle(g_hCertThread);
            g_hCertThread = NULL;
        }
        if (g_hTSAThread) {
            WaitForSingleObject(g_hTSAThread, 5000);
            CloseHandle(g_hTSAThread);
            g_hTSAThread = NULL;
        }
        if (g_hUpdateThread) {
            WaitForSingleObject(g_hUpdateThread, 3000);
            CloseHandle(g_hUpdateThread);
            g_hUpdateThread = NULL;
        }
        if (g_hVerifyThread) {
            WaitForSingleObject(g_hVerifyThread, 5000);
            CloseHandle(g_hVerifyThread);
            g_hVerifyThread = NULL;
        }
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

/* ══════════════════════════════════════════════════════════════ */
/*  Entry point                                                   */
/* ══════════════════════════════════════════════════════════════ */

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
                                 WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
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
    if (g_hFontBold)   DeleteObject(g_hFontBold);
    if (g_hFontTab)    DeleteObject(g_hFontTab);
    if (g_hMonoFont)   DeleteObject(g_hMonoFont);
    if (g_hbrBg)       DeleteObject(g_hbrBg);
    if (g_hbrPanel)    DeleteObject(g_hbrPanel);
    if (g_hbrLogBg)    DeleteObject(g_hbrLogBg);
    if (g_hbrEditBg)   DeleteObject(g_hbrEditBg);
    if (g_hbrAccent)   DeleteObject(g_hbrAccent);

    OleUninitialize();
    return (int)msg.wParam;
}
