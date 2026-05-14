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

static void log_message(HWND hList, const char *fmt, ...)
{
    char buf[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    int idx = (int)SendMessage(hList, LB_ADDSTRING, 0, (LPARAM)buf);
    SendMessage(hList, LB_SETTOPINDEX, idx, 0);
}

static BOOL browse_file(HWND hwnd, const char *filter, const char *title,
                         char *outpath, DWORD outsize)
{
    OPENFILENAMEA ofn;
    memset(&ofn, 0, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = filter;
    ofn.lpstrFile = outpath;
    ofn.nMaxFile = outsize;
    ofn.lpstrTitle = title;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    outpath[0] = '\0';
    return GetOpenFileNameA(&ofn);
}

static BOOL browse_save_file(HWND hwnd, const char *filter, const char *title,
                              char *outpath, DWORD outsize)
{
    OPENFILENAMEA ofn;
    memset(&ofn, 0, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = filter;
    ofn.lpstrFile = outpath;
    ofn.nMaxFile = outsize;
    ofn.lpstrTitle = title;
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    outpath[0] = '\0';
    return GetSaveFileNameA(&ofn);
}

static BOOL browse_folder(HWND hwnd, const char *title, char *outpath)
{
    BROWSEINFOA bi;
    memset(&bi, 0, sizeof(bi));
    bi.hwndOwner = hwnd;
    bi.lpszTitle = title;
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;

    LPITEMIDLIST pidl = SHBrowseForFolderA(&bi);
    if (!pidl) return FALSE;

    BOOL ret = SHGetPathFromIDListA(pidl, outpath);
    CoTaskMemFree(pidl);
    return ret;
}

/* Create a Win32 control helper */
static HWND make_ctrl(HWND parent, const char *cls, const char *text,
                       DWORD style, int x, int y, int w, int h, int id)
{
    return CreateWindowExA(0, cls, text,
                            WS_CHILD | WS_VISIBLE | style,
                            x, y, w, h,
                            parent, (HMENU)(INT_PTR)id, g_hInst, NULL);
}

/* ------------------------------------------------------------------ */
/* Sign page layout                                                    */
/* ------------------------------------------------------------------ */

static void create_sign_page(HWND parent)
{
    g_hPageSign = CreateWindowExA(0, "STATIC", "",
                                   WS_CHILD | WS_VISIBLE,
                                   10, 35, 570, 430, parent, NULL, g_hInst, NULL);

    int y = 10;

    /* Target file/dir */
    make_ctrl(g_hPageSign, "STATIC", "Target (file or directory):", 0, 0, y, 160, 20, 0);
    y += 20;
    make_ctrl(g_hPageSign, "EDIT", "", WS_BORDER | ES_AUTOHSCROLL, 0, y, 450, 24, IDC_EDIT_TARGET);
    make_ctrl(g_hPageSign, "BUTTON", "Browse...", 0, 460, y, 90, 24, IDC_BTN_BROWSE_TGT);
    y += 32;

    /* PFX file */
    make_ctrl(g_hPageSign, "STATIC", "PFX certificate file:", 0, 0, y, 160, 20, 0);
    y += 20;
    make_ctrl(g_hPageSign, "EDIT", "", WS_BORDER | ES_AUTOHSCROLL, 0, y, 450, 24, IDC_EDIT_PFX);
    make_ctrl(g_hPageSign, "BUTTON", "Browse...", 0, 460, y, 90, 24, IDC_BTN_BROWSE_PFX);
    y += 32;

    /* Password */
    make_ctrl(g_hPageSign, "STATIC", "PFX password:", 0, 0, y, 160, 20, 0);
    y += 20;
    make_ctrl(g_hPageSign, "EDIT", "", WS_BORDER | ES_AUTOHSCROLL | ES_PASSWORD, 0, y, 300, 24, IDC_EDIT_PASSWORD);
    y += 32;

    /* Timestamp URL */
    make_ctrl(g_hPageSign, "STATIC", "Timestamp server URL (optional):", 0, 0, y, 250, 20, 0);
    y += 20;
    make_ctrl(g_hPageSign, "EDIT", "http://timestamp.digicert.com",
              WS_BORDER | ES_AUTOHSCROLL, 0, y, 450, 24, IDC_EDIT_TIMESTAMP);
    y += 32;

    /* Output dir */
    make_ctrl(g_hPageSign, "STATIC", "Output directory (optional, blank = overwrite):", 0, 0, y, 320, 20, 0);
    y += 20;
    make_ctrl(g_hPageSign, "EDIT", "", WS_BORDER | ES_AUTOHSCROLL, 0, y, 450, 24, IDC_EDIT_OUTDIR);
    make_ctrl(g_hPageSign, "BUTTON", "Browse...", 0, 460, y, 90, 24, IDC_BTN_BROWSE_OUT);
    y += 32;

    /* Checkboxes */
    make_ctrl(g_hPageSign, "BUTTON", "Recursive (scan subdirectories)",
              BS_AUTOCHECKBOX, 0, y, 300, 20, IDC_CHK_RECURSIVE);
    y += 24;
    make_ctrl(g_hPageSign, "BUTTON", "Force re-sign already signed files",
              BS_AUTOCHECKBOX, 0, y, 300, 20, IDC_CHK_FORCE);
    y += 32;

    /* Sign button */
    make_ctrl(g_hPageSign, "BUTTON", "Sign Files",
              BS_DEFPUSHBUTTON, 0, y, 120, 32, IDC_BTN_SIGN);
    y += 40;

    /* Progress bar */
    g_hProgress = make_ctrl(g_hPageSign, PROGRESS_CLASSA, "",
                             0, 0, y, 550, 20, IDC_PROGRESS);
    y += 28;

    /* Log listbox */
    g_hLog = make_ctrl(g_hPageSign, "LISTBOX", "",
                        WS_BORDER | WS_VSCROLL | LBS_NOTIFY | LBS_NOINTEGRALHEIGHT,
                        0, y, 550, 180, IDC_LIST_LOG);
}

/* ------------------------------------------------------------------ */
/* Certificate generation page layout                                  */
/* ------------------------------------------------------------------ */

static void create_cert_page(HWND parent)
{
    g_hPageCert = CreateWindowExA(0, "STATIC", "",
                                   WS_CHILD,
                                   10, 35, 570, 430, parent, NULL, g_hInst, NULL);

    int y = 10;

    make_ctrl(g_hPageCert, "STATIC",
              "Generate FileSigner certificates (Root CA + Code Signing).\n"
              "Import the Root CA into Windows Trusted Root store to trust signed files.",
              0, 0, y, 550, 40, 0);
    y += 50;

    /* Output directory */
    make_ctrl(g_hPageCert, "STATIC", "Output directory:", 0, 0, y, 160, 20, 0);
    y += 20;
    make_ctrl(g_hPageCert, "EDIT", "./certs", WS_BORDER | ES_AUTOHSCROLL,
              0, y, 450, 24, IDC_EDIT_CERT_DIR);
    make_ctrl(g_hPageCert, "BUTTON", "Browse...", 0, 460, y, 90, 24, IDC_BTN_BROWSE_CD);
    y += 32;

    /* Validity days */
    make_ctrl(g_hPageCert, "STATIC", "Signer cert validity (days):", 0, 0, y, 200, 20, 0);
    y += 20;
    make_ctrl(g_hPageCert, "EDIT", "90", WS_BORDER | ES_AUTOHSCROLL | ES_NUMBER,
              0, y, 100, 24, IDC_EDIT_CERT_DAYS);
    y += 32;

    /* Generate button */
    make_ctrl(g_hPageCert, "BUTTON", "Generate Certificates",
              BS_DEFPUSHBUTTON, 0, y, 180, 32, IDC_BTN_GENERATE);
    y += 40;

    /* Status label */
    make_ctrl(g_hPageCert, "STATIC", "", 0, 0, y, 550, 120, IDC_LBL_CERT_STATUS);
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
    SendMessage(ctx->hProgress, PBM_SETPOS, (WPARAM)(current * 100 / total), 0);

    if (success == 1)
        log_message(ctx->hLog, "[OK] %s", filename);
    else if (success == 0)
        log_message(ctx->hLog, "[SKIP/FAIL] %s", filename);

    MSG msg;
    while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
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
        /* Create tab control */
        g_hTab = CreateWindowExA(0, WC_TABCONTROLA, "",
                                  WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
                                  0, 0, 590, 28, hwnd, (HMENU)IDC_TAB, g_hInst, NULL);

        TCITEMA tie;
        tie.mask = TCIF_TEXT;
        tie.pszText = "Sign";
        TabCtrl_InsertItem(g_hTab, 0, &tie);
        tie.pszText = "Generate Certificates";
        TabCtrl_InsertItem(g_hTab, 1, &tie);

        /* Create pages */
        create_sign_page(hwnd);
        create_cert_page(hwnd);
        switch_tab(0);

        /* Init common controls */
        SendMessage(g_hProgress, PBM_SETRANGE32, 0, 100);

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

        /* --- Sign page controls --- */
        if (id == IDC_BTN_BROWSE_TGT) {
            char path[MAX_PATH] = {0};
            if (browse_folder(hwnd, "Select target directory", path))
                SetDlgItemTextA(hwnd, IDC_EDIT_TARGET, path);
        }
        else if (id == IDC_BTN_BROWSE_PFX) {
            char path[MAX_PATH] = {0};
            if (browse_file(hwnd, "PFX Files\0*.pfx;*.p12\0All Files\0*.*\0",
                            "Select PFX file", path, MAX_PATH))
                SetDlgItemTextA(hwnd, IDC_EDIT_PFX, path);
        }
        else if (id == IDC_BTN_BROWSE_OUT) {
            char path[MAX_PATH] = {0};
            if (browse_folder(hwnd, "Select output directory", path))
                SetDlgItemTextA(hwnd, IDC_EDIT_OUTDIR, path);
        }
        else if (id == IDC_BTN_SIGN) {
            char target[MAX_PATH], pfx[MAX_PATH], password[256], ts_url[512], outdir[MAX_PATH];
            GetDlgItemTextA(hwnd, IDC_EDIT_TARGET, target, MAX_PATH);
            GetDlgItemTextA(hwnd, IDC_EDIT_PFX, pfx, MAX_PATH);
            GetDlgItemTextA(hwnd, IDC_EDIT_PASSWORD, password, 256);
            GetDlgItemTextA(hwnd, IDC_EDIT_TIMESTAMP, ts_url, 512);
            GetDlgItemTextA(hwnd, IDC_EDIT_OUTDIR, outdir, MAX_PATH);

            if (strlen(target) == 0) { MessageBoxA(hwnd, "Please select a target file or directory.", "Error", MB_OK | MB_ICONERROR); break; }
            if (strlen(pfx) == 0) { MessageBoxA(hwnd, "Please select a PFX file.", "Error", MB_OK | MB_ICONERROR); break; }

            int recursive = IsDlgButtonChecked(hwnd, IDC_CHK_RECURSIVE) == BST_CHECKED;
            int force = IsDlgButtonChecked(hwnd, IDC_CHK_FORCE) == BST_CHECKED;
            const char *ts = (strlen(ts_url) > 0) ? ts_url : NULL;
            const char *out = (strlen(outdir) > 0) ? outdir : NULL;

            HWND hBtn = GetDlgItem(hwnd, IDC_BTN_SIGN);
            EnableWindow(hBtn, FALSE);
            SendMessage(g_hProgress, PBM_SETPOS, 0, 0);
            SendMessage(g_hLog, LB_RESETCONTENT, 0, 0);
            log_message(g_hLog, "Starting signing process...");

            OpenSSL_add_all_algorithms();

            SignProgressCtx ctx = { g_hProgress, g_hLog, hBtn };
            int count;

            if (directory_exists(target)) {
                if (out && !directory_exists(out)) create_directory(out);
                count = batch_sign(target, pfx, password[0] ? password : NULL,
                                    ts, out, force, recursive,
                                    sign_progress_cb, &ctx);
            } else if (file_exists(target)) {
                log_message(g_hLog, "Signing: %s", target);
                if (authenticode_sign(target, pfx, password[0] ? password : NULL,
                                       ts, out ? out : target)) {
                    count = 1;
                    log_message(g_hLog, "[OK] Done");
                } else {
                    count = 0;
                    log_message(g_hLog, "[FAIL] Signing failed");
                }
                SendMessage(g_hProgress, PBM_SETPOS, 100, 0);
            } else {
                log_message(g_hLog, "Error: Target not found: %s", target);
                count = 0;
            }

            log_message(g_hLog, "Finished. Signed %d file(s).", count);

            EVP_cleanup();
            CRYPTO_cleanup_all_ex_data();
            EnableWindow(hBtn, TRUE);
        }

        /* --- Cert page controls --- */
        else if (id == IDC_BTN_BROWSE_CD) {
            char path[MAX_PATH] = {0};
            if (browse_folder(hwnd, "Select output directory", path))
                SetDlgItemTextA(hwnd, IDC_EDIT_CERT_DIR, path);
        }
        else if (id == IDC_BTN_GENERATE) {
            char dir[MAX_PATH], days_str[16];
            GetDlgItemTextA(hwnd, IDC_EDIT_CERT_DIR, dir, MAX_PATH);
            GetDlgItemTextA(hwnd, IDC_EDIT_CERT_DAYS, days_str, 16);

            if (strlen(dir) == 0) { MessageBoxA(hwnd, "Please select an output directory.", "Error", MB_OK | MB_ICONERROR); break; }

            int days = atoi(days_str);
            if (days <= 0) days = 90;

            if (!directory_exists(dir)) create_directory(dir);

            HWND hBtn = GetDlgItem(hwnd, IDC_BTN_GENERATE);
            EnableWindow(hBtn, FALSE);
            SetDlgItemTextA(hwnd, IDC_LBL_CERT_STATUS, "Generating...");

            OpenSSL_add_all_algorithms();
            ERR_load_crypto_strings();

            if (cert_generate(dir, NULL, "FileSigner", days)) {
                char msg[512];
                snprintf(msg, sizeof(msg),
                         "Certificates generated successfully!\n\n"
                         "Files created in: %s\n\n"
                         "IMPORTANT: Import FileSigner_RootCA.cer into\n"
                         "Windows 'Trusted Root Certification Authorities'\n"
                         "store to trust signed executables.", dir);
                SetDlgItemTextA(hwnd, IDC_LBL_CERT_STATUS, msg);
                MessageBoxA(hwnd, msg, "Success", MB_OK | MB_ICONINFORMATION);
            } else {
                SetDlgItemTextA(hwnd, IDC_LBL_CERT_STATUS, "Generation failed! Check console for details.");
                MessageBoxA(hwnd, "Certificate generation failed.", "Error", MB_OK | MB_ICONERROR);
            }

            EVP_cleanup();
            CRYPTO_cleanup_all_ex_data();
            ERR_free_strings();
            EnableWindow(hBtn, TRUE);
        }

        return 0;
    }

    case WM_SIZE:
    {
        /* Could handle resizing here */
        return 0;
    }

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

/* ------------------------------------------------------------------ */
/* Entry point                                                         */
/* ------------------------------------------------------------------ */

int gui_main(void)
{
    WNDCLASSA wc;
    HWND hwnd;
    MSG msg;

    /* Init common controls */
    INITCOMMONCONTROLSEX icc;
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_TAB_CLASSES | ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    CoInitialize(NULL);

    g_hInst = GetModuleHandleA(NULL);

    /* Register window class */
    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc = WndProc;
    wc.hInstance = g_hInst;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = "FileSignerGUI";
    RegisterClassA(&wc);

    /* Create main window */
    hwnd = CreateWindowExA(0, "FileSignerGUI",
                            "FileSigner - Authenticode PE Signing Tool",
                            WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX,
                            CW_USEDEFAULT, CW_USEDEFAULT,
                            600, 520,
                            NULL, NULL, g_hInst, NULL);

    if (!hwnd) return 1;

    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    /* Message loop */
    while (GetMessage(&msg, NULL, 0, 0)) {
        if (!IsDialogMessage(hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    CoUninitialize();
    return (int)msg.wParam;
}

#endif /* _WIN32 */
