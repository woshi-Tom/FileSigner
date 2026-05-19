#define WIN32_LEAN_AND_MEAN
#define UNICODE
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shlobj.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define _CRT_SECURE_NO_WARNINGS

#include "authenticode.h"
#include "batch_signer.h"
#include "cert_gen.h"
#include "timestamp.h"
#include "resource.h"

#define WC_FILESIGNER L"FileSignerWindow"
#define WM_GUI_UPDATE_ROW  (WM_APP + 1)
#define WM_GUI_SIGN_DONE   (WM_APP + 2)

enum { LV_COL_FILE = 0, LV_COL_STATUS, LV_COL_TSA, LV_COL_RESULT, LV_COL_COUNT };
enum { STAT_PART_INFO = 0, STAT_PART_COUNT };

enum { LV_STATUS_PENDING = 0, LV_STATUS_SIGNING, LV_STATUS_OK, LV_STATUS_FAIL };

#define ID_TB_ADD_FILES   100
#define ID_TB_ADD_FOLDER  101
#define ID_TB_START_SIGN  102

#define ID_FILE_ADD_FILES   40001
#define ID_FILE_ADD_FOLDER  40002
#define ID_FILE_EXIT        40003
#define ID_ACTION_START     40010
#define ID_ACTION_CLEAR     40011
#define ID_SETTINGS_TSA     40020
#define ID_CERT_GEN         40021
#define ID_HELP_ABOUT       40030

#define MAX_STR         1024

typedef struct {
    char pfx_path[MAX_PATH];
    char pfx_password[512];
    char tsa_url[512];
    char output_dir[MAX_PATH];
    int  force;
} SignJobParams;

typedef struct {
    int   count;
    int   *lv_rows;
    WCHAR **paths;
    SignJobParams params;
} SignJob;

static HINSTANCE g_hInst;
static HWND g_hwndMain, g_hwndLV, g_hwndStatus, g_hwndTB;
static int g_signing;

static const WCHAR *
lvs_text(int status)
{
    switch (status) {
    case LV_STATUS_PENDING: return L"Pending";
    case LV_STATUS_SIGNING: return L"Signing...";
    case LV_STATUS_OK:      return L"Signed";
    case LV_STATUS_FAIL:    return L"Failed";
    default:                return L"";
    }
}

static void
status_bar_set_part_text(HWND hwnd, int part, const WCHAR *text)
{
    SendMessageW(hwnd, SB_SETTEXTW, (WPARAM)part, (LPARAM)text);
}

static void
update_status_bar(void)
{
    if (!g_hwndStatus) return;
    WCHAR buf[128];
    int count = ListView_GetItemCount(g_hwndLV);
    if (g_signing)
        swprintf(buf, 128, L"Signing in progress...  Total: %d", count);
    else
        swprintf(buf, 128, L"Ready  |  Files: %d", count);
    status_bar_set_part_text(g_hwndStatus, STAT_PART_INFO, buf);
}


/* ---------------------------------------------------------------- */
/* ListView helpers                                                 */
/* ---------------------------------------------------------------- */

static int
lv_add_item(HWND hwndLV, const WCHAR *path)
{
    LVITEMW lvi;
    memset(&lvi, 0, sizeof(lvi));
    lvi.mask     = LVIF_TEXT | LVIF_PARAM;
    lvi.iItem    = INT_MAX;
    lvi.pszText  = (WCHAR *)path;
    lvi.lParam   = (LPARAM)_wcsdup(path);

    int idx = (int)SendMessageW(hwndLV, LVM_INSERTITEMW, 0, (LPARAM)&lvi);
    if (idx >= 0) {
        lvi.mask     = LVIF_TEXT;
        lvi.iSubItem = LV_COL_STATUS;
        lvi.pszText  = (WCHAR *)L"Pending";
        SendMessageW(hwndLV, LVM_SETITEMW, 0, (LPARAM)&lvi);
    }
    return idx;
}

static void
lv_update_status(HWND hwndLV, int row, int status)
{
    LVITEMW lvi;
    memset(&lvi, 0, sizeof(lvi));
    lvi.mask     = LVIF_TEXT;
    lvi.iItem    = row;
    lvi.iSubItem = LV_COL_STATUS;
    lvi.pszText  = (WCHAR *)lvs_text(status);
    SendMessageW(hwndLV, LVM_SETITEMW, 0, (LPARAM)&lvi);
}

static WCHAR *
lv_get_path(HWND hwndLV, int row)
{
    LVITEMW lvi;
    memset(&lvi, 0, sizeof(lvi));
    lvi.mask   = LVIF_PARAM;
    lvi.iItem  = row;
    SendMessageW(hwndLV, LVM_GETITEMW, 0, (LPARAM)&lvi);
    if (lvi.lParam)
        return _wcsdup((const WCHAR *)lvi.lParam);
    return NULL;
}

static void
lv_clear_all(HWND hwndLV)
{
    /* Free lParam strings */
    int count = ListView_GetItemCount(hwndLV);
    for (int i = 0; i < count; i++) {
        LVITEMW lvi;
        memset(&lvi, 0, sizeof(lvi));
        lvi.mask   = LVIF_PARAM;
        lvi.iItem  = i;
        SendMessageW(hwndLV, LVM_GETITEMW, 0, (LPARAM)&lvi);
        if (lvi.lParam) free((void *)lvi.lParam);
    }
    ListView_DeleteAllItems(hwndLV);
}


/* ---------------------------------------------------------------- */
/* Dialogs                                                          */
/* ---------------------------------------------------------------- */

static INT_PTR CALLBACK
sign_settings_dlg(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    static SignJobParams *out_params;
    static WCHAR pfx_buf[MAX_PATH], outdir_buf[MAX_PATH], pw_buf[512], tsa_buf[512];

    switch (msg) {
    case WM_INITDIALOG: {
        out_params = (SignJobParams *)lParam;
        /* Populate TSA combo */
        HWND hCombo = GetDlgItem(hDlg, 1003);
        for (int i = 0; i < TSA_SERVER_COUNT; i++) {
            WCHAR wlabel[256];
            MultiByteToWideChar(CP_UTF8, 0, g_tsa_servers[i].label, -1, wlabel, 256);
            int idx = (int)SendMessageW(hCombo, CB_ADDSTRING, 0, (LPARAM)wlabel);
            SendMessageW(hCombo, CB_SETITEMDATA, (WPARAM)idx, (LPARAM)i);
        }
        SendMessageW(hCombo, CB_SETCURSEL, 0, 0);
        /* Restore saved values */
        if (out_params->pfx_path[0]) {
            MultiByteToWideChar(CP_UTF8, 0, out_params->pfx_path, -1, pfx_buf, MAX_PATH);
            SetDlgItemTextW(hDlg, 1000, pfx_buf);
        }
        if (out_params->pfx_password[0]) {
            MultiByteToWideChar(CP_UTF8, 0, out_params->pfx_password, -1, pw_buf, 512);
            SetDlgItemTextW(hDlg, 1001, pw_buf);
        }
        if (out_params->tsa_url[0]) {
            MultiByteToWideChar(CP_UTF8, 0, out_params->tsa_url, -1, tsa_buf, 512);
            SetDlgItemTextW(hDlg, 1004, tsa_buf);
        }
        if (out_params->output_dir[0]) {
            MultiByteToWideChar(CP_UTF8, 0, out_params->output_dir, -1, outdir_buf, MAX_PATH);
            SetDlgItemTextW(hDlg, 1005, outdir_buf);
        }
        return TRUE;
    }
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDOK: {
            /* Read values back */
            GetDlgItemTextW(hDlg, 1000, pfx_buf, MAX_PATH);
            GetDlgItemTextW(hDlg, 1001, pw_buf, 512);
            GetDlgItemTextW(hDlg, 1004, tsa_buf, 512);
            GetDlgItemTextW(hDlg, 1005, outdir_buf, MAX_PATH);

            WideCharToMultiByte(CP_UTF8, 0, pfx_buf, -1,
                                out_params->pfx_path, MAX_PATH, NULL, NULL);
            WideCharToMultiByte(CP_UTF8, 0, pw_buf, -1,
                                out_params->pfx_password, 512, NULL, NULL);
            WideCharToMultiByte(CP_UTF8, 0, tsa_buf, -1,
                                out_params->tsa_url, 512, NULL, NULL);
            WideCharToMultiByte(CP_UTF8, 0, outdir_buf, -1,
                                out_params->output_dir, MAX_PATH, NULL, NULL);
            out_params->force = (IsDlgButtonChecked(hDlg, 1006) == BST_CHECKED);

            EndDialog(hDlg, IDOK);
            return TRUE;
        }
        case IDCANCEL:
            EndDialog(hDlg, IDCANCEL);
            return TRUE;
        case 1010: { /* Browse PFX */
            WCHAR file_buf[MAX_PATH] = {0};
            OPENFILENAMEW ofn;
            memset(&ofn, 0, sizeof(ofn));
            ofn.lStructSize  = sizeof(ofn);
            ofn.hwndOwner    = hDlg;
            ofn.lpstrFile    = file_buf;
            ofn.nMaxFile     = MAX_PATH;
            ofn.lpstrFilter  = L"PFX/P12 Files\0*.pfx;*.p12\0All Files\0*.*\0";
            ofn.nFilterIndex = 1;
            ofn.Flags        = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
            if (GetOpenFileNameW(&ofn))
                SetDlgItemTextW(hDlg, 1000, file_buf);
            return TRUE;
        }
        case 1011: { /* Browse output dir */
            BROWSEINFOW bi;
            memset(&bi, 0, sizeof(bi));
            bi.hwndOwner = hDlg;
            bi.lpszTitle = L"Select Output Directory";
            bi.ulFlags   = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
            LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
            if (pidl) {
                WCHAR path[MAX_PATH];
                if (SHGetPathFromIDListW(pidl, path))
                    SetDlgItemTextW(hDlg, 1005, path);
                CoTaskMemFree(pidl);
            }
            return TRUE;
        }
        case 1003: { /* TSA combo selection */
            if (HIWORD(wParam) == CBN_SELCHANGE) {
                HWND hCombo = GetDlgItem(hDlg, 1003);
                int sel = (int)SendMessageW(hCombo, CB_GETCURSEL, 0, 0);
                if (sel >= 0) {
                    int idx = (int)SendMessageW(hCombo, CB_GETITEMDATA, (WPARAM)sel, 0);
                    if (idx >= 0 && idx < TSA_SERVER_COUNT) {
                        WCHAR wurl[512];
                        MultiByteToWideChar(CP_UTF8, 0, g_tsa_servers[idx].url, -1, wurl, 512);
                        SetDlgItemTextW(hDlg, 1004, wurl);
                    }
                }
            }
            return TRUE;
        }
        }
        return FALSE;
    }
    return FALSE;
}

static INT_PTR CALLBACK
cert_gen_dlg(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    (void)lParam;

    switch (msg) {
    case WM_INITDIALOG:
        SetDlgItemInt(hDlg, 1002, CERT_SIGNER_DEFAULT_DAYS, FALSE);
        return TRUE;
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDOK: {
            WCHAR outdir[MAX_PATH] = {0}, pw[256] = {0};
            WCHAR cn[256] = {0}, email[256] = {0};
            GetDlgItemTextW(hDlg, 1000, outdir, MAX_PATH);
            GetDlgItemTextW(hDlg, 1001, pw, 256);
            GetDlgItemTextW(hDlg, 1003, cn, 256);
            GetDlgItemTextW(hDlg, 1004, email, 256);
            int days = GetDlgItemInt(hDlg, 1002, NULL, FALSE);

            char outdir_a[MAX_PATH], pw_a[256], cn_a[256], email_a[256];
            WideCharToMultiByte(CP_UTF8, 0, outdir, -1, outdir_a, MAX_PATH, NULL, NULL);
            WideCharToMultiByte(CP_UTF8, 0, pw, -1, pw_a, 256, NULL, NULL);
            WideCharToMultiByte(CP_UTF8, 0, cn, -1, cn_a, 256, NULL, NULL);
            WideCharToMultiByte(CP_UTF8, 0, email, -1, email_a, 256, NULL, NULL);

            CreateDirectoryA(outdir_a, NULL);
            int ok = cert_generate(outdir_a, NULL,
                                   pw_a[0] ? pw_a : NULL,
                                   days, cn_a[0] ? cn_a : NULL,
                                   email_a[0] ? email_a : NULL);
            WCHAR msg_buf[512];
            if (ok) {
                swprintf(msg_buf, 512, L"Certificate generated successfully in:\n%hs", outdir_a);
                MessageBoxW(hDlg, msg_buf, L"Success", MB_ICONINFORMATION);
            } else {
                swprintf(msg_buf, 512, L"Certificate generation failed.\nCheck output directory: %hs", outdir_a);
                MessageBoxW(hDlg, msg_buf, L"Error", MB_ICONERROR);
            }
            EndDialog(hDlg, IDOK);
            return TRUE;
        }
        case IDCANCEL:
            EndDialog(hDlg, IDCANCEL);
            return TRUE;
        case 1010: { /* Browse output dir */
            BROWSEINFOW bi;
            memset(&bi, 0, sizeof(bi));
            bi.hwndOwner = hDlg;
            bi.lpszTitle = L"Select Output Directory";
            bi.ulFlags   = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
            LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
            if (pidl) {
                WCHAR path[MAX_PATH];
                if (SHGetPathFromIDListW(pidl, path))
                    SetDlgItemTextW(hDlg, 1000, path);
                CoTaskMemFree(pidl);
            }
            return TRUE;
        }
        }
        return FALSE;
    }
    return FALSE;
}


/* ---------------------------------------------------------------- */
/* Worker thread                                                    */
/* ---------------------------------------------------------------- */

static DWORD WINAPI
sign_worker(LPVOID param)
{
    SignJob *job = (SignJob *)param;

    for (int i = 0; i < job->count; i++) {
        PostMessageW(g_hwndMain, WM_GUI_UPDATE_ROW,
                     MAKEWPARAM(job->lv_rows[i], LV_STATUS_SIGNING), 0);

        char pe_path[MAX_PATH];
        WideCharToMultiByte(CP_UTF8, 0, job->paths[i], -1,
                            pe_path, MAX_PATH, NULL, NULL);

        char out_path[MAX_PATH] = {0};
        if (job->params.output_dir[0]) {
            const char *fname = strrchr(pe_path, '\\');
            if (!fname) fname = strrchr(pe_path, '/');
            if (!fname) fname = pe_path;
            else fname++;
            snprintf(out_path, sizeof(out_path), "%s\\%s",
                     job->params.output_dir, fname);
        }

        int ok = authenticode_sign(pe_path,
                                   job->params.pfx_path,
                                   job->params.pfx_password[0] ? job->params.pfx_password : NULL,
                                   job->params.tsa_url[0]      ? job->params.tsa_url : NULL,
                                   out_path[0]                 ? out_path : NULL,
                                   NULL, NULL);

        int status = ok ? LV_STATUS_OK : LV_STATUS_FAIL;
        PostMessageW(g_hwndMain, WM_GUI_UPDATE_ROW,
                     MAKEWPARAM(job->lv_rows[i], status), 0);
    }

    PostMessageW(g_hwndMain, WM_GUI_SIGN_DONE, 0, (LPARAM)job);
    return 0;
}


/* ---------------------------------------------------------------- */
/* Signing orchestration                                            */
/* ---------------------------------------------------------------- */

static void
start_signing(void)
{
    if (g_signing) return;

    /* Count pending items */
    int total = ListView_GetItemCount(g_hwndLV);
    if (total == 0) {
        MessageBoxW(g_hwndMain, L"No files in list.\nAdd files first.", L"FileSigner",
                    MB_ICONINFORMATION);
        return;
    }

    int pending = 0;
    for (int i = 0; i < total; i++) {
        WCHAR buf[32];
        ListView_GetItemText(g_hwndLV, i, LV_COL_STATUS, buf, 32);
        if (wcscmp(buf, L"Pending") == 0) pending++;
    }
    if (pending == 0) {
        MessageBoxW(g_hwndMain, L"All files have been signed.\nUse Clear List to reset.",
                    L"FileSigner", MB_ICONINFORMATION);
        return;
    }

    /* Show sign settings dialog */
    SignJobParams params;
    memset(&params, 0, sizeof(params));
    INT_PTR dlg_ret = DialogBoxParamW(g_hInst, MAKEINTRESOURCEW(101),
                                       g_hwndMain, sign_settings_dlg, (LPARAM)&params);
    if (dlg_ret != IDOK) return;

    if (!params.pfx_path[0]) {
        MessageBoxW(g_hwndMain, L"PFX file is required.", L"FileSigner", MB_ICONWARNING);
        return;
    }

    /* Collect pending files for the worker */
    int *lv_rows = (int *)malloc((size_t)pending * sizeof(int));
    WCHAR **paths = (WCHAR **)malloc((size_t)pending * sizeof(WCHAR *));
    if (!lv_rows || !paths) { free(lv_rows); free(paths); return; }

    int idx = 0;
    for (int i = 0; i < total && idx < pending; i++) {
        WCHAR buf[32];
        ListView_GetItemText(g_hwndLV, i, LV_COL_STATUS, buf, 32);
        if (wcscmp(buf, L"Pending") == 0) {
            lv_rows[idx] = i;
            paths[idx] = lv_get_path(g_hwndLV, i);
            idx++;
        }
    }

    SignJob *job = (SignJob *)malloc(sizeof(SignJob));
    if (!job) { free(lv_rows); free(paths); return; }
    job->count     = pending;
    job->lv_rows   = lv_rows;
    job->paths     = paths;
    job->params    = params;

    g_signing = 1;
    SendMessageW(g_hwndTB, TB_ENABLEBUTTON, ID_TB_START_SIGN, MAKELPARAM(FALSE, 0));
    update_status_bar();

    HANDLE h = CreateThread(NULL, 0, sign_worker, job, 0, NULL);
    if (h) CloseHandle(h);
    else { g_signing = 0; free(job->lv_rows); free(job->paths); free(job); }
}

static void
on_sign_done(SignJob *job)
{
    /* Free worker data */
    for (int i = 0; i < job->count; i++)
        free(job->paths[i]);
    free(job->lv_rows);
    free(job->paths);
    free(job);

    g_signing = 0;
    SendMessageW(g_hwndTB, TB_ENABLEBUTTON, ID_TB_START_SIGN, MAKELPARAM(TRUE, 0));
    update_status_bar();

    /* Count results */
    int ok = 0, fail = 0;
    int total = ListView_GetItemCount(g_hwndLV);
    for (int i = 0; i < total; i++) {
        WCHAR buf[32];
        ListView_GetItemText(g_hwndLV, i, LV_COL_STATUS, buf, 32);
        if (wcscmp(buf, L"Signed") == 0) ok++;
        else if (wcscmp(buf, L"Failed") == 0) fail++;
    }

    WCHAR msg[256];
    swprintf(msg, 256, L"Signing complete.\n\nSigned: %d\nFailed: %d\nTotal:  %d",
             ok, fail, total);
    MessageBoxW(g_hwndMain, msg, L"FileSigner", MB_ICONINFORMATION);
}


/* ---------------------------------------------------------------- */
/* Add files / folders                                              */
/* ---------------------------------------------------------------- */

static void
add_files(void)
{
    WCHAR files[65536] = {0};
    OPENFILENAMEW ofn;
    memset(&ofn, 0, sizeof(ofn));
    ofn.lStructSize  = sizeof(ofn);
    ofn.hwndOwner    = g_hwndMain;
    ofn.lpstrFile    = files;
    ofn.nMaxFile     = 65536;
    ofn.lpstrFilter  = L"PE Files (*.exe;*.dll;*.ocx;*.sys)\0*.exe;*.dll;*.ocx;*.sys\0All Files\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.Flags        = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST |
                        OFN_HIDEREADONLY | OFN_ALLOWMULTISELECT |
                        OFN_EXPLORER;

    if (!GetOpenFileNameW(&ofn)) return;

    /* Multi-select: first token is dir, followed by filenames */
    WCHAR *p = files;
    WCHAR dir[MAX_PATH];
    wcscpy(dir, p);
    p += wcslen(p) + 1;

    if (*p == 0) {
        /* Only one file selected */
        lv_add_item(g_hwndLV, dir);
    } else {
        /* Multiple files */
        while (*p) {
            WCHAR full[MAX_PATH];
            swprintf(full, MAX_PATH, L"%s\\%s", dir, p);
            lv_add_item(g_hwndLV, full);
            p += wcslen(p) + 1;
        }
    }
    update_status_bar();
}

static void
add_folder(void)
{
    BROWSEINFOW bi;
    memset(&bi, 0, sizeof(bi));
    bi.hwndOwner = g_hwndMain;
    bi.lpszTitle = L"Select folder with PE files to sign";
    bi.ulFlags   = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;

    LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
    if (!pidl) return;

    WCHAR dir[MAX_PATH];
    if (!SHGetPathFromIDListW(pidl, dir)) { CoTaskMemFree(pidl); return; }
    CoTaskMemFree(pidl);

    WCHAR pattern[MAX_PATH];
    swprintf(pattern, MAX_PATH, L"%s\\*", dir);

    WIN32_FIND_DATAW ffd;
    HANDLE hFind = FindFirstFileW(pattern, &ffd);
    if (hFind == INVALID_HANDLE_VALUE) {
        MessageBoxW(g_hwndMain, L"Could not open folder.", L"FileSigner", MB_ICONWARNING);
        return;
    }

    int added = 0;
    do {
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        /* Check for PE extension */
        const WCHAR *ext = wcsrchr(ffd.cFileName, L'.');
        if (!ext) continue;
        if (_wcsicmp(ext, L".exe") == 0 || _wcsicmp(ext, L".dll") == 0 ||
            _wcsicmp(ext, L".ocx") == 0 || _wcsicmp(ext, L".sys") == 0) {
            WCHAR full[MAX_PATH];
            swprintf(full, MAX_PATH, L"%s\\%s", dir, ffd.cFileName);
            lv_add_item(g_hwndLV, full);
            added++;
        }
    } while (FindNextFileW(hFind, &ffd) != 0);

    FindClose(hFind);

    if (added == 0)
        MessageBoxW(g_hwndMain, L"No PE files (*.exe, *.dll, *.ocx, *.sys) found.",
                    L"FileSigner", MB_ICONINFORMATION);

    update_status_bar();
}


/* ---------------------------------------------------------------- */
/* Toolbar                                                          */
/* ---------------------------------------------------------------- */

static HWND
create_toolbar(HWND hwndParent)
{
    HWND hwnd = CreateWindowExW(0, TOOLBARCLASSNAME, NULL,
                                 WS_CHILD | WS_VISIBLE | TBSTYLE_FLAT |
                                 TBSTYLE_TOOLTIPS | CCS_NORESIZE,
                                 0, 0, 0, 0, hwndParent, NULL, g_hInst, NULL);
    if (!hwnd) return NULL;

    SendMessageW(hwnd, TB_BUTTONSTRUCTSIZE, sizeof(TBBUTTON), 0);
    SendMessageW(hwnd, TB_SETMAXTEXTROWS, 0, 0);

    TBBUTTON btns[] = {
        { 0, ID_TB_ADD_FILES,  TBSTATE_ENABLED, BTNS_AUTOSIZE | BTNS_SHOWTEXT },
        { 0, ID_TB_ADD_FOLDER, TBSTATE_ENABLED, BTNS_AUTOSIZE | BTNS_SHOWTEXT },
        { 0, 0,                TBSTATE_ENABLED, BTNS_SEP },
        { 0, ID_TB_START_SIGN, TBSTATE_ENABLED, BTNS_AUTOSIZE | BTNS_SHOWTEXT },
    };
    SendMessageW(hwnd, TB_ADDBUTTONS, (WPARAM)ARRAYSIZE(btns), (LPARAM)btns);

    TBBUTTONINFOW bi;
    memset(&bi, 0, sizeof(bi));
    bi.cbSize  = sizeof(bi);
    bi.dwMask  = TBIF_TEXT;

    bi.pszText = L"Add Files";
    SendMessageW(hwnd, TB_SETBUTTONINFOW, ID_TB_ADD_FILES, (LPARAM)&bi);
    bi.pszText = L"Add Folder";
    SendMessageW(hwnd, TB_SETBUTTONINFOW, ID_TB_ADD_FOLDER, (LPARAM)&bi);
    bi.pszText = L"Start Sign";
    SendMessageW(hwnd, TB_SETBUTTONINFOW, ID_TB_START_SIGN, (LPARAM)&bi);

    return hwnd;
}


/* ---------------------------------------------------------------- */
/* ListView                                                         */
/* ---------------------------------------------------------------- */

static HWND
create_listview(HWND hwndParent)
{
    HWND hwnd = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, NULL,
                                 WS_CHILD | WS_VISIBLE | LVS_REPORT |
                                 LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                                 0, 0, 0, 0, hwndParent, NULL, g_hInst, NULL);
    if (!hwnd) return NULL;

    ListView_SetExtendedListViewStyleEx(hwnd,
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER,
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

    LVCOLUMNW lvc;
    memset(&lvc, 0, sizeof(lvc));
    lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
    lvc.fmt  = LVCFMT_LEFT;

    lvc.cx       = 320;
    lvc.pszText  = L"File Name";
    ListView_InsertColumn(hwnd, LV_COL_FILE, &lvc);

    lvc.cx       = 100;
    lvc.pszText  = L"Status";
    ListView_InsertColumn(hwnd, LV_COL_STATUS, &lvc);

    lvc.cx       = 200;
    lvc.pszText  = L"TSA URL";
    ListView_InsertColumn(hwnd, LV_COL_TSA, &lvc);

    lvc.cx       = 200;
    lvc.pszText  = L"Result";
    ListView_InsertColumn(hwnd, LV_COL_RESULT, &lvc);

    return hwnd;
}


/* ---------------------------------------------------------------- */
/* Menu creation                                                    */
/* ---------------------------------------------------------------- */

static HMENU
create_menu_bar(void)
{
    HMENU hMenu = CreateMenu();
    HMENU hFile = CreatePopupMenu();
    HMENU hAction = CreatePopupMenu();
    HMENU hSettings = CreatePopupMenu();
    HMENU hHelp = CreatePopupMenu();

    AppendMenuW(hFile, MF_STRING, ID_FILE_ADD_FILES,  L"Add Files...\tCtrl+A");
    AppendMenuW(hFile, MF_STRING, ID_FILE_ADD_FOLDER, L"Add Folder...\tCtrl+F");
    AppendMenuW(hFile, MF_SEPARATOR, 0, NULL);
    AppendMenuW(hFile, MF_STRING, ID_FILE_EXIT,       L"Exit\tAlt+F4");

    AppendMenuW(hAction, MF_STRING, ID_ACTION_START,  L"Start Sign\tF5");
    AppendMenuW(hAction, MF_STRING, ID_ACTION_CLEAR,  L"Clear List");

    AppendMenuW(hSettings, MF_STRING, ID_SETTINGS_TSA, L"TSA Servers...");
    AppendMenuW(hSettings, MF_STRING, ID_CERT_GEN,     L"Generate Certificate...");

    AppendMenuW(hHelp, MF_STRING, ID_HELP_ABOUT,      L"About FileSigner");

    AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hFile,     L"File");
    AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hAction,   L"Action");
    AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hSettings, L"Settings");
    AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hHelp,     L"Help");

    return hMenu;
}


/* ---------------------------------------------------------------- */
/* Main window procedure                                            */
/* ---------------------------------------------------------------- */

static LRESULT CALLBACK
WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_CREATE: {
        /* Create controls */
        g_hwndTB = create_toolbar(hwnd);
        g_hwndLV = create_listview(hwnd);
        g_hwndStatus = CreateWindowExW(0, STATUSCLASSNAMEW, NULL,
                                        WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
                                        0, 0, 0, 0, hwnd, NULL, g_hInst, NULL);

        /* Accept drag-and-drop */
        DragAcceptFiles(hwnd, TRUE);

        /* Initial status */
        update_status_bar();

    return 0;
    }
    case WM_SIZE: {
        RECT rc;
        GetClientRect(hwnd, &rc);

        /* Size toolbar */
        SendMessageW(g_hwndTB, TB_AUTOSIZE, 0, 0);
        RECT rcTB;
        GetWindowRect(g_hwndTB, &rcTB);
        int tb_h = rcTB.bottom - rcTB.top;

        /* Size status bar */
        SendMessageW(g_hwndStatus, WM_SIZE, 0, 0);
        RECT rcSB;
        GetWindowRect(g_hwndStatus, &rcSB);
        int sb_h = rcSB.bottom - rcSB.top;

        /* Size ListView to fill remaining space */
        MoveWindow(g_hwndLV, 0, tb_h,
                   rc.right, rc.bottom - tb_h - sb_h, TRUE);
        return 0;
    }
    case WM_COMMAND: {
        int id = LOWORD(wParam);
        switch (id) {
        case ID_TB_ADD_FILES:
        case ID_FILE_ADD_FILES:  add_files(); return 0;
        case ID_TB_ADD_FOLDER:
        case ID_FILE_ADD_FOLDER: add_folder(); return 0;
        case ID_FILE_EXIT:       PostQuitMessage(0); return 0;
        case ID_TB_START_SIGN:
        case ID_ACTION_START:    start_signing(); return 0;
        case ID_ACTION_CLEAR:
            if (g_signing) {
                MessageBoxW(hwnd, L"Cannot clear list while signing.",
                            L"FileSigner", MB_ICONWARNING);
            } else {
                lv_clear_all(g_hwndLV);
                update_status_bar();
            }
            return 0;
        case ID_SETTINGS_TSA: {
            WCHAR msg[2048] = L"Built-in TSA Servers:\r\n\r\n";
            for (int i = 0; i < TSA_SERVER_COUNT; i++) {
                WCHAR entry[256];
                MultiByteToWideChar(CP_UTF8, 0, g_tsa_servers[i].label, -1, entry, 256);
                wcscat(msg, L"  \u2022 ");
                wcscat(msg, entry);
                wcscat(msg, L"\r\n");
            }
            wcscat(msg, L"\r\nSelect a TSA server in Start Sign \u2192 Sign Settings.");
            MessageBoxW(hwnd, msg, L"TSA Servers", MB_ICONINFORMATION);
            return 0;
        }
        case ID_CERT_GEN:
            DialogBoxW(g_hInst, MAKEINTRESOURCEW(103), hwnd, cert_gen_dlg);
            return 0;
        case ID_HELP_ABOUT:
            MessageBoxW(hwnd,
                L"FileSigner 2.0\n\n"
                L"Authenticode PE Signing Tool\n"
                L"Built with OpenSSL + native Win32\n\n"
                L"Batch sign PE files (EXE/DLL/OCX/SYS)\n"
                L"with code signing certificates.",
                L"About FileSigner", MB_ICONINFORMATION);
            return 0;
        }
        return 0;
    }
    case WM_GUI_UPDATE_ROW: {
        int row  = LOWORD(wParam);
        int status = HIWORD(wParam);
        lv_update_status(g_hwndLV, row, status);
        update_status_bar();
        return 0;
    }
    case WM_GUI_SIGN_DONE: {
        on_sign_done((SignJob *)lParam);
        return 0;
    }
    case WM_DROPFILES: {
        HDROP hDrop = (HDROP)wParam;
        UINT count = DragQueryFileW(hDrop, 0xFFFFFFFF, NULL, 0);
        for (UINT i = 0; i < count; i++) {
            WCHAR path[MAX_PATH];
            DragQueryFileW(hDrop, i, path, MAX_PATH);
            lv_add_item(g_hwndLV, path);
        }
        DragFinish(hDrop);
        update_status_bar();
        return 0;
    }
    case WM_DESTROY:
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

    /* Initialize common controls (ListView, Toolbar, StatusBar) */
    INITCOMMONCONTROLSEX icc;
    icc.dwSize = sizeof(icc);
    icc.dwICC  = ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    /* COM for SHBrowseForFolder */
    OleInitialize(NULL);

    /* Register window class */
    WNDCLASSEXW wc;
    memset(&wc, 0, sizeof(wc));
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW | CS_DROPSHADOW;
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInstance;
    wc.hIcon         = LoadIconW(hInstance, MAKEINTRESOURCEW(IDI_MAIN_ICON));
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszMenuName  = NULL;
    wc.lpszClassName = WC_FILESIGNER;
    wc.hIconSm       = NULL;

    if (!RegisterClassExW(&wc)) {
        OleUninitialize();
        return 1;
    }

    /* Create window */
    g_hwndMain = CreateWindowExW(0, WC_FILESIGNER, L"FileSigner",
                                  WS_OVERLAPPEDWINDOW,
                                  CW_USEDEFAULT, CW_USEDEFAULT,
                                  900, 600,
                                  NULL, create_menu_bar(), hInstance, NULL);
    if (!g_hwndMain) {
        OleUninitialize();
        return 1;
    }

    ShowWindow(g_hwndMain, nCmdShow ? nCmdShow : SW_SHOWDEFAULT);
    UpdateWindow(g_hwndMain);

    /* Message loop */
    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    /* Drain any leftover sign job messages */
    if (g_signing) {
        MSG dummy;
        while (PeekMessageW(&dummy, NULL, WM_GUI_UPDATE_ROW, WM_GUI_SIGN_DONE, PM_REMOVE));
    }

    OleUninitialize();
    return (int)msg.wParam;
}
