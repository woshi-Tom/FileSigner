#include <windows.h>
#include <stdio.h>

/* Required for OpenSSL DLL on Windows — provides OPENSSL_Applink */
#include <openssl/applink.c>

extern int cli_main(int argc, char *argv[]);

#ifdef HAVE_SCITER
extern int gui_main(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                    LPSTR lpCmdLine, int nCmdShow);
#endif

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow)
{
    /* If command-line arguments are present (beyond exe name), run CLI.
       Attach to the parent console so stdout/stderr output is visible. */
    if (__argc > 1) {
        AttachConsole(ATTACH_PARENT_PROCESS);
        freopen("CONOUT$", "w", stdout);
        freopen("CONOUT$", "w", stderr);
        freopen("CONIN$", "r", stdin);
        return cli_main(__argc, __argv);
    }

#ifdef HAVE_SCITER
    /* Double-click launch — run GUI */
    return gui_main(hInstance, hPrevInstance, lpCmdLine, nCmdShow);
#else
    (void)hInstance; (void)hPrevInstance; (void)lpCmdLine; (void)nCmdShow;
    MessageBoxA(NULL, "Sciter SDK not found.\n\n"
                "Download it and set SCITER_SDK_DIR, or run from command line.\n"
                "https://github.com/c-smile/sciter-sdk",
                "FileSigner", MB_ICONINFORMATION);
    return 1;
#endif
}
