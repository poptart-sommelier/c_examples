/*
https://docs.microsoft.com/en-us/windows/win32/learnwin32/creating-an-object-in-com
http://brandonlive.com/2008/04/27/getting-the-shell-to-run-an-application-for-you-part-2-how/
https://docs.microsoft.com/en-us/windows/win32/api/exdisp/nn-exdisp-ishellwindows
https://github.com/JohanKlos/shorthand3/blob/master/inc/ShellRun.ahk
https://stackoverflow.com/questions/24489936/using-ishelldispatch2-shellexecute-for-launching-a-non-elevated-process-from-an
*** BELOW EXAMPLE IS BASIS FOR THE CODE
https://github.com/microsoft/Windows-classic-samples/blob/master/Samples/Win7Samples/winui/shell/appplatform/ExecInExplorer/ExecInExplorer.cpp
https://docs.microsoft.com/en-us/cpp/cpp/convertstringtobstr?view=vs-2019
*/

/*

Uses shellwindows to launch a process, with explorer.exe as the proxy

*/

// i definitely don't need all this stuff, but it was added slowly as i fell down a rabbit hole, and now i don't feel like removing it
#include <windows.h>
#include <shellapi.h>
#include <tchar.h>
#include <combaseapi.h>
#include <stdio.h>
#include "exdisp.h"
#include "stdbool.h"
#include <ShlDisp.h>
#include <ShObjIdl_core.h>
#include <Shlwapi.h>
#include <ShlObj.h>
#include <comutil.h>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "comsuppw.lib")

int main()
{
    // Simple example, only needs shellapi.h and combaseapi.h as imports (maybe not even that)
    // ShellExecute(NULL, _T("open"), _T("c:\\windows\\system32\\notepad.exe"), NULL, NULL, SW_RESTORE);

    /*
    We can do this if we only know the CLSID, and not the name of the COM object (for example, ShellWindows)

    LPCLSID clsidShellWindows;
    LPCOLESTR clsidString = L"{9BA05972-F6A8-11CF-A442-00A0C90A8F39}";
    HRESULT hr;

    hr = CLSIDFromString(clsidString, &clsidShellWindows);
    */

    HRESULT hr = CoInitialize(NULL);

    // create an instance of ShellWindows, assigned to psw
    IShellWindows* psw;
    hr = CoCreateInstance(CLSID_ShellWindows, NULL, CLSCTX_LOCAL_SERVER, IID_PPV_ARGS(&psw));
    if (SUCCEEDED(hr)) {
        HWND hwnd;
        IDispatch* pdisp;
        VARIANT vEmpty = {};

        // use shellwindows to get a handle to the desktop for use with idispatch
        // https://docs.microsoft.com/en-us/windows/win32/api/exdisp/nf-exdisp-ishellwindows-findwindowsw
        if (S_OK == psw->FindWindowSW(&vEmpty, &vEmpty, SWC_DESKTOP, (long*)&hwnd, SWFO_NEEDDISPATCH, &pdisp)) {
            IShellBrowser* psb;

            // use idispatch to go back to the parent (toplevelbrowser?)
            // https://docs.microsoft.com/en-us/windows/win32/api/shlwapi/nf-shlwapi-iunknown_queryservice
            hr = IUnknown_QueryService(pdisp, SID_STopLevelBrowser, IID_PPV_ARGS(&psb));
            if (SUCCEEDED(hr))
            {
                // get current shellview, whatever that is...
                // https://docs.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-ishellbrowser-queryactiveshellview
                IShellView* psv;
                hr = psb->QueryActiveShellView(&psv);

                // use shellview to get itemobject
                // https://docs.microsoft.com/en-us/windows/win32/api/shobjidl_core/nn-shobjidl_core-ishellview
                // https://docs.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-ishellview-getitemobject
                IDispatch* pdispBackground;
                HRESULT hr = psv->GetItemObject(SVGIO_BACKGROUND, IID_PPV_ARGS(&pdispBackground));
                if (SUCCEEDED(hr))
                {
                    IShellFolderViewDual* psfvd;
                    hr = pdispBackground->QueryInterface(IID_PPV_ARGS(&psfvd));
                    if (SUCCEEDED(hr))
                    {
                        // https://docs.microsoft.com/en-us/windows/win32/api/shldisp/nf-shldisp-ishellfolderviewdual-get_application
                        IDispatch* pdisp;
                        hr = psfvd->get_Application(&pdisp);
                        if (SUCCEEDED(hr))
                        {
                            // https://docs.microsoft.com/en-us/windows/win32/shell/ishelldispatch2-object
                            IShellDispatch2* psd;
                            char pProcessName[] = "notepad.exe";
                            BSTR bstrProcessName = _com_util::ConvertStringToBSTR(pProcessName);
                            
                            _bstr_t bstrOperation("open");
                            VARIANT varOperation;
                            varOperation.vt = VT_BSTR;
                            varOperation.bstrVal = bstrOperation;

                            hr = pdisp->QueryInterface(IID_PPV_ARGS(&psd));
                            hr = psd->ShellExecuteW(bstrProcessName, vEmpty, vEmpty, varOperation, vEmpty);
                        }
                    }
                }
            }
        }
    }
}
