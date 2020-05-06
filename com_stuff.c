
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
#include <ShlObj.h>
#include <Shlwapi.h>

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

    HRESULT hr = CoInitialize( NULL );

    // create an instance of ShellWindows, assigned to psw
    IShellWindows *psw;
    hr = CoCreateInstance( &CLSID_ShellWindows, NULL, CLSCTX_LOCAL_SERVER, &IID_IShellWindows, &psw );
    if ( SUCCEEDED( hr ) )
    {
        HWND hwnd;
        IDispatch *pdisp;
        VARIANT vEmpty = {0};

        // use shellwindows to get a handle to the desktop for use with idispatch
        // https://docs.microsoft.com/en-us/windows/win32/api/exdisp/nf-exdisp-ishellwindows-findwindowsw
        if ( S_OK == psw->lpVtbl->FindWindowSW( psw, &vEmpty, &vEmpty, SWC_DESKTOP, (long *)&hwnd, SWFO_NEEDDISPATCH, &pdisp ) )
        {
            IShellBrowser *psb;

            // use idispatch to go back to the parent (toplevelbrowser?)
            // https://docs.microsoft.com/en-us/windows/win32/api/shlwapi/nf-shlwapi-iunknown_queryservice
            hr = IUnknown_QueryService( (IUnknown*)pdisp, &SID_STopLevelBrowser, &IID_IShellBrowser, &psb );
            if ( SUCCEEDED( hr ) )
            {
                // get current shellview, whatever that is...
                // https://docs.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-ishellbrowser-queryactiveshellview
                IShellView *psv;
                hr = psb->lpVtbl->QueryActiveShellView( psb, &psv );

                // use shellview to get itemobject
                // https://docs.microsoft.com/en-us/windows/win32/api/shobjidl_core/nn-shobjidl_core-ishellview
                // https://docs.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-ishellview-getitemobject
                IDispatch *pdispBackground;
                HRESULT hr = psv->lpVtbl->GetItemObject( psv, SVGIO_BACKGROUND, &IID_IDispatch, &pdispBackground );
                if ( SUCCEEDED( hr ) )
                {
                    IShellFolderViewDual *psfvd;
                    hr = pdispBackground->lpVtbl->QueryInterface( pdispBackground, &IID_IShellFolderViewDual, &psfvd );
                    if ( SUCCEEDED( hr ) )
                    {
                        // https://docs.microsoft.com/en-us/windows/win32/api/shldisp/nf-shldisp-ishellfolderviewdual-get_application
                        IDispatch *pdisp;
                        hr = psfvd->lpVtbl->get_Application( psfvd, &pdisp );
                        if ( SUCCEEDED( hr ) )
                        {
                            // https://docs.microsoft.com/en-us/windows/win32/shell/ishelldispatch2-object
                            IShellDispatch2 *psd;
                            BSTR bProcessName = SysAllocString( L"notepad.exe" );
                            BSTR bOperation = SysAllocString( L"open" );

                            VARIANT varOperation;
                            varOperation.vt = VT_BSTR;
                            varOperation.bstrVal = bOperation;

                            hr = pdisp->lpVtbl->QueryInterface( pdisp, &IID_IShellDispatch2, &psd );
                            hr = psd->lpVtbl->ShellExecute( psd, bProcessName, vEmpty, vEmpty, varOperation, vEmpty );

                            SysFreeString( bProcessName );
                            SysFreeString( bOperation );
                        }
                    }
                }
            }
        }
    }
}
