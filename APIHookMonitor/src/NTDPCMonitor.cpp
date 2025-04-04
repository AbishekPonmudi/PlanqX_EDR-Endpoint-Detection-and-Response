#include <Windows.h>
#include <iostream>
#include <comdef.h>
#include <Wbemidl.h>
#include <tlhelp32.h>


#pragma comment(lib, "wbemuuid.lib")

void KillProcessByName(const std::wstring& processName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnap, &pe32)) {
        do {
            if (!_wcsicmp(pe32.szExeFile, processName.c_str())) {
                HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
                if (hProcess) {
                    TerminateProcess(hProcess, 0);
                    CloseHandle(hProcess);
                    std::wcout << L"Malicious process terminated: " << processName << L" (PID: " << pe32.th32ProcessID << L")" << std::endl;
                }
            }
        } while (Process32Next(hSnap, &pe32));
    }

    CloseHandle(hSnap);
}

void MonitorProcesses() {
    HRESULT hres;

    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        std::cerr << "Failed to initialize COM library." << std::endl;
        return;
    }

    hres = CoInitializeSecurity(
        NULL, -1, NULL, NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_NONE, NULL);

    if (FAILED(hres)) {
        std::cerr << "Failed to initialize security." << std::endl;
        CoUninitialize();
        return;
    }

    IWbemLocator* pLoc = NULL;
    hres = CoCreateInstance(
        CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLoc);

    if (FAILED(hres)) {
        std::cerr << "Failed to create IWbemLocator object." << std::endl;
        CoUninitialize();
        return;
    }

    IWbemServices* pSvc = NULL;
    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),
        NULL, NULL, 0, NULL, 0, 0, &pSvc);

    if (FAILED(hres)) {
        std::cerr << "Could not connect to  EDR Server Panel." << std::endl;
        pLoc->Release();
        CoUninitialize();
        return;
    }

    std::cout << "Connected to EDR Server Panel. looking your computer " << std::endl;

    hres = CoSetProxyBlanket(
        pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE,
        NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_NONE);

    if (FAILED(hres)) {
        std::cerr << "Could not set proxy blanket." << std::endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return;
    }

    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecNotificationQuery(
        _bstr_t("WQL"),
        _bstr_t("SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL, &pEnumerator);

    if (FAILED(hres)) {
        std::cerr << "Query for process creation events failed." << std::endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return;
    }

    IWbemClassObject* pEventObj = NULL;
    ULONG retVal = 0;

    while (pEnumerator) {
        hres = pEnumerator->Next(WBEM_INFINITE, 1, &pEventObj, &retVal);
        if (FAILED(hres) || retVal == 0) {
            continue;
        }

        VARIANT var;
        hres = pEventObj->Get(L"TargetInstance", 0, &var, 0, 0);
        if (SUCCEEDED(hres) && var.vt == VT_UNKNOWN) {
            IUnknown* pUnk = V_UNKNOWN(&var);
            IWbemClassObject* pProcObj = NULL;
            pUnk->QueryInterface(IID_IWbemClassObject, (void**)&pProcObj);

            if (pProcObj) {
                VARIANT varProcName;
                hres = pProcObj->Get(L"Name", 0, &varProcName, 0, 0);
                if (SUCCEEDED(hres) && varProcName.vt == VT_BSTR) {
                    std::wstring processName = varProcName.bstrVal;
                    std::wcout << L"Process Created: " << processName << std::endl;

                    if (processName == L"calc.exe" || processName == L"malicious.exe" || L"CalculatorApp.exe") {
                        MessageBox(NULL, L"Malicious activity detected! Process will be terminated.", L"EDR Alert", MB_OK | MB_ICONERROR);
                        KillProcessByName(processName);
                    }
                }
                VariantClear(&varProcName);
                pProcObj->Release();
            }
            pUnk->Release();
        }
        VariantClear(&var);
        pEventObj->Release();
    }

    // Cleanup
    pSvc->Release();
    pLoc->Release();
    pEnumerator->Release();
    CoUninitialize();
}

int main() {
    std::cout << "EDR Process Monitoring Started..." << std::endl;
    MonitorProcesses();
    return 0;
}