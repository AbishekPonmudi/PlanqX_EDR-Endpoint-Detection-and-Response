
#include "ApiOperation.h"


std::string API_OP(const std::string& Filehash) {
    std::string response;
    HINTERNET hSession = WinHttpOpen(L"WinHTTP PlanqX/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,

        WINHTTP_NO_PROXY_BYPASS, 0);

    if (!hSession) {
        std::cerr << "Failed to open WinHTTP session: " << GetLastError() << std::endl;
        return "";
    }

    HINTERNET hConnect = WinHttpConnect(hSession, L"mb-api.abuse.ch", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        std::cerr << "Failed to connect to server: Forwarder Connection Error ! " << GetLastError() << std::endl;
        WinHttpCloseHandle(hSession);
        return "";
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/api/v1/", NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);

    if (!hRequest) {
        std::cerr << "Failed to open HTTP request: " << GetLastError() << std::endl;
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }
    // QUERY TO ANALYSE THE MALWARE FROM MALAPI DATABASE -> ONLINE || ALSO APPLICABLE WITH LOCAL DB USING API - HASH
    const wchar_t* headers = L"Content-Type: application/x-www-form-urlencoded\r\n"
        L"Auth-Key:eca393be6faa22f08882c3cc5a9b1702ce1f1b8727165bd6";
    std::string postData = "query=get_info&hash=" + Filehash;

    BOOL result = WinHttpSendRequest(hRequest,
        headers, -1L,
        (LPVOID)postData.c_str(),
        (DWORD)postData.size(),
        (DWORD)postData.size(), 0);

    if (!result) {
        std::cerr << "Failed to send request: " << GetLastError() << std::endl;
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }

    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        std::cerr << "Failed to receive response: " << GetLastError() << std::endl;
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }

    DWORD dwSize = 0;
    DWORD bytesRead = 0;
    do {
        if (WinHttpQueryDataAvailable(hRequest, &dwSize) && dwSize > 0) {
            char* buffer = new char[dwSize + 1];
            ZeroMemory(buffer, dwSize + 1);
            if (WinHttpReadData(hRequest, buffer, dwSize, &bytesRead)) {
                response.append(buffer, bytesRead);
            }
            else {
                std::cerr << "Failed to read data: " << GetLastError() << std::endl;
            }
            delete[] buffer;
        }
    } while (dwSize > 0);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return response;
}
