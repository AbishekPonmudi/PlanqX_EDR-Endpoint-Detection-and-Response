param (
    [string]$CertPath
)

Write-Host "Received CertPath: $CertPath" -ForegroundColor Cyan

try {
    if (-not $CertPath) {
        Write-Host "Certificate path not provided" -ForegroundColor Red
        exit 1
    }

    if (Test-Path $CertPath) {
        $certCommand = Get-PfxCertificate -FilePath $CertPath
        Import-PfxCertificate -FilePath $CertPath -CertStoreLocation Cert:\CurrentUser\Root -Exportable
        Write-Host "Certificate initialized in intermediate location" -ForegroundColor Green
        
        $thumbprint = $certCommand.Thumbprint
        
        $intermediateStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("CA", "CurrentUser")
        $intermediateStore.Open("ReadWrite")
        
        $cert = $intermediateStore.Certificates | Where-Object { $_.Thumbprint -eq $thumbprint }
        
        if ($cert) {
            $trustedRootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "CurrentUser")
            $trustedRootStore.Open("ReadWrite")
            $trustedRootStore.Add($cert)
            $trustedRootStore.Close()
            $intermediateStore.Remove($cert)
            Write-Host "Certificate successfully moved to trusted store" -ForegroundColor Green
        } else {
            Write-Host "Certificate not found in intermediate store" -ForegroundColor Yellow
        }
        
        $intermediateStore.Close()
    } else {
        Write-Host "Certificate file not found at: $CertPath" -ForegroundColor Yellow
    }
} catch {
    Write-Host "Error installing certificate: $_" -ForegroundColor Red
}