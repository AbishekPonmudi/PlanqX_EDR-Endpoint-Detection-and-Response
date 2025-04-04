
$certlocation = "certificate.p12"

# get the certificate from the location to install on store
$certcommand = Get-PfxCertificate -FilePath $certlocation
Import-pfxCertificate -FilePath $certlocation -CertStoreLocation Cert:\CurrentUser\Root -Exportable
Write-Output " <<<< Certificate intillized on the intermidiate location >>>>"