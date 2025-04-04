
# """ This code is written by havox
# # Copyrights(2024)@ Under MIT LICENSE
#  Author = Havox """

# Certificate location
$certlocation = "certificate.p12"

# get the certificate from the location to install on store
$certcommand = Get-PfxCertificate -FilePath $certlocation
Import-pfxCertificate -FilePath $certlocation -CertStoreLocation Cert:\CurrentUser\Root -Exportable
Write-Output " <<<< Certificate intillized on the intermidiate location >>>>"

$thumprint = $certcommand.Thumbprint

function Move-certificatetotrusted {
    param (
        [string]$storelocation,
        [string]$thumprint
    )
    $intermidiatestore = New-Object system.security.cryptography.X509Certificates.X509Store("CA", $storeLocation)
    $intermidiatestore.open("ReadWrite")

    # to find the certification by thumprint
    $cert = $intermidiatestore.certificates | Where-Object { $_.Thumbprint -eq $thumprint} 

    # move to trusted from intermidiate path
    if ($cert){
        $trustedrootstore = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", $storeLocation)
        $trustedrootstore.open("Readwrite")
        $trustedrootstore.Add($cert)
        $trustedrootstore.close()
        $intermidiatestore.remove($cert)
        Write-Output " <<<< Certificate installed sucessfully on the trusted sucessfully >>>> "
    }
    else{
        Write-Output " !!!! Certification not found !!!! "
    }
    $intermidiatestore.close()
}

Move-certificatetotrusted -storelocation "CurrentUser" -thumprint $thumprint
