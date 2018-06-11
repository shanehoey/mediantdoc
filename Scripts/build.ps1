exit

set-location $env:USERPROFILE\github\mediantdoc

$NuGetApiKey
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert
$cert | format-table subject,issuer

$version = "0.0.3"

Update-ScriptFileInfo -Path ".\mediantDoc\mediantDoc.ps1" -Version $version -Author "Shane Hoey" -Copyright "2018 Shane Hoey" `
                        -RequiredModules WordDoc  -ProjectUri https://shanehoey.github.io/mediantdoc -ReleaseNotes https://shanehoey.github.io/mediantdoc `
                        -LicenseUri https://shanehoey.github.io/mediantdoc/license -Tags "Mediant" -Description "Create an As-Built Document for an AudioCodes Mediant Gateway"

Import-Module -name PowerShellProTools
$script =  ".\mediantDoc\mediantDoc.ps1"
$bundle =  ".\release\mediantDoc_v$($version.replace(".","_"))\"

Merge-Script -Script $script -OutputPath $bundle -Bundle

copy .\license $bundle

Set-AuthenticodeSignature -filepath "$($bundle)mediantDoc.ps1" -Certificate $cert
(Get-AuthenticodeSignature -FilePath "$($bundle)mediantDoc.ps1").Status

set-location $bundle

.\mediantDoc.ps1
. .\mediantdoc.ps1 -MediantDevice "172.30.30.30" -mediantDeviceCredential (get-credential -username "Admin" -message "Password for Admin") 
### IMPORTANT ONLY RUN AFTER ALL ABOVE IS COMPLETED
pause
Publish-Script -path .\mediantdoc.ps1 -NuGetApiKey $NuGetApiKey