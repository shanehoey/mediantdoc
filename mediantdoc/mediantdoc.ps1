
<#PSScriptInfo

.VERSION 0.0.1

.GUID 3f2891e3-e02e-4b8c-ae49-3dcf2a2335b3

.AUTHOR Shane Hoey

.COMPANYNAME 

.COPYRIGHT 2018 Shane Hoey

.TAGS Mediant

.LICENSEURI https://shanehoey.github.io/mediantdoc/license

.PROJECTURI https://shanehoey.github.io/mediantdoc

.ICONURI 

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS 

.EXTERNALSCRIPTDEPENDENCIES 

.RELEASENOTES
https://shanehoey.github.io/mediantdoc

#> 

#Requires -Module WordDoc




<# 

.DESCRIPTION 
Create an As-Built Document for an AudioCodes Mediant Gateway

#> 
<#
MIT License

Copyright (c) 2016-2018 Shane Hoey

Permission is hereby granted, free of charge, to any person obtaining a copy 
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

#>
[cmdletbinding(DefaultParameterSetName = "Default")]
Param(  

    [ValidateNotNullOrEmpty()]
    [ValidateScript( {(Test-Path $_) -and ((Get-Item $_).Extension -eq ".ini")})]  
    [Parameter(ValueFromPipeline = $false, Mandatory = $false, ParameterSetName = "MediantConfigFile")]
    [string]$MediantConfigFile,

    [ValidateNotNullOrEmpty()]
    [Parameter(ValueFromPipeline = $false, Mandatory = $false, ParameterSetName = "MediantDevice")]
    [string]$MediantDevice,

    [ValidateNotNullOrEmpty()]
    [Parameter(ValueFromPipeline = $false, Mandatory = $false, ParameterSetName = "MediantDevice")]
    $MediantDeviceCredential,

    [ValidateNotNullOrEmpty()]
    [ValidateSet("HTTP", "HTTPS")]
    [Parameter(ValueFromPipeline = $false, Mandatory = $false, ParameterSetName = "MediantDevice")]
    [string]$MediantDeviceProtocol = "HTTP",

    [ValidateNotNullOrEmpty()]  
    [ValidateScript( {(Test-Path $_) -and ((Get-Item $_).Extension -like ".do*x")})]  
    [Parameter(ValueFromPipeline = $false, Mandatory = $false, ParameterSetName = "MediantConfigFile")]
    [Parameter(ValueFromPipeline = $false, Mandatory = $false, ParameterSetName = "MediantDevice")]
    [Parameter(ValueFromPipeline = $false, Mandatory = $false, ParameterSetName = "Default")]
    [string]$WordTemplate,  
    
    [ValidateNotNullOrEmpty()]  
    [ValidateScript( {(Test-Path $_) -and ((Get-Item $_).Extension -like ".json")})]  
    [Parameter(ValueFromPipeline = $false, Mandatory = $false, ParameterSetName = "MediantConfigFile")]
    [Parameter(ValueFromPipeline = $false, Mandatory = $false, ParameterSetName = "MediantDevice")]
    [Parameter(ValueFromPipeline = $false, Mandatory = $false, ParameterSetName = "Default")]
    [string]$DesignJson,

    [Parameter(ValueFromPipeline = $false, Mandatory = $false, ParameterSetName = "MediantConfigFile")]
    [Parameter(ValueFromPipeline = $false, Mandatory = $false, ParameterSetName = "MediantDevice")]
    [Parameter(ValueFromPipeline = $false, Mandatory = $false, ParameterSetName = "Default")]
    [switch]$DownloadSampleDesignText,

    [Parameter( Mandatory = $false, ParameterSetName = "MediantConfigFile")]
    [Parameter( Mandatory = $false, ParameterSetName = "MediantDevice")]
    [Parameter( Mandatory = $false, ParameterSetName = "Default")]
    [bool]$notifyupdates = $true

)

try { import-module -name WordDoc -ErrorAction Stop } catch { Write-Warning "WordDoc Module is required , to install ->  install-module -name worddoc -scope currentuser"; break }
try { import-module -name Mediant -ErrorAction Stop } catch { Write-Warning "Mediant Module is Optional, to install ->  install-module -name mediant -scope currentuser`n" ; $mediantimportfail = $true }

$section = @{}
$section["CoverPage"] = $true
$section["MediantOverview"] = $true
$section["IPNetwork"] = $true
$section["SignalingMedia"] = $true
$section["Administration"] = $true
$section["Troubleshoot"] = $true
$section["Endpage"] = $true
$section["Appendix"] = $true
$section["Dev"] = $true # this should only be  true when developing the script as it adds sections not yet completed

. .\classes.ps1
. .\functions.ps1
. .\parameter_default.ps1
. .\parameter_index.ps1
. .\wordtemplate.ps1
. .\sampletext.ps1
. .\versionControl.ps1
. .\ConfigINI.ps1
. .\pscustomobject.ps1
. .\worddocument.ps1
