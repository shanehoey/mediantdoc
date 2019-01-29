### mediantDoc
Document an AudioCodes Mediant Gateway/SBC directly from powershell

## THIS IS AN EARLY PREVIEW

The latest release is hosted on PowerShell Gallery https://www.powershellgallery.com/packages/WordDoc/

Distributed under MIT License
https://www.github.com/worddoc/license.md

Distributed under the MIT License
This project is distrubuted undet the MIT License. The license can be viewed here

Project Notes
This Project contains Powershell sample scripts that can be reused / adapted. Please do not just execute scripts without understanding what each and every line will do.


# CCE Design Doc Script

Quickly and effortless create a Skype for Business Cloud Connector Eddition (CCE) Design Document or As Built Document using cloudconnector.ini and Powershell.

## Hightlights include:
 * Generate a full Design or As Built document from the cloudconnectpr.ini file
 * Full List of Servers Created
 * Firewall Requirements
 * Certificate Requirements

## Easy Installation via PowerShell Gallery
``` powershell
install-module worddoc -scope currentuser
install-module mediant -scope currentuser
install-script mediantdoc -scope currentuser
```

## Easy Updates via PowerShell Gallery
``` powershell
update-module worddoc -scope currentuser
update-module mediant -scope currentuser
update-script mediantdoc -scope currentuser
```

## Example
.\mediantdoc.ps1
