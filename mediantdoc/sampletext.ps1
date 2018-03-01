
try {

    if ($PSBoundParameters.ContainsKey('DownloadSampleDesignText')) {
        $MediantDocText = ((invoke-WebRequest -uri "https://shanehoey.com/mediantdoc.json" -ContentType "text/plain").content -split '\n') | convertfrom-json
    }
    else {
        write-host "Download Sample Design Text ?" -foregroundcolor Yellow
        switch (($host.ui.PromptForChoice("", "Do you want to use the online Design Template  ??`nIMPORTANT: the current online template may only have placeholder text, as text is getting added after script is published", [System.Management.Automation.Host.ChoiceDescription[]]((New-Object System.Management.Automation.Host.ChoiceDescription "&No"), (New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Download a standard design text example")), 1))) {
            1 {  
                Write-verbose -Message "Downloading design document from shanehoey.com/mediantdoc.json" -Verbose
                $MediantDocText = ((invoke-WebRequest -uri "https://shanehoey.com/mediantdoc.json" -ContentType "text/plain").content -split '\n') | convertfrom-json
                Write-verbose -Message "Downloading MediantDoc.json Complete" -Verbose
            }
        }
    }
} 
catch {
    write-warning "Unable to download cloudconnector design template, Defaulting to no design text"
    Remove-Variable MediantDocText -ErrorAction SilentlyContinue
}
