
try 
{ 
    if ($PSBoundParameters.ContainsKey('MediantConfigFile')) 
    {
        $MediantConfigINI = get-content (get-item -path $MediantConfigINI).fullname
    }    
    if ($PSBoundParameters.ContainsKey('MediantDevice')) 
    {
        try { import-module -name Mediant -ErrorAction Stop } catch { Write-Warning "Mediant Module not installed, to install ->  install-module -name mediant -scope currentuser - disabling mediant functions" }
        $mediantdevice = Get-MediantDevice -Mediant $MediantDevice -http $MediantDeviceProtocol -Credential $MediantDeviceCredential
        $MediantConfigini = (Get-MediantDeviceFileIni -MediantDevice $mediantdevice) -split '\n'
        Remove-Variable -name mediantdevice -ErrorAction SilentlyContinue
    }
    
    if (!($MediantConfigini))  
    { 
        $title = $NULL 
        $message = $NULL 
        $Open = New-Object System.Management.Automation.Host.ChoiceDescription "&Open Existing File", "Open Existing config.ini file"
        $Download = New-Object System.Management.Automation.Host.ChoiceDescription "&Download a Sample Config", "Download a Sample Config from shanehoey.com"
        $Connect = New-Object System.Management.Automation.Host.ChoiceDescription "&Connect to Mediant Device", "Download a Config directly from a Mediant device"
        if ($mediantimportfail)
        {
            $Options = [System.Management.Automation.Host.ChoiceDescription[]]($Open,$Download)
            remove-variable mediantimportfail
        }
        else 
        {
            $Options = [System.Management.Automation.Host.ChoiceDescription[]]($Open,$Download,$Connect)
        }
        switch ($host.ui.PromptForChoice($title, $message, $options, 0)) 
            {
                0   {  
                        write-host "Opening existing File" -foregroundcolor Yellow
                        Write-warning -Message "Due to a bug the open file dialog box may be behind other windows"
                        Add-Type -AssemblyName System.Windows.Forms
                        $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
                        $OpenFileDialog.initialDirectory = [Environment]::GetFolderPath('MyDocuments')
                        $OpenFileDialog.filter = 'config.ini (*.ini)|*.ini'
                        $OpenFileDialog.title = 'Select MediantConfig.ini to import'
                        $result = $OpenFileDialog.ShowDialog((New-Object System.Windows.Forms.Form -Property @{TopMost = $true }))
                        if ($result -eq [Windows.Forms.DialogResult]::OK) 
                        {
                            $MediantConfigini = get-content -path $OpenFileDialog.filename
                        }
                        else 
                        {
                            Write-Verbose "No file selected" -VERBOSE
                            throw "No File Selected"
                        } 
                        Remove-Variable -Name OpenFileDialog  -ErrorAction SilentlyContinue
                        Remove-Variable -name result  -ErrorAction SilentlyContinue
                    }
                    1   {  
                        write-host "Downloading Mediantconfig.ini from shanehoey.com/mediantconfig.ini" -foregroundcolor Yellow
                        $MediantConfigini = (invoke-WebRequest -uri "https://shanehoey.com/mediantconfig.ini" -ContentType "text/plain").content -split '\n'
                        Write-host "Dowloading Complete"
                    }
                    2   {  
                        write-host "Connecting to Mediant Device" -foregroundcolor Yellow
                        try { import-module -name Mediant -ErrorAction Stop } catch { Write-Warning "Mediant PowerShell Module not installed, Please manually download a config file or install Mediant PowerShell module (install-module -name mediant -scope currentuser) before continiung ...exiting" }        
                        $MediantConfigini = (Get-MediantDeviceFileIni -MediantDevice (Get-MediantDevice)) -split '\n'
                        Write-verbose -Message "Downloading mediantconfig.ini Complete" 
                    }
            }
        Remove-Variable -name title,message,open,download,connect -ErrorAction SilentlyContinue
    }

    $ini = convertfrom-MediantDocConfigIni -MediantConfigini ($MediantConfigini).replace("[ ","[").replace(" ]","]")
    remove-item MediantConfigini -ErrorAction SilentlyContinue
}
catch 
{
    Write-warning "Sorry unable to get mediant config.ini file, please try again"
    Break
}