
if ($PSBoundParameters.ContainsKey('WordTemplate')) {
    $TemplateFile = (get-item -path $WordTemplate).fullname
}    
else { 
    write-host "Load Word Template ?" -foregroundcolor Yellow
    switch (($host.ui.PromptForChoice("", "Do you want to use an existing word Document as a Template ??", [System.Management.Automation.Host.ChoiceDescription[]]((New-Object System.Management.Automation.Host.ChoiceDescription "&Yes"), (New-Object System.Management.Automation.Host.ChoiceDescription "&No")), 1))) {
        0 {  
            Write-warning -Message "Due to a bug the open file dialog box may be behind other windows"
            Add-Type -AssemblyName System.Windows.Forms
            $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
            $OpenFileDialog.initialDirectory = [Environment]::GetFolderPath('MyDocuments')
            $OpenFileDialog.filter = 'Word Document (*.docx)|*.docx|Word Template (*.dotx)|*.dotx'
            $OpenFileDialog.title = 'Select Word Template to import'
            $result = $OpenFileDialog.ShowDialog((New-Object System.Windows.Forms.Form -Property @{TopMost = $true }))
            if ($result -eq [Windows.Forms.DialogResult]::OK) {
                $TemplateFile = $OpenFileDialog.filename
            }
            else {
                Write-Verbose "No file selected" -VERBOSE
            } 
            Remove-Variable -Name OpenFileDialog  -ErrorAction SilentlyContinue
            Remove-Variable -name result  -ErrorAction SilentlyContinue

        }
    }
}