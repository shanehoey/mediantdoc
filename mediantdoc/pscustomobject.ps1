
foreach ($item  in $ini.keys) {
    switch ($item)
    {
        { $item -eq "Mediant" } { Set-Variable -Name $item -Value ( ConvertFrom-MediantDocMediantParameter ) }
        { $ini[$item].ContainsKey("FORMAT $($item)_Index") } { Set-Variable -Name $item -Value ( ConvertFrom-MediantDocTable -item $item -itemindex (get-variable -name "itemindex_$($item)" -erroraction silentlycontinue -verbose ).value ) }
        Default { Set-Variable -Name $item -Value (ConvertFrom-MediantDocList -item $item -itemindex (get-variable -name "itemindex_$($item)" -erroraction silentlycontinue -verbose).value ) }
    }
}


if ($missingparameter) {
    Write-warning "*****************************" 
    Write-warning "Missing Parameters Found" 
    Write-warning "*****************************" 
    write-warning "Please help improve this script by logging an issue on github.com/shanehoey/mediantdoc for the above missing parameters"
    start-sleep -seconds 5

}