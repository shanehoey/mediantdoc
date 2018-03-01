
#region Version Control & 14 Day usage stats
# Please do not remove this section,
# It is only used for version Control and unique users via github 
# I only see number of unique users over 14 days period, 
# Collecting the stats gives me an indication how often this script is used to determine if I should continue developing it, or concentrate on other projects
# If you want to silence the notice set notify to $false rather than deleting the section
# thank in advance

$thisversion = "daf55f23-1547-4923-9953-a50f5c8d7316"
try 
{
    $Version = (Invoke-WebRequest -Uri https://shanehoey.com/versions/mediantdoc/ -UserAgent cceDesignDoc -Method Get -DisableKeepAlive -TimeoutSec 2).content | convertfrom-json
    if (($thisversion -ne $version.release) -and ($thisversion -ne $version.dev)) {
        Write-Verbose -message "mediantDoc has been updated" -Verbose
    
        if ($notifyupdates) { 
            Write-Host -object "**********************`nmediantDoc has been Updated`n**********************`nMore details available at $($version.link)"
            start-sleep -Seconds 5 
        }
    }
}
catch 
{
Write-Warning "unable to check for updates"
}

#endregion
