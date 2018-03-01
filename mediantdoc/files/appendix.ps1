

if($section.Appendix) 
{ 
    Add-WordBreak -breaktype NewPage
    Add-WordBreak -breaktype Paragraph
    Add-WordText 'APPENDIX A - Config.ini' -WDBuiltinStyle wdStyleTitle
    $wd = (Get-WordDocument)
    $wd.Application.Selection.Font.size = '9'
    $wd.Application.Selection.Font.name = 'Courier New'
    switch -regex ($MediantConfigini) 
    {
      '^((;.*)|(\[.+\])|(.+?\s*=.*))$'  
      {
        Write-Verbose "$_"
        $wd.Application.Selection.TypeText("$($_)`n") 
      } 
      default 
      {
        Write-Verbose "Ignore -> $_"
      }
    }
    Remove-Variable -Name wd
}
