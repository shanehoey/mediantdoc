
if($section.MediantOverview) { 
    $heading = 'Mediant Overview'
    $text = $MediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
    Add-mediantDocParagraph -heading $heading -headingtype 1 -text $text -NewPage 

    $heading = 'Device Details'
    $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
    Add-mediantDocParagraph -heading $heading -headingtype 2 -NewPage -text $text 
    Add-WordTable -Object $Mediant.viewDoc() @GridTableBlack -VerticleTable -FirstColumn $FALSE -HeaderRow $False

    $heading = "Key Features"
    Add-mediantDocParagraph -heading $heading -headingtype 2 -text ($Mediant.viewKeyfeatures().where({$_ -notmatch "^$"}) | Out-String) 
}