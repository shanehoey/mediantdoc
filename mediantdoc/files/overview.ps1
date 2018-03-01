
if($section.MediantOverview) { 
    $heading = 'Mediant Overview'
    $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
    Add-mediantDocParagraph -heading $heading -headingtype 1 -text $text  -NewPage 

    $heading = 'Device Details'
    $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
    Add-mediantDocParagraph -heading $heading -headingtype 2 -NewPage -text $text
    Add-WordTable -Object $Mediant.viewDoc() @GridTableBlack -VerticleTable -FirstColumn $False -HeaderRow $False

    $heading = "Key Features"
    Add-mediantDocParagraph -heading $heading -headingtype 2 -text ($Mediant.viewKeyfeatures().where({$_ -notmatch "^$"}) | Out-String) 
    #TODO FIX 
    #Add-WordTable -Object $Mediant.viewKeyfeatures()  @GridTable -VerticleTable -FirstColumn $False  -HeaderRow $False 
}
