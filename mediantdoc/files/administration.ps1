

if($section.Administration) 
{ 
    if($section.dev) { 
    #Administration
    $heading = 'Administration'
    $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
    Add-mediantDocParagraph -heading $heading -headingtype 1 -text $text -NewPage 
    
    #region Web & CLI 
    $heading = 'Web & CLI'
    $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
    Add-mediantDocParagraph -heading $heading -headingtype 2 -text $text -NewPage 

        #Local Users
        $heading = 'Local Users'
        $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
        Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 

        #Authentication Server
        $heading = 'Authentication Server'
        $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
        Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 

        #Web Settings
        $heading = 'Web Settings'
        $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
        Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 

        #CLI Settings
        $heading = 'CLI Settings'
        $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
        Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 

        #Access List
        $heading = 'Access List'
        $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
        Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 

    #endregion

    #region SNMP
    $heading = 'SNMP'
    $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
    Add-mediantDocParagraph -heading $heading -headingtype 2 -text $text -NewPage 

        #SNMP Community Settings
        $heading = 'SNMP Community Settings'
        $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
        Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 

        #SNMP Trap Destinations
        $heading = 'SNMP Trap Destinations'
        $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
        Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage        

        #SNMP Trusted Managers
        $heading = 'SNMP Trused Managers'
        $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
        Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage         

        #SNMP V3 Users
        $heading = 'SNMP V3 Users'
        $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
        Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage         

    #endregion
    }
}