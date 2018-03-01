
if($section.Troubleshoot) { 
    if ($section.dev)  
    { 

    $heading = 'TroubleShoot'
    $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
    Add-mediantDocParagraph -heading $heading -headingtype 1 -text $text -NewPage 
    
        #region Logging
        $heading = 'Logging'
        $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
        Add-mediantDocParagraph -heading $heading -headingtype 2 -text $text -NewPage 
    
            #Syslog Settings
            $heading = 'Syslog Settings'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 

            #Settings
            $heading = 'Logging Settings'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 

            #Filters
            $heading = 'Logging Filters'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
    
        #endregion
    
        #region Call Detail Record
        $heading = 'Call Detail Record'
        $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
        Add-mediantDocParagraph -heading $heading -headingtype 2 -text $text -NewPage
    
            #Call Detail Record Settings
            $heading = 'Call Detail Record Settings'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
    
            #Test CDR Format
            $heading = 'Test CDR Format'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            
            #SBC CDR Format
            $heading = 'SBC CDR Format'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 

        #endregion
    
        #region Test Call
        $heading = 'Test Call'
        $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
        Add-mediantDocParagraph -heading $heading -headingtype 2 -text $text -NewPage 
                
            #Test Call Settings
            $heading = 'Test Call Settings'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
    
            #Test Call Rules
            $heading = 'Test Call Rules'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
    
        #endregion
    
        #region Debug
        $heading = 'Debug'
        $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
        Add-mediantDocParagraph -heading $heading -headingtype 2 -text $text -NewPage 
    
            #Debug Files
            $heading = 'Debug Files'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
    
        #endregion
    }

}
