

#region Signaling & Media
if($section.SignalingMedia) { 
    $heading = 'Signaling & Media'
    $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
    Add-mediantDocParagraph -heading $heading -headingtype 1 -text $text -NewPage 
    
        #region Core Entities
        $heading = 'Core Entities'
        $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
        Add-mediantDocParagraph -heading $heading -headingtype 2 -text $text -NewPage 
            
            #region Applications Enabling
            $heading = 'Applications Enabling'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            add-wordtable -Object $SIPParams.viewApplicationsEnabling_General() @GridTableBlack -VerticleTable -HeaderRow $false
            #endregion 
    
            #region SRDs
            $heading = 'SRDs'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage
            if ($SRD) 
            { 
              add-wordtable -Object $SRD.viewOverview() @GridTableBlack
              foreach ($item in $SRD) {
                add-wordtable -Object $item.viewGeneral() @GridTableGrey -VerticleTable
                add-wordtable -Object $item.viewRegistration() @GridTableBlack -VerticleTable -HeaderRow $false
              }
            }
            else
            {
              Add-WordText -text 'SRD not configured' -WDBuiltinStyle wdStyleBlockQuotation
            }
            #endregion 
    
            #region SIP Interfaces
            $heading = 'SIP Interfaces'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            if ($SIPInterface) 
            { 
              add-wordtable -Object $SIPInterface.viewOverview() @GridTableBlack 
              foreach ($item in $SIPInterface) 
              {
                add-wordtable -Object $item.viewGeneral() @GridTableGrey -VerticleTable
                add-wordtable -Object $item.viewClassification() @GridTableGrey -VerticleTable -HeaderRow $false
                add-wordtable -Object $item.viewMedia() @GridTableGrey -VerticleTable -HeaderRow $false
                add-wordtable -Object $item.viewSecurity() @GridTableGrey -VerticleTable -HeaderRow $false
              }
            }
            else
            {
              Add-WordText -text 'SIP Interfaces not configured' -WDBuiltinStyle wdStyleBlockQuotation
            }
            #endregion 
    
            #region Media Realms
            $heading = 'Media Realms'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            if ($cpMediarealm) 
            { 
              add-wordtable -Object $cpMediarealm.viewOverview() @GridTableBlack -VerticleTable
              foreach ($item in $cpMediarealm) 
              {
                add-wordtable -Object $item.viewGeneral() @GridTableGrey -VerticleTable
                add-wordtable -Object $item.viewQualityofExperience() @GridTableGrey -VerticleTable -HeaderRow $false
              }
            }
            else
            {
              Add-WordText -text 'Media Realms not configured' -WDBuiltinStyle wdStyleBlockQuotation
            }
            if ($RemoteMediaSubnet) 
            {
            add-wordtable -Object $RemoteMediaSubnet.viewOverview() @GridTableBlack -VerticleTable
            }
            if ($MediaRealmExtension) 
            {
            add-wordtable -Object $MediaRealmExtension.viewOverview() @GridTableBlack -VerticleTable
            }
            #endregion 
    
            #region Proxy Sets
            $heading = 'Proxy Sets'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            
            if ($ProxySet) 
            { 
              add-wordtable -Object $ProxySet.viewOverview() @GridTableBlack 
              foreach ($item in $ProxySet) 
              {
                add-wordtable -Object $ProxySet.viewGeneral() @GridTableGrey -VerticleTable
                add-wordtable -Object $ProxySet.viewKeepAlive() @GridTableGrey -VerticleTable -HeaderRow $false
                add-wordtable -Object $ProxySet.viewRedundancy() @GridTableGrey -VerticleTable -HeaderRow $false
                add-wordtable -Object $ProxySet.viewAdvanced() @GridTableGrey -VerticleTable -HeaderRow $false
               }
            }
            else
            {
              Add-WordText -text 'Proxy Sets not configured' -WDBuiltinStyle wdStyleBlockQuotation
            }
    
            #region Proxy Addresses
            $heading = 'Proxy Address'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            if ($ProxyIP) 
            { 
              add-wordtable -Object $ProxyIP.viewOverview() @GridTableBlack 
            }
            else
            {
              Add-WordText -text 'Proxy Addresses not configured' -WDBuiltinStyle wdStyleBlockQuotation
            }
            #endregion 
    
            #endregion 
    
            #region IP Groups
            $heading = 'IP Groups'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            if ($IPGroup)
            { 
              add-wordtable -Object $IPGroup.viewOverview() @GridTableBlack 
              foreach ($item in $IPGroup) {
                add-wordtable -Object $item.viewGeneral() @GridTableGrey -VerticleTable
                add-wordtable -Object $item.viewSBCGeneral() @GridTableGrey -VerticleTable -HeaderRow $false
                add-wordtable -Object $item.viewAdvanced() @GridTableGrey -VerticleTable -HeaderRow $false
                add-wordtable -Object $item.viewSBCAdvanced() @GridTableGrey -VerticleTable -HeaderRow $false
                add-wordtable -Object $item.viewQualityofExperience() @GridTableGrey -VerticleTable -HeaderRow $false
                add-wordtable -Object $item.viewMessageManipulation() @GridTableGrey -VerticleTable -HeaderRow $false
                add-wordtable -Object $item.viewSBCRegistrationAuthentication() @GridTableGrey -VerticleTable -HeaderRow $false
                add-wordtable -Object $item.viewGWGroupStatus() @GridTableGrey -VerticleTable -HeaderRow $false
              }
            }
            else
            {
              Add-WordText -text '$heading not configured' -WDBuiltinStyle wdStyleBlockQuotation
            }
            #endregion 
    
        #endregion 
    
        #region Media
        $heading = 'Media'
        $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
        Add-mediantDocParagraph -heading $heading -headingtype 2 -text $text -NewPage 
     
            #region Media Security
            if ($section.Dev) 
            { 
              $heading = 'Media Security'
              $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
              Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
              Add-WordText -text 'MediaSecurity - General' -WDBuiltinStyle wdStyleBlockQuotation
              Add-WordText -text 'MediaSecurity - Master Key Identifier' -WDBuiltinStyle wdStyleBlockQuotation
              Add-WordText -text 'MediaSecurity - Authentication & Encryption' -WDBuiltinStyle wdStyleBlockQuotation
            }
            #endregion 
    
            #region RTP/RTCP Settings
            if ($section.Dev) 
            { 
              $heading = 'RTP/RTCP Settings'
              $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
              Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            }
            #endregion 
    
            #region Voice Settings
            if ($section.Dev) 
            { 
              $heading = 'Voice Settings'
              $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
              Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            }
            #endregion 
    
            #region Fax/Modem/CID Settings
            if ($section.Dev) 
            { 
              $heading = 'Fax/Modem/CID Settings'
              $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
              Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            }
            #endregion 
    
            #region Media Settings
            if ($section.Dev) 
            { 
              $heading = 'MediaSecurity'
              $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
              Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            }
           #endregion 
    
            #region DSP Settings
            if ($section.Dev) 
            { 
              $heading = 'MediaSecurity'
              $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
              Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            }
            #endregion 
    
            #region Quality of Experience
            $heading = 'Quality of Experience'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            
                #region Session Experiance Manager
                if ($section.Dev) 
                { 
                  $heading = 'Session Experiance Manager'
                  $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
                  Add-mediantDocParagraph -heading $heading -headingtype 4 -text $text -NewPage 
                }
                #endregion 
    
                #region Quality of Experiance Profile
                $heading = 'Quality of Experiance Profile'
                $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
                Add-mediantDocParagraph -heading $heading -headingtype 4 -text $text -NewPage 
                if ($QOEProfile)
                { 
                  add-wordtable -Object $QOEProfile.viewOverview() @GridTableBlack 
                }
                else
                {
                  Add-WordText -text 'Quality of Experiance Profile not configured' -WDBuiltinStyle wdStyleBlockQuotation
                }
                  
                #endregion 
    
                #region Bandwidth Profile
                $heading = 'Bandwidth Profile'
                $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
                Add-mediantDocParagraph -heading $heading -headingtype 4 -text $text -NewPage 
                if ($BWProfile)
                { 
                  add-wordtable -Object $BWProfile.viewOverview() @GridTableBlack 
                }
                else
                {
                  Add-WordText -text 'Bandwidth Profile not configured' -WDBuiltinStyle wdStyleBlockQuotation
                }
                #endregion 
    
                #region Quality of Service Rules
                $heading = 'Quality of Service Rules'
                $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
                Add-mediantDocParagraph -heading $heading -headingtype 4 -text $text -NewPage 
                if ($QualityOfServiceRules)
                { 
                  add-wordtable -Object $QualityOfServiceRules.viewOverview() @GridTableBlack 
                }
                else
                {
                  Add-WordText -text 'Quality of Service Rules not configured' -WDBuiltinStyle wdStyleBlockQuotation
                }
                #endregion 
    
            #endregion 
    
        #endregion 
    
        #region Coders & Profiles
        $heading = 'Coders & Profiles'
        $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
        Add-mediantDocParagraph -heading $heading -headingtype 2 -text $text -NewPage 
     
            #region IP Profiles
            $heading = 'IP Profiles'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            if($IpProfile)
            { 
                Add-WordTable -object $IpProfile.viewOverview() @GridTableBlack
                foreach ($item in $IpProfile) 
                {
                    Add-WordTable $item.viewGeneral() @GridTableBlack -VerticleTable 
                    Add-WordTable $item.viewMediaSecurity() @GridTableBlack -VerticleTable -HeaderRow $false
                    Add-WordTable $item.viewSBCEarlyMedia() @GridTableBlack -VerticleTable -HeaderRow $false
                    Add-WordTable $item.viewSBCMedia() @GridTableBlack -VerticleTable -HeaderRow $false
                    Add-WordTable $item.viewQualityofService() @GridTableBlack -VerticleTable -HeaderRow $false
                    Add-WordTable $item.viewSBCJitterBuffer() @GridTableBlack -VerticleTable -HeaderRow $false
                    Add-WordTable $item.viewVoice() @GridTableBlack -VerticleTable -HeaderRow $false
                    Add-WordTable $item.viewSBCSignalling() @GridTableBlack -VerticleTable -HeaderRow $false
                    Add-WordTable $item.viewSBCRegistration() @GridTableBlack -VerticleTable -HeaderRow $false
                    Add-WordTable $item.viewSBCForwardandTransfer() @GridTableBlack -VerticleTable -HeaderRow $false
                    Add-WordTable $item.viewSbcHold() @GridTableBlack -VerticleTable -HeaderRow $false
                    Add-WordTable $item.viewSbcfax() @GridTableBlack -VerticleTable -HeaderRow $false
                    Add-WordTable $item.viewMedia() @GridTableBlack -VerticleTable -HeaderRow $false
                    Add-WordTable $item.viewGateway() @GridTableBlack -VerticleTable -HeaderRow $false
                }
            }
            else
            {
              Add-WordText -text '$heading not configured' -WDBuiltinStyle wdStyleBlockQuotation
            }
            #endregion 
    
            #region Coder Settings
            if ($section.Dev) 
            { 
            $heading = 'Coder Settings'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            }
            #endregion 
    
            #region Coder Groups
            if ($section.Dev) 
            { 
            $heading = 'Coder Groups'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            }
            #endregion 
    
            #region Allowed Audio Coders Groups
            if ($section.Dev) 
            { 
              $heading = 'Allowed Audio Coders Groups'
              $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
              Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
              Add-WordTable -Object $AllowedAudioCoders.viewOverview() @GridTableBlack
            }
            #endregion 
    
            #region Allowed Video Coders Groups
            if ($section.Dev) 
            { 
            $heading = 'Allowed Video Coders Groups'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            Add-WordTable -Object $AllowedAudioCoders.viewOverview() @GridTableBlack
            }
            #endregion 
    
        #endregion 
    
        #region SBC
        $heading = 'SBC'
        $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
        Add-mediantDocParagraph -heading $heading -headingtype 2 -text $text -NewPage 
     
            #region Classification
            $heading = 'Classification'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            Add-WordTable -Object $Classification.viewOverview() @GridTableBlack
            #endregion
    
            #region Routing 
            $heading = 'Routing'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
        
                #region Routing Policies
                $heading = 'Routing Policies'
                $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
                Add-mediantDocParagraph -heading $heading -headingtype 4 -text $text -NewPage 
                Add-WordTable -Object $SBCRoutingPolicy.viewOverview() @GridTableBlack
                #endregion
        
                #region IP to IP Routing
                $heading = 'IP to IP Routing'
                $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
                Add-mediantDocParagraph -heading $heading -headingtype 4 -text $text -NewPage 
                Add-WordTable -Object $IP2IPRouting.viewOverview() @GridTableBlack
                #endregion
    
                #region Alternative Reasons
                $heading = 'Alternative Reasons'
                $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
                Add-mediantDocParagraph -heading $heading -headingtype 4 -text $text -NewPage 
                Add-WordTable -Object $SBCAlternativeRoutingReasons.viewOverview() @GridTableBlack
                #endregion
    
                #region IP Group Set
                $heading = 'IP Group Set'
                $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
                Add-mediantDocParagraph -heading $heading -headingtype 4 -text $text -NewPage
                Add-WordTable -Object $IPGroupSet.viewOverview() @GridTableBlack 
                #endregion
    
            #endregion
    
            #region Manipulation
            $heading = 'Manipulations'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
    
                
                #region Inbound Manipulations
                $heading = 'Inbound Manipulations' 
                $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
                Add-mediantDocParagraph -heading $heading -headingtype 4 -text $text -NewPage 
                Add-WordTable -Object $IPInboundManipulation.viewOverview() @GridTableBlack 
                #endregion
      
                #region Outbound Manipulations
                $heading =  'Outbound Manipulations' 
                $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
                Add-mediantDocParagraph -heading $heading -headingtype 4 -text $text -NewPage 
                Add-WordTable -Object $IPOutboundManipulation.viewOverview() @GridTableBlack 
                
                #endregion
    
            #endregion
    
            #region SBC General Settings
            if ($section.Dev) 
            { 
            $heading = 'SBC General Settings'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            }
            #endregion
    
            #region Admission Control
            $heading = 'Admission Control' 
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 4 -text $text -NewPage 
            Add-WordTable -Object $SBCAdmissionControl.viewOverview() @GridTableBlack 
            #endregion
    
            #region Dial Plan 
            $heading = 'Dial Plan' 
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 4 -text $text -NewPage 
            Add-WordTable -Object $Dialplan.viewOverview() @GridTableBlack 
            #endregion
    
            #region Malicious Signiture
            $heading = 'Malicious Signature'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 4 -text $text -NewPage 
            Add-WordTable -Object $MaliciousSignatureDB.viewOverview() @GridTableBlack 
            #endregion
    
        #endregion 
    
        #region Sip Definitions
        $heading = 'Sip Definitions'
        $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
        Add-mediantDocParagraph -heading $heading -headingtype 2 -text $text -NewPage 
     
            #region Accounts
            if ($accounts) { 
              $heading = 'Accounts'
              $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
              Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
              Add-WordTable -Object $accounts.viewOverview() @GridTableBlack 
            }
            #endregion
    
            #region SIP Definitions General Settings
            if ($section.Dev) 
            { 
            $heading = 'SIP Definitions General Settings'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            }
            #endregion
    
            #region Message Structure
            if ($section.Dev) 
            { 
            $heading = 'Message Structure'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            }
            #endregion
    
            #region Transport Settings
            if ($section.Dev) 
            { 
              $heading = 'Transport Settings'
              $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
              Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            }
            #endregion
    
            #region Proxy & Registration 
            if ($section.Dev) 
            { 
            $heading = 'Proxy & Registration '
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            }
            #endregion
    
            #region Priority and Emergency
            if ($section.Dev) 
            { 
              $heading = 'Priority and Emergency'
              $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
              Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            }
            #endregion
    
            #region Call Setup Rules
            $heading = 'Call Setup Rules'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            IF ($CallSetupRules) 
            {   
              Add-WordTable -Object $CallSetupRules.viewOverview() @GridTableBlack -NoParagraph -HeaderRow $false
              foreach ($item in $CallSetupRules) { 
                  Add-WordTable -Object $item.viewGeneral() @GridTableBlack -HeaderRow $false
                  Add-WordTable -Object $item.viewAction() @GridTableBlack -HeaderRow $false
              }
            }
            ELSE 
            {
              Add-WordText -text 'Call Setup Rules not configured' -WDBuiltinStyle wdStyleBlockQuotation
            }
            #endregion
    
            #region Least Cost Routing 
            if ($section.Dev) 
            { 
            $heading = 'Least Cost Routing '
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            }
                #region Cost Groups 
                if ($section.Dev) 
                { 
                $heading = 'Cost Groups '
                $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
                Add-mediantDocParagraph -heading $heading -headingtype 4 -text $text -NewPage 
                }
                #endregion 
    
            #endregion
    
        #endregion 
    
        #region Message Manipulation
        $heading = 'Message Manipulation'
        $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
        Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
        
            #region Message Manipulations
            $heading = 'Message Manipulations'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            IF ($MessageManipulations) 
            { 
              
              Add-WordTable -Object $MessageManipulations.viewOverview() @GridTableBlack -NoParagraph -HeaderRow $false
              foreach ($item in $MessageManipulations) 
              { 
                  Add-WordTable -Object $item.viewGeneral() @GridTableBlack -HeaderRow $false
                  Add-WordTable -Object $item.viewMatch() @GridTableBlack -HeaderRow $false
                  Add-WordTable -Object $item.viewAction() @GridTableBlack -HeaderRow $false
              }
            }
            ELSE 
            {
              Add-WordText -text 'Message Manipulations not configured' -WDBuiltinStyle wdStyleBlockQuotation
            }
            #endregion 
    
            #region Message Conditions
            $heading = 'Message Conditions'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            
            IF ($CallSetupRules) 
            { 
              
              Add-WordTable -Object $CallSetupRules.viewOverview() @GridTableBlack -NoParagraph -HeaderRow $false
              foreach ($item in $CallSetupRules) { 
                  Add-WordTable -Object $item.viewGeneral() @GridTableBlack -HeaderRow $false
                  Add-WordTable -Object $item.viewAction() @GridTableBlack -HeaderRow $false
              }
            }
            ELSE 
            {
              Add-WordText -text 'Call Setup Rules not configured' -WDBuiltinStyle wdStyleBlockQuotation
            }
            #endregion
    
            #region Message Policies
            $heading = 'Message Conditions'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 2 -text $text -NewPage 
            IF ($MessagePolicy) 
            { 
              
              Add-WordTable -Object $MessagePolicy.viewOverview() @GridTableBlack -NoParagraph -HeaderRow $false
              foreach ($item in $MessagePolicy) { 
                  Add-WordTable -Object $item.viewGeneral() @GridTableBlack -HeaderRow $false
                  Add-WordTable -Object $item.viewLimits() @GridTableBlack -HeaderRow $false
                  Add-WordTable -Object $item.viewPolicies() @GridTableBlack -HeaderRow $false
              }
            }
            ELSE 
            {
              Add-WordText -text 'Message Policies not configured' -WDBuiltinStyle wdStyleBlockQuotation
            }
            #endregion
            
            #endregion
    
        #endregion 
    
        #region Intrusion Detection
        $heading = 'Intrusion Detection'
        $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
        Add-mediantDocParagraph -heading $heading -headingtype 2 -text $text -NewPage 
     
            #region  IDS General Settings
            if ($section.Dev) 
            { 
            $heading = 'Intrusion Detection'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage     
            }
            #endregion 
    
        #endregion 
    
        #region Sip Recording
        $heading = 'Sip Recording'
        $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
        Add-mediantDocParagraph -heading $heading -headingtype 2 -text $text -NewPage 
      
            #region SIP Recording Settings
            if ($section.Dev) 
            { 
                $heading = 'Sip Recording Settings'
                $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
                Add-mediantDocParagraph -heading $heading -headingtype 4 -text $text -NewPage 
            }
            #endregion 
    
            #region SIP Recording Rules
            if ($section.Dev) 
            { 
            $heading = 'Sip Recording Rules'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            }
            #endregion 
    
        #endregion 
    
    }
    #endregion     