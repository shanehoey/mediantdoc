
if($section.IPNetwork) { 

    $heading = 'IP Network'
    $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
    Add-mediantDocParagraph -heading $heading -headingtype 1 -text $text -NewPage 
    
        #region Core Entities
        $heading = 'Core Entities'
        $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
        Add-mediantDocParagraph -heading $heading -headingtype 2 -text $text -NewPage 
        
            #IP Interface
            $heading = 'IP Interface'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            Add-WordTable -Object $InterfaceTable.viewOverview() @GridTableBlack
            if($InterfaceTable) 
            { 
                foreach ($item in $InterfaceTable) 
                { 
                    Add-WordTable -Object $Item.viewGeneral() @GridTableGrey -VerticleTable 
                    Add-WordTable -Object $Item.viewIPAddress() @GridTableGrey -VerticleTable -header $false
                    Add-WordTable -Object $Item.viewDNS() @GridTableGrey -VerticleTable  -HeaderRow $false
                }
            }
            else 
            {
                Add-WordText -text "$heading not configured" -WDBuiltinStyle wdStyleIntenseQuote
            }

            #Ethernet Devices
            $heading = 'Ethernet Devices'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            if($DeviceTable) 
            { 
                Add-WordTable -Object $DeviceTable.viewOverview() @GridTableBlack
                foreach ($item in $DeviceTable) 
                { 
                    Add-WordTable -Object $item.viewGeneral() @GridTableGrey -VerticleTable 
                }
            }
            else 
            {
              Add-WordText -text "$heading not configured" -WDBuiltinStyle wdStyleIntenseQuote
            }

            #Ethernet Groups
            $heading = 'Ethernet Groups'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            if($EtherGroupTable) 
            { 
                Add-WordTable -Object ($EtherGroupTable | select Ethergrouptable_Group,Ethergrouptable_Mode) @GridTableBlack 
                foreach ($item in $EtherGroupTable) 
                { 
                    Add-WordTable -Object $item.viewOverview() @GridTableGrey -VerticleTable     
                }
            }
            else 
            {
              Add-WordText -text "$heading not configured" -WDBuiltinStyle wdStyleIntenseQuote
            }

            #Physical Ports
            $heading = 'Physical Ports'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            if ($PhysicalPortsTable)
            {
                 Add-WordTable -Object ($PhysicalPortsTable.viewOverview() ) @GridTableBlack
                foreach ($item in $PhysicalPortsTable) 
                { 
                    Add-WordTable -Object $item.viewGeneral() @GridTableGrey -VerticleTable
                    Add-WordTable -Object $item.viewEthernetGroup() @GridTableGrey -VerticleTable -HeaderRow $false
                }
            }
            else 
            {
              Add-WordText -text "$heading not configured" -WDBuiltinStyle wdStyleIntenseQuote
            }

            #Static Routes
            $heading = 'Static Routes'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            IF ($StaticRouteTable) 
            { 
                Add-WordTable -Object $StaticRouteTable.viewOverview() @GridTableBlack
                foreach ($item in $StaticRouteTable) 
                {
                    Add-WordTable -Object $item.viewGeneral() @GridTableGrey -VerticleTable -HeaderRow $FALSE
                }
            }
            else 
            {
              Add-WordText -text "$heading not configured" -WDBuiltinStyle wdStyleIntenseQuote
            }

            #HA Settings
            $heading = 'HA Settings'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            if($SYSTEMparams.HAPingEnabled -eq 1) 
            { 
                Add-WordTable -Object $SYSTEMparams.viewHASettings_HighAvailability() @GridTableBlack -VerticleTable -HeaderRow $false
                Add-WordTable -Object $SYSTEMparams.viewHASettings_NetworkReachability() @GridTableGrey -VerticleTable -HeaderRow $false
            }
            else 
            {
              Add-WordText -text "$heading Currently Disabled" -WDBuiltinStyle wdStyleIntenseQuote
              Add-WordTable -Object $SYSTEMparams.viewHASettings_HighAvailability() @GridTableBlack -VerticleTable -HeaderRow $false
              Add-WordTable -Object $SYSTEMparams.viewHASettings_NetworkReachability() @GridTableGrey -VerticleTable -HeaderRow $false
            }

            #Nat Translation
            $heading = 'Nat Translation'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            if ($NATTranslation) 
            { 
              Add-WordTable -Object $NATTranslation.viewSource() @GridTableBlack 
              Add-WordTable -Object $NATTranslation.viewTarget() @GridTableGrey
            }
            else 
            {
              Add-WordText -text "$heading not configured" -WDBuiltinStyle wdStyleIntenseQuote
            }

    
        #endregion
    
        #region Security 
        $heading = 'Security'
        $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
        Add-mediantDocParagraph -heading $heading -headingtype 2 -text $text -NewPage 
    
            #TLS Contexts
            $heading = 'TLS Contexts'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            IF ($TLSContexts) 
            { 
                Add-WordTable -Object $TLSContexts.viewOverview() @GridTableBlack
                foreach ($item in $tlsContexts) 
                { 
                    Add-WordTable -Object $TLSContexts.viewGeneral() @GridTableGrey -VerticleTable -HeaderRow $true
                    Add-WordTable -Object $TLSContexts.viewOCSP() @GridTableGrey -VerticleTable -HeaderRow $false
                }
            }
            else 
            {
              Add-WordText -text "$heading not configured" -WDBuiltinStyle wdStyleIntenseQuote
            }

            #Firewall
            $heading = 'Firewall'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            IF ($accesslist) 
            {  
                Add-WordTable -Object $accesslist.viewOverview() @GridTableBlack 
                foreach ($item in $accesslist) 
                {
                    Add-WordTable -Object $item.viewMatch() @GridTableGrey -VerticleTable
                    Add-WordTable -Object $item.viewAction() @GridTableGrey -VerticleTable -HeaderRow $false
                }
            }
            else 
            {
              Add-WordText -text "$heading not configured" -WDBuiltinStyle wdStyleIntenseQuote
            }

            #Security Settings
            $heading = 'Security Settings'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            Add-WordTable -Object $SYSTEMparams.viewSecuritySettings_TLSGeneral() @GridTableBlack  -VerticleTable -HeaderRow $False
            Add-WordTable -Object $SIPParams.viewSecuritySettings_SipOverTLS() @GridTableBlack  -VerticleTable -HeaderRow $False
            Add-WordTable -Object $WEBParams.viewSecuritySettings_Management() @GridTableBlack -VerticleTable -HeaderRow $False

        #endregion
    
        #region Quality
        $heading = 'Quality'
        $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
        Add-mediantDocParagraph -heading $heading -headingtype 2 -text $text -NewPage 
    
            #Qos Settings
            $heading = 'Qos Settings'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            if ($BSPParams)
            {
                Add-WordTable -Object $BSPParams.viewQosSettings_General() @GridTableBlack -verticletable -FirstColumn $true -HeaderRow $false
            }
            else 
            {
                Add-WordText -text "$heading not configured" -WDBuiltinStyle wdStyleIntenseQuote
            }

            #Qos Mapping
            $heading = 'Qos Mapping'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            IF ($DiffServToVlanPriority) 
            {  
              Add-WordTable -Object $DiffServToVlanPriority.view() @GridTableBlack 
            }
            else 
            {
              Add-WordText -text "$heading not configured" -WDBuiltinStyle wdStyleIntenseQuote
            }

    
        #endregion
    
        #region Radius & Ldap
        $heading = 'Radius & Ldap'
        $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
        Add-mediantDocParagraph -heading $heading -headingtype 2 -text $text -NewPage 
    
            #RADIUS Servers
            $heading = 'RADIUS Servers'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            IF ($RadiusServers) 
            {  
              Add-WordTable -Object $RadiusServers.viewOverview() @GridTableBlack 
            }
            else
            {
                Add-WordText -text "$heading not configured" -WDBuiltinStyle wdStyleIntenseQuote
            }
    
            #LDAP Settings
            $heading = 'LDAP Settings'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            if ($SIPParams.LDAPGeneral -eq 1) 
            {
                Add-WordTable -Object $sipparams.viewLDAPSettings() @GridTableBlack -VerticleTable -HeaderRow $false
                Add-WordTable -Object $sipparams.viewLDAPActiveDirectory() @GridTableBlack -VerticleTable -HeaderRow $false
                Add-WordTable -Object $sipparams.viewLDAPCache() @GridTableBlack -VerticleTable -HeaderRow $false
            }
            else 
            {
                Add-WordText -text "$heading not ENABLED" -WDBuiltinStyle wdStyleIntenseQuote
                Add-WordTable -Object $sipparams.viewLDAPSettings() @GridTableBlack -VerticleTable -HeaderRow $false
                Add-WordTable -Object $sipparams.viewLDAPActiveDirectory() @GridTableBlack -VerticleTable -HeaderRow $false
                Add-WordTable -Object $sipparams.viewLDAPCache() @GridTableBlack -VerticleTable -HeaderRow $false
            }

            #LDAP Server Groups
            $heading = 'LDAP Server Groups'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            if ($LdapServerGroups) 
            {  
              Add-WordTable -Object $LdapServerGroups.viewOverview() @GridTableBlack 
              foreach ($item in $LdapServerGroups) 
              {
                  Add-WordTable -Object $item.viewGeneral() @GridTableGrey -VerticleTable -HeaderRow $false
                  Add-WordTable -Object $item.viewCache() @GridTableGrey -VerticleTable -HeaderRow $false
              }
            }
            else
            {
                Add-WordText -text "$heading not configured" -WDBuiltinStyle wdStyleIntenseQuote
            }

            #LDAP Servers
            $heading = 'LDAP Servers'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            IF ($LdapConfiguration) 
            {  
              Add-WordTable -Object $LdapConfiguration.viewOverview() @GridTableBlack 
              foreach ($item in $LdapConfiguration) 
              {
                Add-WordTable -Object $item.viewGeneral() @GridTableGrey -VerticleTable -HeaderRow $false
                Add-WordTable -Object $item.viewQuery() @GridTableGrey -VerticleTable -HeaderRow $false 
                Add-WordTable -Object $item.viewConnection() @GridTableGrey -VerticleTable -HeaderRow $false
              }
            }
            else
            {
                Add-WordText -text "$heading not configured" -WDBuiltinStyle wdStyleIntenseQuote
            }

        #endregion
    
        #region Advanced
        $heading = 'Advanced'
        $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
        Add-mediantDocParagraph -heading $heading -headingtype 2 -text $text -NewPage 
    
            #Network Settings
            $heading = 'Network Settings'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            if ($BSPParams) 
            {
                Add-WordTable -Object $BSPParams.viewNetworkSettings_ICMP() @GridTableBlack -VerticleTable -HeaderRow $false
                Add-WordTable -Object $BSPParams.viewNetworkSettings_DHCP() @GridTableBlack -NoParagraph -VerticleTable -HeaderRow $false
            }
            else
            {
                Add-WordText -text "$heading not configured" -WDBuiltinStyle wdStyleIntenseQuote
            }

            #DHCP Servers
            $heading = 'DHCP Servers'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            IF ($DhcpServer) 
            {  
              Add-WordTable -Object $DhcpServer.viewGeneral() @GridTableBlack  -VerticleTable
              Add-WordTable -Object $DhcpServer.viewDNS() @GridTableGrey  -VerticleTable -HeaderRow $false
              Add-WordTable -Object $DhcpServer.viewNetbios() @GridTableGrey  -VerticleTable -HeaderRow $false
              Add-WordTable -Object $DhcpServer.viewTimeandDate() @GridTableGrey -VerticleTable -HeaderRow $false
              Add-WordTable -Object $DhcpServer.viewBootFile() @GridTableGrey -VerticleTable -HeaderRow $false
              Add-WordTable -Object $DhcpServer.viewRouter() @GridTableGrey -VerticleTable -HeaderRow $false
              Add-WordTable -Object $DhcpServer.viewSip() @GridTableGrey -VerticleTable -HeaderRow $false
              if ($DhcpVendorClass) { Add-WordTable -Object $DhcpVendorClass.viewOverview() @GridTableGrey }
              if ($DhcpOption) { Add-WordTable -Object $DhcpOption.viewOverview() @GridTableGrey }
              if ($DhcpStaticIP) { Add-WordTable -Object $DhcpStaticIP.viewOverview() @GridTableGrey }
            }
            else
            {
                Add-WordText -text "$heading not configured" -WDBuiltinStyle wdStyleIntenseQuote
            }
        #endregion
    
        #region DNS
        $heading = 'DNS'
        $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
        Add-mediantDocParagraph -heading $heading -headingtype 2 -text $text -NewPage 
    
            #Internal DNS
            $heading = 'Internal DNS'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            IF ($DNS2IP) 
            {  
                Add-WordTable -Object $DNS2IP.viewOverview() @GridTableBlack 
                foreach ($item in $DNS2IP) { 
                    Add-WordTable -Object $item.viewgeneral() @GridtableGrey -VerticleTable
                }
            }
            else
            {
                Add-WordText -text "$heading not configured" -WDBuiltinStyle wdStyleIntenseQuote
            }
            #Internal SRV
            $heading = 'Internal SRV'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            IF ($SRV2IP) 
            {  
                Add-WordTable -Object $SRV2IP.viewOverview() @GridtableBlack 
                foreach ($item in $SRV2IP) 
                { 
                    Add-WordTable -Object $item.viewGeneral() @GridtableGrey -VerticleTable
                    Add-WordTable -Object $item.view1stEntry() @GridtableGrey -VerticleTable -HeaderRow $false
                    Add-WordTable -Object $item.view2ndEntry() @GridtableGrey -VerticleTable -HeaderRow $false
                    Add-WordTable -Object $item.view3rdEntry() @GridtableGrey -VerticleTable -Headerrow $false
                }
            }
            else
            {
                Add-WordText -text "$heading not configured" -WDBuiltinStyle wdStyleIntenseQuote
            }
    
        #endregion 
    
        #region Web Services
        $heading = 'Web Services'
        $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
        Add-mediantDocParagraph -heading $heading -headingtype 2 -text $text -NewPage 
    
            #Web Service Settings
            $heading = 'Web Service Settings'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            if ($ControlProtocolsParams) 
            { 
                Add-WordTable -Object $ControlProtocolsParams.viewGeneral() @GridTableBlack
            }
            else
            {
                Add-WordText -text "$heading not configured" -WDBuiltinStyle wdStyleIntenseQuote
            }    
            
            #Remote Web Services
            $heading = 'Remote Web Services'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            IF ($HTTPRemoteServices) 
            {  
                Add-WordTable -Object $HTTPRemoteServices @GridTableBlack
                Add-WordTable -Object $HTTPRemoteHosts @GridTableBlack
            }
            else
            {
                Add-WordText -text "$heading not configured" -WDBuiltinStyle wdStyleIntenseQuote
            }
    
        #endregion

        #region HTTP Proxy 
        $heading = 'HTTP Proxy'
        $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
        Add-mediantDocParagraph -heading $heading -headingtype 2 -text $text -NewPage 

            #General Settings
            $heading = 'General Settings'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            if ($SIPParams.HTTPProxyApplication -eq 1 ) 
            {
                Add-WordTable -Object $sipparams.viewHTTPProxy() @GridTableBlack -VerticleTable
            }
            else
            {
                Add-WordText -text "$heading not Enabled" -WDBuiltinStyle wdStyleIntenseQuote
                Add-WordTable -Object $sipparams.viewHTTPProxy() @GridTableBlack -VerticleTable -HeaderRow $false -FirstColumn $true
            }

            #HTTP Interfaces
            $heading = 'HTTP Interfaces'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            if ($HTTPInterface) 
            {   
                Add-WordTable -Object $HTTPInterface.viewoverview() @GridTableBlack
                foreach ($item in $HTTPInterface) 
                {
                   Add-wordtable -object $item.viewGeneral() @GridTableGrey -VerticleTable
                   Add-wordtable -object $item.viewSecurity() @GridTableGrey -VerticleTable -HeaderRow $false
                }
            }
            else
            {
                Add-WordText -text "$heading not configured" -WDBuiltinStyle wdStyleIntenseQuote
            }

            #HTTP Proxy Service
            $heading = 'HTTP Proxy Service'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            if ($HTTPProxyService) 
            {
                Add-WordTable -Object $HTTPProxyService.viewOverview() @GridTableBlack -VerticleTable
                foreach ($item in $HTTPProxyService) 
                {
                   Add-wordtable -object $item.viewGeneral() @GridTableGrey -VerticleTable
                }
            }
            else
            {
                Add-WordText -text "$heading not configured" -WDBuiltinStyle wdStyleIntenseQuote
            }

            #HTTP Proxy Host
            $heading = 'HTTP Proxy Hosts'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            if ($HTTPProxyHost) 
            { 
                Add-WordTable -Object $HTTPProxyHost.viewOverview() @GridTableBlack
                foreach ($item in $HTTPProxyHost) 
                {
                    Add-wordtable -object $item.viewGeneral() @GridTableGrey -VerticleTable
                    Add-wordtable -object $item.viewSecurity() @GridTableGrey -VerticleTable -HeaderRow $false
                }
            }
            else 
            {
                Add-WordText -text "$heading not configured" -WDBuiltinStyle wdStyleIntenseQuote
            }

  
            #EMS Services
            $heading = 'EMS Services'
            $text = $mediantDocText."text$($heading.replace(' ','').replace('&','').replace('/',''))"
            Add-mediantDocParagraph -heading $heading -headingtype 3 -text $text -NewPage 
            if ($emsservice) 
            {
                Add-WordTable -Object $emsservice.viewOverview() @GridTableBlack
                foreach ($item in $emsservice) 
                {
                    Add-wordtable -object $item.viewGeneral() @GridTableGrey -VerticleTable -NoParagraph
                    Add-wordtable -object $item.viewDevice() @GridTableGrey -VerticleTable -NoParagraph
                    Add-wordtable -object $item.viewEMS() @GridTableGrey -VerticleTable -HeaderRow $true
                }
            }
            else
            {
                Add-WordText -text "$heading not configured" -WDBuiltinStyle wdStyleIntenseQuote
            }

        #endregion
    }
