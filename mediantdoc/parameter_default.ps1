$DisableEnable = @{"0" = "Disable"; "1" = "Enable"} 
$EnableDisable = @{"0" = "Enable"; "1" = "Disable"} 
$YesNo = @{"0" = "Yes"; "1" = "No"} 
$NoYes = @{"0" = "No"; "1" = "Yes"} 

$3xxBehavior = @{"0" = "Forward"; "1" = "Redirect"}
$AuthenticationMode = @{ "0" = "Per Endpoint"; "1" = "Per Gateway"; "3" = "Per FXS"; }
$CDRReportLevel = @{ "0" = "None"; "1" = "End Call"; "2" = "Start End Call"; "3" = "Connect & End Call"; "4" = "Start & End & Connect Call" }
$DeviceTable_Tagging = @{ "0" = "Untagged"; "1" = "Tagged"; }
$DNSQueryType = @{ "0" = "A-Record"; "1" = "SRV"; "2" = "NAPTR" }
$EnablePtime = @{"0" = "Remove 'ptime'"; "1" = "include 'ptime'"}
$EtherGroupTable_Mode = @{ "0" = "None"; "1" = "Single"; "2" = "2RX/1TX"; "3" = "2RX/2TX" }
$FaxVBDBehavior = @{"0" = "VBD Coder"; "1" = "IsFaxUsed"}
$InterfaceTable_ApplicationTypes = @{ "0" = "OAMP"; "1" = "Media"; "2" = "Control"; "3" = "OAMP + Media"; "4" = "OAMP + Control"; "5" = "Media + Control"; "6" = "OAMP + Media + Control"}
$InterfaceTable_InterfaceMode = @{"3" = "IPv6 Manual Prefix"; "4" = "IPv6 Manual"; "10" = "IPv4 Manual"} 
$IsCiscoSCEMode = @{"0" = "No Cisco Gatway"; "1" = "CiscoGateway"}
$MediaCDRReportLevel = @{"0" = "None"; "1" = "End Media"; "2" = "Start & End Media"; "3" = "Update & End Media"; "4" = "Start & End & Update Media"}
$MultiPtimeFormat = @{"0" = "None"; "1" = "PacketCable"}
$PhysicalPortsTable_SpeedDuplex = @{ "0" = "10BaseT Half Duplex"; "1" = "10BaseT Full Duplex"; "2" = "100BaseT Half Duplex"; "3" = "100BaseT Full Duplex"; "4" = "Auto Negotiation (default)"; "6" = "1000BaseT Half Duplex"; "7" = "1000BaseT Full Duplex"; }
$PrackMode = @{ "0" = "Disable"; "1" = "Supported "; "2" = "Required"; }
$ProxyDNSQueryType = @{ "0" = "A-Record"; "1" = "SRV"; "2" = "NAPTR" }
$ProxyRedundancyMode = @{ "0" = "Parking"; "1" = "Homing" }
$RegistrarTransportType = @{ "-1" = "Not Configured"; "0" = "UDP"; "1" = "TCP"; "2" = "TLS" }
$ReleaseIP2ISDNCallOnProgressWithCause = @{ "0" = "Default"; "1" = "SIP 4xx EarlyMedia"; "2" = "Always SIP 4xx"; }
$RemoveToTagInFailureResponse = @{ "0" = "Do not remove tag"; "1" = "Remove tag"; }
$SelectSourceHeaderForCalledNumber = @{ "0" = "Request-URI-Header"; "1" = "To Header"; "2" = "P-Called-Party-ID"}
$SessionExpiresMethod = @{ "0" = "Re-Invite"; "1" = "Update"; }
$SIP183Behaviour = @{ "0" = "Progress"; "1" = "Alert "; }
$SIPChallengeCachingMode = @{ "0" = "None"; "1" = "Invite Only"; "2" = "Full" }
$SIPReroutingMode = @{ "0" = "Standard"; "1" = "Proxy"; "2" = "Routing Table" }
$SIPTransportType = @{"0" = "UDP(Default)"; "1" = "TCP"; "2" = "TLS (SIPS)"}
$TelnetServerEnable = @{"0" = "Disable"; "1" = "Enable Unsecured"; "2" = "Enable Secured"}
$TGRProutingPrecedence = @{"0" = "IP to Tel Routing Table"; "1" = "tgrp"}
$TLSContexts_DHKeySize = @{ "1024" = "1024"; "2048" = "2048" }
$TLSContexts_OcspDefaultResponse = @{ "0" = "Reject"; "1" = "Allow" }
$TLSContexts_TLSVersion = @{ "0" = "Any - Including SSLv3 "; "1" = "TLSv1.0"; "2" = "TLSv1.1"; "3" = "TLSv1.0 + TLSv1.1"; "4" = "TLSv1.2"; "5" = "TLSv1.0 + TLSv1.2"; "6" = "TLSv1.1 + TLSv1.2"; "7" = "TLSv1.0 +TLSv1.1 +TLSv1.2" }
$TrunkStatusReportingMode = @{ "0" = "Disable"; "1" = "Don't reply OPTIONS"; "2" = "Don’t send Keep-Alive"; "3" = "Don’t Reply and Send"; }
$UseGatewayNameForOptions = @{ "0" = "No"; "1" = "Yes"; "2" = "Server" }
$UseSIPTgrp = @{"0" = "Disable"; "1" = "Send Only"; "2" = "Send and Recieve"; "3" = "Hotline"; "4" = "Hotline Extended"}
$WebUsers_Status = @{"0" = "New"; "1" = "Valid"; "2" = "Failed Login"; "3" = "Inactivity"} 
$WebUsers_UserLevel = @{"50" = "Monitor"; "100" = "Administrator"; "200" = "Security Administrator"; "220" = "Master"} 
$GwDebugLevel = @{"0"="No Debug";"1"="Basic";"5"="Detailed "}
$SyslogFacility = @{"16"="Local0";"17"="Local1";"18"="Local2";"19"="Local3";"20"="Local4";"21"="Local5";"22"="Local6";"23"="Local7"}
$CallDurationUnits = @{"0"="Seconds";"1"="Deciseconds";"2"="Centiseconds";"3"="Milliseconds"}
$TelnetServerEnable = @{"0"="Disable";"1"="Enable Unsecured";"2"="Enable Secured"}
$DefaultTerminalWindowHeight = @{"-1"="CLI Window Height";"0"="Window";}