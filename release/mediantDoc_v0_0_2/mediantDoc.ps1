
<#PSScriptInfo

.VERSION 0.0.2

.GUID 3f2891e3-e02e-4b8c-ae49-3dcf2a2335b3

.AUTHOR Shane Hoey

.COMPANYNAME 

.COPYRIGHT 2018 Shane Hoey

.TAGS Mediant

.LICENSEURI https://shanehoey.github.io/mediantdoc/license

.PROJECTURI https://shanehoey.github.io/mediantdoc

.ICONURI 

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS 

.EXTERNALSCRIPTDEPENDENCIES 

.RELEASENOTES
https://shanehoey.github.io/mediantdoc

#> 

#Requires -Module WordDoc











<# 

.DESCRIPTION 
Create an As-Built Document for an AudioCodes Mediant Gateway

#> 
<#
MIT License

Copyright (c) 2016-2018 Shane Hoey

Permission is hereby granted, free of charge, to any person obtaining a copy 
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

#>
[cmdletbinding(DefaultParameterSetName = "Default")]
Param(  

    [ValidateNotNullOrEmpty()]
    [ValidateScript( {(Test-Path $_) -and ((Get-Item $_).Extension -eq ".ini")})]  
    [Parameter(ValueFromPipeline = $false, Mandatory = $false, ParameterSetName = "MediantConfigFile")]
    [string]$MediantConfigFile,

    [ValidateNotNullOrEmpty()]
    [Parameter(ValueFromPipeline = $false, Mandatory = $false, ParameterSetName = "MediantDevice")]
    [string]$MediantDevice,

    [ValidateNotNullOrEmpty()]
    [Parameter(ValueFromPipeline = $false, Mandatory = $false, ParameterSetName = "MediantDevice")]
    $MediantDeviceCredential,

    [ValidateNotNullOrEmpty()]
    [ValidateSet("HTTP", "HTTPS")]
    [Parameter(ValueFromPipeline = $false, Mandatory = $false, ParameterSetName = "MediantDevice")]
    [string]$MediantDeviceProtocol = "HTTP",

    [ValidateNotNullOrEmpty()]  
    [ValidateScript( {(Test-Path $_) -and ((Get-Item $_).Extension -like ".do*x")})]  
    [Parameter(ValueFromPipeline = $false, Mandatory = $false, ParameterSetName = "MediantConfigFile")]
    [Parameter(ValueFromPipeline = $false, Mandatory = $false, ParameterSetName = "MediantDevice")]
    [Parameter(ValueFromPipeline = $false, Mandatory = $false, ParameterSetName = "Default")]
    [string]$WordTemplate,  
    
    [ValidateNotNullOrEmpty()]  
    [ValidateScript( {(Test-Path $_) -and ((Get-Item $_).Extension -like ".json")})]  
    [Parameter(ValueFromPipeline = $false, Mandatory = $false, ParameterSetName = "MediantConfigFile")]
    [Parameter(ValueFromPipeline = $false, Mandatory = $false, ParameterSetName = "MediantDevice")]
    [Parameter(ValueFromPipeline = $false, Mandatory = $false, ParameterSetName = "Default")]
    [string]$DesignJson,

    [Parameter(ValueFromPipeline = $false, Mandatory = $false, ParameterSetName = "MediantConfigFile")]
    [Parameter(ValueFromPipeline = $false, Mandatory = $false, ParameterSetName = "MediantDevice")]
    [Parameter(ValueFromPipeline = $false, Mandatory = $false, ParameterSetName = "Default")]
    [switch]$DownloadSampleDesignText,

    [Parameter( Mandatory = $false, ParameterSetName = "MediantConfigFile")]
    [Parameter( Mandatory = $false, ParameterSetName = "MediantDevice")]
    [Parameter( Mandatory = $false, ParameterSetName = "Default")]
    [bool]$notifyupdates = $true,

    [Parameter( Mandatory = $false, ParameterSetName = "MediantConfigFile")]
    [Parameter( Mandatory = $false, ParameterSetName = "MediantDevice")]
    [Parameter( Mandatory = $false, ParameterSetName = "Default")]
    [string]$DocumentTitle = "MediantDoc by Shane Hoey",

    [Parameter( Mandatory = $false, ParameterSetName = "MediantConfigFile")]
    [Parameter( Mandatory = $false, ParameterSetName = "MediantDevice")]
    [Parameter( Mandatory = $false, ParameterSetName = "Default")]
    [string]$DocumentCustomer = "Shane Hoey"

)

try { import-module -name WordDoc -ErrorAction Stop } catch { Write-Warning "WordDoc Module is required , to install ->  install-module -name worddoc -scope currentuser"; break }
try { import-module -name Mediant -ErrorAction Stop } catch { Write-Warning "Mediant Module is Optional, to install ->  install-module -name mediant -scope currentuser`n" ; $mediantimportfail = $true }

$section = @{}
$section["CoverPage"] = $true
$section["MediantOverview"] = $true
$section["IPNetwork"] = $true
$section["SignalingMedia"] = $true
$section["Administration"] = $true
$section["Troubleshoot"] = $true
$section["Endpage"] = $true
$section["Appendix"] = $true
$section["Dev"] = $true # this should only be  true when developing the script as it adds sections not yet completed

#requires -Version 5.0

#Lists
class Mediant {
  [string]$Mediant_Board
  [string]$Mediant_BoardType
  [string]$Mediant_KeyFeatures
  [string]$Mediant_SerialNumber
  [string]$Mediant_SoftwareVersion
  [string]$Mediant_DSPSoftwareVersion
}
Update-TypeData -TypeName Mediant -MemberType ScriptMethod -MemberName 'view' -Value { $this }  -Force
Update-TypeData -TypeName Mediant -MemberType ScriptMethod -MemberName 'viewDoc' -Value { $this | Select-Object -Property Mediant_Board, Mediant_BoardType, Mediant_SerialNumber, Mediant_SoftwareVersion, Mediant_DSPSoftwareVersion } -Force
Update-TypeData -TypeName Mediant -MemberType ScriptMethod -MemberName 'viewKeyfeatures' -Value { $this.Mediant_KeyFeatures } -Force

$itemindex_mediant.foreach({ update-typedata -typename Mediant -MemberType AliasProperty -Membername $_.split("_")[1] -value $_   })

class SystemParams {
  #Security Settings
  $RequireStrictCert = '0'
  $TLSExpiryCheckStart = '60'
  $TLSExpiryCheckPeriod = '7'
  #NTP
  $NTPServerIP
  $NTPSecondaryServerIP
  $NTPUpdateInterval
  $ntpAuthMd5Key
  $NTPServerUTCOffset
  #Daylight Savings
  $DayLightSavingTimeEnable
  $DayLightSavingTimeStart
  $DayLightSavingTimeEnd
  $DayLightSavingTimeOffset
  #TR069
  $TR069ACSPASSWORD 
  $TR069CONNECTIONREQUESTPASSWORD
  #Telnet
  $TelnetServerEnable = '1'
  $TelnetServerPort = '23'
  $TelnetServerIdleDisconnect = '0'
  $TelnetMaxSessions = '2'
  $CLIPrivPass
  $DefaultTerminalWindowHeight = '-1'
  #SSH
  $SSHServerEnable = '0' 
  $SSHServerPort = '22'
  $SSHAdminKey 
  $SSHRequirePublicKey = '0'
  $SSHMaxPayloadSize = '32768' 
  $SSHMaxBinaryPacketSize = '35000'
  $SSHMaxSessions = '5'
  $SSHMaxLoginAttempts = '3'
  $SSHEnableLastLoginMessage = '1'
  #Syslog
  $EnableSyslog = '0'
  $SyslogServerIP = '0.0.0.0'
  $SyslogServerPort = '514'
  $CDRSyslogServerIP 
  $CDRReportLevel = '0'
  $MediaCDRReportLevel = '0'
  $CDRLocalMaxFileSize = '1024'
  $CDRLocalMaxNumOfFiles = '5'
  $CDRLocalInterval = '60'
  $GwDebugLevel = '0'
  $EnableNonCallCdr  = '0'
  $SyslogOptimization = '0' 
  $MaxBundleSyslogLength = '1220'
  $SyslogCpuProtection = '0'
  $DebugLevelHighThreshold = '90'
  $SyslogFacility = '16' 
  $CallDurationUnits = '0'
  $TimeZoneFormat 
  $CDRSyslogSeqNum = '0'
  $SendAcSessionIDHeader = '0'
  $ActivityListToLog
  $EnableParametersMonitoring = '0'
  $FacilityTrace = '0'
  $DebugRecordingDestIP
  $DebugRecordingDestPort
  $EnableCoreDump = '0'
  $CoreDumpDestIP
  $CallFlowReportMode = '0'
  #HA Settings
  $HARemoteAddress = '0.0.0.0'
  $HARevertiveEnabled = '0' 
  $HAPriority = '5'
  $HAUnitIdName = "" 
  $HAPingEnabled = '0' 
  $HAPingDestination = '::'
  $HAPingSourceIfName
  $HAPingTimeout = '1'
  $HAPingRetries = '2'
  #AuthenticationServerGeneral
  $DefaultAccessLevel =200
  #Unordered
  $EnableActivityTrap
  $LDAPServiceEnable

}
Update-TypeData -TypeName SystemParams -MemberType Scriptmethod -MemberName 'viewHASettings_HighAvailability' -Value { $this | Select-Object -Property HARemoteAddress, HARevertiveEnabled, HAPriority, HAUnitIdName} -Force    
Update-TypeData -TypeName SystemParams -MemberType Scriptmethod -MemberName 'viewHASettings_NetworkReachability' -Value { $this | Select-Object -Property  HAPingEnabled, HAPingDestination, HAPingSourceIfName, HAPingTimeout, HAPingRetries } -Force    
Update-TypeData -TypeName SystemParams -MemberType Scriptmethod -MemberName 'viewSecuritySettings_TLSGeneral' -Value { $this | Select-Object -Property RequireStrictCert, TLSExpiryCheckStart, TLSExpiryCheckPeriod } -Force      
Update-TypeData -TypeName SystemParams -MemberType Scriptmethod -MemberName 'viewAuthenticationServerGeneral' -Value { $this | Select-Object -Property DefaultAccessLevel } -Force      

class BSPParams {
  
  #DHCP
  $DHCPEnable = '0'
  #QosSettings
  $PremiumServiceClassMediaDiffServ ="46"
  $PremiumServiceClassControlDiffServ = "24"
  $GoldServiceClassDiffServ = "26"
  $BronzeServiceClassDiffServ = "10"
  #ICMP
  $DisableICMPRedirects = '0'
  $DisableICMPUnreachable = '0'
  #
  $PCMLawSelect 
  $BaseUDPPort
  $UdpPortSpacing
  $EnterCpuOverloadPercent
  $ExitCpuOverloadPercent
  $RoutingServerGroupStatus
  $QOEServerIp
  $QOEEnableTLS
  $QOERedundantServerIp
  $QoETLSContextName
  $QOEReportMode
  $INIFileVersion
}
Update-TypeData -TypeName BSPParams -MemberType Scriptmethod -MemberName 'viewQosSettings_General' -Value { $this | Select-Object -Property "PremiumServiceClassMediaDiffServ","PremiumServiceClassControlDiffServ","GoldServiceClassDiffServ","BronzeServiceClassDiffServ" } -Force
Update-TypeData -TypeName BSPParams -MemberType Scriptmethod -MemberName 'viewNetworkSettings_ICMP' -Value { $this | Select-Object -Property "DisableICMPRedirects","DisableICMPUnreachable" } -Force
Update-TypeData -TypeName BSPParams -MemberType Scriptmethod -MemberName 'viewNetworkSettings_DHCP' -Value { $this | Select-Object -Property "DHCPEnable" } -Force

class ControlProtocolsParams {
  $RoutingServerGroupStatus
  $AdminStateLockControl
}
Update-TypeData -TypeName ControlProtocolsParams -MemberType Scriptmethod -MemberName 'viewGeneral' -Value { $this | Select-Object -Property @{n="Topology Status";e={$_.RoutingServerGroupStatus} } } -Force

class MEGACOParams {
  $EP_Num_0
  $EP_Num_1
  $EP_Num_2 
  $EP_Num_3
  $EP_Num_4
}

class VoiceEngineParams {

  #General
  $EnableMediaSecurity = 0
  $AriaProtocolSupport
  #Master Key Idenifier 
  $SRTPTxPacketMKISize
  #Authentication & Encryption
  $RTPAuthenticationDisableTx
  $RTCPEncryptionDisableTx
  $RTPEncryptionDisableTx
  $SRTPTunnelingValidateRTPRxAuthentication
  $SRTPTunnelingValidateRTCPRxAuthentication
  #Robustness
  $TimeoutToRelatchRTPMsec
  $TimeoutToRelatchSRTPMsec
  $TimeoutToRelatchSilenceMsec
  $TimeoutToRelatchRTCPMsec
  $NewRtpStreamPackets
  $NewSRTPStreamPackets 
  $NewRtcpStreamPackets
  $NewSRtcpStreamPackets
  #MediaSettingsGeneral
  $NatMode
  $EnableContinuityTones = 0
  $L1L1ComplexRxUDPPort = 0
  $L1L1ComplexTxUDPPort = 0
  $EnableSilenceCompression 
  $EnableEchoCanceller
  $VoiceVolume
  $InputGain
  $BrokenConnectionEventTimeout
  $DTMFVolume
  $DTMFTransportType
  $CallerIDTransportType 
  $CallerIDType 
  $FaxTransportMode 
  $V21ModemTransportType
  $V22ModemTransportType  
  $V23ModemTransportType  
  $V32ModemTransportType  
  $V34ModemTransportType  
  $FaxRelayMaxRate 
  $FaxRelayECMEnable 
  $FaxRelayRedundancyDepth 
  $FaxRelayEnhancedRedundancyDepth 
  $CNGDetectorMode  
  $DJBufMinDelay
  $DJBufOptFactor 
  $RTPRedundancyDepth 
  $RTPPackingFactor 
  $RFC2833TxPayloadType 
  $RFC2833RxPayloadType 
  $RFC2198PayloadType
  $FaxBypassPayloadType 
  $ModemBypassPayloadType
  $EnableStandardSIDPayloadType 
  $EnableAnswerDetector 
  $AnswerDetectorActivityDelay 
  $AnswerDetectorSilenceTime 
  $AnswerDetectorRedirection
  $AnswerDetectorSensitivity 
  $EnableEnergyDetector
  $EnergyDetectorQualityFactor
  $EnergyDetectorThreshold
  $EnablePatternDetector
  $EnableDSPIPMDetectors 
  $ACTIVESPEAKERSNOTIFICATIONMININTERVAL
  $DTMFGenerationTwist 
  $AMDDetectionSensitivity
  $G729EVMaxBitRate
  $G729EVLocalMBS
  $G729EVReceiveMBS 
  $NTEMaxDuration 
  $CEDTransferMode 
  $AMDBeepDetectionTimeout 
  $AMDBeepDetectionSensitivity 
  $MSRTAForwardErrorCorrectionEnable  
  $AMDSensitivityLevel 
  $AMDSensitivityParameterSuit 
  $RtpFWNonConfiguredPTHandling 
  $SilkTxInbandFEC  
  $ECHOCANCELLERType
  $ACOUSTICECHOSUPPMAXERLTHRESHOLD 
  $ACOUSTICECHOSUPPATTENUATIONINTENSITY 
  $ACOUSTICECHOSUPPMINREFDELAYx10MS 
  $ACOUSTICECHOSUPPRESSORSUPPORT
  $AmrOctetAlignedEnable 
  $RTPFWInvalidPacketHandling 
  $MediaSecurityBehaviour 
  $EnableSymmetricMKI 
  $SRTPofferedSuites = 0
  $ResetSRTPStateUponRekey 
}
Update-TypeData -TypeName WebParams -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | Select-Object -Property * } -Force
Update-TypeData -TypeName WebParams -MemberType Scriptmethod -MemberName 'viewRobustness' -Value { $this | Select-Object -Property TimeoutToRelatchRTPMsec,TimeoutToRelatchSRTPMsec,TimeoutToRelatchSilenceMsec,TimeoutToRelatchRTCPMsec,NewRtpStreamPackets,NewSRTPStreamPackets,NewRtcpStreamPackets,NewSRtcpStreamPackets } -Force

class WebParams {
  #AUthenticationServerGeneral  
  $MGMTUSELOCALUSERSDATABASE = 0
  $MGMTBEHAVIORONTIMEOUT = 1
  $MGMTLOGINCACHEMODE = 1
  $MGMTLOGINCACHETIMEOUT = 900
  #AUthenticationServerRadius  
  $EnableRADIUS = 0
  $WEBRADIUSLOGIN = 0
  $RadiusVSAVendorID =5003
  $RadiusVSAAccessAttribute =35
  $RADIUSTo = 2 
  $RADIUSRetransmission = 1 
  #AuthenticationServerLDAP
  $MGMTLDAPLOGIN = 0 
  $CustomerSN 
  $DenyAccessOnFailCount = '3'
  $DenyAuthenticationTimer = '60'
  $DisableWebConfig = '0'
  $DisplayLoginInformation = '0'
  $EnableMgmtTwoFactorAuthentication = '0'
  $EnableWebAccessFromAllInterfaces = '0'
  $EnforcePasswordComplexity = '0'
  $HTTPport = '80'
  $HTTPSCipherString
  $HTTPSPort = '80'
  $HTTPSRequireClientCertificate = '0' 
  $LogoFileName
  $LogoWidth = '145'
  $ResetWebPassword = '0'
  $UseProductName = '0'
  $UserInactivityTimer = '90'
  $UserProductName 
  $UseWebLogo = '0'
  $WebAccessList_0 = '0.0.0.0'
  $WebAccessList_1 = '0.0.0.0'
  $WebAccessList_10 = '0.0.0.0'
  $WebAccessList_11 = '0.0.0.0'
  $WebAccessList_12 = '0.0.0.0'
  $WebAccessList_13 = '0.0.0.0'
  $WebAccessList_14 = '0.0.0.0'
  $WebAccessList_15 = '0.0.0.0'
  $WebAccessList_16 = '0.0.0.0'
  $WebAccessList_17 = '0.0.0.0'
  $WebAccessList_18 = '0.0.0.0'
  $WebAccessList_19 = '0.0.0.0'
  $WebAccessList_2 = '0.0.0.0'
  $WebAccessList_20 = '0.0.0.0'
  $WebAccessList_21 = '0.0.0.0'
  $WebAccessList_22 = '0.0.0.0'
  $WebAccessList_23 = '0.0.0.0'
  $WebAccessList_24 = '0.0.0.0'
  $WebAccessList_25 = '0.0.0.0'
  $WebAccessList_26 = '0.0.0.0'
  $WebAccessList_27 = '0.0.0.0'
  $WebAccessList_28 = '0.0.0.0'
  $WebAccessList_29 = '0.0.0.0'
  $WebAccessList_3 = '0.0.0.0'
  $WebAccessList_30 = '0.0.0.0'
  $WebAccessList_31 = '0.0.0.0'
  $WebAccessList_32 = '0.0.0.0'
  $WebAccessList_33 = '0.0.0.0'
  $WebAccessList_34 = '0.0.0.0'
  $WebAccessList_35 = '0.0.0.0'
  $WebAccessList_36 = '0.0.0.0'
  $WebAccessList_37 = '0.0.0.0'
  $WebAccessList_38 = '0.0.0.0'
  $WebAccessList_39 = '0.0.0.0'
  $WebAccessList_4 = '0.0.0.0'
  $WebAccessList_40 = '0.0.0.0'
  $WebAccessList_41 = '0.0.0.0'
  $WebAccessList_42 = '0.0.0.0'
  $WebAccessList_43 = '0.0.0.0'
  $WebAccessList_44 = '0.0.0.0'
  $WebAccessList_45 = '0.0.0.0'
  $WebAccessList_46 = '0.0.0.0'
  $WebAccessList_47 = '0.0.0.0'
  $WebAccessList_48 = '0.0.0.0'
  $WebAccessList_49 = '0.0.0.0'
  $WebAccessList_5 = '0.0.0.0'
  $WebAccessList_6 = '0.0.0.0'
  $WebAccessList_7 = '0.0.0.0'
  $WebAccessList_8 = '0.0.0.0'
  $WebAccessList_9 = '0.0.0.0'
  $WebLoginBlockAutoComplete = '0'
  $WebLogoText 
  $WebSessionTimeout = '15'
  $WebUserPassChangeInterval = '1140'    
}
Update-TypeData -TypeName WebParams -MemberType Scriptmethod -MemberName 'viewSecuritySettings_Management' -Value { $this | Select-Object -Property EnableMgmtTwoFactorAuthentication } -Force

class SipParams { 
  #SIP Over TLS 
  $TLSRehadshaleInterval = '0'
  $SIPSRequireClientCertificate = '0'
  $PeerHostnameVerificationMode = '0'
  $VerifyServerCertificate = '0'
  $TLSRemoteSubjectName = ""
  #HTTPProxy
  $HTTPProxyApplication = '0'
  $HTTPPROXYSYSLOGDEBUGLEVEL =  '0'
  #LDAPSettings
  $LDAPGeneral = '0'
  $LDAPAUTHFILTER = ''
  #LDAPActiveDirectory
  $LDAPNUMERICATTRIBUTES = '' 
  $MSLDAPOCSNUMATTRIBUTENAME = 'msRTCSIP-Line'
  $MSLDAPPBXNUMATTRIBUTENAME = 'telephoneNumber'
  $MSLDAPMOBILENUMATTRIBUTENAME = 'mobile'
  $MSLDAPDISPLAYNAMEATTRIBUTENAME = 'displayName'
  $MSLDAPPRIVATENUMATTRIBUTENAME = 'msRTCSIP-PrivateLine'
  $MSLDAPPRIMARYKEY = 'telephoneNumber'
  $MSLDAPSECONDARYKEY = ''
  #LDAPCACHE
  $LDAPCACHEENABLE = '0'
  $LDAPCACHEENTRYTIMEOUT = ''
  $LDAPCACHEENTRYREMOVALTIMEOUT = ''
  #ApplicationsEnabling
  $ENABLESBCAPPLICATION = '1'
  #MediaSettingsGeneral
  $MEDIACHANNELS = '-1'
  $ENFORCEMEDIAORDER
  #MediaSettingsSBCSettings
  $SBCPREFERENCESMODE
  $SBCENFORCEMEDIAORDER
  #to sort
  $DECLAREAUDCCLIENT
  $RegistrationTime = '180'
  $SIPT1RTX
  $SIPT2RTX
  $SipGatewayName 
  $PROXYREDUNDANCYMODE 
  $GwDebugLevel = '0'
  $SIPMAXRTX
  $DisconnectOnBrokenConnection 
  $NoRTPDetectionTimeout 
  $RegistrationRetryTime = '30'
  $UseGatewayNameForOptions = '0'
  $SipTransportType  = '0'
  $GWREGISTRATIONNAME
  $SBCMaxCallDuration
  $REGISTRATIONTIMEDIVIDER = '50'
  $EnableSips = '0'
  $USETELURIFORASSERTEDID = '0'
  $EnableREASONHEADER = '0'
  $COMFORTNOISENEGOTIATION
  $EnableTCPCONNECTIONREUSE = '0'
  $RtcpXrReportMode
  $PROXYIPLISTREFRESHTIME
  $EnableGRUU 
  $DNSQUERYType
  $PROXYDNSQUERYType 
  $HOTSWAPRTX
  $SIPTCPTIMEOUT = '32'
  $REGISTRATIONTIMETHRESHOLD
  $REGISTERONINVITEFAILURE
  $SIPSDPSESSIONOWNER = 'AudiocodesGW'
  $SIPCHALLENGECACHINGMODE
  $RETRYAFTERTIME 
  $FAXCNGMODE 
  $TLSREHANDSHAKEINTERVAL 
  $REREGISTERONCONNECTIONFAILURE 
  $ReliableConnectionPersistentMode = '0'
  $ALLOWUNCLASSIFIEDCALLS 
  $TRANSCODINGMODE 
  $SBCDirectMedia 
  $EnableSINGLEDSPTRANSCODING = '0'
  $FAKERETRYAFTER 
  $SBC3XXBEHAVIOR 
  $SBCREFERBEHAVIOR
  $SBCKEEPCONTACTUSERINREGISTER
  $SBCMAXFORWARDSLIMIT
  $SBCALERTTIMEOUT
  $EMPTYAUTHORIZATIONHEADER
  $SBCGRUUMODE
  $SBCMINSE 
  $SBCPROXYREGISTRATIONTIME 
  $SBCUSERREGISTRATIONTIME
  $SBCSURVIVABILITYREGISTRATIONTIME 
  $SBCEXTENSIONSPROVISIONINGMODE
  $AUTHNONCEDURATION 
  $AUTHQOP
  $SBCEnableBYEAUTHENTICATION 
  $E911CALLBACKTIMEOUT
  $ENUMSERVICE
  $UseProxyIPasHost = '0'
  $SBCFORKINGHANDLINGMODE
  $SBCSESSIONEXPIRES
  $EnableSIPREC = '0' 
  $SBCSHAREDLINEREGMODE 
  $SBCDIVERSIONURIType 
  $SIPNATDETECTION 
  $EnableIDS = '0'
  $EnableNonInvite408Reply 
  $SendRejectOnOverload 
  $DisplayDefaultSIPPort  = '0'
  $PUBLICATIONIPGROUPID 
  $ENERGYDETECTORCMD 
  $ANSWERDETECTORCMD 
  $SBCSendTryingToSubscribe 
  $SBCUSERREGISTRATIONGRACETIME
  $SBCRtcpXrReportMode 
  $SIPRECSERVERDESTUSERNAME 
  $MAXGENERATEDREGISTERSRATE 
  $SBCDBROUTINGSEARCHMODE 
  $SBCPREEMPTIONMODE 
  $SBCEMERGENCYCONDITION 
  $SBCEMERGENCYRTPDIFFSERV 
  $SBCEMERGENCYSIGNALINGDIFFSERV 
  $WEBSOCKETPROTOCOLKEEPALIVEPERIOD 
  $IDSAlarmClearPeriod = '300'
  #Master Key Identifyer
  $ENABLESYMMETRICMKI
}
Update-TypeData -TypeName SipParams -MemberType Scriptmethod -MemberName 'viewSecuritySettings_SipOverTLS' -Value { $this | Select-Object -Property TLSRehadshaleInterval, VerifyServerCertificate, PeerHostnameVerificationMode, SIPSRequireClientCertificate, TLSRemoteSubjectName } -Force
Update-TypeData -TypeName SipParams -MemberType Scriptmethod -MemberName 'viewHTTPProxy' -Value { $this | Select-Object -Property HTTPProxyApplication,HTTPPROXYSYSLOGDEBUGLEVEL } -Force  
Update-TypeData -TypeName SipParams -MemberType Scriptmethod -MemberName 'viewLDAPSettings' -Value { $this | Select-Object -Property LDAPGeneral,LDAPAUTHFILTER } -Force
Update-TypeData -TypeName SipParams -MemberType Scriptmethod -MemberName 'viewLDAPActiveDirectory' -Value { $this | Select-Object -Property   LDAPNUMERICATTRIBUTES,MSLDAPOCSNUMATTRIBUTENAME,MSLDAPPBXNUMATTRIBUTENAME,MSLDAPMOBILENUMATTRIBUTENAME,MSLDAPDISPLAYNAMEATTRIBUTENAME,MSLDAPPRIVATENUMATTRIBUTENAME,MSLDAPPRIMARYKEY,MSLDAPSECONDARYKEY } -Force
Update-TypeData -TypeName SipParams -MemberType Scriptmethod -MemberName 'viewLDAPCache' -Value { $this | Select-Object -Property LDAPCACHEENABLE,LDAPCACHEENTRYTIMEOUT,LDAPCACHEENTRYREMOVALTIMEOUT } -Force
Update-TypeData -TypeName SipParams -MemberType Scriptmethod -MemberName 'viewApplicationsEnabling_General' -Value { $this | Select-Object -Property ENABLESBCAPPLICATION } -Force
  
class SNMPParams {
  $DisableSNMP = '0'
  $SNMPManagerTrapPort 
  $SNMPManagerIsUsed 
  $SNMPManagerTrapSendingEnable 
  $SNMPManagerTableIP_0 = '0.0.0.0'
  $SNMPManagerTableIP_1 = '0.0.0.0'
  $SNMPManagerTableIP_2 = '0.0.0.0'
  $SNMPManagerTableIP_3 = '0.0.0.0'
  $SNMPManagerTableIP_4 = '0.0.0.0'
  $SNMPTRUSTEDMGR = '0.0.0.0'
  $SNMPREADONLYCOMMUNITYSTRING_0 = ''
  $SNMPREADONLYCOMMUNITYSTRING_1 = ''
  $SNMPREADONLYCOMMUNITYSTRING_2 = ''
  $SNMPREADONLYCOMMUNITYSTRING_3 = ''
  $SNMPREADONLYCOMMUNITYSTRING_4 = ''
  $SNMPREADWRITECOMMUNITYSTRING_0 = ''
  $SNMPREADWRITECOMMUNITYSTRING_1 = ''
  $SNMPREADWRITECOMMUNITYSTRING_2 = ''
  $SNMPREADWRITECOMMUNITYSTRING_3 = ''
  $SNMPREADWRITECOMMUNITYSTRING_4 = '' 
  $SNMPTRAPCOMMUNITYSTRING = '' 
  $SNMPTrapManagerHostName = ''
  $SNMPPort = '161'
  $ChassisPhysicalAlias 
  $ChassisPhysicalAssetID
  $ifAlias
  $SendKeepAliveTrap = '0'
  $KeepAliveTrapPort = '161'
  $PM_EnableThresholdAlarms = '0'
  $SNMPSysOid = '1.3.6.1.5.1.5003.8.1.1'
  $SNMPTrapEnterpriseOid = '1.3.6.1.4.1.5003.9.10.1.21'
  $acUserInputAlarmDescription 
  $acUserInputAlarmSeverity 
  $AlarmHistoryTableMaxSize = '500'
  $ActiveAlarmTableMaxSize = '120'
  $NoAlarmForDisabledPort = '0'
  $SNMPEngineIDString

}

#Tables 

class InterfaceTable { 
  $InterfaceTable_ApplicationTypes
  $InterfaceTable_InterfaceMode
  $InterfaceTable_IPAddress = '0.0.0.0'
  $InterfaceTable_PrefixLength = '16'
  $InterfaceTable_Gateway = '0.0.0.0'
  $InterfaceTable_VlanID
  $InterfaceTable_InterfaceName
  $InterfaceTable_PrimaryDNSServerIPAddress = '0.0.0.0'
  $InterfaceTable_SecondaryDNSServerIPAddress = '0.0.0.0'
  $InterfaceTable_UnderlyingDevice
}
Update-TypeData -TypeName InterfaceTable -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | Select-Object -Property InterfaceTable_InterfaceName,InterfaceTable_ApplicationTypes,InterfaceTable_IPAddress,InterfaceTable_UnderlyingDevice } -Force
Update-TypeData -TypeName InterfaceTable -MemberType Scriptmethod -MemberName 'viewGeneral' -Value { $this | Select-Object -Property InterfaceTable_InterfaceName, InterfaceTable_ApplicationTypes, InterfaceTable_UnderlyingDevice } -Force
Update-TypeData -TypeName InterfaceTable -MemberType Scriptmethod -MemberName 'viewDNS' -Value { $this | Select-Object -Property InterfaceTable_PrimaryDNSServerIPAddress, InterfaceTable_SecondaryDNSServerIPAddress } -Force
Update-TypeData -TypeName InterfaceTable -MemberType Scriptmethod -MemberName 'viewIPAddress' -Value { $this | Select-Object -Property InterfaceTable_InterfaceMode, InterfaceTable_IPAddress, InterfaceTable_PrefixLength, InterfaceTable_Gateway } -Force
$itemindex_InterfaceTable.foreach({ update-typedata -typename InterfaceTable -MemberType AliasProperty -Membername $_.split("_")[1] -value $_ })

class DeviceTable {
  $DeviceTable_VlanID = 1
  $DeviceTable_UnderlyingInterface = ""
  $DeviceTable_DeviceName = ""
  $DeviceTable_Tagging = 1
  $DeviceTable_MTU = 1500
}
Update-TypeData -TypeName DeviceTable -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object DeviceTable_DeviceName,DeviceTable_UnderlyingInterface } -Force
Update-TypeData -TypeName DeviceTable -MemberType Scriptmethod -MemberName 'viewGeneral' -Value { $this | Select-Object -Property DeviceTable_DeviceName, DeviceTable_VlanID, DeviceTable_UnderlyingInterface, DeviceTable_Tagging, DeviceTable_MTU } -Force
$itemindex_DeviceTable.foreach({ update-typedata -typename DeviceTable -MemberType AliasProperty -Membername $_.split("_")[1] -value $_ })

class EtherGroupTable {
  $EtherGroupTable_Group
  $EtherGroupTable_Mode = 2
  $EtherGroupTable_Member1
  $EtherGroupTable_Member2
}
Update-TypeData -TypeName EtherGroupTable -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object EtherGroupTable_Group,EtherGroupTable_Mode,EtherGroupTable_Member1,EtherGroupTable_Member2 } -Force
$itemindex_EtherGroupTable.foreach({ update-typedata -typename EtherGroupTable -MemberType AliasProperty -Membername $_.split("_")[1] -value $_ })

class PhysicalPortsTable {
  $PhysicalPortsTable_Port
  $PhysicalPortsTable_Mode
  $PhysicalPortsTable_SpeedDuplex
  $PhysicalPortsTable_PortDescription
  $PhysicalPortsTable_GroupMember
  $PhysicalPortsTable_GroupStatus
}
Update-TypeData -TypeName PhysicalPortsTable -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object PhysicalPortsTable_Port,PhysicalPortsTable_Mode,PhysicalPortsTable_GroupStatus } -Force
Update-TypeData -TypeName PhysicalPortsTable -MemberType Scriptmethod -MemberName 'viewGeneral' -Value { $this | Select-Object -Property PhysicalPortsTable_Port, PhysicalPortsTable_PortDescription, PhysicalPortsTable_Mode, PhysicalPortsTable_SpeedDuplex } -Force
Update-TypeData -TypeName PhysicalPortsTable -MemberType Scriptmethod -MemberName 'viewEthernetGroup' -Value { $this | Select-Object -Property PhysicalPortsTable_GroupMember, PhysicalPortsTable_GroupStatus } -Force
$itemindex_PhysicalPortsTable.foreach({ update-typedata -typename PhysicalPortsTable -MemberType AliasProperty -Membername $_.split("_")[1] -value $_ })

class StaticRouteTable {
  $StaticRouteTable_DeviceName
  $StaticRouteTable_Destination = '0.0.0.0'
  $StaticRouteTable_PrefixLength = '16'
  $StaticRouteTable_Gateway = '0.0.0.0'
  $StaticRouteTable_Description
}
Update-TypeData -TypeName StaticRouteTable -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object StaticRouteTable_Destination,StaticRouteTable_Gateway } -Force
Update-TypeData -TypeName StaticRouteTable -MemberType Scriptmethod -MemberName 'viewGeneral' -Value { $this | Select-Object -Property StaticRouteTable_Destination, StaticRouteTable_PrefixLength, StaticRouteTable_Gateway, StaticRouteTable_DeviceName,  StaticRouteTable_Description } -Force
  
class NATTranslation{
  $NATTranslation_SrcIPInterfaceName
  $NATTranslation_TargetIPAddress
  $NATTranslation_SourceStartPort
  $NATTranslation_SourceEndPort
  $NATTranslation_TargetStartPort
  $NATTranslation_TargetEndPort
}
Update-TypeData -TypeName NATTranslation -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object * } -Force
Update-TypeData -TypeName NATTranslation -MemberType Scriptmethod -MemberName 'viewSource' -Value { $this | Select-Object -Property NATTranslation_SrcIPInterfaceName, NATTranslation_SourceStartPort, NATTranslation_SourceEndPort } -Force
Update-TypeData -TypeName NATTranslation -MemberType Scriptmethod -MemberName 'viewTarget' -Value { $this | Select-Object -Property NATTranslation_TargetIPAddress, NATTranslation_TargetStartPort, NATTranslation_TargetEndPort } -Force
   
class TLSContexts {
  $TLSContexts_Name
  $TLSContexts_TLSVersion = 0
  $TLSContexts_DTLSVersion = 0
  $TLSContexts_ServerCipherString = 'RC4:AES128'
  $TLSContexts_ClientCipherString = 'DEFAULT'
  $TLSContexts_RequireStrictCert = 0
  $TLSContexts_OcspEnable = 0
  $TLSContexts_OcspServerPrimary = '0.0.0.0'
  $TLSContexts_OcspServerSecondary = '0.0.0.0'
  $TLSContexts_OcspServerPort = 2560
  $TLSContexts_OcspDefaultResponse = 0
  $TLSContexts_DHKeySize = 0
}
Update-TypeData -TypeName TLSContexts -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | Select-Object -Property TLSContexts_Name, TLSContexts_TLSVersion, TLSContexts_DTLSVersion, TLSContexts_ServerCipherString } -Force
Update-TypeData -TypeName TLSContexts -MemberType Scriptmethod -MemberName 'viewGeneral' -Value { $this | Select-Object -Property TLSContexts_Name, TLSContexts_TLSVersion, TLSContexts_DTLSVersion, TLSContexts_ServerCipherString, TLSContexts_ClientCipherString, TLSContexts_RequireStrictCert, TLSContexts_DHKeySize } -Force
Update-TypeData -TypeName TLSContexts -MemberType Scriptmethod -MemberName 'viewOCSP' -Value { $this | Select-Object -Property TLSContexts_OcspEnable, TLSContexts_OcspServerPrimary, TLSContexts_OcspServerSecondary, TLSContexts_OcspServerPort, TLSContexts_OcspDefaultResponse } -Force
 
class AccessList {
  $AccessList_Source_IP = '0.0.0.0'
  $AccessList_Source_Port = '0'
  $AccessList_PrefixLen = '0'
  $AccessList_Start_Port = '0'
  $AccessList_End_Port = '65535'
  $AccessList_Protocol = 'ANY'
  $AccessList_Use_Specific_Interface = '0'
  $AccessList_Interface_ID
  $AccessList_Packet_Size = '0'
  $AccessList_Byte_Rate = '0'
  $AccessList_Byte_Burst = '0'
  $AccessList_Allow_Type = '0'
  $AccessList_Allow_Type_enum = '0'
}
Update-TypeData -TypeName AccessList -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object AccessList_Index,AccessList_Source_IP,ACCESSLIST_Allow_type_enum } -Force
Update-TypeData -TypeName AccessList -MemberType Scriptmethod -MemberName 'viewMatch'    -value { $this | select-object AccessList_Index,AccessList_Source_IP,AccessList_Source_Port,AccessList_PrefixLen,AccessList_Start_Port,AccessList_End_Port,AccessList_Protocol,AccessList_Use_Specific_Interface,AccessList_Interface_ID } -Force
Update-TypeData -TypeName AccessList -MemberType Scriptmethod -MemberName 'viewAction'   -Value { $this | select-object AccessList_Allow_Type,ACCESSLIST_Allow_type_enum,AccessList_Packet_Size,AccessList_Byte_Rate,AccessList_Byte_Burst } -Force

class DiffServToVlanPriority {
  $DiffServToVlanPriority_DiffServ = '0' 
  $DiffServToVlanPriority_VlanPriority = '0'
}
Update-TypeData -TypeName DiffServToVlanPriority -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object DiffServToVlanPriority_DiffServ,DiffServToVlanPriority_VlanPriority } -Force

class RadiusServers {
  $RadiusServers_ServerGroup
  $RadiusServers_IPAddress = '0.0.0.0'
  $RadiusServers_AuthenticationPort = '1645'
  $RadiusServers_AccountingPort = '1646'
  $RadiusServers_SharedSecret
}
Update-TypeData -TypeName RadiusServers -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object RadiusServers_IPAddress,RadiusServers_AuthenticationPort,RadiusServers_AccountingPort,@{n="RadiusServers_SharedSecret";e={"SharedSecret"} } } -Force

class LDAPServerGroups { 
  $LdapServerGroups_Name
  $LdapServerGroups_ServerType  = '0'
  $LdapServerGroups_SearchMethod = '0'
  $LdapServerGroups_CacheEntryTimeout ='1200'
  $LdapServerGroups_CacheEntryRemovalTimeout ='0'
  $LdapServerGroups_SearchDnsMethod = '1'
}
Update-TypeData -TypeName LDAPServerGroups -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object LdapServerGroups_Name,LdapServerGroups_ServerType } -Force
Update-TypeData -TypeName LDAPServerGroups -MemberType Scriptmethod -MemberName 'viewGeneral' -Value { $this | select-object LdapServerGroups_Name,LdapServerGroups_ServerType,LdapServerGroups_SearchMethod,LdapServerGroups_SearchDnsMethod } -Force
Update-TypeData -TypeName LDAPServerGroups -MemberType Scriptmethod -MemberName 'viewCache' -Value { $this | select-object LdapServerGroups_CacheEntryTimeout,LdapServerGroups_CacheEntryRemovalTimeout } -Force

class LdapConfiguration {
  $LdapConfiguration_Group
  $LdapConfiguration_LdapConfServerIp
  $LdapConfiguration_LdapConfServerPort = "389"
  $LdapConfiguration_LdapConfServerMaxRespondTime ='3000'
  $LdapConfiguration_LdapConfServerDomainName
  $LdapConfiguration_LdapConfPassword = ""
  $LdapConfiguration_LdapConfBindDn
  $LdapConfiguration_Interface
  $LdapConfiguration_MngmAuthAtt
  $LdapConfiguration_useTLS = "0"
  $LdapConfiguration_ConnectionStatus
  $LdapConfiguration_ContextName
  $LdapConfiguration_LdapConfInterfaceType
  $LdapConfiguration_Type
  $LdapConfiguration_VerifyCertificate
}
Update-TypeData -TypeName LdapConfiguration -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object LdapConfiguration_Group,LdapConfiguration_LdapConfServerIp } -Force
Update-TypeData -TypeName LdapConfiguration -MemberType Scriptmethod -MemberName 'viewGeneral' -Value { $this | select-object LdapConfiguration_Interface,LdapConfiguration_useTLS,LdapConfiguration_ContextName } -Force
Update-TypeData -TypeName LdapConfiguration -MemberType Scriptmethod -MemberName 'viewQuery' -Value { $this | select-object LdapConfiguration_LdapConfPassword,LdapConfiguration_LdapConfBindDn,LdapConfiguration_MngmAuthAtt } -Force
Update-TypeData -TypeName LdapConfiguration -MemberType Scriptmethod -MemberName 'viewConnection' -Value { $this | select-object LdapConfiguration_LdapConfServerIp,LdapConfiguration_LdapConfServerPort,LdapConfiguration_LdapConfServerMaxRespondTime,LdapConfiguration_LdapConfServerDomainName } -Force


class DhcpServer { 
  $DhcpServer_InterfaceName
  $DhcpServer_StartIPAddress = '192.168.0.100'
  $DhcpServer_EndIPAddress = '192.168.0.148'
  $DhcpServer_SubnetMask = '255.255.255.0'
  $DhcpServer_LeaseTime
  $DhcpServer_DNSServer1 = '0.0.0.0'
  $DhcpServer_DNSServer2 = '0.0.0.0'
  $DhcpServer_NetbiosNameServer
  $DhcpServer_NetbiosNodeType
  $DhcpServer_NTPServer1 = '0.0.0.0'
  $DhcpServer_NTPServer2 = '0.0.0.0'
  $DhcpServer_TimeOffset = '0'
  $DhcpServer_TftpServer
  $DhcpServer_BootFileName
  $DhcpServer_ExpandBootfileName
  $DhcpServer_OverrideRouter = '0.0.0.0'
  $DhcpServer_SipServer
  $DhcpServer_SipServerType
}
Update-TypeData -TypeName DhcpServer -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object DhcpServer_Index,DhcpServer_StartIPAddress,DhcpServer_SubnetMask } -Force
Update-TypeData -TypeName DhcpServer -MemberType ScriptMethod -MemberName 'viewGeneral' -Value { $this | Select-Object -Property DhcpServer_InterfaceName, DhcpServer_StartIPAddress, DhcpServer_EndIPAddress, DhcpServer_SubnetMask, DhcpServer_LeaseTime } -Force
Update-TypeData -TypeName DhcpServer -MemberType ScriptMethod -MemberName 'viewDNS' -Value { $this  | Select-Object -Property DhcpServer_DNSServer1, DhcpServer_DNSServer2 } -Force
Update-TypeData -TypeName DhcpServer -MemberType ScriptMethod -MemberName 'viewNetBios' -Value {  $this | Select-Object -Property DhcpServer_NetbiosNameServer, DhcpServer_NetbiosNodeType } -Force
Update-TypeData -TypeName DhcpServer -MemberType ScriptMethod -MemberName 'viewTimeandDate' -Value { $this | Select-Object -Property DhcpServer_NTPServer1, DhcpServer_NTPServer2, DhcpServer_TimeOffset } -Force
Update-TypeData -TypeName DhcpServer -MemberType ScriptMethod -MemberName 'viewBootFile' -Value { $this | Select-Object -Property DhcpServer_TftpServer, DhcpServer_BootFileName, DhcpServer_ExpandBootfileName } -Force
Update-TypeData -TypeName DhcpServer -MemberType ScriptMethod -MemberName 'viewRouter' -Value { $this | Select-Object -Property DhcpServer_OverrideRouter } -Force
Update-TypeData -TypeName DhcpServer -MemberType ScriptMethod -MemberName 'viewSip' -Value { $this | Select-Object -Property DhcpServer_SipServer, DhcpServer_SipServerType } -Force

class DhcpVendorClass {
  $DhcpVendorClass_DhcpServerIndex
  $DhcpVendorClass_VendorClassId
}
Update-TypeData -TypeName DhcpVendorClass -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object * } -Force
Update-TypeData -TypeName DhcpVendorClass -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object * } -Force
Update-TypeData -TypeName DhcpVendorClass -MemberType Scriptmethod -MemberName 'viewGeneral' -Value { $this | select-object DhcpVendorClass_DhcpServerIndex,DhcpVendorClass_VendorClassId } -Force

class DhcpOption {
  $DhcpOption_DhcpServerIndex
  $DhcpOption_Option
  $DhcpOption_Type
  $DhcpOption_Value
  $DhcpOption_ExpandValue
}
Update-TypeData -TypeName DhcpOption -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object * } -Force
Update-TypeData -TypeName DhcpOption -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object * } -Force
Update-TypeData -TypeName DhcpOption -MemberType Scriptmethod -MemberName 'viewGeneral' -Value { $this | select-object DhcpOption_DhcpServerIndex,DhcpOption_Option,DhcpOption_TypeDhcpOption_Value,DhcpOption_ExpandValue } -Force

class DhcpStaticIP {
  $DhcpStaticIP_DhcpServerIndex
  $DhcpStaticIP_IPAddress
  $DhcpStaticIP_MACAddress
}
Update-TypeData -TypeName DhcpStaticIP -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object * } -Force
Update-TypeData -TypeName DhcpStaticIP -MemberType Scriptmethod -MemberName 'viewGeneral' -Value { $this | select-object DhcpStaticIP_DhcpServerIndex,DhcpStaticIP_IPAddress,DhcpStaticIP_MACAddress } -Force

class DNS2IP {
  $Dns2Ip_DomainName
  $Dns2Ip_FirstIpAddress
  $Dns2Ip_SecondIpAddress
  $Dns2Ip_ThirdIpAddress
}
Update-TypeData -TypeName DNS2IP -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object DNS2IP_Index,Dns2Ip_DomainName,Dns2Ip_FirstIpAddress } -Force
Update-TypeData -TypeName DNS2IP -MemberType Scriptmethod -MemberName 'viewGeneral' -Value { $this | select-object Dns2Ip_DomainName,Dns2Ip_FirstIpAddress,Dns2Ip_SecondIpAddress,Dns2Ip_ThirdIpAddress } -Force
 
class SRV2IP {
  $SRV2IP_InternalDomain
  $SRV2IP_TransportType
  $SRV2IP_Dns1
  $SRV2IP_Priority1
  $SRV2IP_Weight1
  $SRV2IP_Port1
  $SRV2IP_Dns2
  $SRV2IP_Priority2
  $SRV2IP_Weight2
  $SRV2IP_Port2
  $SRV2IP_Dns3
  $SRV2IP_Priority3
  $SRV2IP_Weight3
  $SRV2IP_Port3
}
Update-TypeData -TypeName SRV2IP -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object SRV2IP_Index,SRV2IP_InternalDomain } -Force
Update-TypeData -TypeName SRV2IP -MemberType Scriptmethod -MemberName 'viewGeneral' -Value { $this | select-object SRV2IP_InternalDomain,SRV2IP_TransportType } -Force
Update-TypeData -TypeName SRV2IP -MemberType Scriptmethod -MemberName 'view1stEntry' -Value { $this | select-object SRV2IP_Dns1,SRV2IP_Priority1,SRV2IP_Weight1,SRV2IP_Port1 } -Force
Update-TypeData -TypeName SRV2IP -MemberType Scriptmethod -MemberName 'view2ndEntry' -Value { $this | select-object SRV2IP_Dns2,SRV2IP_Priority2,SRV2IP_Weight2,SRV2IP_Port2 } -Force
Update-TypeData -TypeName SRV2IP -MemberType Scriptmethod -MemberName 'view3rdEntry' -Value { $this | select-object SRV2IP_Dns3,SRV2IP_Priority3,SRV2IP_Weight3,SRV2IP_Port3 } -Force

class HTTPRemoteServices {
  $HTTPRemoteServices_Name
  $HTTPRemoteServices_Path
  $HTTPRemoteServices_HTTPType
  $HTTPRemoteServices_Policy
  $HTTPRemoteServices_LoginNeeded
  $HTTPRemoteServices_PersistentConnection
  $HTTPRemoteServices_NumOfSockets
  $HTTPRemoteServices_AuthUserName
  $HTTPRemoteServices_AuthPassword
  $HTTPRemoteServices_TLSContext
  $HTTPRemoteServices_VerifyCertificate
  $HTTPRemoteServices_TimeOut
  $HTTPRemoteServices_KeepAliveTimeOut
  $HTTPRemoteServices_ServiceStatus
}
Update-TypeData -TypeName HTTPRemoteServices -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object * } -Force
Update-TypeData -TypeName HTTPRemoteServices -MemberType Scriptmethod -MemberName 'viewGeneral' -Value { $this | Select-Object -Property HTTPRemoteServices_Name, HTTPRemoteServices_HTTPType, HTTPRemoteServices_Path, HTTPRemoteServices_ServiceStatus } -Force
Update-TypeData -TypeName HTTPRemoteServices -MemberType Scriptmethod -MemberName 'viewConnection' -Value {  $this | Select-Object -Property HTTPRemoteServices_Policy, HTTPRemoteServices_PersistentConnection, HTTPRemoteServices_NumOfSockets } -Force
Update-TypeData -TypeName HTTPRemoteServices -MemberType Scriptmethod -MemberName 'viewLogin' -Value {  $this | Select-Object -Property HTTPRemoteServices_LoginNeeded, HTTPRemoteServices_AuthUserName, HTTPRemoteServices_AuthPassword } -Force
Update-TypeData -TypeName HTTPRemoteServices -MemberType Scriptmethod -MemberName 'viewSecurity' -Value {  $this | Select-Object -Property HTTPRemoteServices_TLSContext, HTTPRemoteServices_VerifyCertificate } -Force
Update-TypeData -TypeName HTTPRemoteServices -MemberType Scriptmethod -MemberName 'viewTimeouts' -Value {  $this | Select-Object -Property HTTPRemoteServices_TimeOut, HTTPRemoteServices_KeepAliveTimeOut } -Force

class HTTPInterface{
 $HTTPInterface_InterfaceName
  $HTTPInterface_NetworkInterface
  $HTTPInterface_Protocol
  $HTTPInterface_Port
  $HTTPInterface_TLSContext
  $HTTPInterface_VerifyCert
}
Update-TypeData -TypeName HTTPInterface -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object HTTPInterface_InterfaceName,HTTPInterface_NetworkInterface,HTTPInterface_Protocol } -Force
Update-TypeData -TypeName HTTPInterface -MemberType Scriptmethod -MemberName 'viewGeneral' -Value { $this | select-object HTTPInterface_InterfaceName,HTTPInterface_NetworkInterface,HTTPInterface_Protocol,HTTPInterface_Port } -Force
Update-TypeData -TypeName HTTPInterface -MemberType Scriptmethod -MemberName 'viewSecurity' -Value { $this | select-object HTTPInterface_TLSContext,HTTPInterface_VerifyCert } -Force

class HTTPProxyService {
  $HTTPProxyService_ServiceName
  $HTTPProxyService_ListeningInterface
  $HTTPProxyService_URLPrefix
  $HTTPProxyService_KeepAliveMode
}
Update-TypeData -TypeName HTTPProxyService -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object HTTPProxyService_Index,HTTPProxyService_ServiceName } -Force
Update-TypeData -TypeName HTTPProxyService -MemberType Scriptmethod -MemberName 'viewGeneral' -Value { $this | select-object HTTPProxyService_ServiceName,HTTPProxyService_ListeningInterface,HTTPProxyService_URLPrefix,HTTPProxyService_KeepAliveMode} -Force
     
class HTTPProxyHost {
  $HTTPProxyHost_HTTPProxyServiceId
  $HTTPProxyHost_HTTPProxyHostId
  $HTTPProxyHost_NetworkInterface
  $HTTPProxyHost_IpAddress
  $HTTPProxyHost_Protocol
  $HTTPProxyHost_Port
  $HTTPProxyHost_TLSContext
  $HTTPProxyHost_VerifyCert
}
Update-TypeData -TypeName HTTPProxyHost -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object HTTPProxyHost_Index,HTTPProxyHost_NetworkInterface } -Force
Update-TypeData -TypeName HTTPProxyHost -MemberType Scriptmethod -MemberName 'viewGeneral' -Value { $this | select-object HTTPProxyHost_NetworkInterface,HTTPProxyHost_IpAddress,HTTPProxyHost_Protocol,HTTPProxyHost_Port } -Force
Update-TypeData -TypeName HTTPProxyHost -MemberType Scriptmethod -MemberName 'viewSecurity' -Value { $this | select-object HTTPProxyHost_TLSContext,HTTPProxyHost_VerifyCert } -Force

class HTTPRemoteHosts { 
  $HTTPRemoteHosts_HTTPRemoteServiceIndex
  $HTTPRemoteHosts_RemoteHostIndex
  $HTTPRemoteHosts_Name
  $HTTPRemoteHosts_Address
  $HTTPRemoteHosts_Port
  $HTTPRemoteHosts_Interface
  $HTTPRemoteHosts_HTTPTransportType
  $HTTPRemoteHosts_HostStatus
    
}
Update-TypeData -TypeName HTTPRemoteHosts -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object * } -Force

class EMSService {
    $EMSService_ServiceName
    $EMSService_PrimaryServer
    $EMSService_SecondaryServer
    $EMSService_DeviceLoginInterface
    $EMSService_EMSInterface
}
Update-TypeData -TypeName EMSService -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object EMSService_Index,EMSService_ServiceName } -Force
Update-TypeData -TypeName EMSService -MemberType Scriptmethod -MemberName 'viewGeneral' -Value { $this | select-object EMSService_ServiceName } -Force
Update-TypeData -TypeName EMSService -MemberType Scriptmethod -MemberName 'viewDevice' -Value { $this | select-object EMSService_DeviceLoginInterface } -Force
Update-TypeData -TypeName EMSService -MemberType Scriptmethod -MemberName 'viewEMS' -Value { $this | select-object EMSService_EMSInterface,EMSService_PrimaryServer,EMSService_SecondaryServer } -Force

class SRD {
  $SRD_Name
  $SRD_IntraSRDMediaAnchoring
  $SRD_BlockUnRegUsers = '0'
  $SRD_MaxNumOfRegUsers = '-1'
  $SRD_EnableUnAuthenticatedRegistrations = '1'
  $SRD_SharingPolicy = '0'
  $SRD_UsedByRoutingServer = '0'
  $SRD_SBCOperationMode = '0'
  $SRD_SBCRoutingPolicyName
  $SRD_SBCDialPlanName
}
Update-TypeData -TypeName SRD -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object SRD_Name,SRD_SharingPolicy,SRD_SBCOperationMode } -Force
Update-TypeData -TypeName SRD -MemberType Scriptmethod -MemberName 'viewGeneral' -Value { $this | select-object SRD_Name,SRD_SharingPolicy,SRD_SBCOperationMode,SRD_SBCRoutingPolicyName,SRD_UsedByRoutingServer } -Force
Update-TypeData -TypeName SRD -MemberType Scriptmethod -MemberName 'viewRegistration' -Value { $this | select-object SRD_MaxNumOfRegUsers,SRD_EnableUnAuthenticatedRegistrations,SRD_BlockUnRegUsers  } -Force

class SIPInterface {
  $SIPInterface_InterfaceName
  $SIPInterface_NetworkInterface
  $SIPInterface_ApplicationType
  $SIPInterface_UDPPort = '5060'
  $SIPInterface_TCPPort = '5060'
  $SIPInterface_TLSPort = '5061'
  $SIPInterface_AdditionalUDPPorts
  $SIPInterface_SRDName
  $SIPInterface_MessagePolicyName
  $SIPInterface_TLSContext
  $SIPInterface_TLSMutualAuthentication
  $SIPInterface_TCPKeepaliveEnable ='0'
  $SIPInterface_ClassificationFailureResponseType = '500'
  $SIPInterface_PreClassificationManSet
  $SIPInterface_EncapsulatingProtocol = '0'
  $SIPInterface_MediaRealm
  $SIPInterface_SBCDirectMedia = '0'
  $SIPInterface_BlockUnRegUsers ='-1'
  $SIPInterface_MaxNumOfRegUsers
  $SIPInterface_EnableUnAuthenticatedRegistrations = '-1'
  $SIPInterface_UsedByRoutingServer = '0'
  $SIPInterface_TopologyLocation = '0'
  $SIPInterface_PreParsingManSetName
}
Update-TypeData -TypeName SIPInterface -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object SIPInterface_InterfaceName,SIPInterface_ApplicationType,SIPInterface_UDPPort,SIPInterface_TCPPort,SIPInterface_TLSPort } -Force
Update-TypeData -TypeName SIPInterface -MemberType Scriptmethod -MemberName 'viewGeneral' -Value { $this | select-object SIPInterface_InterfaceName,SIPInterface_TopologyLocation,SIPInterface_NetworkInterface,SIPInterface_ApplicationType,SIPInterface_UDPPort,SIPInterface_TCPPort,SIPInterface_TLSPort,SIPInterface_EncapsulatingProtocol,SIPInterface_TCPKeepaliveEnable,SIPInterface_UsedByRoutingServer } -Force
Update-TypeData -TypeName SIPInterface -MemberType Scriptmethod -MemberName 'viewClassification' -Value { $this | select-object SIPInterface_ClassificationFailureResponseType,SIPInterface_PreClassificationManSet } -Force
Update-TypeData -TypeName SIPInterface -MemberType Scriptmethod -MemberName 'viewMedia' -Value { $this | select-object SIPInterface_MediaRealm,SIPInterface_SBCDirectMedia } -Force
Update-TypeData -TypeName SIPInterface -MemberType Scriptmethod -MemberName 'viewSecurity' -Value { $this | select-object SIPInterface_TLSContext,SIPInterface_TLSMutualAuthentication,SIPInterface_MessagePolicyName,SIPInterface_EnableUnAuthenticatedRegistrations,SIPInterface_MaxNumOfRegUsers } -Force

class CpMediaRealm {
  $CpMediaRealm_MediaRealmName
  $CpMediaRealm_IPv4IF
  $CpMediaRealm_IPv6IF
  $CpMediaRealm_PortRangeStart
  $CpMediaRealm_MediaSessionLeg
  $CpMediaRealm_PortRangeEnd
  $CpMediaRealm_IsDefault
  $CpMediaRealm_QoeProfile
  $CpMediaRealm_BWProfile
  $CpMediaRealm_TopologyLocation
}
Update-TypeData -TypeName CpMediaRealm -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object CpMediaRealm_MediaRealmName,CpMediaRealm_IsDefault } -Force
Update-TypeData -TypeName CpMediaRealm -MemberType Scriptmethod -MemberName 'viewGeneral' -Value { $this | select-object CpMediaRealm_MediaRealmName,CpMediaRealm_TopologyLocation,CpMediaRealm_IPv4IF,CpMediaRealm_IPv6IF,CpMediaRealm_PortRangeStart,CpMediaRealm_MediaSessionLeg,CpMediaRealm_PortRangeEnd,CpMediaRealm_IsDefault } -Force
Update-TypeData -TypeName CpMediaRealm -MemberType Scriptmethod -MemberName 'viewQualityofExperience' -Value { $this | select-object CpMediaRealm_QoeProfile,CpMediaRealm_BWProfile } -Force

class RemoteMediaSubnet {
  $RemoteMediaSubnet_Realm
  $RemoteMediaSubnet_RemoteMediaSubnetIndex
  $RemoteMediaSubnet_RemoteMediaSubnetName
  $RemoteMediaSubnet_PrefixLength = '16'
  $RemoteMediaSubnet_AddressFamily = '2'
  $RemoteMediaSubnet_DstIPAddress ='0.0.0.0'
  $RemoteMediaSubnet_QOEProfileName
  $RemoteMediaSubnet_BWProfileName =''
}
Update-TypeData -TypeName RemoteMediaSubnet -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object * } -Force
Update-TypeData -TypeName RemoteMediaSubnet -MemberType Scriptmethod -MemberName 'viewGeneral' -Value { $this | select-object RemoteMediaSubnet_RemoteMediaSubnetName,RemoteMediaSubnet_PrefixLength,RemoteMediaSubnet_AddressFamily,RemoteMediaSubnet_DstIPAddress,RemoteMediaSubnet_QOEProfileName,RemoteMediaSubnet_BWProfileName } -Force


class MediaRealmExtension {
  $MediaRealmExtension_MediaRealmIndex
  $MediaRealmExtension_ExtensionIndex
  $MediaRealmExtension_IPv4IF
  $MediaRealmExtension_IPv6IF
  $MediaRealmExtension_PortRangeStart
  $MediaRealmExtension_PortRangeEnd
  $MediaRealmExtension_MediaSessionLeg
}

Update-TypeData -TypeName MediaRealmExtension -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object MediaRealmExtension_IPv4IF,MediaRealmExtension_IPv6IF,MediaRealmExtension_PortRangeStart,MediaRealmExtension_PortRangeEnd,MediaRealmExtension_MediaSessionLeg } -Force
Update-TypeData -TypeName MediaRealmExtension -MemberType Scriptmethod -MemberName 'viewGeneral' -Value { $this | select-object MediaRealmExtension_IPv4IF,MediaRealmExtension_IPv6IF,MediaRealmExtension_PortRangeStartMediaRealmExtension_PortRangeEnd,MediaRealmExtension_MediaSessionLeg } -Force

class ProxySet {

  $ProxySet_ProxyName
  $ProxySet_EnableProxyKeepAlive
  $ProxySet_ProxyKeepAliveTime
  $ProxySet_ProxyLoadBalancingMethod
  $ProxySet_IsProxyHotSwap
  $ProxySet_SRDName
  $ProxySet_ClassificationInput
  $ProxySet_TLSContextName
  $ProxySet_ProxyRedundancyMode
  $ProxySet_DNSResolveMethod
  $ProxySet_KeepAliveFailureResp
  $ProxySet_GWIPv4SIPInterfaceName
  $ProxySet_SBCIPv4SIPInterfaceName
  $ProxySet_GWIPv6SIPInterfaceName
  $ProxySet_SBCIPv6SIPInterfaceName
  $ProxySet_MinActiveServersLB
  $ProxySet_SuccessDetectionRetries
  $ProxySet_SuccessDetectionInterval
  $ProxySet_FailureDetectionRetransmissions
  
}
Update-TypeData -TypeName ProxySet -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object ProxySet_ProxyName,ProxySet_EnableProxyKeepAlive,ProxySet_IsProxyHotSwap,ProxySet_ProxyLoadBalancingMethod,ProxySet_ProxyLoadBalancingMethod,ProxySet_ProxyLoadBalancingMethod } -Force
Update-TypeData -TypeName ProxySet -MemberType Scriptmethod -MemberName 'viewGeneral' -Value { $this | select-object ProxySet_ProxyName,ProxySet_SBCIPv4SIPInterfaceName,ProxySet_GWIPv4SIPInterfaceName,ProxySet_SBCIPv4SIPInterfaceName,ProxySet_GWIPv6SIPInterfaceName,ProxySet_SBCIPv6SIPInterfaceName,ProxySet_TLSContextName  } -Force
Update-TypeData -TypeName ProxySet -MemberType Scriptmethod -MemberName 'viewKeepalive' -Value { $this | select-object ProxySet_ProxyKeepAliveTime, ProxySet_KeepAliveFailureResp, ProxySet_SuccessDetectionRetries, ProxySet_SuccessDetectionInterval,ProxySet_FailureDetectionRetransmissions } -Force
Update-TypeData -TypeName ProxySet -MemberType Scriptmethod -MemberName 'viewRedundancy' -Value { $this | select-object ProxySet_MinActiveServersLB,ProxySet_ProxyLoadBalancingMethod,ProxySet_IsProxyHotSwap,ProxySet_ProxyLoadBalancingMethod } -Force
Update-TypeData -TypeName ProxySet -MemberType Scriptmethod -MemberName 'viewAdvanced' -Value { $this | select-object ProxySet_ClassificationInput,ProxySet_DNSResolveMethod  } -Force

class proxyIP {
  $ProxyIp_ProxySetId
  $ProxyIp_ProxyIpIndex
  $ProxyIp_IpAddress
  $ProxyIp_TransportType
}
Update-TypeData -TypeName proxyIP -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object ProxyIp_IpAddress,ProxyIp_TransportType } -Force
Update-TypeData -TypeName proxyIP -MemberType Scriptmethod -MemberName 'viewGeneral' -Value { $this | select-object ProxyIp_IpAddress,ProxyIp_TransportType } -Force


class IPGroup { 
  $IPGroup_Type
  $IPGroup_Name
  $IPGroup_ProxySetName
  $IPGroup_SIPGroupName
  $IPGroup_ContactUser
  $IPGroup_SipReRoutingMode
  $IPGroup_AlwaysUseRouteTable
  $IPGroup_SRDName
  $IPGroup_MediaRealm
  $IPGroup_ClassifyByProxySet
  $IPGroup_ProfileName
  $IPGroup_MaxNumOfRegUsers
  $IPGroup_InboundManSet
  $IPGroup_OutboundManSet
  $IPGroup_RegistrationMode
  $IPGroup_AuthenticationMode
  $IPGroup_MethodList
  $IPGroup_EnableSBCClientForking
  $IPGroup_SourceUriInput
  $IPGroup_DestUriInput
  $IPGroup_ContactName
  $IPGroup_Username
  $IPGroup_Password
  $IPGroup_UUIFormat
  $IPGroup_QOEProfile
  $IPGroup_BWProfile
  $IPGroup_AlwaysUseSourceAddr
  $IPGroup_MsgManUserDef1
  $IPGroup_MsgManUserDef2
  $IPGroup_SIPConnect
  $IPGroup_SBCPSAPMode
  $IPGroup_DTLSContext
  $IPGroup_CreatedByRoutingServer
  $IPGroup_UsedByRoutingServer
  $IPGroup_SBCOperationMode
  $IPGroup_SBCRouteUsingRequestURIPort
  $IPGroup_SBCKeepOriginalCallID
  $IPGroup_TopologyLocation
  $IPGroup_SBCDialPlanName
  $IPGroup_CallSetupRulesSetId
  $IPGroup_Tags
  $IPGroup_SBCUserStickiness
  $IPGroup_UserUDPPortAssignment
}


Update-TypeData -TypeName IPGroup -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object IPGroup_Name,IPGroup_SRDName,IPGroup_ProxySetName,IPGroup_ProxySetNameIPGroup_MediaRealm } -Force
Update-TypeData -TypeName IPGroup -MemberType Scriptmethod -MemberName 'viewGeneral' -Value { $this | select-object IPGroup_Name,IPGroup_TopologyLocation,IPGroup_TypeIPGroup_ProxySetName,IPGroup_ProfileName,IPGroup_SRDName,IPGroup_MediaRealm,IPGroup_ContactName,IPGroup_SIPGroupName,IPGroup_ContactUser } -Force
Update-TypeData -TypeName IPGroup -MemberType Scriptmethod -MemberName 'viewSBCGeneral' -Value { $this | select-object IPGroup_ClassifyByProxySet,IPGroup_SBCOperationMode,IPGroup_EnableSBCClientForking } -Force
Update-TypeData -TypeName IPGroup -MemberType Scriptmethod -MemberName 'viewAdvanced' -Value { $this | select-object IPGroup_UUIFormat,IPGroup_AlwaysUseSourceAddr } -Force
Update-TypeData -TypeName IPGroup -MemberType Scriptmethod -MemberName 'viewSBCAdvanced' -Value { $this | select-object IPGroup_SourceUriInput,IPGroup_DestUriInput,IPGroup_SIPConnect,IPGroup_SBCPSAPMode,IPGroup_CreatedByRoutingServer,IPGroup_UsedByRoutingServer,IPGroup_SBCRouteUsingRequestURIPort,IPGroup_DTLSContext,IPGroup_SBCKeepOriginalCallID,IPGroup_SBCDialPlanName,IPGroup_CallSetupRulesSetId } -Force
Update-TypeData -TypeName IPGroup -MemberType Scriptmethod -MemberName 'viewQualityofExperience' -Value { $this | select-object IPGroup_QOEProfile,IPGroup_BWProfile } -Force
Update-TypeData -TypeName IPGroup -MemberType Scriptmethod -MemberName 'viewMessageManipulation' -Value { $this | select-object IPGroup_InboundManSet,IPGroup_OutboundManSet,IPGroup_MsgManUserDef1,IPGroup_MsgManUserDef2 } -Force  
Update-TypeData -TypeName IPGroup -MemberType Scriptmethod -MemberName 'viewSBCRegistrationAuthentication' -Value { $this | select-object IPGroup_MaxNumOfRegUsers,IPGroup_RegistrationMode,IPGroup_AuthenticationMode,IPGroup_MethodList,IPGroup_Username,IPGroup_Password } -Force
Update-TypeData -TypeName IPGroup -MemberType Scriptmethod -MemberName 'viewGWGroupStatus' -Value { $this | select-object * } -Force



class QOEProfile {
  $QOEProfile_Name
  $QOEProfile_SensitivityLevel
}
Update-TypeData -TypeName QOEProfile -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object * } -Force     
       
class BWProfile {
  $BWProfile_Name
  $BWProfile_EgressAudioBW
  $BWProfile_IngressAudioBW
  $BWProfile_EgressVideoBW
  $BWProfile_IngressVideoBW
  $BWProfile_TotalEgressBW
  $BWProfile_TotalIngressBW
  $BWProfile_WarningThreshold
  $BWProfile_MinorThreshold
  $BWProfile_hysteresis
  $BWProfile_GenerateAlarms
}
Update-TypeData -TypeName BWProfile -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object * } -Force     


class QualityOfServiceRules {
  $QualityOfServiceRules_IPGroupName
  $QualityOfServiceRules_RuleMetric
  $QualityOfServiceRules_Severity
  $QualityOfServiceRules_RuleAction
  $QualityOfServiceRules_CallsRejectDuration
  $QualityOfServiceRules_AltIPProfileName
}
Update-TypeData -TypeName QualityOfServiceRules -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object * } -Force     

class IpProfile { 
  #General
  $IpProfile_ProfileName
  $IpProfile_CreatedByRoutingServer
  #MediaSecurity
  $IpProfile_SBCMediaSecurityBehaviour
  $IpProfile_EnableSymmetricMKI
  $IpProfile_MKISize
  $IpProfile_SBCEnforceMKISize
  $IpProfile_SBCMediaSecurityMethod
  $IpProfile_ResetSRTPStateUponRekey
  $IpProfile_GenerateSRTPKeys
  $IpProfile_SBCRemoveCryptoLifetimeInSDP
  #SBC EARLY MEDIA 
  $IpProfile_SBCRemoteEarlyMediaSupport
  $IpProfile_SBCRemoteMultiple18xSupport
  $IpProfile_SBCRemoteEarlyMediaResponseType
  $IpProfile_SBCRemoteMultipleEarlyDialogs
  $IpProfile_SBCRemoteMultipleAnswersMode
  $IpProfile_SBCRemoteEarlyMediaRTP
  $IpProfile_SBCRemoteSupportsRFC3960
  $IpProfile_SBCRemoteCanPlayRingback
  $IpProfile_SBCGenerateRTP
  #SBC MEDIA
  $IpProfile_TranscodingMode
  $IpProfile_SBCExtensionCodersGroupName
  $IpProfile_SBCAllowedAudioCodersGroupName
  $IpProfile_SBCAllowedCodersMode
  $IpProfile_SBCAllowedVideoCodersGroupName
  $IpProfile_SBCAllowedMediaTypes
  $IpProfile_SBCDirectMediaTag
  $IpProfile_SBCRFC2833Behavior
  $IpProfile_SBC2833DTMFPayloadType
  $IpProfile_SBCAlternativeDTMFMethod
  $IpProfile_SBCSDPPtimeAnswer
  $IpProfile_SBCPreferredPTime
  $IpProfile_SBCUseSilenceSupp
  $IpProfile_SBCRTPRedundancyBehavior
  $IpProfile_SBCRTCPMode
  $IpProfile_SBCJitterCompensation
  $IpProfile_SBCIceMode
  $IpProfile_SBCSDPHandleRTCPAttribute
  $IpProfile_SBCRTCPMux
  $IpProfile_SBCRTCPFeedback
  $IpProfile_SBCVoiceQualityEnhancement
  $IpProfile_SBCMaxOpusBW
  #QUALITY OF SERVICE
  $IpProfile_IPDiffServ
  $IpProfile_SigIPDiffServ
  #SBC Jitter Buffer 
  $IpProfile_JitterBufMinDelay
  $IpProfile_JitterBufOptFactor
  $IpProfile_SCE
  $IpProfile_JitterBufMaxDelay
  #Voice
  $IpProfile_EnableEchoCanceller
  $IpProfile_InputGain
  $IpProfile_VoiceVolume
  #SBCSignalling
  $IpProfile_SbcPrackMode
  $IpProfile_SBCAssertIdentity
  $IpProfile_SBCDiversionMode
  $IpProfile_SBCHistoryInfoMode
  $IpProfile_SBCSessionExpiresMode
  $IpProfile_SBCRemoteUpdateSupport
  $IpProfile_SBCRemoteReinviteSupport
  $IpProfile_SBCRemoteDelayedOfferSupport
  $IpProfile_SBCRemoteRepresentationMode
  $IpProfile_SBCKeepVIAHeaders
  $IpProfile_SBCKeepRoutingHeaders
  $IpProfile_SBCKeepUserAgentHeader
  $IpProfile_SBCHandleXDetect
  $IpProfile_SBCISUPBodyHandling
  $IpProfile_SBCISUPVariant
  $IpProfile_SBCMaxCallDuration
  #SBC REGISTRATION
  $IpProfile_SBCUserRegistrationTime
  $IpProfile_SBCUserBehindUdpNATRegistrationTime
  $IpProfile_SBCUserBehindTcpNATRegistrationTime
  #SBC FORWARD AND TRANSFER
  $IpProfile_SBCRemoteReferBehavior
  $IpProfile_SBCRemoteReplacesBehavior
  $IpProfile_SBCPlayRBTToTransferee
  $IpProfile_SBCRemote3xxBehavior
  #SBC HOLD
  $IpProfile_SBCRemoteHoldFormat
  $IpProfile_SBCReliableHeldToneSource
  $IpProfile_SBCPlayHeldTone
  #SBC FAX
  $IpProfile_SBCFaxBehavior
  $IpProfile_SBCFaxOfferMode
  $IpProfile_SBCFaxAnswerMode
  $IpProfile_SBCRemoteRenegotiateOnFaxDetection
  #MEDIA
  $IpProfile_DisconnectOnBrokenConnection
  $IpProfile_MediaIPVersionPreference
  $IpProfile_RTPRedundancyDepth
  #GATEWAY
  $IpProfile_AMDSensitivityParameterSuit
  $IpProfile_AMDSensitivityLevel
  $IpProfile_AMDMaxGreetingTime
  $IpProfile_AMDMaxPostSilenceGreetingTime
  #ToSort
  $IpProfile_CodersGroupName
  $IpProfile_IpPreference
  $IpProfile_IsFaxUsed
  $IpProfile_CNGmode
  $IpProfile_VxxTransportType
  $IpProfile_NSEMode
  $IpProfile_IsDTMFUsed
  $IpProfile_PlayRBTone2IP
  $IpProfile_EnableEarlyMedia
  $IpProfile_ProgressIndicator2IP
  $IpProfile_CopyDest2RedirectNumber
  $IpProfile_MediaSecurityBehaviour
  $IpProfile_CallLimit
  $IpProfile_FirstTxDtmfOption
  $IpProfile_SecondTxDtmfOption
  $IpProfile_RxDTMFOption
  $IpProfile_EnableHold
  $IpProfile_AddIEInSetup
  $IpProfile_SBCSendMultipleDTMFMethods
  $IpProfile_SBCFaxCodersGroupName
  $IpProfile_EnableQSIGTunneling
  $IpProfile_EnableEarly183
  $IpProfile_EarlyAnswerTimeout
  $IpProfile_AmdMode
  $IpProfile_SBCAdaptRFC2833BWToVoiceCoderBW
  $IpProfile_SBCFaxReroutingMode
  $IpProfile_LocalRingbackTone
  $IpProfile_LocalHeldTone
}


#SBC MEDIA


Update-TypeData -TypeName IpProfile -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object IpProfile_ProfileName } -Force     
Update-TypeData -TypeName IpProfile -MemberType Scriptmethod -MemberName 'viewGeneral' -Value { $this | select-object IpProfile_ProfileName,IpProfile_CreatedByRoutingServer } -Force     
Update-TypeData -TypeName IpProfile -MemberType Scriptmethod -MemberName 'viewMediaSecurity' -Value { $this | select-object IpProfile_SBCMediaSecurityBehaviour,IpProfile_EnableSymmetricMKI,IpProfile_MKISize,IpProfile_SBCEnforceMKISize,IpProfile_SBCMediaSecurityMethod,IpProfile_ResetSRTPStateUponRekey,IpProfile_GenerateSRTPKeys,IpProfile_SBCRemoveCryptoLifetimeInSDP } -Force     
Update-TypeData -TypeName IpProfile -MemberType Scriptmethod -MemberName 'viewSBCEarlyMedia' -Value { $this | select-object IpProfile_SBCRemoteEarlyMediaSupport,IpProfile_SBCRemoteMultiple18xSupport,IpProfile_SBCRemoteEarlyMediaResponseType,IpProfile_SBCRemoteMultipleEarlyDialogs,IpProfile_SBCRemoteMultipleAnswersMode,IpProfile_SBCRemoteEarlyMediaRTP,IpProfile_SBCRemoteSupportsRFC3960,IpProfile_SBCRemoteCanPlayRingback,IpProfile_SBCGenerateRTP } -Force     
Update-TypeData -TypeName IpProfile -MemberType Scriptmethod -MemberName 'viewSBCMedia' -Value { $this | select-object $IpProfile_TranscodingMode,IpProfile_SBCExtensionCodersGroupName,IpProfile_SBCAllowedAudioCodersGroupName,IpProfile_SBCAllowedCodersMode,IpProfile_SBCAllowedVideoCodersGroupName,IpProfile_SBCAllowedMediaTypes,IpProfile_SBCDirectMediaTag,IpProfile_SBCRFC2833Behavior,IpProfile_SBC2833DTMFPayloadType,IpProfile_SBCAlternativeDTMFMethod,IpProfile_SBCSDPPtimeAnswer,IpProfile_SBCPreferredPTime,IpProfile_SBCUseSilenceSupp,IpProfile_SBCRTPRedundancyBehavior,IpProfile_SBCRTCPMode,IpProfile_SBCJitterCompensation,IpProfile_SBCIceMode,IpProfile_SBCSDPHandleRTCPAttribute,IpProfile_SBCRTCPMux,IpProfile_SBCRTCPFeedback,IpProfile_SBCVoiceQualityEnhancement,IpProfile_SBCMaxOpusBW   } -Force     
Update-TypeData -TypeName IpProfile -MemberType Scriptmethod -MemberName 'viewQualityofService' -Value { $this | select-object IpProfile_IPDiffServ,IpProfile_SigIPDiffServ } -Force     
Update-TypeData -TypeName IpProfile -MemberType Scriptmethod -MemberName 'viewSBCJitterBuffer' -Value { $this | select-object IpProfile_JitterBufMinDelay,IpProfile_JitterBufOptFactor,IpProfile_SCE,IpProfile_JitterBufMaxDelay } -Force
Update-TypeData -TypeName IpProfile -MemberType Scriptmethod -MemberName 'viewVoice' -Value { $this | select-object IpProfile_EnableEchoCanceller,IpProfile_InputGain,IpProfile_VoiceVolume } -Force
Update-TypeData -TypeName IpProfile -MemberType Scriptmethod -MemberName 'viewSBCSignalling' -Value { $this | select-object IpProfile_SbcPrackMode,IpProfile_SBCAssertIdentity,IpProfile_SBCDiversionMode,IpProfile_SBCHistoryInfoMode,IpProfile_SBCSessionExpiresMode,IpProfile_SBCRemoteUpdateSupport,IpProfile_SBCRemoteReinviteSupport,IpProfile_SBCRemoteDelayedOfferSupport,IpProfile_SBCRemoteRepresentationMode,IpProfile_SBCKeepVIAHeaders,IpProfile_SBCKeepRoutingHeaders,IpProfile_SBCKeepUserAgentHeader,IpProfile_SBCHandleXDetect,IpProfile_SBCISUPBodyHandling,IpProfile_SBCISUPVariant,IpProfile_SBCMaxCallDuration } -Force
Update-TypeData -TypeName IpProfile -MemberType Scriptmethod -MemberName 'viewSBCRegistration' -Value { $this | select-object IpProfile_SBCUserRegistrationTime,IpProfile_SBCUserBehindUdpNATRegistrationTime,IpProfile_SBCUserBehindTcpNATRegistrationTime } -Force
Update-TypeData -TypeName IpProfile -MemberType Scriptmethod -MemberName 'viewSBCForwardandTransfer' -Value { $this | select-object IpProfile_SBCRemoteReferBehavior,IpProfile_SBCRemoteReplacesBehavior,IpProfile_SBCPlayRBTToTransferee,IpProfile_SBCRemote3xxBehavior } -Force
Update-TypeData -TypeName IpProfile -MemberType Scriptmethod -MemberName 'viewSbcHold' -Value { $this | select-object IpProfile_SBCRemoteHoldFormat,IpProfile_SBCReliableHeldToneSource,IpProfile_SBCPlayHeldTone } -Force
Update-TypeData -TypeName IpProfile -MemberType Scriptmethod -MemberName 'viewSbcfax' -Value { $this | select-object IpProfile_SBCFaxBehavior,IpProfile_SBCFaxOfferMode,IpProfile_SBCFaxAnswerMode,IpProfile_SBCRemoteRenegotiateOnFaxDetection } -Force
Update-TypeData -TypeName IpProfile -MemberType Scriptmethod -MemberName 'viewMedia' -Value { $this | select-object IpProfile_DisconnectOnBrokenConnection,IpProfile_MediaIPVersionPreference,IpProfile_RTPRedundancyDepth } -Force
Update-TypeData -TypeName IpProfile -MemberType Scriptmethod -MemberName 'viewGateway' -Value { $this | select-object IpProfile_AMDSensitivityParameterSuit,IpProfile_AMDSensitivityLevel,IpProfile_AMDMaxGreetingTime,IpProfile_AMDMaxPostSilenceGreetingTime } -Force

class Classification {
  $Classification_ClassificationName
  $Classification_MessageConditionName
  $Classification_SRDName
  $Classification_SrcSIPInterfaceName
  $Classification_SrcAddress
  $Classification_SrcPort
  $Classification_SrcTransportType
  $Classification_SrcUsernamePrefix
  $Classification_SrcHost
  $Classification_DestUsernamePrefix
  $Classification_DestHost
  $Classification_ActionType
  $Classification_SrcIPGroupName
  $Classification_DestRoutingPolicy
  $Classification_IpProfileName
}
Update-TypeData -TypeName Classification -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object * } -Force     

class SBCRoutingPolicy {
  $SBCRoutingPolicy_Name
  $SBCRoutingPolicy_LCREnable
  $SBCRoutingPolicy_LCRAverageCallLength
  $SBCRoutingPolicy_LCRDefaultCost
  $SBCRoutingPolicy_LdapServerGroupName
}
Update-TypeData -TypeName SBCRoutingPolicy -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object * } -Force     

class IP2IPRouting {
  $IP2IPRouting_RouteName
  $IP2IPRouting_RoutingPolicyName
  $IP2IPRouting_SrcIPGroupName
  $IP2IPRouting_SrcUsernamePrefix
  $IP2IPRouting_SrcHost
  $IP2IPRouting_DestUsernamePrefix
  $IP2IPRouting_DestHost
  $IP2IPRouting_RequestType
  $IP2IPRouting_MessageConditionName
  $IP2IPRouting_ReRouteIPGroupName
  $IP2IPRouting_Trigger
  $IP2IPRouting_CallSetupRulesSetId
  $IP2IPRouting_DestType
  $IP2IPRouting_DestIPGroupName
  $IP2IPRouting_DestSIPInterfaceName
  $IP2IPRouting_DestAddress
  $IP2IPRouting_DestPort
  $IP2IPRouting_DestTransportType
  $IP2IPRouting_AltRouteOptions
  $IP2IPRouting_GroupPolicy
  $IP2IPRouting_CostGroup
  $IP2IPRouting_DestTags
  $IP2IPRouting_SrcTags
  $IP2IPRouting_IPGroupSetName
  $IP2IPRouting_RoutingTagName
  $IP2IPRouting_InternalAction
}
Update-TypeData -TypeName IP2IPRouting -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object * } -Force     

class SBCAlternativeRoutingReasons {
  $SBCAlternativeRoutingReasons_ReleaseCause
}
Update-TypeData -TypeName SBCAlternativeRoutingReasons -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object * } -Force     

class IPGroupSet {
  $IPGroupSet_Name
  $IPGroupSet_Policy
  $IPGroupSet_Tags
}
Update-TypeData -TypeName IPGroupSet -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object * } -Force     

class IPInboundManipulation {
  $IPInboundManipulation_ManipulationName
  $IPInboundManipulation_IsAdditionalManipulation
  $IPInboundManipulation_ManipulatedURI
  $IPInboundManipulation_ManipulationPurpose
  $IPInboundManipulation_SrcIPGroupName
  $IPInboundManipulation_SrcUsernamePrefix
  $IPInboundManipulation_SrcHost
  $IPInboundManipulation_DestUsernamePrefix
  $IPInboundManipulation_DestHost
  $IPInboundManipulation_RequestType
  $IPInboundManipulation_RemoveFromLeft
  $IPInboundManipulation_RemoveFromRight
  $IPInboundManipulation_LeaveFromRight
  $IPInboundManipulation_Prefix2Add
  $IPInboundManipulation_Suffix2Add
}
Update-TypeData -TypeName IPInboundManipulation -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object * } -Force     

class IPOutboundManipulation {
  $IPOutboundManipulation_ManipulationName
  $IPOutboundManipulation_RoutingPolicyName
  $IPOutboundManipulation_IsAdditionalManipulation
  $IPOutboundManipulation_SrcIPGroupName
  $IPOutboundManipulation_DestIPGroupName
  $IPOutboundManipulation_SrcUsernamePrefix
  $IPOutboundManipulation_SrcHost
  $IPOutboundManipulation_DestUsernamePrefix
  $IPOutboundManipulation_DestHost
  $IPOutboundManipulation_CallingNamePrefix
  $IPOutboundManipulation_MessageConditionName
  $IPOutboundManipulation_RequestType
  $IPOutboundManipulation_ReRouteIPGroupName
  $IPOutboundManipulation_Trigger
  $IPOutboundManipulation_ManipulatedURI
  $IPOutboundManipulation_RemoveFromLeft
  $IPOutboundManipulation_RemoveFromRight
  $IPOutboundManipulation_LeaveFromRight
  $IPOutboundManipulation_Prefix2Add
  $IPOutboundManipulation_Suffix2Add
  $IPOutboundManipulation_PrivacyRestrictionMode
  $IPOutboundManipulation_DestTags
  $IPOutboundManipulation_SrcTags
}
Update-TypeData -TypeName IPOutboundManipulation -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object * } -Force     

class account {
  $Account_ServedTrunkGroup
  $Account_ServedIPGroupName
  $Account_ServingIPGroupName
  $Account_Username
  $Account_Password
  $Account_HostName
  $Account_ContactUser
  $Account_Register
  $Account_RegistrarStickiness
  $Account_RegistrarSearchMode
  $Account_RegEventPackageSubscription
  $Account_ApplicationType
  $Account_RegByServedIPG
  $Account_UDPPortAssignment
}
Update-TypeData -TypeName account -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object * } -Force     

class CostGroupTable {
  $CostGroupTable_CostGroupName
  $CostGroupTable_DefaultConnectionCost
  $CostGroupTable_DefaultMinuteCost
}
Update-TypeData -TypeName CostGroupTable -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object * } -Force     

class CostGroupTimebands {
  $CostGroupTimebands_StartTime
  $CostGroupTimebands_EndTime
  $CostGroupTimebands_ConnectionCost
  $CostGroupTimebands_MinuteCost
}
Update-TypeData -TypeName CostGroupTimebands -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object * } -Force     

class IDSRule {
  $IDSRule_Policy
  $IDSRule_RuleID
  $IDSRule_Reason
  $IDSRule_ThresholdScope
  $IDSRule_ThresholdWindow
  $IDSRule_MinorAlarmThreshold
  $IDSRule_MajorAlarmThreshold
  $IDSRule_CriticalAlarmThreshold
  $IDSRule_DenyThreshold
  $IDSRule_DenyPeriod
}
Update-TypeData -TypeName IDSRule -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object * } -Force     

class IDSMatch {
  $IDSMatch_SIPInterface
  $IDSMatch_ProxySet
  $IDSMatch_Subnet
  $IDSMatch_Policy
}
Update-TypeData -TypeName IDSMatch -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object * } -Force     

class MaliciousSignatureDB {
  $MaliciousSignatureDB_Name
  $MaliciousSignatureDB_Pattern
}
Update-TypeData -TypeName MaliciousSignatureDB -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object MaliciousSignatureDB_Name,MaliciousSignatureDB_Pattern } -Force     



class SIPRecRouting {
  $SIPRecRouting_RecordedIPGroupName 
  $SIPRecRouting_RecordedSourcePrefix
  $SIPRecRouting_RecordedDestinationPrefix
  $SIPRecRouting_PeerIPGroupName 
  $SIPRecRouting_PeerTrunkGroupID
  $SIPRecRouting_Caller
  $SIPRecRouting_SRSIPGroupName
  $SIPRecRouting_SRSRedundantIPGroupName
}
Update-TypeData -TypeName SIPRecRouting -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object * } -Force     

class PerformanceProfile {
  $PerformanceProfile_Entity
  $PerformanceProfile_IPGroupName
  $PerformanceProfile_SRDName
  $PerformanceProfile_PMType
  $PerformanceProfile_MinorThreshold
  $PerformanceProfile_MajorThreshold
  $PerformanceProfile_Hysteresis
  $PerformanceProfile_MinimumSample
  $PerformanceProfile_WindowSize
}
Update-TypeData -TypeName PerformanceProfile -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object * } -Force     

class LoggingFilters {
  $LoggingFilters_FilterType
  $LoggingFilters_Value
  $LoggingFilters_LogDestination
  $LoggingFilters_CaptureType
  $LoggingFilters_Mode
}
Update-TypeData -TypeName LoggingFilters -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object * } -Force     

class CallSetupRules { 
  $CallSetupRules_RulesSetID
  $CallSetupRules_QueryType
  $CallSetupRules_QueryTarget
  $CallSetupRules_AttributesToQuery
  $CallSetupRules_AttributesToGet
  $CallSetupRules_RowRole
  $CallSetupRules_Condition
  $CallSetupRules_ActionSubject
  $CallSetupRules_ActionType
  $CallSetupRules_ActionValue
}
Update-TypeData -TypeName CallSetupRules -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object CallSetupRules_RulesSetID,CallSetupRules_QueryType,CallSetupRules_QueryTarget } -Force     
Update-TypeData -TypeName CallSetupRules -MemberType Scriptmethod -MemberName 'viewGeneral' -Value { $this | select-object CallSetupRules_RulesSetID,CallSetupRules_QueryType,CallSetupRules_QueryTarget,CallSetupRules_AttributesToQuery,CallSetupRules_AttributesToGet,CallSetupRules_RowRole,CallSetupRules_Condition } -Force     
Update-TypeData -TypeName CallSetupRules -MemberType Scriptmethod -MemberName 'viewAction' -Value { $this | select-object CallSetupRules_ActionSubject,CallSetupRules_ActionType,CallSetupRules_ActionValue } -Force     

class WebUsers { 
    $WebUsers_Username
    $WebUsers_Password
    $WebUsers_Status
    $WebUsers_PwAgeInterval
    $WebUsers_SessionLimit
    $WebUsers_SessionTimeout
    $WebUsers_BlockTime
    $WebUsers_UserLevel
    $WebUsers_PwNonce
    $WebUsers_SSHPublicKey
}
Update-TypeData -TypeName WebUsers -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object WebUsers_Username,WebUsers_Status,WebUsers_UserLevel } -Force     

class MessagePolicy { 
  $MessagePolicy_MaxMessageLength
  $MessagePolicy_MaxHeaderLength
  $MessagePolicy_MaxBodyLength
  $MessagePolicy_MaxNumHeaders
  $MessagePolicy_MaxNumBodies
  $MessagePolicy_SendRejection
  $MessagePolicy_MethodList
  $MessagePolicy_MethodListType
  $MessagePolicy_BodyList
  $MessagePolicy_BodyListType
  $MessagePolicy_UseMaliciousSignatureDB
  $MessagePolicy_Name
}
Update-TypeData -TypeName MessagePolicy -MemberType Scriptmethod -MemberName 'viewOverview' -Value { $this | select-object * } -Force     


function Convertfrom-MediantDocConfigIni 
{
  param ( $MediantConfigini )

  #Credit Oliver Lipkau
  #https://blogs.technet.microsoft.com/heyscriptingguy/2011/08/20/use-powershell-to-work-with-any-ini-file/
    
  $ini = @{}
  $section = 'Mediant'
  $ini[$section] = @{}

  switch -regex ($MediantConfigini) {
    '^(;.*)'  
    {
      #Comment
      Write-Verbose -Message "COMMENT -> $_"
      $value = $matches[1]
      $CommentCount = $CommentCount + 1
      $name = 'Comment' + $CommentCount
      $ini[$section][$name] = $value
      continue
    } 
    '^\[([^\\].+)\]'  
    {
      #Section
      Write-Host -Object "Imported:   $($matches[1].Replace(' ',''))" -ForegroundColor cyan
      Write-Verbose -Message "SECTION -> $_"
      $section = $matches[1].Replace(' ','')
      $ini[$section] = @{}
      $CommentCount = 0
      continue
    }
    '^(.+?)\s*=(.*)'  
    {
      #Key
      Write-Verbose -Message "KEY    -> $_"
      $name, $value = $matches[1..2]
      $ini[$section][$name] = $value
      continue
    }
    default 
    {
      Write-Verbose -Message "Ignore -> $_"
    }
  }
  return $ini
}
function ConvertFrom-MediantDocTable 
{ 
    [CmdletBinding()]
    param (
        $item,
        $itemindex,
        $ini = $ini
        )

    Write-Verbose -Message "Converting $item"

    try 
    {
        $object = $ini[$item]
        if ($object -eq $null) { throw "Not Configured $item" }

        [array]$objectIndex = $object["FORMAT $($item)_Index"].trim().trimend(';').Split(',').trim()

        foreach ($o in ($object.keys.where( { $_ -like "$item*" })) ) 
        { 
            try
            { 
                $result = New-Object $item
                $result | Add-Member -membertype NoteProperty -Name ("$($item)_Index") -Value $o -Force
                Write-Verbose -Message "class $item" 
            }
            catch 
            {
                $result = New-Object -TypeName PSCustomObject
                $result | Add-Member -membertype NoteProperty -Name ("$($item)_Index") -Value $o -Force
                foreach ($i in $itemindex)
                {
                  $result | Add-Member -membertype NoteProperty -Name $i -Value ''
                }
                $result.pstypenames.insert(0,"$item")
                Write-Verbose -Message "psCustomObject $item"
            }
        
            for ($i = 0; $i -lt $objectIndex.Count; $i++) 
            {
                try 
                {
                    $result.($objectIndex[$i]) = $($object.$o.trim().trimend(';').Split(',')[$i].trim().trimstart([char]0x0022).trimend([char]0x0022))
                    Write-Verbose -Message "$($objectIndex[$i]) = $($result.($objectIndex[$i]))"
                }
                catch 
                {
                    Write-Warning "   *** Parameter not documented ->  [$item]$($objectIndex[$i])" 
                    $Script:MissingParameter = $TRUE
                    $result | Add-Member -MemberType NoteProperty -Name ($objectIndex[$i]) -Value $($object.$o.trim().trimend(';').Split(',')[$i].trim().trimstart([char]0x0022).trimend([char]0x0022))
                    Write-Verbose -Message "$($objectIndex[$i]) = $($result.($objectIndex[$i]))"
                }
            }
        $result 
    }
    Update-TypeData -TypeName "$item" -MemberType Scriptmethod -MemberName 'view' -Value { $this  } -Force
    Write-Host -Object "Converted:  $item" -ForegroundColor DarkCyan
  }
  catch 
  {
    Write-Host -Object "Skipping:   $item" -ForegroundColor DarkCyan
  }
}

function ConvertFrom-MediantDocMediantParameter {
    $item = 'Mediant'
    $result = New-Object $item

    Switch -regex ($ini[$item].Values) 
    {
      '^;Board: (.*)$' { $result | Add-Member -Name 'Mediant_Board' -Value $matches[1] -MemberType NoteProperty -Force }
      '^;Board Type: (.*)$' { $result | Add-Member -Name 'Mediant_BoardType' -Value $matches[1] -MemberType NoteProperty -Force }
      '^;;;Key features:(.*)$'  { $result | Add-Member -Name 'Mediant_KeyFeatures' -Value $matches[1].split(';') -MemberType NoteProperty -Force }
      '^;Serial Number: (.*)$'  { $result | Add-Member -Name 'Mediant_SerialNumber' -Value $matches[1] -MemberType NoteProperty -Force }
      '^;Software Version: (.*)$' { $result | Add-Member -Name 'Mediant_SoftwareVersion' -Value $matches[1] -MemberType NoteProperty -Force }
      '^;DSP Software Version: (.*)$' { $result | Add-Member -Name 'Mediant_DSPSoftwareVersion' -Value $matches[1] -MemberType NoteProperty -Force  }
    }
    return $result
}

function ConvertFrom-MediantDocList 
{ 
  [CmdletBinding()]
  param (
    $item,
    $itemindex,
    $ini = $ini
  )

  Write-Verbose -Message "Converting $item" 

  try 
  {
    $object = $ini[$item]

    if ($object.keys.where({ $_ -notlike 'Comment*' }).count -eq 0)
    {
      throw "Skipping Empty $item" 
    }

    try
    {
      $result = New-Object $item
      Write-Verbose -Message "class $item" 
    }
    catch 
    {
      $result = New-Object -TypeName PSCustomObject
      if ($itemindex) {
          foreach ($i in $itemindex) {
             $result | Add-Member -MemberType NoteProperty -Name $i -Value $null -Force
             Write-Verbose -Message "Adding member $i"
          }
      }
      $result.pstypenames.insert(0,"$item")
      Write-Verbose -Message "PSCustomObject $item"
    }

    foreach ($o in ( $object.keys.where({ $_ -notlike 'Comment*' }) ) ) 
    {
        try 
        {     
            $result.$o = $object[$o]
        }
        catch
        {
            Write-Warning "   *** Parameter not documented ->  [$item]$o"
            $Script:MissingParameter = $true
            $result | Add-Member -MemberType NoteProperty -Name $o -Value $object[$o] -Force
        }
    }
    Update-TypeData -TypeName "$item" -MemberType Scriptmethod -MemberName 'view' -Value { $this } -Force
    Write-Host -Object "Converted:  $item" -ForegroundColor DarkCyan
    $result
  }
  catch 
  {
    Write-Host -Object "Skipping:   $item" -ForegroundColor DarkCyan
  }
}

function update-mediantDocParameter 
{
  [CmdletBinding()]
  Param ( 
    [Parameter(Position = 0, mandatory = $true)]
    [AllowEmptyString()]
    [string]$Parameter,  
    [Parameter(Position = 1, mandatory = $false)]
    [AllowEmptyString()]
    [string]$DefaultValue = '',
    [Parameter(Position = 2, mandatory = $false)]
  [hashtable]$ParameterLookup)
    
  Write-Verbose -Message "Parameter->       $Parameter" 
  Write-Verbose -Message "DefaultValue->    $DefaultValue"
  Write-Verbose -Message "ParameterLookup-> $ParameterLookup"

  if ($Parameter -eq '') 
  {
    $Parameter = $DefaultValue 
  }
    
  if ($PSBoundParameters.ContainsKey('ParameterLookup')) 
  {
    if ($ParameterLookup.containskey($Parameter)) 
    {
      return $ParameterLookup[$Parameter] 
    }
    else 
    {
      return $Parameter 
    }
  }
  else 
  {
    return $Parameter
  }
}

function Add-mediantDocParagraph 
{
  param(
    [Parameter(Position = 3, mandatory = $false)]
    [switch]$NewPage,
    [Parameter(Position = 0, mandatory = $false)]
    [string]$heading,
    [Parameter(Position = 1, mandatory = $false)]
    [ValidateSet('1', '2', '3', '4')]
    [String]$headingtype = 2,
    [Parameter(Position = 2, mandatory = $false)]
    [array]$text
  )

  if ($NewPage) 
  {
    Add-WordBreak -breaktype NewPage
  }
  if ($heading) 
  {
    Write-Host -Object "Documenting $heading" -ForegroundColor Cyan
    Add-WordText -text $heading -WDBuiltinStyle "wdStyleHeading$headingtype"
    Add-WordBreak -breaktype Paragraph
  }
  if ($text) 
  {
    foreach ($t in $text) 
    {
      Add-WordText -text $t -WDBuiltinStyle wdStyleNormal
    }
    Add-WordBreak -breaktype Paragraph
  }
}

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
$TrunkStatusReportingMode = @{ "0" = "Disable"; "1" = "Don't reply OPTIONS"; "2" = "Donâ€™t send Keep-Alive"; "3" = "Donâ€™t Reply and Send"; }
$UseGatewayNameForOptions = @{ "0" = "No"; "1" = "Yes"; "2" = "Server" }
$UseSIPTgrp = @{"0" = "Disable"; "1" = "Send Only"; "2" = "Send and Recieve"; "3" = "Hotline"; "4" = "Hotline Extended"}
$WebUsers_Status = @{"0" = "New"; "1" = "Valid"; "2" = "Failed Login"; "3" = "Inactivity"} 
$WebUsers_UserLevel = @{"50" = "Monitor"; "100" = "Administrator"; "200" = "Security Administrator"; "220" = "Master"} 
$GwDebugLevel = @{"0"="No Debug";"1"="Basic";"5"="Detailed "}
$SyslogFacility = @{"16"="Local0";"17"="Local1";"18"="Local2";"19"="Local3";"20"="Local4";"21"="Local5";"22"="Local6";"23"="Local7"}
$CallDurationUnits = @{"0"="Seconds";"1"="Deciseconds";"2"="Centiseconds";"3"="Milliseconds"}
$TelnetServerEnable = @{"0"="Disable";"1"="Enable Unsecured";"2"="Enable Secured"}
$DefaultTerminalWindowHeight = @{"-1"="CLI Window Height";"0"="Window";}
#([Mediant]::new()).GetType().GetProperties().Name.foreach({"'$itemindex__',"})
$itemindex_AccessList = 'AccessList_Source_IP', 'AccessList_Source_Port', 'AccessList_PrefixLen', 'AccessList_Start_Port', 'AccessList_End_Port', 'AccessList_Protocol', 'AccessList_Use_Specific_Interface', 'AccessList_Interface_ID', 'AccessList_Packet_Size', 'AccessList_Byte_Rate', 'AccessList_Byte_Burst', 'AccessList_Allow_Type','AccessList_Allow_Type_enum'
$itemindex_Account = 'Account_ServedTrunkGroup', 'Account_ServedIPGroupName', 'Account_ServingIPGroupName', 'Account_Username', 'Account_Password', 'Account_HostName', 'Account_ContactUser', 'Account_Register', 'Account_RegistrarStickiness', 'Account_RegistrarSearchMode', 'Account_RegEventPackageSubscription', 'Account_ApplicationType', 'Account_RegByServedIPG', 'Account_UDPPortAssignment'
$itemindex_AllowedAudioCoders = 'AllowedAudioCoders_AllowedAudioCodersGroupName', 'AllowedAudioCoders_AllowedAudioCodersIndex', 'AllowedAudioCoders_CoderID', 'AllowedAudioCoders_UserDefineCoder'
$itemindex_AllowedAudioCodersGroups = 'AllowedAudioCodersGroups_Name'
$itemindex_AllowedVideoCoders = 'AllowedVideoCoders_AllowedVideoCodersGroupName', 'AllowedVideoCoders_AllowedVideoCodersIndex', 'AllowedVideoCoders_UserDefineCoder'
$itemindex_AllowedVideoCodersGroups = 'AllowedVideoCodersGroups_Name'
$itemindex_AudioCoders = "AudioCoders_AudioCodersGroupId","AudioCoders_AudioCodersIndex", "AudioCoders_Name","AudioCoders_pTime", "AudioCoders_rate", "AudioCoders_PayloadType","AudioCoders_Sce", "AudioCoders_CoderSpecific"
$itemindex_AudioCodersGroups = "AudioCodersGroups_Name"
$itemindex_Authentication = "Authentication_UserId","Authentication_UserPassword", "Authentication_Module","Authentication_Port"
$itemindex_BSPParams = 'GOLDSERVICECLASSDIFFSERV','PCMLawSelect','DHCPEnable','BaseUDPPort','PREMIUMSERVICECLASSMEDIADIFFSERV','PREMIUMSERVICECLASSCONTROLDIFFSERV','BRONZESERVICECLASSDIFFSERV','DisableICMPRedirects','DisableICMPUnreachable','UdpPortSpacing','EnterCpuOverloadPercent','ExitCpuOverloadPercent','RoutingServerGroupStatus','QOEServerIp','QOEEnableTLS','QOERedundantServerIp','QoETLSContextName','QOEReportMode','INIFileVersio'
$itemindex_BWProfile = 'BWProfile_Name', 'BWProfile_EgressAudioBW', 'BWProfile_IngressAudioBW', 'BWProfile_EgressVideoBW', 'BWProfile_IngressVideoBW', 'BWProfile_TotalEgressBW', 'BWProfile_TotalIngressBW', 'BWProfile_WarningThreshold','BWProfile_MinorThreshold', 'BWProfile_hysteresis', 'BWProfile_GenerateAlarms'
$itemindex_CallerDisplayInfo = "CallerDisplayInfo_DisplayString","CallerDisplayInfo_IsCidRestricted", "CallerDisplayInfo_Module","CallerDisplayInfo_Port"
$itemindex_CallingNameMapIp2Tel = "CallingNameMapIp2Tel_ManipulationName","CallingNameMapIp2Tel_DestinationPrefix","CallingNameMapIp2Tel_SourcePrefix","CallingNameMapIp2Tel_CallingNamePrefix","CallingNameMapIp2Tel_SourceAddress","CallingNameMapIp2Tel_RemoveFromLeft","CallingNameMapIp2Tel_RemoveFromRight","CallingNameMapIp2Tel_LeaveFromRight","CallingNameMapIp2Tel_Prefix2Add"
$itemindex_CallingNameMapTel2Ip = "CallingNameMapTel2Ip_ManipulationName","CallingNameMapTel2Ip_DestinationPrefix","CallingNameMapTel2Ip_SourcePrefix","CallingNameMapTel2Ip_CallingNamePrefix","CallingNameMapTel2Ip_SrcTrunkGroupID","CallingNameMapTel2Ip_RemoveFromLeft","CallingNameMapTel2Ip_RemoveFromRight","CallingNameMapTel2Ip_LeaveFromRight","CallingNameMapTel2Ip_Prefix2Add","CallingNameMapTel2Ip_Suffix2Add"
$itemindex_CallSetupRules = "CallSetupRules_RulesSetID","CallSetupRules_QueryType", "CallSetupRules_QueryTarget","CallSetupRules_AttributesToQuery", "CallSetupRules_AttributesToGet","CallSetupRules_RowRole", "CallSetupRules_Condition","CallSetupRules_ActionSubject", "CallSetupRules_ActionType","CallSetupRules_ActionValue"
$itemindex_Classification = 'Classification_ClassificationName', 'Classification_MessageConditionName', 'Classification_SRDName', 'Classification_SrcSIPInterfaceName', 'Classification_SrcAddress', 'Classification_SrcPort', 'Classification_SrcTransportType', 'Classification_SrcUsernamePrefix', 'Classification_SrcHost', 'Classification_DestUsernamePrefix', 'Classification_DestHost', 'Classification_ActionType', 'Classification_SrcIPGroupName', 'Classification_DestRoutingPolicy', 'Classification_IpProfileName'
$itemindex_ConditionTable = 'ConditionTable_Condition', 'ConditionTable_Description'
$itemindex_ControlProtocolsParams = 'RoutingServerGroupStatus','QOEServerIp','QOEEnableTLS','QOERedundantServerIp','QoETLSContextName','QOEReportMode'
$itemindex_CostGroupTable = 'CostGroupTable_CostGroupName', 'CostGroupTable_DefaultConnectionCost', 'CostGroupTable_DefaultMinuteCost'
$itemindex_CostGroupTimebands = 'CostGroupTimebands_StartTime', 'CostGroupTimebands_EndTime', 'CostGroupTimebands_ConnectionCost', 'CostGroupTimebands_MinuteCost'
$itemindex_CpMediaRealm = 'CpMediaRealm_MediaRealmName', 'CpMediaRealm_IPv4IF', 'CpMediaRealm_IPv6IF', 'CpMediaRealm_PortRangeStart', 'CpMediaRealm_MediaSessionLeg', 'CpMediaRealm_PortRangeEnd', 'CpMediaRealm_IsDefault', 'CpMediaRealm_QoeProfile', 'CpMediaRealm_BWProfile', 'CpMediaRealm_TopologyLocation'
$itemindex_DeviceTable = 'DeviceTable_VlanID', 'DeviceTable_UnderlyingInterface', 'DeviceTable_DeviceName', 'DeviceTable_Tagging', 'DeviceTable_MTU'
$itemindex_DhcpOption = 'DhcpOption_DhcpServerIndex', 'DhcpOption_Option', 'DhcpOption_Type', 'DhcpOption_Value', 'DhcpOption_ExpandValue'
$itemindex_DhcpServer = 'DhcpServer_InterfaceName', 'DhcpServer_StartIPAddress', 'DhcpServer_EndIPAddress', 'DhcpServer_SubnetMask', 'DhcpServer_LeaseTime', 'DhcpServer_DNSServer1', 'DhcpServer_DNSServer2', 'DhcpServer_NetbiosNameServer', 'DhcpServer_NetbiosNodeType', 'DhcpServer_NTPServer1', 'DhcpServer_NTPServer2', 'DhcpServer_TimeOffset', 'DhcpServer_TftpServer', 'DhcpServer_BootFileName', 'DhcpServer_ExpandBootfileName', 'DhcpServer_OverrideRouter', 'DhcpServer_SipServer', 'DhcpServer_SipServerType'
$itemindex_DhcpStaticIP = 'DhcpStaticIP_DhcpServerIndex', 'DhcpStaticIP_IPAddress', 'DhcpStaticIP_MACAddress'
$itemindex_DhcpVendorClass = 'DhcpVendorClass_DhcpServerIndex', 'DhcpVendorClass_VendorClassId'
$itemindex_DialPlan = 'DialPlan_Name'
$itemindex_DiffServToVlanPriority = 'DiffServToVlanPriority_DiffServ', 'DiffServToVlanPriority_VlanPriority'
$itemindex_DNS2IP = 'Dns2Ip_DomainName', 'Dns2Ip_FirstIpAddress', 'Dns2Ip_SecondIpAddress', 'Dns2Ip_ThirdIpAddress'
$itemindex_EMSService_ServiceName = "EMSService_ServiceName","EMSService_PrimaryServer", "EMSService_SecondaryServer","EMSService_DeviceLoginInterface", "EMSService_EMSInterface"
$itemindex_EnableCallerID = "EnableCallerID_IsEnabled","EnableCallerID_Module", "EnableCallerID_Port"
$itemindex_EtherGroupTable = 'EtherGroupTable_Group', 'EtherGroupTable_Mode', 'EtherGroupTable_Member1', 'EtherGroupTable_Member2'
$itemindex_GwRoutingPolicy = 'GwRoutingPolicy_Name','GwRoutingPolicy_LCREnable','GwRoutingPolicy_LCRAverageCallLength','GwRoutingPolicy_LCRDefaultCost','GwRoutingPolicy_LdapServersGroupName'
$itemindex_GWCDRFormat = "GWCDRFormat_CDRType","GWCDRFormat_FieldType", "GWCDRFormat_Title","GWCDRFormat_RadiusType", "GWCDRFormat_RadiusID"
$itemindex_HTTPInterface = 'HTTPInterface_NetworkInterface', 'HTTPInterface_Protocol', 'HTTPInterface_Port', 'HTTPInterface_TLSContext', 'HTTPInterface_VerifyCert'
$itemindex_HTTPProxyHost = 'HTTPProxyHost_HTTPProxyServiceId', 'HTTPProxyHost_HTTPProxyHostId', 'HTTPProxyHost_NetworkInterface', 'HTTPProxyHost_IpAddress', 'HTTPProxyHost_Protocol', 'HTTPProxyHost_Port', 'HTTPProxyHost_TLSContext', 'HTTPProxyHost_VerifyCert'
$itemindex_HTTPProxyService = 'HTTPProxyService_ServiceName', 'HTTPProxyService_ListeningInterface', 'HTTPProxyService_URLPrefix', 'HTTPProxyService_KeepAliveMode'
$itemindex_HTTPRemoteHosts = 'HTTPRemoteHosts_HTTPRemoteServiceIndex', 'HTTPRemoteHosts_RemoteHostIndex', 'HTTPRemoteHosts_Name', 'HTTPRemoteHosts_Address', 'HTTPRemoteHosts_Port', 'HTTPRemoteHosts_Interface', 'HTTPRemoteHosts_HTTPTransportType', 'HTTPRemoteHosts_HostStatus'
$itemindex_HTTPRemoteServices = 'HTTPRemoteServices_Name', 'HTTPRemoteServices_Path', 'HTTPRemoteServices_HTTPType', 'HTTPRemoteServices_Policy', 'HTTPRemoteServices_LoginNeeded', 'HTTPRemoteServices_PersistentConnection', 'HTTPRemoteServices_NumOfSockets', 'HTTPRemoteServices_AuthUserName', 'HTTPRemoteServices_AuthPassword', 'HTTPRemoteServices_TLSContext', 'HTTPRemoteServices_VerifyCertificate', 'HTTPRemoteServices_TimeOut', 'HTTPRemoteServices_KeepAliveTimeOut', 'HTTPRemoteServices_ServiceStatus'
$itemindex_IDSMatch = 'IDSMatch_SIPInterface', 'IDSMatch_ProxySet', 'IDSMatch_Subnet', 'IDSMatch_Policy'
$itemindex_IDSPolicy = 'IDSPolicy_Name', 'IDSPolicy_Description'
$itemindex_IDSRule = 'IDSRule_Policy', 'IDSRule_RuleID', 'IDSRule_Reason', 'IDSRule_ThresholdScope', 'IDSRule_ThresholdWindow', 'IDSRule_MinorAlarmThreshold', 'IDSRule_MajorAlarmThreshold', 'IDSRule_CriticalAlarmThreshold', 'IDSRule_DenyThreshold', 'IDSRule_DenyPeriod'
$itemindex_InterfaceTable = "InterfaceTable_ApplicationTypes","InterfaceTable_InterfaceMode","InterfaceTable_IPAddress", "InterfaceTable_PrefixLength","InterfaceTable_Gateway", "InterfaceTable_VlanID","InterfaceTable_InterfaceName","InterfaceTable_PrimaryDNSServerIPAddress","InterfaceTable_SecondaryDNSServerIPAddress","InterfaceTable_UnderlyingDevice"
$itemindex_IP2IPRouting = 'IP2IPRouting_RouteName', 'IP2IPRouting_RoutingPolicyName', 'IP2IPRouting_SrcIPGroupName', 'IP2IPRouting_SrcUsernamePrefix', 'IP2IPRouting_SrcHost', 'IP2IPRouting_DestUsernamePrefix', 'IP2IPRouting_DestHost', 'IP2IPRouting_RequestType', 'IP2IPRouting_MessageConditionName', 'IP2IPRouting_ReRouteIPGroupName', 'IP2IPRouting_Trigger', 'IP2IPRouting_CallSetupRulesSetId', 'IP2IPRouting_DestType', 'IP2IPRouting_DestIPGroupName', 'IP2IPRouting_DestSIPInterfaceName', 'IP2IPRouting_DestAddress', 'IP2IPRouting_DestPort', 'IP2IPRouting_DestTransportType', 'IP2IPRouting_AltRouteOptions', 'IP2IPRouting_GroupPolicy', 'IP2IPRouting_CostGroup', 'IP2IPRouting_DestTags', 'IP2IPRouting_SrcTags', 'IP2IPRouting_IPGroupSetName', 'IP2IPRouting_RoutingTagName', 'IP2IPRouting_InternalAction'
$itemindex_IPGroup = 'IPGroup_Type', 'IPGroup_Name', 'IPGroup_ProxySetName', 'IPGroup_SIPGroupName', 'IPGroup_ContactUser', 'IPGroup_SipReRoutingMode', 'IPGroup_AlwaysUseRouteTable', 'IPGroup_SRDName', 'IPGroup_MediaRealm', 'IPGroup_ClassifyByProxySet', 'IPGroup_ProfileName', 'IPGroup_MaxNumOfRegUsers', 'IPGroup_InboundManSet', 'IPGroup_OutboundManSet', 'IPGroup_RegistrationMode', 'IPGroup_AuthenticationMode', 'IPGroup_MethodList', 'IPGroup_EnableSBCClientForking', 'IPGroup_SourceUriInput', 'IPGroup_DestUriInput', 'IPGroup_ContactName', 'IPGroup_Username', 'IPGroup_Password', 'IPGroup_UUIFormat', 'IPGroup_QOEProfile', 'IPGroup_BWProfile', 'IPGroup_AlwaysUseSourceAddr', 'IPGroup_MsgManUserDef1', 'IPGroup_MsgManUserDef2', 'IPGroup_SIPConnect', 'IPGroup_SBCPSAPMode', 'IPGroup_DTLSContext', 'IPGroup_CreatedByRoutingServer', 'IPGroup_UsedByRoutingServer', 'IPGroup_SBCOperationMode', 'IPGroup_SBCRouteUsingRequestURIPort', 'IPGroup_SBCKeepOriginalCallID', 'IPGroup_TopologyLocation', 'IPGroup_SBCDialPlanName', 'IPGroup_CallSetupRulesSetId', 'IPGroup_Tags', 'IPGroup_SBCUserStickiness', 'IPGroup_UserUDPPortAssignment'
$itemindex_IPGroupSet = 'IPGroupSet_Name', 'IPGroupSet_Policy', 'IPGroupSet_Tags'
$itemindex_IPGroupSetMember = "IPGroupSetMember_IPGroupSetId","IPGroupSetMember_IPGroupSetMemberIndex","IPGroupSetMember_IPGroupName","IPGroupSetMember_Weight"
$itemindex_IPInboundManipulation = 'IPInboundManipulation_ManipulationName', 'IPInboundManipulation_IsAdditionalManipulation', 'IPInboundManipulation_ManipulatedURI', 'IPInboundManipulation_ManipulationPurpose', 'IPInboundManipulation_SrcIPGroupName', 'IPInboundManipulation_SrcUsernamePrefix', 'IPInboundManipulation_SrcHost', 'IPInboundManipulation_DestUsernamePrefix', 'IPInboundManipulation_DestHost', 'IPInboundManipulation_RequestType', 'IPInboundManipulation_RemoveFromLeft', 'IPInboundManipulation_RemoveFromRight', 'IPInboundManipulation_LeaveFromRight', 'IPInboundManipulation_Prefix2Add', 'IPInboundManipulation_Suffix2Add'
$itemindex_IPOutboundManipulation = 'IPOutboundManipulation_ManipulationName', 'IPOutboundManipulation_RoutingPolicyName', 'IPOutboundManipulation_IsAdditionalManipulation', 'IPOutboundManipulation_SrcIPGroupName', 'IPOutboundManipulation_DestIPGroupName', 'IPOutboundManipulation_SrcUsernamePrefix', 'IPOutboundManipulation_SrcHost', 'IPOutboundManipulation_DestUsernamePrefix', 'IPOutboundManipulation_DestHost', 'IPOutboundManipulation_CallingNamePrefix', 'IPOutboundManipulation_MessageConditionName', 'IPOutboundManipulation_RequestType', 'IPOutboundManipulation_ReRouteIPGroupName', 'IPOutboundManipulation_Trigger', 'IPOutboundManipulation_ManipulatedURI', 'IPOutboundManipulation_RemoveFromLeft', 'IPOutboundManipulation_RemoveFromRight', 'IPOutboundManipulation_LeaveFromRight', 'IPOutboundManipulation_Prefix2Add', 'IPOutboundManipulation_Suffix2Add', 'IPOutboundManipulation_PrivacyRestrictionMode', 'IPOutboundManipulation_DestTags', 'IPOutboundManipulation_SrcTags'
$itemindex_IpProfile = 'IpProfile_ProfileName', 'IpProfile_IpPreference', 'IpProfile_CodersGroupName', 'IpProfile_IsFaxUsed', 'IpProfile_JitterBufMinDelay', 'IpProfile_JitterBufOptFactor', 'IpProfile_IPDiffServ', 'IpProfile_SigIPDiffServ', 'IpProfile_SCE', 'IpProfile_RTPRedundancyDepth', 'IpProfile_CNGmode', 'IpProfile_VxxTransportType', 'IpProfile_NSEMode', 'IpProfile_IsDTMFUsed', 'IpProfile_PlayRBTone2IP', 'IpProfile_EnableEarlyMedia', 'IpProfile_ProgressIndicator2IP', 'IpProfile_EnableEchoCanceller', 'IpProfile_CopyDest2RedirectNumber', 'IpProfile_MediaSecurityBehaviour', 'IpProfile_CallLimit', 'IpProfile_DisconnectOnBrokenConnection', 'IpProfile_FirstTxDtmfOption', 'IpProfile_SecondTxDtmfOption', 'IpProfile_RxDTMFOption', 'IpProfile_EnableHold', 'IpProfile_InputGain', 'IpProfile_VoiceVolume', 'IpProfile_AddIEInSetup', 'IpProfile_SBCExtensionCodersGroupName', 'IpProfile_MediaIPVersionPreference', 'IpProfile_TranscodingMode', 'IpProfile_SBCAllowedMediaTypes', 'IpProfile_SBCAllowedAudioCodersGroupName', 'IpProfile_SBCAllowedVideoCodersGroupName', 'IpProfile_SBCAllowedCodersMode', 'IpProfile_SBCMediaSecurityBehaviour', 'IpProfile_SBCRFC2833Behavior', 'IpProfile_SBCAlternativeDTMFMethod', 'IpProfile_SBCSendMultipleDTMFMethods', 'IpProfile_SBCAssertIdentity', 'IpProfile_AMDSensitivityParameterSuit', 'IpProfile_AMDSensitivityLevel', 'IpProfile_AMDMaxGreetingTime', 'IpProfile_AMDMaxPostSilenceGreetingTime', 'IpProfile_SBCDiversionMode', 'IpProfile_SBCHistoryInfoMode', 'IpProfile_EnableQSIGTunneling', 'IpProfile_SBCFaxCodersGroupName', 'IpProfile_SBCFaxBehavior', 'IpProfile_SBCFaxOfferMode', 'IpProfile_SBCFaxAnswerMode', 'IpProfile_SbcPrackMode', 'IpProfile_SBCSessionExpiresMode', 'IpProfile_SBCRemoteUpdateSupport', 'IpProfile_SBCRemoteReinviteSupport', 'IpProfile_SBCRemoteDelayedOfferSupport', 'IpProfile_SBCRemoteReferBehavior', 'IpProfile_SBCRemote3xxBehavior', 'IpProfile_SBCRemoteMultiple18xSupport', 'IpProfile_SBCRemoteEarlyMediaResponseType', 'IpProfile_SBCRemoteEarlyMediaSupport', 'IpProfile_EnableSymmetricMKI', 'IpProfile_MKISize', 'IpProfile_SBCEnforceMKISize', 'IpProfile_SBCRemoteEarlyMediaRTP', 'IpProfile_SBCRemoteSupportsRFC3960', 'IpProfile_SBCRemoteCanPlayRingback', 'IpProfile_EnableEarly183', 'IpProfile_EarlyAnswerTimeout', 'IpProfile_SBC2833DTMFPayloadType', 'IpProfile_SBCUserRegistrationTime', 'IpProfile_ResetSRTPStateUponRekey', 'IpProfile_AmdMode', 'IpProfile_SBCReliableHeldToneSource', 'IpProfile_GenerateSRTPKeys', 'IpProfile_SBCPlayHeldTone', 'IpProfile_SBCRemoteHoldFormat', 'IpProfile_SBCRemoteReplacesBehavior', 'IpProfile_SBCSDPPtimeAnswer', 'IpProfile_SBCPreferredPTime', 'IpProfile_SBCUseSilenceSupp', 'IpProfile_SBCRTPRedundancyBehavior', 'IpProfile_SBCPlayRBTToTransferee', 'IpProfile_SBCRTCPMode', 'IpProfile_SBCJitterCompensation', 'IpProfile_SBCRemoteRenegotiateOnFaxDetection', 'IpProfile_JitterBufMaxDelay', 'IpProfile_SBCUserBehindUdpNATRegistrationTime', 'IpProfile_SBCUserBehindTcpNATRegistrationTime', 'IpProfile_SBCSDPHandleRTCPAttribute', 'IpProfile_SBCRemoveCryptoLifetimeInSDP', 'IpProfile_SBCIceMode', 'IpProfile_SBCRTCPMux', 'IpProfile_SBCMediaSecurityMethod', 'IpProfile_SBCHandleXDetect', 'IpProfile_SBCRTCPFeedback', 'IpProfile_SBCRemoteRepresentationMode', 'IpProfile_SBCKeepVIAHeaders', 'IpProfile_SBCKeepRoutingHeaders', 'IpProfile_SBCKeepUserAgentHeader', 'IpProfile_SBCRemoteMultipleEarlyDialogs', 'IpProfile_SBCRemoteMultipleAnswersMode', 'IpProfile_SBCDirectMediaTag', 'IpProfile_SBCAdaptRFC2833BWToVoiceCoderBW', 'IpProfile_CreatedByRoutingServer', 'IpProfile_SBCFaxReroutingMode', 'IpProfile_SBCMaxCallDuration', 'IpProfile_SBCGenerateRTP', 'IpProfile_SBCISUPBodyHandling', 'IpProfile_SBCISUPVariant', 'IpProfile_SBCVoiceQualityEnhancement', 'IpProfile_SBCMaxOpusBW', 'IpProfile_LocalRingbackTone', 'IpProfile_LocalHeldTone'                     
$itemindex_ISDNSuppServ = "ISDNSuppServ_PhoneNumber","ISDNSuppServ_LocalPhoneNumber", "ISDNSuppServ_Module","ISDNSuppServ_Port", "ISDNSuppServ_UserId","ISDNSuppServ_UserPassword", "ISDNSuppServ_CallerID","ISDNSuppServ_IsPresentationRestricted","ISDNSuppServ_IsCallerIDEnabled", "ISDNSuppServ_CFB2PhoneNumber","ISDNSuppServ_CFNR2PhoneNumber","ISDNSuppServ_CFU2PhoneNumber", "ISDNSuppServ_NoReplyTime"
$itemindex_LdapConfiguration = 'LdapConfiguration_Group', 'LdapConfiguration_LdapConfServerIp', 'LdapConfiguration_LdapConfServerPort', 'LdapConfiguration_LdapConfServerMaxRespondTime', 'LdapConfiguration_LdapConfServerDomainName', 'LdapConfiguration_LdapConfPassword', 'LdapConfiguration_LdapConfBindDn', 'LdapConfiguration_Interface', 'LdapConfiguration_MngmAuthAtt', 'LdapConfiguration_useTLS', 'LdapConfiguration_ConnectionStatus','LdapConfiguration_LdapConfInterfaceType','LdapConfiguration_Type','LdapConfiguration_VerifyCertificate'
$itemindex_LDAPServerGroups = 'LdapServerGroups_Name', 'LdapServerGroups_ServerType', 'LdapServerGroups_SearchMethod', 'LdapServerGroups_CacheEntryTimeout', 'LdapServerGroups_CacheEntryRemovalTimeout', 'LdapServerGroups_SearchDnsMethod'
$itemindex_LoggingFilters = 'LoggingFilters_FilterType', 'LoggingFilters_Value', 'LoggingFilters_LogDestination', 'LoggingFilters_CaptureType', 'LoggingFilters_Mode'
$itemindex_MaliciousSignatureDB = 'MaliciousSignatureDB_Name', 'MaliciousSignatureDB_Pattern'
$itemindex_mediant = 'Mediant_Board','Mediant_BoardType','Mediant_KeyFeatures','Mediant_SerialNumber','Mediant_SoftwareVersion','Mediant_DSPSoftwareVersion'
$itemindex_MediaRealmExtension = "MediaRealmExtension_MediaRealmIndex","MediaRealmExtension_ExtensionIndex", "MediaRealmExtension_IPv4IF","MediaRealmExtension_IPv6IF", "MediaRealmExtension_PortRangeStart","MediaRealmExtension_PortRangeEnd","MediaRealmExtension_MediaSessionLeg"
$itemindex_MediaRealmExtenstion = 'MediaRealmExtension_MediaRealmIndex','MediaRealmExtension_ExtensionIndex','MediaRealmExtension_IPv4IF','MediaRealmExtension_IPv6IF','MediaRealmExtension_PortRangeStart','MediaRealmExtension_PortRangeEnd','MediaRealmExtension_MediaSessionLeg'
$itemindex_MEGACOParams = 'EP_Num_0','EP_Num_1','EP_Num_2','EP_Num_3','EP_Num_4'
$itemindex_MessageManipulations = 'MessageManipulations_ManipulationName','MessageManipulations_ManSetID', 'MessageManipulations_MessageType', 'MessageManipulations_Condition', 'MessageManipulations_ActionSubject', 'MessageManipulations_ActionType', 'MessageManipulations_ActionValue', 'MessageManipulations_RowRole'
$itemindex_MessagePolicy = 'MessagePolicy_MaxMessageLength', 'MessagePolicy_MaxHeaderLength', 'MessagePolicy_MaxBodyLength', 'MessagePolicy_MaxNumHeaders', 'MessagePolicy_MaxNumBodies', 'MessagePolicy_SendRejection', 'MessagePolicy_MethodList', 'MessagePolicy_MethodListType', 'MessagePolicy_BodyList', 'MessagePolicy_BodyListType', 'MessagePolicy_UseMaliciousSignatureDB','MessagePolicy_Name'
$itemindex_MgmntLDAPGroups = "MgmntLDAPGroups_LdapConfigurationIndex","MgmntLDAPGroups_GroupIndex","MgmntLDAPGroups_Level", "MgmntLDAPGroups_Group"
$itemindex_NATTranslation = 'NATTranslation_SrcIPInterfaceName', 'NATTranslation_TargetIPAddress', 'NATTranslation_SourceStartPort', 'NATTranslation_SourceEndPort', 'NATTranslation_TargetStartPort', 'NATTranslation_TargetEndPort'
$itemindex_NumberMapIp2Tel = "NumberMapIp2Tel_ManipulationName","NumberMapIp2Tel_DestinationPrefix","NumberMapIp2Tel_SourcePrefix","NumberMapIp2Tel_SourceAddress","NumberMapIp2Tel_NumberType", "NumberMapIp2Tel_NumberPlan","NumberMapIp2Tel_RemoveFromLeft","NumberMapIp2Tel_RemoveFromRight","NumberMapIp2Tel_LeaveFromRight","NumberMapIp2Tel_Prefix2Add", "NumberMapIp2Tel_Suffix2Add","NumberMapIp2Tel_IsPresentationRestricted"
$itemindex_NumberMapTel2Ip = "NumberMapTel2Ip_ManipulationName","NumberMapTel2Ip_DestinationPrefix","NumberMapTel2Ip_SourcePrefix","NumberMapTel2Ip_SourceAddress","NumberMapTel2Ip_NumberType", "NumberMapTel2Ip_NumberPlan","NumberMapTel2Ip_RemoveFromLeft","NumberMapTel2Ip_RemoveFromRight","NumberMapTel2Ip_LeaveFromRight","NumberMapTel2Ip_Prefix2Add", "NumberMapTel2Ip_Suffix2Add","NumberMapTel2Ip_IsPresentationRestricted","NumberMapTel2Ip_SrcTrunkGroupID", "NumberMapTel2Ip_SrcIPGroupID"
$itemindex_PerformanceProfile = 'PerformanceProfile_Entity', 'PerformanceProfile_IPGroupName', 'PerformanceProfile_SRDName', 'PerformanceProfile_PMType', 'PerformanceProfile_MinorThreshold', 'PerformanceProfile_MajorThreshold', 'PerformanceProfile_Hysteresis', 'PerformanceProfile_MinimumSample', 'PerformanceProfile_WindowSize'
$itemindex_PhysicalPortsTable = 'PhysicalPortsTable_Port', 'PhysicalPortsTable_Mode', 'PhysicalPortsTable_SpeedDuplex', 'PhysicalPortsTable_PortDescription', 'PhysicalPortsTable_GroupMember', 'PhysicalPortsTable_GroupStatus'
$itemindex_PreParsingManipulationRules = "PreParsingManipulationRules_PreParsingManSetName","PreParsingManipulationRules_RuleIndex","PreParsingManipulationRules_MessageType", "PreParsingManipulationRules_Pattern","PreParsingManipulationRules_ReplaceWith"
$itemindex_PreParsingManipulationSets = "PreParsingManipulationSets_Name"
$itemindex_ProxyIp = 'ProxyIp_ProxySetId', 'ProxyIp_ProxyIpIndex', 'ProxyIp_IpAddress', 'ProxyIp_TransportType'
$itemindex_ProxySet = 'ProxySet_ProxyName', 'ProxySet_EnableProxyKeepAlive', 'ProxySet_ProxyKeepAliveTime', 'ProxySet_ProxyLoadBalancingMethod', 'ProxySet_IsProxyHotSwap', 'ProxySet_SRDName', 'ProxySet_ClassificationInput', 'ProxySet_TLSContextName', 'ProxySet_ProxyRedundancyMode', 'ProxySet_DNSResolveMethod', 'ProxySet_KeepAliveFailureResp', 'ProxySet_GWIPv4SIPInterfaceName', 'ProxySet_SBCIPv4SIPInterfaceName', 'ProxySet_GWIPv6SIPInterfaceName', 'ProxySet_SBCIPv6SIPInterfaceName', 'ProxySet_MinActiveServersLB', 'ProxySet_SuccessDetectionRetries', 'ProxySet_SuccessDetectionInterval', 'ProxySet_FailureDetectionRetransmissions'
$itemindex_QOEProfile = 'QOEProfile_Name', 'QOEProfile_SensitivityLevel'
$itemindex_QOEColorRules = "QOEColorRules_QoeProfile", "QOEColorRules_ColorRuleIndex", "QOEColorRules_monitoredParam", "QOEColorRules_direction", "QOEColorRules_profile", "QOEColorRules_MinorThreshold", "QOEColorRules_MinorHysteresis", "QOEColorRules_MajorThreshold", "QOEColorRules_MajorHysteresis"
$itemindex_QualityOfServiceRules = 'QualityOfServiceRules_IPGroupName', 'QualityOfServiceRules_RuleMetric', 'QualityOfServiceRules_Severity', 'QualityOfServiceRules_RuleAction', 'QualityOfServiceRules_CallsRejectDuration', 'QualityOfServiceRules_AltIPProfileName'
$itemindex_RadiusServers = 'RadiusServers_ServerGroup', 'RadiusServers_IPAddress', 'RadiusServers_AuthenticationPort', 'RadiusServers_AccountingPort', 'RadiusServers_SharedSecret'
$itemindex_RedirectNumberMapIp2Tel = "RedirectNumberMapIp2Tel_ManipulationName","RedirectNumberMapIp2Tel_DestinationPrefix","RedirectNumberMapIp2Tel_RedirectPrefix","RedirectNumberMapIp2Tel_SourceAddress","RedirectNumberMapIp2Tel_SrcHost","RedirectNumberMapIp2Tel_DestHost","RedirectNumberMapIp2Tel_NumberType","RedirectNumberMapIp2Tel_NumberPlan","RedirectNumberMapIp2Tel_RemoveFromLeft","RedirectNumberMapIp2Tel_RemoveFromRight","RedirectNumberMapIp2Tel_LeaveFromRight","RedirectNumberMapIp2Tel_Prefix2Add","RedirectNumberMapIp2Tel_Suffix2Add","RedirectNumberMapIp2Tel_IsPresentationRestricted"
$itemindex_RedirectNumberMapTel2Ip = "RedirectNumberMapTel2Ip_ManipulationName","RedirectNumberMapTel2Ip_DestinationPrefix","RedirectNumberMapTel2Ip_RedirectPrefix","RedirectNumberMapTel2Ip_NumberType","RedirectNumberMapTel2Ip_NumberPlan","RedirectNumberMapTel2Ip_RemoveFromLeft","RedirectNumberMapTel2Ip_RemoveFromRight","RedirectNumberMapTel2Ip_LeaveFromRight","RedirectNumberMapTel2Ip_Prefix2Add","RedirectNumberMapTel2Ip_Suffix2Add","RedirectNumberMapTel2Ip_IsPresentationRestricted","RedirectNumberMapTel2Ip_SrcTrunkGroupID"
$itemindex_RemoteMediaSubnet = "RemoteMediaSubnet_Realm","RemoteMediaSubnet_RemoteMediaSubnetIndex","RemoteMediaSubnet_RemoteMediaSubnetName","RemoteMediaSubnet_PrefixLength","RemoteMediaSubnet_AddressFamily","RemoteMediaSubnet_DstIPAddress","RemoteMediaSubnet_QOEProfileName","RemoteMediaSubnet_BWProfileName"
$itemindex_ResourcePriorityNetworkDomains = "ResourcePriorityNetworkDomains_Name", "ResourcePriorityNetworkDomains_EnableIp2TelInterworking","ResourcePriorityNetworkDomains_Ip2TelInterworking"
$itemindex_SBCAdmissionControl = 'SBCAdmissionControl_AdmissionControlName', 'SBCAdmissionControl_LimitType', 'SBCAdmissionControl_IPGroupName', 'SBCAdmissionControl_SRDName', 'SBCAdmissionControl_SIPInterfaceName', 'SBCAdmissionControl_RequestType', 'SBCAdmissionControl_RequestDirection', 'SBCAdmissionControl_Limit', 'SBCAdmissionControl_LimitPerUser', 'SBCAdmissionControl_Rate', 'SBCAdmissionControl_MaxBurst', 'SBCAdmissionControl_Reservation'
$itemindex_SBCAlternativeRoutingReasons = 'SBCAlternativeRoutingReasons_ReleaseCause'
$itemindex_SBCCDRFormat = 'SBCCDRFormat_CDRType', 'SBCCDRFormat_FieldType', 'SBCCDRFormat_Title', 'SBCCDRFormat_RadiusType', 'SBCCDRFormat_RadiusID'
$itemindex_SBCRoutingPolicy = 'SBCRoutingPolicy_Name', 'SBCRoutingPolicy_LCREnable', 'SBCRoutingPolicy_LCRAverageCallLength', 'SBCRoutingPolicy_LCRDefaultCost', 'SBCRoutingPolicy_LdapServerGroupName'
$itemindex_SIPInterface = 'SIPInterface_InterfaceName', 'SIPInterface_NetworkInterface', 'SIPInterface_ApplicationType', 'SIPInterface_UDPPort', 'SIPInterface_TCPPort', 'SIPInterface_TLSPort', 'SIPInterface_AdditionalUDPPorts', 'SIPInterface_SRDName', 'SIPInterface_MessagePolicyName', 'SIPInterface_TLSContext', 'SIPInterface_TLSMutualAuthentication', 'SIPInterface_TCPKeepaliveEnable', 'SIPInterface_ClassificationFailureResponseType', 'SIPInterface_PreClassificationManSet', 'SIPInterface_EncapsulatingProtocol', 'SIPInterface_MediaRealm', 'SIPInterface_SBCDirectMedia', 'SIPInterface_BlockUnRegUsers', 'SIPInterface_MaxNumOfRegUsers', 'SIPInterface_EnableUnAuthenticatedRegistrations', 'SIPInterface_UsedByRoutingServer', 'SIPInterface_TopologyLocation', 'SIPInterface_PreParsingManSetName'
$itemindex_SipParams = 'TLSRehadshaleInterval','VerifyServerCertificate','PeerHostnameVerificationMode','SIPSRequireClientCertificate','MEDIACHANNELS','RegistrationTime','RegistrationRetryTime','UseGatewayNameForOptions','SipTransportType','REGISTRATIONTIMEDIVIDER','EnableSips','USETELURIFORASSERTEDID','EnableREASONHEADER','EnableTCPCONNECTIONREUSE','SIPTCPTIMEOUT','SIPSDPSESSIONOWNER','ReliableConnectionPersistentMode','EnableSINGLEDSPTRANSCODING','MSLDAPPBXNUMATTRIBUTENAME','MSLDAPOCSNUMATTRIBUTENAME','MSLDAPMOBILENUMATTRIBUTENAME','MSLDAPPRIVATENUMATTRIBUTENAME','MSLDAPDISPLAYNAMEATTRIBUTENAME','MSLDAPPRIMARYKEY','MSLDAPSECONDARYKEY','UseProxyIPasHost','EnableSIPREC','EnableIDS','DisplayDefaultSIPPort','HTTPProxyApplication','HTTPPROXYSYSLOGDEBUGLEVEL','IDSAlarmClearPeriod','TLSRemoteSubjectName','DECLAREAUDCCLIENT','SIPT1RTX','SIPT2RTX','SipGatewayName','PROXYREDUNDANCYMODE','SIPMAXRTX','DisconnectOnBrokenConnection','NoRTPDetectionTimeout','GWREGISTRATIONNAME','SBCMaxCallDuration','COMFORTNOISENEGOTIATION','RtcpXrReportMode','PROXYIPLISTREFRESHTIME','EnableGRUU','DNSQUERYType','PROXYDNSQUERYType','HOTSWAPRTX','REGISTRATIONTIMETHRESHOLD','REGISTERONINVITEFAILURE','SIPCHALLENGECACHINGMODE','RETRYAFTERTIME','FAXCNGMODE','TLSREHANDSHAKEINTERVAL','REREGISTERONCONNECTIONFAILURE','ALLOWUNCLASSIFIEDCALLS','TRANSCODINGMODE','SBCDirectMedia','FAKERETRYAFTER','SBC3XXBEHAVIOR','SBCREFERBEHAVIOR','SBCKEEPCONTACTUSERINREGISTER','SBCMAXFORWARDSLIMIT','SBCALERTTIMEOUT','EMPTYAUTHORIZATIONHEADER','SBCGRUUMODE','SBCMINSE','SBCPROXYREGISTRATIONTIME','SBCUSERREGISTRATIONTIME','SBCSURVIVABILITYREGISTRATIONTIME','SBCPREFERENCESMODE','SBCEXTENSIONSPROVISIONINGMODE','AUTHNONCEDURATION','AUTHQOP','SBCEnableBYEAUTHENTICATION','E911CALLBACKTIMEOUT','ENUMSERVICE','SBCFORKINGHANDLINGMODE','SBCSESSIONEXPIRES','SBCENFORCEMEDIAORDER','ENFORCEMEDIAORDER','SBCSHAREDLINEREGMODE','SBCDIVERSIONURIType','SIPNATDETECTION','EnableNonInvite408Reply','SendRejectOnOverload','PUBLICATIONIPGROUPID','ENERGYDETECTORCMD','ANSWERDETECTORCMD','SBCSendTryingToSubscribe','SBCUSERREGISTRATIONGRACETIME','SBCRtcpXrReportMode','SIPRECSERVERDESTUSERNAME','MAXGENERATEDREGISTERSRATE','SBCDBROUTINGSEARCHMODE','SBCPREEMPTIONMODE','SBCEMERGENCYCONDITION','SBCEMERGENCYRTPDIFFSERV','SBCEMERGENCYSIGNALINGDIFFSERV','WEBSOCKETPROTOCOLKEEPALIVEPERIOD','GwDebugLevel'
$itemindex_SIPRecRouting = 'SIPRecRouting_RecordedIPGroupName', 'SIPRecRouting_RecordedSourcePrefix', 'SIPRecRouting_RecordedDestinationPrefix', 'SIPRecRouting_PeerIPGroupName', 'SIPRecRouting_PeerTrunkGroupID', 'SIPRecRouting_Caller', 'SIPRecRouting_SRSIPGroupName', 'SIPRecRouting_SRSRedundantIPGroupName'
$itemindex_SNMPParams = 'DisableSNMP','SNMPManagerTableIP_0','SNMPManagerTableIP_1','SNMPManagerTableIP_2','SNMPManagerTableIP_3','SNMPManagerTableIP_4','SNMPTRUSTEDMGR','SNMPREADONLYCOMMUNITYSTRING_0','SNMPREADONLYCOMMUNITYSTRING_1','SNMPREADONLYCOMMUNITYSTRING_2','SNMPREADONLYCOMMUNITYSTRING_3','SNMPREADONLYCOMMUNITYSTRING_4','SNMPREADWRITECOMMUNITYSTRING_0','SNMPREADWRITECOMMUNITYSTRING_1','SNMPREADWRITECOMMUNITYSTRING_2','SNMPREADWRITECOMMUNITYSTRING_3','SNMPREADWRITECOMMUNITYSTRING_4','SNMPTRAPCOMMUNITYSTRING','SNMPTrapManagerHostName','SNMPPort','SendKeepAliveTrap','KeepAliveTrapPort','PM_EnableThresholdAlarms','SNMPSysOid','SNMPTrapEnterpriseOid','AlarmHistoryTableMaxSize','ActiveAlarmTableMaxSize','NoAlarmForDisabledPort','SNMPManagerTrapPort','SNMPManagerIsUsed','SNMPManagerTrapSendingEnable','ChassisPhysicalAlias','ChassisPhysicalAssetID','ifAlias','acUserInputAlarmDescription','acUserInputAlarmSeverity','SNMPEngineIDString'
$itemindex_SNMPUsers =  'SNMPUsers_Username', 'SNMPUsers_AuthProtocol','SNMPUsers_PrivProtocol','SNMPUsers_AuthKey','SNMPUsers_PrivKey', 'SNMPUsers_Group'
$itemindex_SourceNumberMapIp2Tel = "SourceNumberMapIp2Tel_ManipulationName","SourceNumberMapIp2Tel_DestinationPrefix","SourceNumberMapIp2Tel_SourcePrefix","SourceNumberMapIp2Tel_SourceAddress","SourceNumberMapIp2Tel_NumberType","SourceNumberMapIp2Tel_NumberPlan","SourceNumberMapIp2Tel_RemoveFromLeft","SourceNumberMapIp2Tel_RemoveFromRight","SourceNumberMapIp2Tel_LeaveFromRight","SourceNumberMapIp2Tel_Prefix2Add","SourceNumberMapIp2Tel_Suffix2Add","SourceNumberMapIp2Tel_IsPresentationRestricted"
$itemindex_SourceNumberMapTel2Ip = "SourceNumberMapTel2Ip_ManipulationName","SourceNumberMapTel2Ip_DestinationPrefix","SourceNumberMapTel2Ip_SourcePrefix","SourceNumberMapTel2Ip_NumberType","SourceNumberMapTel2Ip_NumberPlan","SourceNumberMapTel2Ip_RemoveFromLeft","SourceNumberMapTel2Ip_RemoveFromRight","SourceNumberMapTel2Ip_LeaveFromRight","SourceNumberMapTel2Ip_Prefix2Add","SourceNumberMapTel2Ip_Suffix2Add","SourceNumberMapTel2Ip_IsPresentationRestricted","SourceNumberMapTel2Ip_SrcTrunkGroupID"
$itemindex_SRD = 'SRD_Name', 'SRD_IntraSRDMediaAnchoring', 'SRD_BlockUnRegUsers', 'SRD_MaxNumOfRegUsers', 'SRD_EnableUnAuthenticatedRegistrations', 'SRD_SharingPolicy', 'SRD_UsedByRoutingServer', 'SRD_SBCOperationMode', 'SRD_SBCRoutingPolicyName','SRD_SBCDialPlanName'
$itemindex_SRV2IP = 'SRV2IP_InternalDomain', 'SRV2IP_TransportType', 'SRV2IP_Dns1', 'SRV2IP_Priority1', 'SRV2IP_Weight1', 'SRV2IP_Port1', 'SRV2IP_Dns2', 'SRV2IP_Priority2', 'SRV2IP_Weight2', 'SRV2IP_Port2', 'SRV2IP_Dns3', 'SRV2IP_Priority3', 'SRV2IP_Weight3', 'SRV2IP_Port3'
$itemindex_StaticRouteTable = 'StaticRouteTable_DeviceName', 'StaticRouteTable_Destination', 'StaticRouteTable_PrefixLength', 'StaticRouteTable_Gateway', 'StaticRouteTable_Description'
$itemindex_SystemParams = 'RequireStrictCert','TLSExpiryCheckStart','TLSExpiryCheckPeriod','TelnetServerEnable','TelnetServerPort','TelnetServerIdleDisconnect','TelnetMaxSessions','DefaultTerminalWindowHeight','SSHServerEnable','SSHServerPort','SSHRequirePublicKey','SSHMaxPayloadSize','SSHMaxBinaryPacketSize','SSHMaxSessions','SSHMaxLoginAttempts','SSHEnableLastLoginMessage','EnableSyslog','SyslogServerIP','SyslogServerPort','CDRReportLevel','MediaCDRReportLevel','CDRLocalMaxFileSize','CDRLocalMaxNumOfFiles','CDRLocalInterval','GwDebugLevel','EnableNonCallCdr','SyslogOptimization','MaxBundleSyslogLength','SyslogCpuProtection','DebugLevelHighThreshold','SyslogFacility','CallDurationUnits','CDRSyslogSeqNum','SendAcSessionIDHeader','EnableParametersMonitoring','FacilityTrace','EnableCoreDump','CallFlowReportMode','HARemoteAddress','HARevertiveEnabled','HAPriority','HAPingEnabled','HAPingDestination','HAPingTimeout','HAPingRetries','DefaultAccessLevel','EnableActivityTrap','NTPServerIP','NTPSecondaryServerIP','NTPUpdateInterval','ntpAuthMd5Key','NTPServerUTCOffset','DayLightSavingTimeEnable','DayLightSavingTimeStart','DayLightSavingTimeEnd','DayLightSavingTimeOffset','TR069ACSPASSWORD','TR069CONNECTIONREQUESTPASSWORD','CLIPrivPass','SSHAdminKey','CDRSyslogServerIP','TimeZoneFormat','ActivityListToLog','DebugRecordingDestIP','DebugRecordingDestPort','CoreDumpDestIP','HAUnitIdName','HAPingSourceIfName','LDAPSERVICEENABLE'
$itemindex_TargetOfChannel = "TargetOfChannel_Destination","TargetOfChannel_Type", "TargetOfChannel_Module","TargetOfChannel_Port","TargetOfChannel_HotLineToneDuration"
$itemindex_TelProfile = "TelProfile_ProfileName","TelProfile_TelPreference", "TelProfile_CodersGroupName","TelProfile_IsFaxUsed", "TelProfile_JitterBufMinDelay","TelProfile_JitterBufOptFactor", "TelProfile_IPDiffServ","TelProfile_SigIPDiffServ", "TelProfile_DtmfVolume", "TelProfile_InputGain","TelProfile_VoiceVolume", "TelProfile_EnableReversePolarity","TelProfile_EnableCurrentDisconnect", "TelProfile_EnableDigitDelivery","TelProfile_EnableEC", "TelProfile_MWIAnalog", "TelProfile_MWIDisplay","TelProfile_FlashHookPeriod", "TelProfile_EnableEarlyMedia","TelProfile_ProgressIndicator2IP", "TelProfile_TimeForReorderTone","TelProfile_EnableDIDWink", "TelProfile_IsTwoStageDial","TelProfile_DisconnectOnBusyTone", "TelProfile_EnableVoiceMailDelay","TelProfile_DialPlanIndex", "TelProfile_Enable911PSAP","TelProfile_SwapTelToIpPhoneNumbers", "TelProfile_EnableAGC","TelProfile_ECNlpMode", "TelProfile_DigitalCutThrough","TelProfile_EnableFXODoubleAnswer", "TelProfile_CallPriorityMode","TelProfile_FXORingTimeout", "TelProfile_JitterBufMaxDelay","TelProfile_PlayBusyTone2Isdn"
$itemindex_Test_Call = 'Test_Call_EndpointURI', 'Test_Call_CalledURI', 'Test_Call_RouteBy', 'Test_Call_IPGroupName', 'Test_Call_DestAddress', 'Test_Call_DestTransportType', 'Test_Call_SIPInterfaceName', 'Test_Call_ApplicationType', 'Test_Call_AutoRegister', 'Test_Call_UserName', 'Test_Call_Password', 'Test_Call_CallParty', 'Test_Call_MaxChannels', 'Test_Call_CallDuration', 'Test_Call_CallsPerSecond', 'Test_Call_TestMode', 'Test_Call_TestDuration', 'Test_Call_Play', 'Test_Call_ScheduleInterval', 'Test_Call_QOEProfile', 'Test_Call_BWProfile'
$itemindex_TLSContexts = 'TLSContexts_Name', 'TLSContexts_TLSVersion', 'TLSContexts_DTLSVersion', 'TLSContexts_ServerCipherString', 'TLSContexts_ClientCipherString', 'TLSContexts_RequireStrictCert', 'TLSContexts_OcspEnable', 'TLSContexts_OcspServerPrimary', 'TLSContexts_OcspServerSecondary', 'TLSContexts_OcspServerPort', 'TLSContexts_OcspDefaultResponse', 'TLSContexts_DHKeySize'
$itemindex_TrunkGroup = "TrunkGroup_TrunkGroupNum","TrunkGroup_FirstTrunkId", "TrunkGroup_FirstBChannel","TrunkGroup_LastBChannel", "TrunkGroup_FirstPhoneNumber","TrunkGroup_ProfileName", "TrunkGroup_LastTrunkId", "TrunkGroup_Module"
$itemindex_TrunkGroupSettings = "TrunkGroupSettings_TrunkGroupId","TrunkGroupSettings_ChannelSelectMode","TrunkGroupSettings_RegistrationMode","TrunkGroupSettings_GatewayName","TrunkGroupSettings_ContactUser","TrunkGroupSettings_ServingIPGroupName","TrunkGroupSettings_MWIInterrogationType","TrunkGroupSettings_TrunkGroupName","TrunkGroupSettings_UsedByRoutingServer"
$itemindex_VoiceEngineParams = 'EnableContinuityTones','L1L1ComplexRxUDPPort','L1L1ComplexTxUDPPort','EnableMediaSecurity','SRTPofferedSuites','RTPAuthenticationDisableTx','RTPEncryptionDisableTx','RTCPEncryptionDisableTx','SRTPTunnelingValidateRTPRxAuthentication','SRTPTunnelingValidateRTCPRxAuthentication','EnableSilenceCompression','EnableEchoCanceller','VoiceVolume','InputGain','BrokenConnectionEventTimeout','DTMFVolume','DTMFTransportType','CallerIDTransportType','CallerIDType','FaxTransportMode','V21ModemTransportType','V22ModemTransportType','V23ModemTransportType','V32ModemTransportType','V34ModemTransportType','FaxRelayMaxRate','FaxRelayECMEnable','FaxRelayRedundancyDepth','FaxRelayEnhancedRedundancyDepth','CNGDetectorMode','DJBufMinDelay','DJBufOptFactor','RTPRedundancyDepth','RTPPackingFactor','RFC2833TxPayloadType','RFC2833RxPayloadType','RFC2198PayloadType','FaxBypassPayloadType','ModemBypassPayloadType','EnableStandardSIDPayloadType','NatMode','EnableAnswerDetector','AnswerDetectorActivityDelay','AnswerDetectorSilenceTime','AnswerDetectorRedirection','AnswerDetectorSensitivity','EnableEnergyDetector','EnergyDetectorQualityFactor','EnergyDetectorThreshold','EnablePatternDetector','EnableDSPIPMDetectors','ACTIVESPEAKERSNOTIFICATIONMININTERVAL','DTMFGenerationTwist','AMDDetectionSensitivity','G729EVMaxBitRate','G729EVLocalMBS','G729EVReceiveMBS','NTEMaxDuration','CEDTransferMode','AMDBeepDetectionTimeout','AMDBeepDetectionSensitivity','MSRTAForwardErrorCorrectionEnable','AMDSensitivityLevel','AMDSensitivityParameterSuit','RtpFWNonConfiguredPTHandling','SilkTxInbandFEC','NewRtpStreamPackets','TimeoutToRelatchRTPMsec','TimeoutToRelatchSRTPMsec','TimeoutToRelatchSilenceMsec','NewSRTPStreamPackets','ECHOCANCELLERType','ACOUSTICECHOSUPPMAXERLTHRESHOLD','ACOUSTICECHOSUPPATTENUATIONINTENSITY','ACOUSTICECHOSUPPMINREFDELAYx10MS','ACOUSTICECHOSUPPRESSORSUPPORT','AmrOctetAlignedEnable','NewRtcpStreamPackets','NewSRtcpStreamPackets','TimeoutToRelatchRTCPMsec','RTPFWInvalidPacketHandling','MediaSecurityBehaviour','SRTPTxPacketMKISize','EnableSymmetricMKI','ResetSRTPStateUponRekey'
$itemindex_WebParams = 'DenyAccessOnFailCount','DenyAuthenticationTimer','DisableWebConfig','DisplayLoginInformation','EnableMgmtTwoFactorAuthentication','EnableWebAccessFromAllInterfaces','EnforcePasswordComplexity','HTTPport','HTTPSPort','HTTPSRequireClientCertificate','LogoWidth','ResetWebPassword','UseProductName','UserInactivityTimer','UseWebLogo','WebAccessList_0','WebAccessList_1','WebAccessList_10','WebAccessList_11','WebAccessList_12','WebAccessList_13','WebAccessList_14','WebAccessList_15','WebAccessList_16','WebAccessList_17','WebAccessList_18','WebAccessList_19','WebAccessList_2','WebAccessList_20','WebAccessList_21','WebAccessList_22','WebAccessList_23','WebAccessList_24','WebAccessList_25','WebAccessList_26','WebAccessList_27','WebAccessList_28','WebAccessList_29','WebAccessList_3','WebAccessList_30','WebAccessList_31','WebAccessList_32','WebAccessList_33','WebAccessList_34','WebAccessList_35','WebAccessList_36','WebAccessList_37','WebAccessList_38','WebAccessList_39','WebAccessList_4','WebAccessList_40','WebAccessList_41','WebAccessList_42','WebAccessList_43','WebAccessList_44','WebAccessList_45','WebAccessList_46','WebAccessList_47','WebAccessList_48','WebAccessList_49','WebAccessList_5','WebAccessList_6','WebAccessList_7','WebAccessList_8','WebAccessList_9','WebLoginBlockAutoComplete','WebSessionTimeout','WebUserPassChangeInterval','CustomerSN','EnableRADIUS','HTTPSCipherString','LogoFileName','MgmtBEHAVIORONTIMEOUT','MgmtLDAPLOGIN','MgmtLOGINCACHEMODE','MgmtLOGINCACHETIMEOUT','RADIUSRetransmission','RADIUSTo','RadiusVSAAccessAttribute','RadiusVSAVendorID','UserProductName','WebLogoText','WEBRADIUSLOGIN'
$itemindex_WebUsers = "WebUsers_Username", "WebUsers_Password", "WebUsers_Status", "WebUsers_PwAgeInterval", 'WebUsers_SessionLimit', 'WebUsers_SessionTimeout', 'WebUsers_BlockTime', 'WebUsers_UserLevel', 'WebUsers_PwNonce', 'WebUsers_SSHPublicKey'


if ($PSBoundParameters.ContainsKey('WordTemplate')) {
    $TemplateFile = (get-item -path $WordTemplate).fullname
}    
else { 
    write-host "Load Word Template ?" -foregroundcolor Yellow
    
    switch (($host.ui.PromptForChoice("", "Do you want to use an existing word Document as a Template ??", [System.Management.Automation.Host.ChoiceDescription[]]((New-Object System.Management.Automation.Host.ChoiceDescription "&Yes"), (New-Object System.Management.Automation.Host.ChoiceDescription "&No")), 1))) {
        0 {  
            Write-warning -Message "Due to a bug the open file dialog box may be behind other windows"
            Add-Type -AssemblyName System.Windows.Forms
            $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
            $OpenFileDialog.initialDirectory = [Environment]::GetFolderPath('MyDocuments')
            $OpenFileDialog.filter = 'Word Document (*.docx)|*.docx|Word Template (*.dotx)|*.dotx'
            $OpenFileDialog.title = 'Select Word Template to import'
            $result = $OpenFileDialog.ShowDialog((New-Object System.Windows.Forms.Form -Property @{TopMost = $true }))
            if ($result -eq [Windows.Forms.DialogResult]::OK) {
                $TemplateFile = $OpenFileDialog.filename
            }
            else {
                Write-Verbose "No file selected" -VERBOSE
            } 
            Remove-Variable -Name OpenFileDialog  -ErrorAction SilentlyContinue
            Remove-Variable -name result  -ErrorAction SilentlyContinue

        }
    }
}

try {

    if ($PSBoundParameters.ContainsKey('DownloadSampleDesignText')) {
        $MediantDocText = ((invoke-WebRequest -uri "https://shanehoey.com/mediantdoc.json" -ContentType "text/plain").content -split '\n') | convertfrom-json
    }
    else {
        write-host "Download Sample Design Text ?" -foregroundcolor Yellow
        switch (($host.ui.PromptForChoice("", "Do you want to use the online Design Template  ??`nIMPORTANT: the current online template may only have placeholder text, as text is getting added after script is published", [System.Management.Automation.Host.ChoiceDescription[]]((New-Object System.Management.Automation.Host.ChoiceDescription "&No"), (New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Download a standard design text example")), 1))) {
            1 {  
                Write-verbose -Message "Downloading design document from shanehoey.com/mediantdoc.json" -Verbose
                $MediantDocText = ((invoke-WebRequest -uri "https://shanehoey.com/mediantdoc.json" -ContentType "text/plain").content -split '\n') | convertfrom-json
                Write-verbose -Message "Downloading MediantDoc.json Complete" -Verbose
            }
        }
    }
} 
catch {
    write-warning "Unable to download cloudconnector design template, Defaulting to no design text"
    Remove-Variable MediantDocText -ErrorAction SilentlyContinue
}


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


try 
{ 
    if ($PSBoundParameters.ContainsKey('MediantConfigFile')) 
    {
        $MediantConfigINI = get-content (get-item -path $MediantConfigINI).fullname
    }    
    if ($PSBoundParameters.ContainsKey('MediantDevice')) 
    {
        try { import-module -name Mediant -ErrorAction Stop } catch { Write-Warning "Mediant Module not installed, to install ->  install-module -name mediant -scope currentuser - disabling mediant functions" }
        $mediantdevice = Get-MediantDevice -Mediant $MediantDevice -http $MediantDeviceProtocol -Credential $MediantDeviceCredential
        $MediantConfigini = (Get-MediantDeviceFileIni -MediantDevice $mediantdevice) -split '\n'
        Remove-Variable -name mediantdevice -ErrorAction SilentlyContinue
    }
    
    if (!($MediantConfigini))  
    { 
        $title = $NULL 
        $message = $NULL 
        $Open = New-Object System.Management.Automation.Host.ChoiceDescription "&Open Existing File", "Open Existing config.ini file"
        $Download = New-Object System.Management.Automation.Host.ChoiceDescription "&Download a Sample Config", "Download a Sample Config from shanehoey.com"
        $Connect = New-Object System.Management.Automation.Host.ChoiceDescription "&Connect to Mediant Device", "Download a Config directly from a Mediant device"
        if ($mediantimportfail)
        {
            $Options = [System.Management.Automation.Host.ChoiceDescription[]]($Open,$Download)
            remove-variable mediantimportfail
        }
        else 
        {
            $Options = [System.Management.Automation.Host.ChoiceDescription[]]($Open,$Download,$Connect)
        }
        switch ($host.ui.PromptForChoice($title, $message, $options, 0)) 
            {
                0   {  
                        write-host "Opening existing File" -foregroundcolor Yellow
                        Write-warning -Message "Due to a bug the open file dialog box may be behind other windows"
                        Add-Type -AssemblyName System.Windows.Forms
                        $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
                        $OpenFileDialog.initialDirectory = [Environment]::GetFolderPath('MyDocuments')
                        $OpenFileDialog.filter = 'config.ini (*.ini)|*.ini'
                        $OpenFileDialog.title = 'Select MediantConfig.ini to import'
                        $result = $OpenFileDialog.ShowDialog((New-Object System.Windows.Forms.Form -Property @{TopMost = $true }))
                        if ($result -eq [Windows.Forms.DialogResult]::OK) 
                        {
                            $MediantConfigini = get-content -path $OpenFileDialog.filename
                        }
                        else 
                        {
                            Write-Verbose "No file selected" -VERBOSE
                            throw "No File Selected"
                        } 
                        Remove-Variable -Name OpenFileDialog  -ErrorAction SilentlyContinue
                        Remove-Variable -name result  -ErrorAction SilentlyContinue
                    }
                    1   {  
                        write-host "Downloading Mediantconfig.ini from shanehoey.com/mediantconfig.ini" -foregroundcolor Yellow
                        $MediantConfigini = (invoke-WebRequest -uri "https://shanehoey.com/mediantconfig.ini" -ContentType "text/plain").content -split '\n'
                        Write-host "Dowloading Complete"
                    }
                    2   {  
                        write-host "Connecting to Mediant Device" -foregroundcolor Yellow
                        try { import-module -name Mediant -ErrorAction Stop } catch { Write-Warning "Mediant PowerShell Module not installed, Please manually download a config file or install Mediant PowerShell module (install-module -name mediant -scope currentuser) before continiung ...exiting" }        
                        $MediantConfigini = (Get-MediantDeviceFileIni -MediantDevice (Get-MediantDevice)) -split '\n'
                        Write-verbose -Message "Downloading mediantconfig.ini Complete" 
                    }
            }
        Remove-Variable -name title,message,open,download,connect -ErrorAction SilentlyContinue
    }

    $ini = convertfrom-MediantDocConfigIni -MediantConfigini ($MediantConfigini).replace("[ ","[").replace(" ]","]")
    remove-item MediantConfigini -ErrorAction SilentlyContinue
}
catch 
{
    Write-warning "Sorry unable to get mediant config.ini file, please try again"
    Break
}

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

$GridTableBlue = @{
  'WdAutoFitBehavior'    = 'wdAutoFitWindow'
  'WdDefaultTableBehavior' = 'wdWord9TableBehavior'
  'GridTable'            = 'Grid Table 4'
  'GridAccent'           = 'Accent 1'
  'BandedRow'            = $False
}

$v = @{
  'WdAutoFitBehavior'    = 'wdAutoFitWindow'
  'WdDefaultTableBehavior' = 'wdWord9TableBehavior'
  'GridTable'            = 'Grid Table 4'
  'BandedRow'            = $False
}

$GridTableGrey = @{
  'WdAutoFitBehavior'    = 'wdAutoFitWindow'
  'WdDefaultTableBehavior' = 'wdWord9TableBehavior'
  'GridTable'            = 'Grid Table 4'
  'GridAccent'           = 'Accent 3'
  'BandedRow'            = $False
}

New-WordInstance
New-WordDocument
if($templatefile)
{
    Add-WordTemplate -filename $templatefile
}

#Turn of spelling to speed up creating doc
(get-wordInstance).options.checkspellingasyoutype = $false


if($section.CoverPage) { 

  #Add Coverpage
  for ($i = 0; $i -lt 18; $i++) { Add-WordBreak -breaktype Paragraph }
  Add-WordText -text $DocumentTitle -WDBuiltinStyle wdStyleTitle -TextColor wdColorWhite
  Add-WordText -text $DocumentCustomer -WDBuiltinStyle wdStyleSubtitle -TextColor wdColorWhite
  for ($i = 0; $i -lt  4; $i++) { Add-WordBreak -breaktype Paragraph }

  $fa_github  = [char]0xf09b
  $fontawesometext = "Font Awesome 5 Brands Regular"
  add-wordtext  -text $fa_github -Font $fontawesometext -Size 18 -NoParagraph -TextColor wdColorWhite
  add-wordtext " https://shanehoey.github.io/worddoc/" -Size 18 -TextColor wdColorWhite 

  $pagewidth = (get-worddocument).pagesetup.pagewidth
  $pageheight = (get-worddocument).pagesetup.pageheight
  add-wordshape -shape msoShapeRectangle -left 0 -top 0 -Width $pagewidth -Height ($pageheight/2) -zorder msoSendBehindText -UserPicture "https://www.audiocodes.com/media/12499/mediant-1000-left-transparent.png" 
  add-wordshape -shape msoShapeRectangle -left 0 -top ($pageheight/2) -Width $pagewidth -Height ($pageheight/2) -zorder msoSendBehindText -themecolor msoThemeColorDark1 

  #Fixes to implement into modules 
  #set to RelativeVerticalPosition
  #(Get-WordDocument).Shapes(1).LockAnchor = -1
  #(Get-WordDocument).Shapes(2).LockAnchor = -1

  Add-WordBreak -breaktype Section

  #AddLicense
  Add-WordBreak -breaktype Paragraph
  Add-WordText -text 'This document has been created with wordDoc which has been distributed under the MIT license. For more information visit http://shanehoey.github.io/worddoc/' -Align wdAlignParagraphJustify
  $license = "MIT License`nCopyright (c) 2016-2018 Shane Hoey`rPermission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the 'Software'), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:`nThe above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.`nTHE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE."
  Add-WordText -text $license -WDBuiltinStyle wdStyleNormal -Bold -Align wdAlignParagraphJustify
  #Add Shameless Plug
  for ($i = 0; $i -lt 3; $i++) 
  {
      Add-WordBreak -breaktype Paragraph 
  }
  Add-WordText -text 'Are you using this commercially? Show your appreciation and encourage more development of this script at https://paypal.me/shanehoey' -WDBuiltinStyle wdStyleIntenseQuote -TextColor wdColorBlack

  #Table of Contents
  Add-WordBreak -breaktype NewPage
  Add-WordText -text 'Contents' -WDBuiltinStyle wdStyleTOCHeading -TextColor wdColorBlack
  Add-WordTOC 
  Add-WordBreak -breaktype NewPage

  #Update Document Settings
  Set-WordBuiltInProperty -WdBuiltInProperty wdPropertytitle -text $DocumentTitle
  Set-WordBuiltInProperty -WdBuiltInProperty wdPropertySubject -text "$Documenttitle for $documentCustomer"
  Set-WordBuiltInProperty -WdBuiltInProperty wdPropertyAuthor -text $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGEAbgBlACAASABvAGUAeQA=')))
  Set-WordBuiltInProperty -WdBuiltInProperty wdPropertyComments -text $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcABzADoALwAvAHMAaABhAG4AZQBoAG8AZQB5AC4AZwBpAHQAaAB1AGIALgBpAG8ALwB3AG8AcgBkAGQAbwBjAC8A')))
  Set-WordBuiltInProperty -WdBuiltInProperty wdPropertyManager -text $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGEAbgBlACAASABvAGUAeQA=')))

    
    #License
    $license = "MIT License`nCopyright (c) 2016-2018 Shane Hoey`rPermission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the 'Software'), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:`nThe above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.`nTHE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE."
    Add-WordBreak -breaktype NewPage
    Add-WordText -text 'This document has been created with MediantDoc which has been distributed under the MIT license. For more information visit http://shanehoey.github.io/worddoc/mediant' -WDBuiltinStyle wdStyleBookTitle
    Add-WordBreak -breaktype Paragraph
    #bug with bold/italic in worddoc module
    #$selection = (Get-WordDocument).application.selection
    #$selection.font.Bold = $False
    #$selection.ParagraphFormat.Alignment = 3
    Add-WordText -text $license -WDBuiltinStyle wdStyleNormal
    Add-WordBreak -breaktype NewPage
    
    #Shameless Plug
    for ($i = 0; $i -lt 3; $i++) 
    {
      Add-WordBreak -breaktype Paragraph 
    }
    Add-WordText -text 'Are you using this commercially? Show your appreciation and encourage more development of this script at https://paypal.me/shanehoey' -WDBuiltinStyle wdStyleIntenseQuote -TextColor wdColorBlack
    for ($i = 0; $i -lt 3; $i++) 
    {
      Add-WordBreak -breaktype Paragraph 
    }
    Add-WordText -text 'Have a suggestion on how to improve the script ? https://github.com/shanehoey/mediantdoc/issues/' -WDBuiltinStyle wdStyleIntenseQuote -TextColor wdColorBlack
    Add-WordBreak -breaktype Paragraph 

    }


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


if ($section.EndPage)  
{
   Add-WordBreak -breaktype NewPage  
  for ($i = 0; $i -lt 16; $i++) { Add-WordBreak -breaktype Paragraph }
  $fa_github  = [char]0xf09b
  $fontawesometext = "Font Awesome 5 Brands Regular"
  add-wordtext  -text $fa_github -Font $fontawesometext -Size 18 -NoParagraph -TextColor wdColorWhite
  add-wordtext " https://shanehoey.github.io/worddoc/" -Size 18 -TextColor wdColorWhite -Align wdAlignParagraphCenter

  $pagewidth = (get-worddocument).pagesetup.pagewidth
  $pageheight = (get-worddocument).pagesetup.pageheight
  add-wordshape -shape msoShapeRectangle -left 0 -top 0 -Width $pagewidth -Height $pageheight -zorder msoSendBehindText -themecolor msoThemeColorDark1

}

Update-WordTOC

# SIG # Begin signature block
# MIINCgYJKoZIhvcNAQcCoIIM+zCCDPcCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUwqx0WLetkeD2vzu9e3My7SuR
# EG6gggpMMIIFFDCCA/ygAwIBAgIQDq/cAHxKXBt+xmIx8FoOkTANBgkqhkiG9w0B
# AQsFADByMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMTEwLwYDVQQDEyhEaWdpQ2VydCBTSEEyIEFz
# c3VyZWQgSUQgQ29kZSBTaWduaW5nIENBMB4XDTE4MDEwMzAwMDAwMFoXDTE5MDEw
# ODEyMDAwMFowUTELMAkGA1UEBhMCQVUxGDAWBgNVBAcTD1JvY2hlZGFsZSBTb3V0
# aDETMBEGA1UEChMKU2hhbmUgSG9leTETMBEGA1UEAxMKU2hhbmUgSG9leTCCASIw
# DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANAI9q03Pl+EpWcVZ7PQ3AOJ17k6
# OoS9SCIbZprs7NhyRIg7mKzxdcHMnjKwUe/7NDlt5mYzXT2yY/0MeUkyspiEs1+t
# eiHJ6IIs9llWgPGOkV4Ro5fZzlutqeeaomEW/ulH7mVjihVCR6mP/O09YSNo0Dv4
# AltYmVXqhXTB64NdwupL2G8fmTmVUJsww9abtGxy3mhL/l2W3VBcozZbCZVw363p
# 9mjeR9WUz5AxZji042xldKB/97cNHd/2YyWuJ8eMlYfRqz1nVgmmpuU+SuApRult
# hy6wNEngVmJBVhH/a8AH29dEZNL9pzhJGRwGBFi+m/vIr5SFhQVFZYJy79kCAwEA
# AaOCAcUwggHBMB8GA1UdIwQYMBaAFFrEuXsqCqOl6nEDwGD5LfZldQ5YMB0GA1Ud
# DgQWBBROEIC6bKfPIk2DtUTZh7HSa5ajqDAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0l
# BAwwCgYIKwYBBQUHAwMwdwYDVR0fBHAwbjA1oDOgMYYvaHR0cDovL2NybDMuZGln
# aWNlcnQuY29tL3NoYTItYXNzdXJlZC1jcy1nMS5jcmwwNaAzoDGGL2h0dHA6Ly9j
# cmw0LmRpZ2ljZXJ0LmNvbS9zaGEyLWFzc3VyZWQtY3MtZzEuY3JsMEwGA1UdIARF
# MEMwNwYJYIZIAYb9bAMBMCowKAYIKwYBBQUHAgEWHGh0dHBzOi8vd3d3LmRpZ2lj
# ZXJ0LmNvbS9DUFMwCAYGZ4EMAQQBMIGEBggrBgEFBQcBAQR4MHYwJAYIKwYBBQUH
# MAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBOBggrBgEFBQcwAoZCaHR0cDov
# L2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0U0hBMkFzc3VyZWRJRENvZGVT
# aWduaW5nQ0EuY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggEBAIly
# KESC2V2sBAl6sIQiHRRgQ9oQdtQamES3fVBNHwmsXl76DdjDURDNi6ptwve3FALo
# ROZHkrjTU+5r6GaOIopKwE4IXkboVoPBP0wJ4jcVm7kcfKJqllSBGZfpnSUjlaRp
# EE5k1XdVAGEoz+m0GG+tmb9gGblHUiCAnGWLw9bmRoGbJ20a0IQ8jZsiEq+91Ft3
# 1vJSBO2RRBgqHTama5GD16OyE3Aps5ypaKYXuq0cnNZCaCasRtDJPolSP4KQ+NVg
# Z/W/rDiO8LNOTDwGcZ2bYScAT88A5KX42wiKnKldmyXnd4ffrwWk8fPngR5sVhus
# Arv6TbwR8dRMGwXwQqMwggUwMIIEGKADAgECAhAECRgbX9W7ZnVTQ7VvlVAIMA0G
# CSqGSIb3DQEBCwUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJ
# bmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0
# IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0xMzEwMjIxMjAwMDBaFw0yODEwMjIxMjAw
# MDBaMHIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNV
# BAsTEHd3dy5kaWdpY2VydC5jb20xMTAvBgNVBAMTKERpZ2lDZXJ0IFNIQTIgQXNz
# dXJlZCBJRCBDb2RlIFNpZ25pbmcgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
# ggEKAoIBAQD407Mcfw4Rr2d3B9MLMUkZz9D7RZmxOttE9X/lqJ3bMtdx6nadBS63
# j/qSQ8Cl+YnUNxnXtqrwnIal2CWsDnkoOn7p0WfTxvspJ8fTeyOU5JEjlpB3gvmh
# hCNmElQzUHSxKCa7JGnCwlLyFGeKiUXULaGj6YgsIJWuHEqHCN8M9eJNYBi+qsSy
# rnAxZjNxPqxwoqvOf+l8y5Kh5TsxHM/q8grkV7tKtel05iv+bMt+dDk2DZDv5LVO
# pKnqagqrhPOsZ061xPeM0SAlI+sIZD5SlsHyDxL0xY4PwaLoLFH3c7y9hbFig3NB
# ggfkOItqcyDQD2RzPJ6fpjOp/RnfJZPRAgMBAAGjggHNMIIByTASBgNVHRMBAf8E
# CDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDAzB5
# BggrBgEFBQcBAQRtMGswJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0
# LmNvbTBDBggrBgEFBQcwAoY3aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0Rp
# Z2lDZXJ0QXNzdXJlZElEUm9vdENBLmNydDCBgQYDVR0fBHoweDA6oDigNoY0aHR0
# cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNy
# bDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJl
# ZElEUm9vdENBLmNybDBPBgNVHSAESDBGMDgGCmCGSAGG/WwAAgQwKjAoBggrBgEF
# BQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzAKBghghkgBhv1sAzAd
# BgNVHQ4EFgQUWsS5eyoKo6XqcQPAYPkt9mV1DlgwHwYDVR0jBBgwFoAUReuir/SS
# y4IxLVGLp6chnfNtyA8wDQYJKoZIhvcNAQELBQADggEBAD7sDVoks/Mi0RXILHwl
# KXaoHV0cLToaxO8wYdd+C2D9wz0PxK+L/e8q3yBVN7Dh9tGSdQ9RtG6ljlriXiSB
# ThCk7j9xjmMOE0ut119EefM2FAaK95xGTlz/kLEbBw6RFfu6r7VRwo0kriTGxycq
# oSkoGjpxKAI8LpGjwCUR4pwUR6F6aGivm6dcIFzZcbEMj7uo+MUSaJ/PQMtARKUT
# 8OZkDCUIQjKyNookAv4vcn4c10lFluhZHen6dGRrsutmQ9qzsIzV6Q3d9gEgzpkx
# Yz0IGhizgZtPxpMQBvwHgfqL2vmCSfdibqFT+hKUGIUukpHqaGxEMrJmoecYpJpk
# Ue8xggIoMIICJAIBATCBhjByMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNl
# cnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMTEwLwYDVQQDEyhEaWdp
# Q2VydCBTSEEyIEFzc3VyZWQgSUQgQ29kZSBTaWduaW5nIENBAhAOr9wAfEpcG37G
# YjHwWg6RMAkGBSsOAwIaBQCgeDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkG
# CSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEE
# AYI3AgEVMCMGCSqGSIb3DQEJBDEWBBRAeCYQtYgwYlMScBXSl/4bAC9JpzANBgkq
# hkiG9w0BAQEFAASCAQC0Eqv1KM8LW5hEmDr8giasukuw16Jx3CvWDqXjih9Bmpmp
# qWoMJ5xU6rvUjvlMTfDeI1qrwCour3MUmvSrKOR+fOGorJpDAllnRUOK2TEoVodU
# BDn/G+93LjAlkUwaMW56X5JMHFQGU1lJALuIfHhO2nL5A2GEf82Fjytz0baUJLBL
# gdHph7y0Mw0sEY1NSXGJ9RDzbNimiCL8H2QKqdH9/8YC7k7DpF9BZzytnQlbQnxJ
# Zcn5jFeWQz6KEAwJr9S29Rp7itVWYeGLRnPI3l+AZPdhvaUFrUHGQPv4YoN2k6Sb
# gry222BXxRDK0XXmS6Hgx4tVFeq8s8mjYErWIpVe
# SIG # End signature block
