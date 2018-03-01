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
