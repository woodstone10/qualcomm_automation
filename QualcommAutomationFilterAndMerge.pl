###########################################################################################
#
# QualcommAutomationFilterAndMerge.pl
#
# General description:
# When you received QMDL (captured logs with ODL) logs, what do you usually do first? 
# QMDL log, captured with ODL (On-Device logging), has small compressed log (size of 100 Mbyte) 
# and separated several files. 
# In case of automatic saved ISF logs, you will face difficult on same situation on separated several files. 
# In driving test, there are dozens of logs its total size over than tens of gigabytes. 
# So it is troublesome and tired to convert ISF and/or replay on QXDM/QCAT due to too many files. 
#
# About this software:
# Thie sample code enables help your easy analysis with a converted (QMDL to ISF), 
# filtered (Packets only you want), and merged ISF file. 
# In addition, PCAP file is generated from ISF for DPL analysis. 
# All processing is automation and all thing you do is just C&P (copy and paste) onto log folter, 
# then run it. 
# Since it done, you will see just one ISF file and PCAP file. 
# Filter extracts essential packets from original logs, which reduces QXDM/QCAT replaying time due to slim down. 
# Merger, and, is useful to play QXDM5 and QCAT, because they allow playing one file at one time. 
# Also, generated and merged PCAP saves your time when DPL anaylsis.
#
# How to use it:
# Step.1: copy and past AutomatedISFFilterAndMerge.pl to the target folder
# Step.2: run QualcommAutomationFilterAndMerge.pl and type output file name
# Step.3: Filtered and merged ISF file, and generated and merged PCAP file
#
# Pre-install required:
# - Perl software is required (Recommend Strawberry perl, download: http://strawberryperl.com/)
# - Copy and paste HelperFunctions4 on C:\Strawberry\perl\site\lib (just one time)
# - Qualcomm QXDM and QCAT
# - Wireshark software is required (download: https://www.wireshark.org/#download)
#
# Created by Jonggil Nam
# https://www.linkedin.com/in/jonggil-nam-6099a162/ | https://github.com/woodstone10 | woodstone10@gmail.com | +82-10-8709-6299 
###########################################################################################

#!/apps/perl/bin
$| = 1; 
use strict;
use File::Basename;
use File::stat;
use Term::ANSIColor qw(:constants);
use Cwd;
use Win32::OLE; #NOTE: Recommend use Strawberry perl (or install Win3/OLE pm in ActiveState perl)
use Win32::OLE::Variant;
use Win32::OLE::NLS qw(:LOCALE :DATE);
use Win32::OLE::NLS qw(:LOCALE :TIME);
use HelperFunctions4; 

use constant FALSE => 0;
use constant false => 0;
use constant TRUE => 1;
use constant true => 1;
use constant NULL => 0;

my $qxdmIConfig = 0;
my $QXDM;
my $nofisf=0;

my $currentDir = getcwd(); 
chdir($currentDir);
my $directory_qcat = "$currentDir/";

print ">Output file name? "; 
my $stdin=<STDIN>;
chomp($stdin);
my $outisf = $stdin.".isf";
my $outpcap = $stdin.".pcap";

my @files = ();
my @filt = ();

print ">Convert qmdl to isf\n";
@files = ();
@files =<*.qmdl>;
foreach my $file (@files){ print "Input:$file\n"; QMDLtoISF($file); }

print ">Pcap Generator\n";
@files = ();
@files = <*.isf>; 
PCAP_Generator(); 

print ">Pcap Merge\n"; 
mergecap($outpcap);

print ">Isf Filter\n";
@files = ();
@files = <*.isf>; 
foreach my $file (@files){ print "Input:$file"; FilterIsf($file); }

print ">Isf Merge\n"; 
@files = ();
@files = <*.isf>; 
CombineIsf($outisf); 

print "Finish\n"; 

sub QMDLtoISF($)
{
	my $in;
	my ($in) = @_; if(not -e $in){ die "Input file $in does not exist\n"; }
	my @in_ = split (/\.qmdl/, $in);
	my $tmp = $in_[0];

	#file name
	my $qmdl = $currentDir."\\".$in;
	my $dlf = $tmp.".dlf";
	my $isf = $tmp.".isf";
	unlink($dlf); 
	unlink($isf); 

	#Convert qmdl to dlf
	my $qcat_app = new Win32::OLE 'QCAT6.Application';
	if(!$qcat_app){ print "ERROR: Unable to invoke the QCAT application.\n"; die; }
	if(!$qcat_app->OpenLog($qmdl)){ print "\nERROR: $qcat_app->{LastError}\n"; die; }
	if(!$qcat_app->SaveAsDLF($dlf)){ print "\nERROR: $qcat_app->{LastError}\n"; die; }
	if($qcat_app != NULL){ $qcat_app->{Visible} = FALSE; $qcat_app = NULL; }
	
	#Convert dlf to isf (QC convertDLFtoISF.pl)
	my $RC = false ;
	$RC = Initialize(); if ($RC == false){ return; }
	my $Version = $QXDM->{AppVersion};
	my $FolderPath = GetPathFromScript();
    my $FileName = $FolderPath . $dlf;
	my $OutputFile =  GetPathFromScript().$isf ;	
	$RC = $QXDM->ConvertToFile($FileName,$OutputFile); 
	if($RC == true){ print "=>$isf\n"; }
	else{ print "Conversion Failed\n"; }

	unlink($dlf); 
}

sub Initialize
{
   my $RC = false;
   $QXDM = QXDMInitialize();
   if ($QXDM == null){ print "\nError launching QXDM"; return $RC; }
   SetQXDM ( $QXDM );
   $RC = true;
   return $RC;
}

sub QXDM_FILTER
{
	qxdmAddItems("ota", 0x1004, ""); #[0x1004] Access Channel Message
	qxdmAddItems("ota", 0x1005, ""); #[0x1005] Reverse Channel Traffic Message
	qxdmAddItems("ota", 0x1006, ""); #[0x1006] Sync Channel Traffic Message
	qxdmAddItems("ota", 0x1007, ""); #[0x1007] Paging Channel Message
	qxdmAddItems("ota", 0x1008, ""); #[0x1008] Forward Channel Traffic Message
	qxdmAddItems("ota", 0x1090, ""); #[0x1090] Forward Dedicated Control Channel Message
	qxdmAddItems("ota", 0x1091, ""); #[0x1091] Reverse Dedicated Control Channel Message
	qxdmAddItems("ota", 0x10D6, ""); #[0x10D6] Broadcast Control Channel Message
	qxdmAddItems("ota", 0x10D7, ""); #[0x10D7] Reverse Enhanced Access Channel Message
	qxdmAddItems("ota", 0x10D8, ""); #[0x10D8] Forward Common Control Channel Message
	qxdmAddItems("ota", 0x1076, ""); #[0x1076] 1xEV Signaling Access Channel
	qxdmAddItems("ota", 0x1077, ""); #[0x1077] 1xEV Signaling Reverse Traffic Channel
	qxdmAddItems("ota", 0x1078, ""); #[0x1078] 1xEV Signaling Control Channel Directed
	qxdmAddItems("ota", 0x1079, ""); #[0x1079] 1xEV Signaling Forward Traffic Channel
	qxdmAddItems("ota", 0x107C, ""); #[0x107C] 1xEV Signaling Control Channel Broadcast
	qxdmAddItems("ota", 0x1085, ""); #[0x1085] 1xEV AC MAC Capsule
	qxdmAddItems("ota", 0x1086, ""); #[0x1086] 1xEV CC MAC Packet
	qxdmAddItems("ota", 0x713A, ""); #[0x713A] UMTS UE OTA
	qxdmAddItems("ota", 0x7B3A, ""); #[0x7B3A] UMTS DSDS NAS Signaling Messages
	qxdmAddItems("ota", 0x512F, ""); #[0x512F] GSM RR Signaling Message
	qxdmAddItems("ota", 0x5226, ""); #[0x5226] GPRS MAC Signaling Message
	qxdmAddItems("ota", 0x5230, ""); #[0x5230] GPRS SM/GMM OTA Signaling Message
	qxdmAddItems("ota", 0x412F, ""); #[0x412F] WCDMA Signaling Messages
	qxdmAddItems("ota", 0xB0C0, ""); #[0xB0C0] LTE RRC OTA Packet
	qxdmAddItems("ota", 0xB0E2, ""); #[0xB0E2] LTE NAS ESM Plain OTA Incoming Message
	qxdmAddItems("ota", 0xB0E3, ""); #[0xB0E3] LTE NAS ESM Plain OTA Outgoing Message
	qxdmAddItems("ota", 0xB0EC, ""); #[0xB0EC] LTE NAS EMM Plain OTA Incoming Message
	qxdmAddItems("ota", 0xB0ED, ""); #[0xB0ED] LTE NAS EMM Plain OTA Outgoing Message
	qxdmAddItems("ota", 0xB800, ""); #[0xB800] NR5G NAS SM5G Plain OTA Incoming Msg
	qxdmAddItems("ota", 0xB801, ""); #[0xB801] NR5G NAS SM5G Plain OTA Outgoing Msg
	qxdmAddItems("ota", 0xB80A, ""); #[0xB80A] NR5G NAS MM5G Plain OTA Incoming Msg
	qxdmAddItems("ota", 0xB80B, ""); #[0xB80B] NR5G NAS MM5G Plain OTA Outgoing Msg
	qxdmAddItems("ota", 0xB814, ""); #[0xB814] NR5G NAS Plain Message Container 
	qxdmAddItems("ota", 0xB821, ""); #[0xB821] NR5G RRC OTA Packet

	qxdmAddItems("msg", 5, 0); #CM
	qxdmAddItems("msg", 5, 1); 
	qxdmAddItems("msg", 5, 2);
	qxdmAddItems("msg", 5, 3);
	qxdmAddItems("msg", 5, 4);
	qxdmAddItems("msg", 14, 1); #RF
	qxdmAddItems("msg", 14, 2); 
	#qxdmAddItems("msg", 15, 0); #SD
	qxdmAddItems("msg", 15, 1);
	qxdmAddItems("msg", 15, 2);
	qxdmAddItems("msg", 15, 3);
	qxdmAddItems("msg", 15, 4);
	#qxdmAddItems("msg", 20, 0); #MMOC
	qxdmAddItems("msg", 20, 1);
	qxdmAddItems("msg", 20, 2);
	qxdmAddItems("msg", 20, 3);
	qxdmAddItems("msg", 20, 4);
	#qxdmAddItems("msg", 21, 0); #UIM
	qxdmAddItems("msg", 21, 1);
	qxdmAddItems("msg", 21, 2);
	qxdmAddItems("msg", 21, 3);
	qxdmAddItems("msg", 21, 4);
	#qxdmAddItems("msg", 58, 0); #Android ADB
	qxdmAddItems("msg", 58, 1);
	qxdmAddItems("msg", 58, 2);
	qxdmAddItems("msg", 58, 3);
	qxdmAddItems("msg", 58, 4);
	qxdmAddItems("msg", 63, 0); #Android QCRIL
	qxdmAddItems("msg", 63, 1);
	qxdmAddItems("msg", 63, 2);
	qxdmAddItems("msg", 63, 3);
	qxdmAddItems("msg", 63, 4);
	qxdmAddItems("msg", 65, 0); #Linux Data
	qxdmAddItems("msg", 65, 1);
	qxdmAddItems("msg", 65, 2);
	qxdmAddItems("msg", 65, 3);
	qxdmAddItems("msg", 65, 4);
	#qxdmAddItems("msg", 90, 0); #MMODE QMI
	qxdmAddItems("msg", 90, 1);
	qxdmAddItems("msg", 90, 2);
	qxdmAddItems("msg", 90, 3);
	qxdmAddItems("msg", 90, 4);
	#qxdmAddItems("msg", 91, 0); #MCFG
	qxdmAddItems("msg", 91, 1);
	qxdmAddItems("msg", 91, 2);
	qxdmAddItems("msg", 91, 3);
	qxdmAddItems("msg", 91, 4);
	#qxdmAddItems("msg", 99, 0); #Policy Manager
	qxdmAddItems("msg", 99, 1);
	qxdmAddItems("msg", 99, 2);
	qxdmAddItems("msg", 99, 3);
	qxdmAddItems("msg", 99, 4);
	#qxdmAddItems("msg", 112, 0); #MRE
	qxdmAddItems("msg", 112, 1);
	qxdmAddItems("msg", 112, 2);
	qxdmAddItems("msg", 112, 3);
	qxdmAddItems("msg", 112, 4);
	qxdmAddItems("msg", 3007, 2);
	qxdmAddItems("msg", 3010, 2);
	qxdmAddItems("msg", 5000, 1);
	qxdmAddItems("msg", 5000, 2);
	qxdmAddItems("msg", 5026, 2);
	qxdmAddItems("msg", 9500, 4);
	qxdmAddItems("msg", 9501, 0);
	qxdmAddItems("msg", 9501, 1);
	qxdmAddItems("msg", 9501, 2);
	qxdmAddItems("msg", 9501, 3);
	qxdmAddItems("msg", 9501, 4);	
	qxdmAddItems("msg", 9502, 5);
	qxdmAddItems("msg", 9507, 2);
	qxdmAddItems("msg", 9509, 1);
	qxdmAddItems("msg", 9509, 2);
	qxdmAddItems("qtrace", 9, 1); 
	qxdmAddItems("qtrace", 42, 0); #MMODE/STRM
	qxdmAddItems("qtrace", 47, 1); 
	qxdmAddItems("qtrace", 76, 3); #QSH/EVENT
	qxdmAddItems("qtrace", 76, 4); #QSH/ANALYSIS
	qxdmAddItems("qtrace", 83, 0);
	qxdmAddItems("qtrace", 85, 5);
	qxdmAddItems("qtrace", 87, 0);
	qxdmAddItems("qtrace", 87, 22);
	qxdmAddItems("qshmetric", 13, 0);	
	#qxdmAddItems("event", 0629, undef); #0629 EVENT_CM_CALL_EVENT_ORIG
	qxdmAddItems("event", 0630, undef); #0630 EVENT_CM_CALL_EVENT_CONNECT
	qxdmAddItems("event", 0631, undef); #0631 EVENT_CM_CALL_EVENT_END
	qxdmAddItems("event", 632, undef); #Common Call Manager
	qxdmAddItems("event", 633, undef); #Common Call Manager
	qxdmAddItems("event", 1020, undef); #1020 EVENT_CM_DATA_AVAILABLE
	qxdmAddItems("event", 1181, undef); #1181 EVENT_CM_CALL_EVENT_ORIG_THR
	qxdmAddItems("event", 1729, undef); #1729 EVENT_CM_DS_CALL_EVENT_ORIG
	qxdmAddItems("event", 1730, undef); #1730 EVENT_CM_DS_CALL_EVENT_CONNECT
	qxdmAddItems("event", 1731, undef); #1731 EVENT_CM_DS_CALL_EVENT_END
	qxdmAddItems("event", 1738, undef); #1738 EVENT_CM_DS_DATA_AVAILABLE
	qxdmAddItems("event", 1921, undef); #1921 EVENT_CM_LTE_BAND_PREF
	qxdmAddItems("event", 1976, undef); #1976 EVENT_DS_EPC_PDN
	qxdmAddItems("event", 2170, undef); #2170 EVENT_DS_DSD_PREFERRED_RADIO
	qxdmAddItems("event", 2222, undef); #2222 EVENT_DS_DSD_ATTACH_PDN_CHANGE
	qxdmAddItems("event", 2471, undef); #Common Call Manager
	qxdmAddItems("event", 2472, undef); #Common Call Manager
	qxdmAddItems("event", 2473, undef); #Common Call Manager
	qxdmAddItems("event", 2478, undef); #2478 EVENT_DS_CALL_STATUS
	qxdmAddItems("event", 2523, undef); #2523 EVENT_PS_SYSTEM_STATUS
	qxdmAddItems("event", 2525, undef); #2525 EVENT_PS_SYSTEM_STATUS_EX
	qxdmAddItems("event", 2565, undef); #2565 EVENT_DS_EPC_PDN_EX
	qxdmAddItems("event", 2567, undef); #2567 EVENT_DS_DSD_PREFERRED_RADIO_INFO
	qxdmAddItems("event", 2695, undef); #Common Call Manager
	qxdmAddItems("event", 3252, undef); #3252 EVENT_DS_3GPP_NR5G_NSA_SWITCH

	#qxdmAddItems("msg", 1002, 0); #Digital Call Processing
	qxdmAddItems("msg", 1002, 1);
	qxdmAddItems("msg", 1002, 2);
	qxdmAddItems("msg", 1002, 3);
	qxdmAddItems("msg", 1002, 4);
	#qxdmAddItems("msg", 1006, 0); #Multiplex Sublayer
	qxdmAddItems("msg", 1006, 1);
	qxdmAddItems("msg", 1006, 2);
	qxdmAddItems("msg", 1006, 3);
	qxdmAddItems("msg", 1006, 4);
	#qxdmAddItems("msg", 1007, 0); #Searcher
	qxdmAddItems("msg", 1007, 1);
	qxdmAddItems("msg", 1007, 2);
	qxdmAddItems("msg", 1007, 3);
	qxdmAddItems("msg", 1007, 4);

	qxdmAddItems("event", 1498, undef); #1498 EVENT_LTE_TIMING_ADVANCE
	qxdmAddItems("event", 1499, undef); #1499 EVENT_LTE_UL_OUT_OF_SYNC
	qxdmAddItems("event", 1501, undef); #1501 EVENT_LTE_RACH_ACCESS_START
	qxdmAddItems("event", 1503, undef); #1503 EVENT_LTE_RACH_ACCESS_RESULT
	qxdmAddItems("event", 1606, undef); #1606 EVENT_LTE_RRC_STATE_CHANGE
	qxdmAddItems("event", 1607, undef); #1607 EVENT_LTE_RRC_OUT_OF_SERVICE
	qxdmAddItems("event", 1608, undef); #1608 EVENT_LTE_RRC_RADIO_LINK_FAILURE
	qxdmAddItems("event", 1611, undef); #1611 EVENT_LTE_RRC_NEW_CELL_IND
	qxdmAddItems("event", 1612, undef); #1612 EVENT_LTE_RRC_CELL_RESEL_FAILURE
	qxdmAddItems("event", 1613, undef); #1613 EVENT_LTE_RRC_HO_FAILURE
	qxdmAddItems("event", 1619, undef); #1619 EVENT_LTE_RRC_SIB_READ_FAILURE
	qxdmAddItems("event", 1935, undef); #1935 EVENT_LTE_RRC_CELL_BLACKLIST_IND
	qxdmAddItems("event", 1970, undef); #1970 EVENT_LTE_RRC_PLMN_SEARCH_START
	qxdmAddItems("event", 1971, undef); #1971 EVENT_LTE_RRC_PLMN_SEARCH_STOP
	qxdmAddItems("event", 1994, undef); #1994 EVENT_LTE_RRC_STATE_CHANGE_TRIGGER
	qxdmAddItems("event", 1995, undef); #1995 EVENT_LTE_RRC_RADIO_LINK_FAILURE_STAT
	qxdmAddItems("event", 1685, undef); #1685 EVENT_LTE_ML1_STATE_CHANGE
	qxdmAddItems("event", 2239, undef); #2239 EVENT_LTE_SCELL_CONFIGURATION
	qxdmAddItems("event", 2240, undef); #2240 EVENT_LTE_SCELL_ACT_DEACT_CMD
	qxdmAddItems("event", 2241, undef); #2241 EVENT_LTE_SCELL_DEACTIVATION_TIMER_EXPIRY
	qxdmAddItems("event", 2242, undef); #2242 EVENT_SCELL_STATE_CHANGE_INTERNAL
	qxdmAddItems("event", 2568, undef); #2568 EVENT_LTE_RRC_NEW_CELL_IND_EXT_EARFCN
	qxdmAddItems("event", 2590, undef); #2590 EVENT_LTE_SCELL_STATE_CHANGE_ENHANCED2
	qxdmAddItems("event", 2595, undef); #2595 EVENT_LTE_TO_LTE REDIRECTION
	qxdmAddItems("event", 2686, undef); #2686 EVENT_LTE_TIMING_ADVANCE_V2
	qxdmAddItems("event", 2687, undef); #2687 EVENT_LTE_UL_OUT_OF_SYNC_V2
	qxdmAddItems("event", 2689, undef); #2689 EVENT_LTE_RACH_ACCESS_START_V2
	qxdmAddItems("event", 2690, undef); #2690 EVENT_LTE_RACH_ACCESS_RESULT_V2
	qxdmAddItems("event", 2728, undef); #2728 EVENT_LTE_SCELL_STATE_CHANGE_ENHANCED3
	qxdmAddItems("log", 0xB060, undef); #[0xB060] LTE MAC Configuration
	qxdmAddItems("log", 0xB061, undef); #[0xB061] LTE MAC Rach Trigger
	qxdmAddItems("log", 0xB062, undef); #[0xB062] LTE MAC Rach Attempt
	qxdmAddItems("log", 0xB063, undef); #[0xB063] LTE MAC DL Transport Block
	qxdmAddItems("log", 0xB064, undef); #[0xB064] LTE MAC UL Transport Block
	qxdmAddItems("log", 0xB081, undef); #[0xB081] LTE RLC DL Config Log packet 
	qxdmAddItems("log", 0xB082, undef); #[0xB082] LTE RLC DL AM All PDU
	qxdmAddItems("log", 0xB083, undef); #[0xB083] LTE RLC DL AM Control PDU
	qxdmAddItems("log", 0xB086, undef); #[0xB086] LTE RLC DL UM Data PDU
	qxdmAddItems("log", 0xB087, undef); #[0xB087] LTE RLC DL Statistics
	qxdmAddItems("log", 0xB089, undef); #[0xB089] LTE RLC eMBMS DATA PDU
	qxdmAddItems("log", 0xB08A, undef); #[0xB08A] LTE RLC eMBMS Statistics
	qxdmAddItems("log", 0xB091, undef); #[0xB091] LTE RLC UL Config Log packet
	qxdmAddItems("log", 0xB092, undef); #[0xB092] LTE RLC UL AM All PDU 
	qxdmAddItems("log", 0xB093, undef); #[0xB093] LTE RLC UL AM Control PDU
	qxdmAddItems("log", 0xB096, undef); #[0xB096] LTE RLC UL UM Data PDU
	qxdmAddItems("log", 0xB097, undef); #[0xB097] LTE RLC UL Statistics
	qxdmAddItems("log", 0xB0A0, undef); #[0xB0A0] LTE PDCP DL Config
	qxdmAddItems("log", 0xB0A1, undef); #[0xB0A1] LTE PDCP DL Data PDU
	qxdmAddItems("log", 0xB0A0, undef); #[0xB0A2] LTE PDCP DL Ctrl PDU
	qxdmAddItems("log", 0xB0A2, undef); #[0xB0A3] LTE PDCP DL Cipher Data PDU
	qxdmAddItems("log", 0xB0A4, undef); #[0xB0A4] LTE PDCP DL Statistics Pkt
	qxdmAddItems("log", 0xB0A5, undef); #[0xB0A5] LTE PDCP DL SRB Integrity Data PDU
	qxdmAddItems("log", 0xB0A6, undef); #[0xB0A6] LTE PDCP DL SDU
	qxdmAddItems("log", 0xB0B0, undef); #[0xB0B0] LTE PDCP UL Config
	qxdmAddItems("log", 0xB0B1, undef); #[0xB0B1] LTE PDCP UL Data PDU
	qxdmAddItems("log", 0xB0B2, undef); #[0xB0B2] LTE PDCP UL Ctrl PDU
	qxdmAddItems("log", 0xB0B3, undef);	#[0xB0B3] LTE PDCP UL Cipher Data PDU
	qxdmAddItems("log", 0xB0B4, undef); #[0xB0B4] LTE PDCP UL Statistics Pkt
	qxdmAddItems("log", 0xB0B5, undef); #[0xB0B5] LTE PDCP UL SRB Integrity Data PDU
	qxdmAddItems("log", 0xB0C1, undef); #[0xB0C1] LTE RRC MIB Message Log Packet
	qxdmAddItems("log", 0xB0C2, undef); #[0xB0C2] LTE RRC Serving Cell Info Log Pkt
	qxdmAddItems("log", 0xB0C3, undef); #[0xB0C3] LTE PLMN Search Request
	qxdmAddItems("log", 0xB0C4, undef); #[0xB0C4] LTE PLMN Search Response
	qxdmAddItems("log", 0xB0CA, undef); #[0xB0CA] LTE RRC Log Meas Info
	qxdmAddItems("log", 0xB0CB, undef); #[0xB0CB] LTE RRC Paging UE
	qxdmAddItems("log", 0xB0CD, undef); #[0xB0CD] LTE RRC Supported CA Combos
	qxdmAddItems("log", 0xB0D1, undef); #[0xB0D1] LTE RRC Cap Related Info
	qxdmAddItems("log", 0xB0D3, undef); #[0xB0D3] LTE RRC Connection Release Info
	qxdmAddItems("log", 0xB0E6, undef); #[0xB0E6] LTE NAS ESM Procedure State
	qxdmAddItems("log", 0xB0EE, undef); #[0xB0EE] LTE NAS EMM State
	qxdmAddItems("log", 0xB0EF, undef); #[0xB0EF] LTE NAS EMM USIM card mode
	qxdmAddItems("log", 0xB0F5, undef); #[0xB0F5] LTE NAS EMM USIM Service Table
	qxdmAddItems("log", 0xB111, undef); #[0xB111] LTE LL1 Rx Agc Log
	qxdmAddItems("log", 0xB113, undef); #[0xB113] LTE LL1 PSS Results
	qxdmAddItems("log", 0xB114, undef); #[0xB114] LTE LL1 Serving Cell Frame Timing
	qxdmAddItems("log", 0xB115, undef); #[0xB115] LTE LL1 SSS Results
	qxdmAddItems("log", 0xB11D, undef); #[0xB11D] LTE LL1 Serving Cell TTL Results
	qxdmAddItems("log", 0xB121, undef); #[0xB121] LTE LL1 Serving Cell COM Loop
	qxdmAddItems("log", 0xB122, undef); #[0xB122] LTE LL1 Serving Cell CER
	qxdmAddItems("log", 0xB123, undef); #[0xB123] LTE LL1 Neighbor Cell CER
	qxdmAddItems("log", 0xB126, undef); #[0xB126] LTE LL1 PDSCH Demapper Configuration
	qxdmAddItems("log", 0xB12C, undef); #[0xB12C] LTE LL1 PHICH Decoding Results
	qxdmAddItems("log", 0xB12E, undef); #[0xB12E] LTE LL1 PBCH Decoding Results
	qxdmAddItems("log", 0xB130, undef); #[0xB130] LTE LL1 PDCCH Decoding Result
	qxdmAddItems("log", 0xB132, undef); #[0xB132] LTE LL1 PDSCH Decoding Results
	qxdmAddItems("log", 0xB139, undef); #[0xB139] LTE LL1 PUSCH Tx Report
	qxdmAddItems("log", 0xB13C, undef); #[0xB13C] LTE LL1 PUCCH Tx Report
	qxdmAddItems("log", 0xB140, undef); #[0xB140] LTE LL1 SRS Tx Report
	qxdmAddItems("log", 0xB144, undef); #[0xB144] LTE LL1 RACH Tx Report
	qxdmAddItems("log", 0xB146, undef); #[0xB146] LTE LL1 UL AGC Tx Report
	qxdmAddItems("log", 0xB14D, undef); #[0xB14D] LTE LL1 PUCCH CSF
	qxdmAddItems("log", 0xB14E, undef); #[0xB14E] LTE LL1 PUSCH CSF
	qxdmAddItems("log", 0xB167, undef); #LTE ML1
	qxdmAddItems("log", 0xB168, undef); #LTE ML1
	qxdmAddItems("log", 0xB169, undef); #LTE ML1
	qxdmAddItems("log", 0xB16A, undef); #LTE ML1
	qxdmAddItems("log", 0xB173, undef); #[0xB173] LTE PDSCH Stat Indication
	qxdmAddItems("log", 0xB176, undef); #[0xB176] LTE Initial Acquisition Results
	qxdmAddItems("log", 0xB193, undef); #[0xB193] LTE ML1 Serving Cell Meas Response
	qxdmAddItems("log", 0xB197, undef); #LTE ML1
	qxdmAddItems("log", 0xB1C9, undef); #[0xB1C9]  LTE ML1 DL BLER Stats

	qxdmAddItems("event", 3184, undef); #3184 EVENT_NR5G_RRC_NEW_CELL_IND_V2
	qxdmAddItems("event", 3189, undef); #3189 EVENT_NR5G_RRC_HO_FAILURE_V2
	qxdmAddItems("event", 3192, undef); #3192 EVENT_NR5G_RRC_RADIO_LINK_FAILURE_STAT_V2
	qxdmAddItems("event", 3243, undef); #3243 EVENT_NR5G_RRC_SCG_FAILURE
	qxdmAddItems("event", 3213, undef); #3213 EVENT_NAS_MM5G_TIMER_START
	qxdmAddItems("event", 3214, undef); #3214 EVENT_NAS_MM5G_TIMER_STOP
	qxdmAddItems("event", 3215, undef); #3215 EVENT_NAS_MM5G_TIMER_EXPIRY	
	qxdmAddItems("log", 0xB822, undef); #[0xB822] NR5G RRC MIB Info
	qxdmAddItems("log", 0xB823, undef); #[0xB823] NR5G RRC Serving Cell Info
	qxdmAddItems("log", 0xB825, undef); #[0xB825] NR5G RRC Configuration Info
	qxdmAddItems("log", 0xB826, undef); #[0xB826] NR5G RRC Supported CA Combos
	qxdmAddItems("log", 0xB827, undef); #[0xB827] NR5G RRC PLMN Search Request
	qxdmAddItems("log", 0xB828, undef); #[0xB828] NR5G RRC PLMN Search Response
	qxdmAddItems("log", 0xB82B, undef); #[0xB82B] NR5G RRC Detected Cell Info
	qxdmAddItems("log", 0xB840, undef); #[0xB840] NR5G PDCP DL Data Pdu
	qxdmAddItems("log", 0xB841, undef); #[0xB841] NR5G PDCP DL Control Pdu
	qxdmAddItems("log", 0xB842, undef); #[0xB842] NR5G PDCP DL Rbs Stats
	qxdmAddItems("log", 0xB84B, undef); #[0xB84B] NR5G L2 DL Config
	qxdmAddItems("log", 0xB84D, undef); #[0xB84D] NR5G RLC DL Stats
	qxdmAddItems("log", 0xB84E, undef); #[0xB84E] NR5G RLC DL Status PDU
	qxdmAddItems("log", 0xB860, undef);	#[0xB860] NR5G PDCP UL Stats
	qxdmAddItems("log", 0xB861, undef); #[0xB861] NR5G PDCP UL Control Pdu
	qxdmAddItems("log", 0xB868, undef); #[0xB868] NR5G RLC UL Stats
	qxdmAddItems("log", 0xB869, undef); #[0xB869] NR5G RLC UL Status PDU
	qxdmAddItems("log", 0xB84C, undef); #[0xB84C] NR5G RLC DL Control PDU
	qxdmAddItems("log", 0xB858, undef); #[0xB858] NR5G L2 DL MCE
	qxdmAddItems("log", 0xB8A0, undef); #[0xB8A0] NR5G MAC LL1 PUSCH Tx
	qxdmAddItems("log", 0xB975, undef); #[0xB975] NR5G ML1 Serving Cell Beam Management
	qxdmAddItems("log", 0xB857, undef); #[0xB857] NR5G L2 DL DATA PDU
	qxdmAddItems("log", 0xB870, undef); #[0xB870] NR5G L2 UL Data Pdu
	qxdmAddItems("log", 0xB871, undef); #[0xB871] NR5G L2 UL Config
	qxdmAddItems("log", 0xB872, undef); #[0xB872] NR5G L2 UL TB
	qxdmAddItems("log", 0xB873, undef); #[0xB873] NR5G L2 UL BSR 
	qxdmAddItems("log", 0xB881, undef); #[0xB881] NR5G MAC UL TB Stats
	qxdmAddItems("log", 0xB880, undef); #[0xB880] NR5G MAC UL TB 
	qxdmAddItems("log", 0xB883, undef); #[0xB883] NR5G MAC UL Physical Channel Schedule Report
	qxdmAddItems("log", 0xB884, undef); #[0xB884] NR5G MAC UL Physical Channel Power Control
	qxdmAddItems("log", 0xB885, undef); #[0xB885] NR5G MAC DCI Info
	qxdmAddItems("log", 0xB886, undef); #[0xB886] NR5G MAC DL TB Report
	qxdmAddItems("log", 0xB887, undef); #[0xB887] NR5G MAC PDSCH Status
	qxdmAddItems("log", 0xB888, undef); #[0xB888] NR5G MAC PDSCH Stats
	qxdmAddItems("log", 0xB889, undef); #[0xB889] NR5G MAC RACH Trigger
	qxdmAddItems("log", 0xB88A, undef); #[0xB88A] NR5G MAC RACH Attempt
	qxdmAddItems("log", 0xB890, undef); #[0xB890] NR5G MAC CDRX Events Info
	qxdmAddItems("log", 0xB891, undef); #[0xB891] NR5G MAC LL1 CSF Indication
	qxdmAddItems("log", 0xB896, undef); #[0xB896] NR5G MAC UCI Payload Information
	qxdmAddItems("log", 0xB89B, undef); #[0xB89B] NR5G MAC UCI Information
	qxdmAddItems("log", 0xB89C, undef); #[0xB89C] NR5G MAC Flow Control
	qxdmAddItems("log", 0xB8A7, undef); #[0xB8A7] NR5G MAC CSF Report
	qxdmAddItems("log", 0xB8C9, undef); #[0xB8C9] NR5G LL1 FW RX Control AGC
	qxdmAddItems("log", 0xB8D1, undef); #[0xB8D1] NR5G LL1 FW TX IU RF
	qxdmAddItems("log", 0xB8D2, undef); #[0xB8D2] NR5G LL1 FW MAC TX IU Power
	qxdmAddItems("log", 0xB8DD, undef); #[0xB8DD] NR5G LL1 FW Serving FTL
	qxdmAddItems("log", 0xB8E2, undef); #[0xB8E2] NR5G LL1 FW CSF Reports
	qxdmAddItems("log", 0xB950, undef); #[0xB950] NR5G ML1 DL Common Config
	qxdmAddItems("log", 0xB951, undef); #[0xB951] NR5G ML1 DL Dedicated Config
	qxdmAddItems("log", 0xB952, undef); #[0xB952] NR5G ML1 DL Handover
	qxdmAddItems("log", 0xB959, undef); #[0xB959] NR5G ML1 RLM Stats
	qxdmAddItems("log", 0xB96D, undef); #[0xB96D] NR5G ML1 Searcher ACQ Config And Response
	qxdmAddItems("log", 0xB96E, undef); #[0xB96E] NR5G ML1 Searcher Measurement Config
	qxdmAddItems("log", 0xB96F, undef); #[0xB96F] NR5G ML1 Searcher Conn Eval
	qxdmAddItems("log", 0xB970, undef); #[0xB970] NR5G ML1 Searcher Idle S Criteria
	qxdmAddItems("log", 0xB975, undef);	#[0xB975] NR5G ML1 Serving Cell Beam Management
	qxdmAddItems("log", 0xB97F, undef); #[0xB97F] NR5G ML1 Searcher Measurement Database Update Ext
	qxdmAddItems("log", 0xB981, undef); #[0xB981] NR5G ML1 FC Information
	qxdmAddItems("log", 0xB98B, undef); #[0xB98B] NR5G ML1 QMI Handler
	qxdmAddItems("log", 0xB98F, undef); #[0xB98F] NR5G ML1 Antenna Switch Diversity
	qxdmAddItems("log", 0xB992, undef); #[0xB992] NR5G ML1 AFC Services
	qxdmAddItems("log", 0xB9A4, undef); #[0xB9A4] NR5G ML1 BFR Ind
	qxdmAddItems("log", 0xB9A5, undef); #[0xB9A5] NR5G ML1 RLM BFD IND
	qxdmAddItems("log", 0xB9A7, undef); #[0xB9A7] NR5G ML1 DLM2 CA Metrics Request
	qxdmAddItems("log", 0xB9BE, undef); #[0xB9BE] NR5G ML1 Search HO Acq Req
	qxdmAddItems("log", 0xB9BF, undef); #[0xB9BF] NR5G ML1 Search HO Acq Confirm
}

sub FilterIsf($)
{	
	my $in;
	my ($in) = @_; if(not -e $in){ die "Input file $in does not exist\n"; }
	my @in_ = split (/\.isf/, $in );	
	my $tmp = $in_[0];

	#file name
	my $isf = $currentDir."\\".$in;
	my $_isf = $tmp."-.isf";
	unlink($_isf);
	my $out = $currentDir."\\".$_isf;		

	#run QXDM
	my $ws = Win32::OLE->new('WScript.Shell');
	my $rc = $ws->run("QXDM.EXE", 1, 0);
	my $qxdm = Win32::OLE->new('QXDM.QXDMAutoApplication') or die "Can't start QXDM";	
	$ws = undef;
	my $qxdmIIsf = $qxdm->GetAutomationWindow2();	
	return 0 if (!$qxdmIIsf);
	my $qxdmHandle = $qxdmIIsf->LoadItemStore($isf);
	return 0 if ($qxdmHandle == 0);
	my $qxdmIClient = $qxdmIIsf->GetClientInterface($qxdmHandle);
	my $qxdmClientHandle = $qxdmIClient->RegisterClient(0);
	$qxdmIConfig = $qxdmIClient->ConfigureClient($qxdmClientHandle);

	#QXDM filter
	QXDM_FILTER();	
	$qxdmIConfig->CommitConfig();	
	$qxdmIClient->PopulateClients();
	$qxdmIClient->CopyAllClientsItems($out);
	$qxdmIClient->UnregisterClient($qxdmClientHandle);
	$qxdmIIsf->CloseItemStoreWithHandle($qxdmHandle);
	($qxdmHandle, $qxdmIClient, $qxdmClientHandle, $qxdmIConfig) = (0, 0, 0xFFFFFFFF, 0);	
	$qxdmIIsf->QuitApplication();
	$qxdmIIsf = 0;
	$qxdm = undef;		

	@filt[$nofisf++] = $tmp."-.isf";
	print " =>".$tmp."-.isf\n"; 
}

sub CombineIsf($)
{
	my ($out) = @_;	
	my $newlist;
	foreach my $file (@filt){ $newlist = join "|", map { $directory_qcat . $_ } @filt; }
	print "Input:$newlist\n";
	#run QCAT
	my $qcat_app = new Win32::OLE 'QCAT6.Application'; 
	if(!$qcat_app){ die "ERROR: Unable to invoke the QCAT application.\n"; }
	$qcat_app->{Visible} = TRUE;
	$qcat_app->OpenLog("$newlist");
	$qcat_app->SortByTime();
	$qcat_app->SaveAsISF($out);
	$qcat_app = NULL;	
}

sub qxdmAddItems
{
	my ($type, $argv1, $argv2) = @_;	
	my %hash = ("event", "AddEvent", "log", "AddLog", "msg", "AddMessage", "string", "AddString", "ota" , "AddOTALog", "qtrace", "AddQshTrace", "qshmetric", "AddQshMetrics");
	my $func = $hash{$type};	
	if(not defined $argv2){ $qxdmIConfig->$func($argv1); }
	else{ $qxdmIConfig->$func($argv1, $argv2); }
}

sub PCAP_Generator()
{
	foreach my $file (@files)
	{
		my $in = $file;
		if(not -e $in){ die "Input file $in does not exist\n"; }
		else{ print "Input:$in =>"; }
		#run PCAP Generator
		system("\"C:\\Program Files (x86)\\QUALCOMM\\QCAT 6.x\\Bin\\PCAP Generator.exe\" $in $currentDir");	
	}
	
	my @logs = <*.log>;
	foreach my $file (@logs){ my $log = $file; unlink "$log"; } #delete .log
}

sub mergecap($)
{	
	my ($out) = @_;
	unlink $out;	
	#run mergecap in Wireshark
	system("\"C:\\Program Files\\Wireshark\\mergecap.exe\" -w $out *_IP.pcap");

	my @pcaps = <*.pcap>;
	foreach my $file (@pcaps){ my $pcap = $file; if($pcap ne $outpcap){unlink "$pcap";} } #delete .pcap (except merged pcap)
}


_END__
