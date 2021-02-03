package HelperFunctions4;
require Exporter;

@ISA     = qw(Exporter);
@EXPORT  = qw(
   Connect
   Disconnect
   DumpItemDetails
   false
   FIELD_TYPE_BOOL
   FIELD_TYPE_FLOAT32
   FIELD_TYPE_FLOAT64
   FIELD_TYPE_INT8
   FIELD_TYPE_INT16
   FIELD_TYPE_INT32
   FIELD_TYPE_INT64
   FIELD_TYPE_STRING_A
   FIELD_TYPE_STRING_ANT
   FIELD_TYPE_STRING_U
   FIELD_TYPE_STRING_UNT
   FIELD_TYPE_UINT8
   FIELD_TYPE_UINT16
   FIELD_TYPE_UINT32
   FIELD_TYPE_UINT64
   GenerateFileName
   GenerateFileName2
   GetPathFromScript
   GetSubsysV2ErrorCode
   IsErrorResponse
   ITEM_STRING_AUTOMATION
   ITEM_STRING_ERROR
   ITEM_STRING_INFO
   ITEM_STRING_STATE
   ITEM_STRING_WARNING
   ITEM_TYPE_DIAG_ERR
   ITEM_TYPE_DIAG_RX
   ITEM_TYPE_DIAG_TX
   ITEM_TYPE_EVENT
   ITEM_TYPE_GPS
   ITEM_TYPE_LOG
   ITEM_TYPE_MESSAGE
   ITEM_TYPE_OTA_LOG
   ITEM_TYPE_STRING
   ITEM_TYPE_SUBSYS_RX
   ITEM_TYPE_SUBSYS_TX
   ITEM_TYPE_SUBSYSV2_DELAYED_RX
   ITEM_TYPE_SUBSYSV2_IMMEDIATE_RX
   ITEM_TYPE_SUBSYSV2_TX
   StartLogging
   StopLogging
   null
   PhoneOffline
   QXDMAPSWindow
   QXDMInitialize
   QXDMInitializeInterface2
   QXDMInitializeNonVisible
   QXDMInitializeNonVisible2
   ResetPhone
   SendRequestAndReturnResponse
   SERVER_CONNECTED
   SERVER_DISCONNECTED
   SERVER_PLAYBACK
   SERVER_PRECONNECT
   SERVER_PREDISCONNECT
   SetQXDM
   SetQXDM2
   true
   VerifySPC
   QuitQXDMApplication
   NO_SUBSCRIPTION_ID
);

use strict;
use Win32::OLE;
use File::Spec;
use Cwd 'abs_path';
use Win32::OLE::Variant;

# ===========================================================================
# FILE:
#    HelperFunctions.pm
#
# DESCRIPTION:
#    Implementation of functions used in my automation script samples.
#
# Copyright (C) 2016-17 Qualcomm Technologies, Incorporated.
#                       All rights reserved.
#                       Qualcomm Proprietary/GTDR
#
# All data and information contained in or disclosed by this document is
# confidential and proprietary information of QUALCOMM Incorporated and all
# rights therein are expressly reserved.  By accepting this material the
# recipient agrees that this material and the information contained therein
# is held in confidence and in trust and will not be used, copied, reproduced
# in whole or in part, nor its contents revealed in any manner to others
# without the express written permission of QUALCOMM Incorporated.
# ===========================================================================
#
# ---------------------------------------------------------------------------
#  Definitions
# ---------------------------------------------------------------------------

#  Miscellaneous constants
use constant null                => 0;
use constant false               => 0;
use constant true                => 1;

# $Item type constants
use constant ITEM_TYPE_DIAG_ERR  => 0;
use constant ITEM_TYPE_DIAG_RX   => 1;
use constant ITEM_TYPE_DIAG_TX   => 2;
use constant ITEM_TYPE_GPS       => 3;
use constant ITEM_TYPE_EVENT     => 4;
use constant ITEM_TYPE_LOG       => 5;
use constant ITEM_TYPE_MESSAGE   => 6;
use constant ITEM_TYPE_STRING    => 7;
use constant ITEM_TYPE_OTA_LOG   => 8;
use constant ITEM_TYPE_SUBSYS_RX => 9;
use constant ITEM_TYPE_SUBSYS_TX => 10;
use constant ITEM_TYPE_SUBSYSV2_IMMEDIATE_RX => 12;
use constant ITEM_TYPE_SUBSYSV2_DELAYED_RX => 13;
use constant ITEM_TYPE_SUBSYSV2_TX => 14;

# String type constants
use constant ITEM_STRING_INFO       => 0; # Informational string
use constant ITEM_STRING_WARNING    => 1; # Warning string
use constant ITEM_STRING_ERROR      => 2; # Error string
use constant ITEM_STRING_AUTOMATION => 3; # Automation string
use constant ITEM_STRING_STATE      => 4; # Connection state string

# DIAG server states
use constant SERVER_DISCONNECTED  => 0;
use constant SERVER_PRECONNECT    => 1;
use constant SERVER_CONNECTED     => 2;
use constant SERVER_PREDISCONNECT => 3;
use constant SERVER_PLAYBACK      => 4;

# Field type constants
use constant FIELD_TYPE_BOOL       => 0;
use constant FIELD_TYPE_INT8       => 1;
use constant FIELD_TYPE_UINT8      => 5;
use constant FIELD_TYPE_INT16      => 2;
use constant FIELD_TYPE_UINT16     => 6;
use constant FIELD_TYPE_INT32      => 3;
use constant FIELD_TYPE_UINT32     => 7;
use constant FIELD_TYPE_INT64      => 4;
use constant FIELD_TYPE_UINT64     => 8;
use constant FIELD_TYPE_STRING_A   => 9;
use constant FIELD_TYPE_STRING_U   => 10;
use constant FIELD_TYPE_STRING_ANT => 13;
use constant FIELD_TYPE_STRING_UNT => 14;
use constant FIELD_TYPE_FLOAT32    => 11;
use constant FIELD_TYPE_FLOAT64    => 12;

# Subscription Id Constant
use constant NO_SUBSCRIPTION_ID    => 0xFFFFFFFF;

# IQXDM/IQXDM2 interfaces used by function in this file (SetQXDM/SetQXDM2
# must be called prior to using any function in this file that requires
# each interface)
my $IQXDM = null;
my $IQXDM2 = null;
my $QXDMApplication = null;
my $IAPSWindow = null;
# ---------------------------------------------------------------------------
# Functions
# ---------------------------------------------------------------------------

sub QXDMInitialize
{
   $IQXDM = QXDMInitializeNonVisible();
   if ($IQXDM)
   {
      $IQXDM->SetVisible(true);
   }

   return $IQXDM;
}

sub QXDMInitializeNonVisible
{
   $IQXDM = null;

   my $osname = $^O;
   if($osname eq 'MSWin32')
   {
      print "Windows platform \n";
      if (!$QXDMApplication)
      {
         $QXDMApplication = new Win32::OLE 'QXDM.QXDMAutoApplication';
      }

      if (!$QXDMApplication)
      {
         print "\nUnable to create QXDM automation interface\n";
      }
      else
      {

      # Get QXDM version
      my $Version = $QXDMApplication->{AutomationVersion};
      print "\nInterface Version: " . $Version . "\n";

         $IQXDM = $QXDMApplication->GetAutomationWindow();
         #print "\nIQXDM is $IQXDM\n";
         $IQXDM2 = $IQXDM;
      }
   }
   return $IQXDM;
}

sub QXDMInitializeInterface2
{
   $IQXDM = QXDMInitializeNonVisible2();
   if ($IQXDM)
   {
      $IQXDM->SetVisible(true);
   }

   return $IQXDM;
}

sub QXDMInitializeNonVisible2
{
   $IQXDM = null;

   my $osname = $^O;
   if($osname eq 'MSWin32')
   {
      print "Windows platform \n";
      if (!$QXDMApplication)
      {
         $QXDMApplication = new Win32::OLE 'QXDM.QXDMAutoApplication';
      }

      if (!$QXDMApplication)
      {
         print "\nUnable to create QXDM automartion interface\n";
      }
      else
      {

      # Get QXDM version
      my $Version = $QXDMApplication->{AutomationVersion};
      print "\nInterface Version: " . $Version . "\n";

         $IQXDM = $QXDMApplication->GetAutomationWindow2();
         #print "\nIQXDM is $IQXDM\n";
         $IQXDM2 = $IQXDM;
      }
   }
   return $IQXDM;
}

sub QXDMAPSWindow
{
   $IAPSWindow = null;

   my $osname = $^O;
   if($osname eq 'MSWin32')
   {
      print "Windows platform \n";
      if (!$QXDMApplication)
      {
         $QXDMApplication = new Win32::OLE 'QXDM.QXDMAutoApplication';
      }

      if (!$QXDMApplication)
      {
         print "\nUnable to create QXDM automartion interface\n";
      }
      else
      {

      # Get QXDM version
      my $Version = $QXDMApplication->{AutomationVersion};
      print "\nInterface Version: " . $Version . "\n";

         $IAPSWindow = $QXDMApplication->GetAPSWindow();
      }
   }
   return $IAPSWindow;
}

# ===========================================================================
# METHOD:
#    SetQXDM
#
# DESCRIPTION:
#    Set IQXDM interface object being used
#
# PARAMETERS:
#    QXDM       [ I ] - QXDM interface object to use
#
# RETURN VALUE:
#    None
# ===========================================================================
sub SetQXDM
{
   my $QXDM = shift;

   $IQXDM = $QXDM;
}

# ===========================================================================
# METHOD:
#    SetQXDM2
#
# DESCRIPTION:
#    Set IQXDM2 interface object being used
#
# PARAMETERS:
#    QXDM2       [ I ] - QXDM2 interface object to use
#
# RETURN VALUE:
#    None
# ===========================================================================
sub SetQXDM2
{
   my $QXDM2 = shift;

   $IQXDM2 = $QXDM2;
}

# ===========================================================================
# METHOD:
#   GetPathFromScript
#
# DESCRIPTION:
#   Get path from current script file name
#
# RETURN VALUE:
#   String ("" upon error)
# ===========================================================================
sub GetPathFromScript()
{
   # Assume failure
   my $Path = "";
   my $Txt = "";

   $Path = abs_path( $ENV{'PWD'} );
   $Path = File::Spec->rel2abs( $Path ) ;
   if (length $Path <= 0)
   {
      $Txt = "Unable to get folder name";
      print "\n$Txt\n";
   }
   else
   {
      if (!($Path =~ /\\$/))
      {
         $Path .= "\\";
      }
   }

   return $Path;
}

# ===========================================================================
# METHOD:
#    GenerateFileName
#
# DESCRIPTION:
#    Generate a unique file name
#
# PARAMETERS:
#    Path        [ I ] - Path to use ("" means use QXDM automation folder)
#    Extension   [ I ] - Desired file extension (leading "." must be included)
#
# RETURN VALUE:
#    String ("" upon error)
# ===========================================================================
sub GenerateFileName
{
   my ( $Path, $Extension ) = @_;
   my $FileName = "";

   if (length( $Path ) <= 0)
   {
      # Use script path
      $Path = GetPathFromScript();
   }

   #  Get GM time string (Wed May 31 03:03:22 2006)
   my $tm = gmtime();

   # Remove whitespace and replace ':' with '.'
   $tm =~ s/\:/\./g;
   my @a = split( / /, $tm );

   # Rearrange date
   my $TodaysDate = "$a[0]_$a[2]_$a[1]_$a[4]_$a[3]_UTC";
   $FileName = $Path . $TodaysDate . $Extension;

   return $FileName;
}

# ===========================================================================
# METHOD:
#    GenerateFileName2
#
# DESCRIPTION:
#    Generate a unique file name
#
# PARAMETERS:
#    Path        [ I ] - Path to use ("" means use QXDM automation folder)
#    Extension   [ I ] - Desired file extension (leading "." must be included)
#
# RETURN VALUE:
#    String ("" upon error)
# ===========================================================================
sub GenerateFileName2
{
   my ( $Path, $Extension , $uebuild ) = @_;
   my $FileName = "";

   if (length( $Path ) <= 0)
   {
   # Use script path
   $Path = GetPathFromScript();
   }
   #Arguments provided by the TE Vendor ( script name and result)
   my $tcname=$ARGV[1];
   my $verdict=$ARGV[2];
   my $tebuild=$ARGV[3];

   #Extracting the current time stamp
   (my $sec,my $min, my $hour,my $mday,my $mon,my $year,my $wday,my $yday,my $isdst) = localtime();
   my @months = qw( Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec );
   my @days = qw(Sun Mon Tue Wed Thu Fri Sat Sun);
   my $year1=$year+1900;

   #Generate the current filename which include the timestamp,TC name,verdict and the file format.
   $FileName=$Path.$verdict."_".$tcname."_".$uebuild."_".$tebuild."_".$mday."_".$months[$mon]."_".$days[$wday]."_".$year1."_".$hour."_".$min."_".$sec.$Extension;


   # $FileName =  .."_".$verdict."_". $TodaysDate.$Extension;
   print(" file name is $FileName \n");
   return $FileName;
}

# ===========================================================================
# METHOD:
#    DumpItemDetails
#
# DESCRIPTION:
#    Dump out item details for the given item
#
# PARAMETERS:
#    $Item        [ I ] - $Item to dump out details for
#    NamePadding  [ I ] - Pad field name output length to X characters
#
# RETURN VALUE:
#    None (Text written to StdOut)
# ===========================================================================
sub DumpItemDetails
{
   my ( $Item, $NamePadding ) = @_;

   if ($Item == null)
   {
      return;
   }

   my $ItemTS =  $Item->GetItemSpecificTimestampText( false, true );
   my $ItemKey = $Item->GetItemKeyText();
   my $ItemName = $Item->GetItemName();

   my $Txt = $ItemTS . " " . $ItemKey . " " . $ItemName;
   print( "$Txt\n" );

   my $ItemFields = $Item->GetItemFields();
   if ($ItemFields != null)
   {
      my $FieldCount = $ItemFields->GetFieldCount();
      for (my $f = 0; $f < $FieldCount; $f++)
      {
         my $Name = $ItemFields->GetFieldName( $f, true );
         my $Value = $ItemFields->GetFieldValueText( $f );

         my $format = "   %-${NamePadding}s = %s\n";
         printf( $format, $Name, $Value );
      }
   }
}

# ===========================================================================
# METHOD:
#    Connect
#
# DESCRIPTION:
#    Connect to the given port, waiting for the connection come up
#
#    NOTE: Requires IQXDM be set via SetQXDM() call
#
# PARAMETERS:
#    Port        [ I ] - Port to connect to (1, 2, 3, etc.)
#
# RETURN VALUE:
#    bool
# ===========================================================================
sub Connect
{
   my $Port = shift;

   # Assume failure
   my $RC = false;
   my $Txt = "";

   sleep( 2 );

   if ($Port == 0)
   {
      $Txt = "Invalid COM port specified" . $Port;
      print( "$Txt\n" );

      return $RC;
   }

   # Connect to our desired COM port
   $IQXDM->{COMPort} = $Port;

   if (0 == $IQXDM->{COMPort})
   {

      $Txt = "QXDM unable to connect to COM" . $Port;
      print( "$Txt\n" );
      return $RC
   }

    # Success!
    $Txt = "QXDM connected to COM" . $Port;
    print( "$Txt\n" );
    $RC = true;

   return $RC;
}


# ===========================================================================
# METHOD:
#    Disconnect
#
# DESCRIPTION:
#    Disconnect, waiting for the action to complete
#
#    NOTE: Requires IQXDM be set via SetQXDM() call
#
# RETURN VALUE:
#    bool
# ===========================================================================
sub Disconnect
{
   # Assume failure
   my $RC = false;

   print( "\nDisconnecting Phone ... " );
   # Disconnect
   $IQXDM->{COMPort} = 0;

   # Wait until DIAG server state transitions to disconnected
   # (we do this for up to five seconds)
   my $WaitCount = 0;
   my $ServerState = SERVER_CONNECTED;
   while ($ServerState != SERVER_DISCONNECTED && $WaitCount < 5)
   {
      sleep( 1 );

      $ServerState = $IQXDM2->GetServerState();
      $WaitCount++;
   }

   my $Txt = "";
   if ($ServerState == SERVER_DISCONNECTED)
   {
      # Success!
      $Txt = "QXDM successfully disconnected";
      print( "$Txt\n" );
      $RC = true;
   }
   else
   {
      $Txt = "QXDM unable to disconnect";
      print( "$Txt\n" );
   }

   return $RC;
}

# ===========================================================================
# METHOD:
#    GetSubsysV2ErrorCode
#
# DESCRIPTION:
#    Return the error code from a subsystem dispatch V2 response
#
# PARAMETERS:
#    $Item        [ I ] - $Item to extract error code from
#
# RETURN VALUE:
#    Error code (as per the standard 0 means no error)
# ===========================================================================
sub GetSubsysV2ErrorCode
{
   my $Item = shift;

   # Assume failure
   my $RC = false;

   if ($Item == null)
   {
      return $RC;
   }

   my $ItemKey = $Item->GetItemKeyText();
   my $ItemType = $Item->GetItemType();
   if ($ItemType == ITEM_TYPE_SUBSYS_RX)
   {
      if ($ItemKey eq "[128]")
      {
         # Parse out the status (UINT32, 32 bits, from bit offset [header] 32)
         $RC = $Item->GetItemFieldValue( 6, 32, 32, true );
      }
   }

   return $RC;
}

# ===========================================================================
# METHOD:
#    IsErrorResponse
#
# DESCRIPTION:
#    Is the item an error response?
#
# PARAMETERS:
#    $Item        [ I ] - $Item to check
#
# RETURN VALUE:
#    bool
# ===========================================================================
sub IsErrorResponse
{
   my $Item = shift;

   # Assume failure
   my $RC = false;

   if ($Item == null)
   {
      return $RC;
   }

   my $ItemKey = $Item->GetItemKeyText();
   my $ItemType = $Item->GetItemType();
   if ($ItemType == ITEM_TYPE_DIAG_RX)
   {
      if ($ItemKey eq "[019]" ||
          $ItemKey eq "[020]" ||
          $ItemKey eq "[021]" ||
          $ItemKey eq "[022]" ||
          $ItemKey eq "[023]" ||
          $ItemKey eq "[024]" ||
          $ItemKey eq "[066]" ||
          $ItemKey eq "[071]")
      {
         $RC = true;
      }
   }
   elsif ($ItemType == ITEM_TYPE_SUBSYS_RX)
   {
      my $Status = GetSubsysV2ErrorCode( $Item );
      if ($Status != 0)
      {
         $RC = true;
      }
   }

   return $RC;
}

# ===========================================================================
# METHOD:
#    SendRequestAndReturnResponse
#
# DESCRIPTION:
#    Send a request/wait for and return the response
#
#    NOTE: Requires IQXDM2 be set via SetQXDM2() call
#
# PARAMETERS:
#    RequestName [ I ] - DIAG entity name of the request
#    RequestArgs [ I ] - Arguments used to populate the request (may be "")
#    DumpItems   [ I ] - Dump out item details to StdOut?  If so then set
#                        this to the field name width, if not then set to
#                        zero
#
# RETURN VALUE:
#    The response item (null upon error)
# ===========================================================================
sub SendRequestAndReturnResponse
{
   my ( $RequestName, $RequestArgs, $DumpItems ) = @_;
   my $Txt = "";

   # We need to be connected
   my $ServerState = $IQXDM2->GetServerState();
   if ($ServerState != 2)
   {
      $Txt = "Unable to send request - " . $RequestName;
      print( "$Txt\n" );
      return null;
   }

   # Create a client
   my $ReqHandle = $IQXDM2->RegisterQueueClient( 256 );
   if ($ReqHandle == 0xFFFFFFFF)
   {
      $Txt = "Unable to create client to send request - " . $RequestName;
      print( "$Txt\n" );

      return null;
   }

   # One request with a 1s timeout
   my $ReqID = $IQXDM2->ClientRequestItem( $ReqHandle,
                                           $RequestName,
                                           $RequestArgs,
                                           1,
                                           1000,
                                           1,
                                           1 );

   if ($ReqID == 0)
   {
      $Txt = "Unable to schedule request - " . $RequestName;
      print( "$Txt\n" );

      $IQXDM2->UnregisterClient( $ReqHandle );
      return null;
   }

   my $Secs = 0;
   my $Items = 0;

   # Wait for the response (we know the response has arrived when the number
   # of items in our client goes to two)
   for ($Secs = 0; $Secs < 5; $Secs++)
   {
      # Sleep for 1s
      sleep( 1 );

      # How many items do we have?
      $Items = $IQXDM2->GetClientItemCount( $ReqHandle );
      if ($Items == 2)
      {
         last;
      }
   }

   # Dump out everything in the client?
   if ($DumpItems > 0)
   {
      for (my $Index = 0; $Index < $Items; $Index++)
      {
         my $Item = $IQXDM2->GetClientItem( $ReqHandle, $Index );
         if ($Item != null)
         {
            DumpItemDetails( $Item, $DumpItems );
         }
      }
   }

   if ($Items == 2)
   {
      my $Item = $IQXDM2->GetClientItem( $ReqHandle, 1 );
      if (IsErrorResponse( $Item ) == false)
      {
         $IQXDM2->UnregisterClient( $ReqHandle );
         return $Item;
      }
      else
      {
         $Txt = "Error response received - " . $Item->GetItemName();
         my $Status = GetSubsysV2ErrorCode( $Item );
         if ($Status != 0)
         {
            $Txt .= " [" . $Status . "]";
         }

         print( "$Txt\n" );

         $IQXDM2->UnregisterClient( $ReqHandle );
         return null;
      }
   }
   elsif ($Items == 1)
   {
      $Txt = "Timeout waiting for response to request - " . $RequestName;
      print( "$Txt\n" );

      $IQXDM2->UnregisterClient( $ReqHandle );
      return null;
   }

   $Txt = "Error sending request - " . $RequestName;
   print( "$Txt\n" );

   $IQXDM2->UnregisterClient( $ReqHandle );
   return null;
}

# ===========================================================================
# METHOD:
#    PhoneOffline
#
# DESCRIPTION:
#    Set phone offline
#
#    NOTE: Requires IQXDM be set via SetQXDM() call
#
# RETURN VALUE:
#    bool
# ===========================================================================
sub PhoneOffline
{
   # Assume failure
   my $RC = false;

   print( "Set phone offline ... " );

   # We need to be connected for this to work
   my $ServerState = $IQXDM2->GetServerState();
   if ($ServerState != SERVER_CONNECTED)
   {
      print( "failed (not connected)\n" );
      return $RC;
   }

   my $Status = $IQXDM->OfflineDigital();
   if ($Status == 1)
   {
      print( "succeeded\n" );
      $RC = true;
   }
   else
   {
      print( "failed\n" );
   }

   return $RC;
}

# ===========================================================================
# METHOD:
#    ResetPhone
#
# DESCRIPTION:
#    Attempt to reset the phone and wait for it to come back up
#
#    NOTE: Requires IQXDM/IQXDM2 be set via SetQXDM/SetQXDM2() call
#
# RETURN VALUE:
#    bool
# ===========================================================================
sub ResetPhone
{
   # Assume failure
   my $RC = false;
   my $Txt = "";

   print( "Reset phone ... " );

   # We need to be connected for this to work
   my $ServerState = $IQXDM2->GetServerState();
   if ($ServerState != SERVER_CONNECTED)
   {
      print( "failed (not connected)\n" );
      return $RC;
   }

   # Reset the phone
   my $Status = $IQXDM->ResetPhone();
   if ($Status == 1)
   {
      print( "succeeded\n" );
      $RC = true;
   }
   else
   {
      print( "failed\n" );
      return $RC;
   }

   print( "Waiting for phone to restart ... " );

   # The phone should first disconnect
   my $WaitCount = 0;
   $ServerState = SERVER_CONNECTED;
   $RC = false;

   while ($ServerState != SERVER_DISCONNECTED && $WaitCount < 25)
   {
      sleep( 1 );

      $ServerState = $IQXDM2->GetServerState();
      $WaitCount++;
   }

   if ($ServerState != SERVER_DISCONNECTED)
   {
      print( "Could not disconnect even after 25 secs\n" );
      return $RC;
   }

   # Now wait until DIAG server state transitions back to connected
   # (we do this for up to twenty seconds)
   $WaitCount = 0;
   $ServerState = SERVER_DISCONNECTED;
   print( "\nWaiting for DIAG to come up ... " );
   while ($ServerState != SERVER_CONNECTED && $WaitCount < 20)
   {
      sleep( 1 );

      $ServerState = $IQXDM2->GetServerState();
      $WaitCount++;
   }

   if ($ServerState == SERVER_CONNECTED)
   {
      $Txt = "succeeded";
      print( "$Txt\n" );
      $RC = true;
   }
   else
   {
      $Txt = "failed";
      print( "$Txt\n" );
   }

   return $RC;
}

# ===========================================================================
# METHOD:
#    VerifySPC
#
# DESCRIPTION:
#    Send Diag request to verify SPC
#
#    QXDM      [ I ] - QXDM Window object, from QXDMInitialize()
#    spcString [ I ] - SPC as a string
#    timeout   [ I ] - timeout in ms
#
# RETURN VALUE:
#    bool
# ===========================================================================
sub VerifySPC
{
   my ( $QXDM, $spcString, $timeout ) = @_;

   # Assume failure
   my $RC = false;

   my @spcArray = unpack("CCCCCC", $spcString);
   my @diagCommandArray = (65);
   push (@diagCommandArray, @spcArray);

   my $diagCommandString = pack("CCCCCCC", @diagCommandArray);

   # Build command as variant array of bytes.
   my $diagCommandVariant = Variant(VT_ARRAY | VT_UI1, length $diagCommandString);
   $diagCommandVariant->Put($diagCommandString);
   my $diagReplyString = $QXDM->SendDmIcdPacketEx($diagCommandVariant, $timeout);
   if (defined $diagReplyString)
   {
      my @diagReplyArray = unpack("CC", $diagReplyString);
      $RC = $diagReplyArray[1];
   }
   else
   {
     print "No reply to Service Programming Code Request\n";
   }

   return $RC;
}


1;

sub QuitQXDMApplication
{	 
  $IQXDM->QuitApplication();
  
  if($QXDMApplication)
  {
	 undef $QXDMApplication;
  }
}
