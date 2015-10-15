#!/usr/bin/perl
# Copyright (c) 2015  Bjørn Mork <bjorn@mork.no>
# GPLv2

use strict;
use warnings;
use Data::Dumper;
use Getopt::Long;
use UUID::Tiny ':std';
use IPC::Shareable;
use Fcntl ':mode';
use File::Basename;
use JSON;

my $maxctrl = 4096; # default, will be overridden by ioctl if supported
my $mgmt = "/dev/cdc-wdm0";
my $debug;
my $verbose = 1;
my $usbcomp;
 
# a few global variables
my $lastmbim = 0;
my $lastqmi;
my $dmscid;
my $tid = 1;
    
GetOptions(
    'usbcomp=i' => \$usbcomp,
    'device=s' => \$mgmt,
    'debug!' => \$debug,
    'verbose!' => \$verbose,
    'help|h|?' => \&usage,
    ) || &usage;


### MBIM helpers ###
sub _push {
    my ($buf, $format, @vars) = @_;

    my $add = pack($format, @vars);
    $buf .= $add;

    # update length
    my $len = unpack("V", substr($buf, 4, 4));
    $len += length($add);
    substr($buf, 4, 4) = pack("V", $len);
    return $buf;
}

sub _pop {
    my ($buf, $format, @vars) = @_;

    (@vars) = unpack($format, $buf);
    my $x = pack($format, @vars);
    return $buf .= pack($format, @vars);
}

my %msg = (
# Table 9‐3: Control messages sent from the host to the function 
    'MBIM_OPEN_MSG' => 1,
    'MBIM_CLOSE_MSG' => 2,
    'MBIM_COMMAND_MSG' => 3,
    'MBIM_HOST_ERROR_MSG' => 4, 

# Table 9‐9: Control Messages sent from function to host 
    'MBIM_OPEN_DONE' => 0x80000001,
    'MBIM_CLOSE_DONE' => 0x80000002,
    'MBIM_COMMAND_DONE' => 0x80000003,
    'MBIM_FUNCTION_ERROR_MSG' => 0x80000004,
    'MBIM_INDICATE_STATUS_MSG' => 0x80000007, 
    );

# Table 10‐3: Services Defined by MBIM 
my %uuid = (
    UUID_BASIC_CONNECT => 'a289cc33-bcbb-8b4f-b6b0-133ec2aae6df',
    UUID_SMS           => '533fbeeb-14fe-4467-9f90-33a223e56c3f',
    UUID_USSD          => 'e550a0c8-5e82-479e-82f7-10abf4c3351f',
    UUID_PHONEBOOK     => '4bf38476-1e6a-41db-b1d8-bed289c25bdb',
    UUID_STK           => 'd8f20131-fcb5-4e17-8602-d6ed3816164c',
    UUID_AUTH          => '1d2b5ff7-0aa1-48b2-aa52-50f15767174e',
    UUID_DSS           => 'c08a26dd-7718-4382-8482-6e0d583c4d0e',

# "well known" vendor specific services
    UUID_EXT_QMUX      => 'd1a30bc2-f97a-6e43-bf65-c7e24fb0f0d3', # ref unknown...
    UUID_MULTICARRIER  => '8b569648-628d-4653-9b9f-1025404424e1', # ref http://feishare.com/attachments/article/252/implementing-multimode-multicarrier-devices.pdf
    UUID_MSFWID        => 'e9f7dea2-feaf-4009-93ce-90a3694103b6', # http://msdn.microsoft.com/en-us/library/windows/hardware/jj248721.aspx
    UUID_MS_HOSTSHUTDOWN => '883b7c26-985f-43fa-9804-27d7fb80959c', # http://msdn.microsoft.com/en-us/library/windows/hardware/jj248720.aspx

    );

sub uuid_to_service {
    my $uuid = shift;
    my ($service) = grep { $uuid{$_} eq $uuid } keys %uuid;
    return 'UNKNOWN' unless $service;
    $service =~ s/^UUID_//;
    return $service;
}

# MBIM_MESSAGE_HEADER 
sub init_msg_header {
    my $type = shift;
    return &_push('', "VVV", $type, 0, $tid++);
}

# MBIM_FRAGMENT_HEADER 
sub push_fragment_header {
    my ($buf, $total, $current) = @_;
    return $buf = &_push($buf, "VV", $total, $current);
}

# MBIM_OPEN_MSG
sub mk_open_msg {
    my $buf = &init_msg_header(1); # MBIM_OPEN_MSG  
    $buf = &_push($buf, "V", $maxctrl); # MaxControlTransfer 

    printf "MBIM>: " . "%02x " x length($buf) . "\n", unpack("C*", $buf) if $debug;
    return $buf;
}

# MBIM_CLOSE_MSG
sub mk_close_msg {
    my $buf = &init_msg_header(2); # MBIM_CLOSE_MSG  

    printf "MBIM>: " . "%02x " x length($buf) . "\n", unpack("C*", $buf) if $debug;
    return $buf;
}

# MBIM_COMMAND_MSG  
sub mk_command_msg {
    my ($service, $cid, $type, $info) = @_;

    my $uuid = string_to_uuid($uuid{"UUID_$service"} || $service) || return '';
    my $buf = &init_msg_header(3); # MBIM_COMMAND_MSG  
    $buf = &push_fragment_header($buf, 1, 0);
    $uuid =~ tr/-//d;
    $buf = &_push($buf, "a*", $uuid); # DeviceServiceId  
    $buf = &_push($buf, "VVV",
		  $cid,    # CID
		  $type,   # 0 for a query operation, 1 for a Set operation. 
		  length($info), # InformationBufferLength  
	);
    $buf = &_push($buf, "a*", $info);  # InformationBuffer  
    printf "MBIM>: " . "%02x " x length($buf) . "\n", unpack("C*", $buf) if $debug;
    return $buf;
}

sub decode_mbim {
    my $msg = shift;
    my ($type, $len, $tid) = unpack("VVV", $msg);

    if ($debug) {
	print "MBIM_MESSAGE_HEADER\n";
	printf "  MessageType:\t0x%08x\n", $type;
	printf "  MessageLength:\t%d\n", $len;
	printf "  TransactionId:\t%d\n", $tid;
    }
    if ($type == 0x80000001 || $type == 0x80000002) { # MBIM_OPEN_DONE ||  MBIM_CLOSE_DONE 
	my $status = unpack("V", substr($msg, 12));
	printf "  Status:\t0x%08x\n", $status if $debug;
    } elsif ($type == 0x80000003) { # MBIM_COMMAND_DONE 
	my ($total, $current) = unpack("VV", substr($msg, 12)); # FragmentHeader  
	if ($debug) {
	    print "MBIM_FRAGMENT_HEADER\n";
	    printf "  TotalFragments:\t0x%08x\n", $total;
	    printf "  CurrentFragment:\t0x%08x\n", $current;
	}
	my $uuid = uuid_to_string(substr($msg, 20, 16));
	my $service = &uuid_to_service($uuid);
	print "$service ($uuid)\n"  if $debug;

	my ($cid, $status, $infolen) = unpack("VVV", substr($msg, 36));
	my $info = substr($msg, 48);
	if ($debug) {
	    printf "  CID:\t\t0x%08x\n", $cid;
	    printf "  Status:\t0x%08x\n", $status;
	    print "InformationBuffer [$infolen]:\n";
	}
	if ($infolen != length($info)) {
	    print "Fragmented MBIM transactions are not supported\n";
	} elsif ($service eq "EXT_QMUX") {
	    # save the decoded QMI message
	    $lastqmi = &decode_qmi($info);
	}
	# silently ignoring InformationBuffer payload of other services
    }
    # ignoring all other types of MBIM messages
    
    # save message type
    $lastmbim = $type;   
}

# read from F until timeout
sub read_mbim {
    my $timeout = shift || 0;
    my $found = undef;

    eval {
	local $SIG{ALRM} = sub { die "alarm\n" }; # NB: \n required
	my $raw = '';
	my $msglen = 0;
	alarm $timeout;
	do {
	    my $len = 0;
	    if ($len < 3 || $len < $msglen) {
		my $tmp;
		my $n = sysread(F, $tmp, $maxctrl);
		if ($n) {
		    $len = $n;
		    $raw = $tmp;
		    printf "MBIM<: " . "%02x " x $n . "\n", unpack("C*", $tmp) if $debug;
		} else {
		    $found = 1;
		}
	    }

	    # get expected message length
	    $msglen = unpack("V", substr($raw, 4, 4));

	    if ($len >= $msglen) {
		$len -= $msglen;
		&decode_mbim(substr($raw, 0, $msglen));
		$raw = substr($raw, $msglen);
		$msglen = 0;
		$found = 1;
	    } else {
		warn "$len < $msglen\n";
	    }
	} while (!$found);
	alarm 0;
    };
    if ($@) {
	die unless $@ =~ /^alarm/;   # propagate unexpected errors
    }
}

### QMI helpers ###
my %sysname = (
    0    => "QMI_CTL",
    1    => "QMI_WDS",
    2    => "QMI_DMS",
    3    => "QMI_NAS",
    4    => "QMI_QOS",
    5    => "QMI_WMS",
    6    => "QMI_PDS",
    7    => "QMI_AUTH",
    8    => "QMI_AT",
    9    => "QMI_VOICE",
    0xa  => "QMI_CAT2",
    0xb  => "QMI UIM",
    0xc  => "QMI PBM",
    0xe  => "QMI RMTFS",
    0x10 => "QMI_LOC",
    0x11 => "QMI_SAR",
    0x14 => "QMI_CSD",
    0x15 => "QMI_EFS",
    0x17 => "QMI_TS",
    0x18 => "QMI_TMD",
    0x1a => "QMI_WDA",
    0x1e => "QMI_QCMAP",
    0x24 => "QMI_PDC",
    0xe0 => "QMI_CAT", # duplicate!
    0xe1 => "QMI_RMS",
    0xe2 => "QMI_OMA",
    );


# $tlvs = { type1 => packdata, type2 => packdata, .. 
sub mk_qmi {
    my ($sys, $cid, $msgid, $tlvs) = @_;

    # create tlvbytes
    my $tlvbytes = '';
    foreach my $tlv (keys %$tlvs) {
	$tlvbytes .= pack("Cv", $tlv, length($tlvs->{$tlv})) . $tlvs->{$tlv};
    }
    my $tlvlen = length($tlvbytes);
    if ($sys != 0) {
	return pack("CvCCCCvvv", 1, 12 + $tlvlen, 0, $sys, $cid, 0, $tid++, $msgid, $tlvlen) . $tlvbytes;
    } else {
	return pack("CvCCCCCvv", 1, 11 + $tlvlen, 0, 0, 0, 0, $tid++, $msgid, $tlvlen) . $tlvbytes;
    }
}

sub decode_qmi {
    my $packet = shift;
    return {} unless $packet;

    printf "%02x " x length($packet) . "\n", unpack("C*", $packet) if $debug;

    my $ret = {};
    @$ret{'tf','len','ctrl','sys','cid'} = unpack("CvCCC", $packet);
    return {} unless ($ret->{tf} == 1);

    # tid is 1 byte for QMI_CTL and 2 bytes for the others...
    @$ret{'flags','tid','msgid','tlvlen'} = unpack($ret->{sys} == 0 ? "CCvv" : "Cvvv" , substr($packet, 6));
    my $tlvlen = $ret->{'tlvlen'};
    my $tlvs = substr($packet, $ret->{'sys'} == 0 ? 12 : 13 );

    # add the tlvs
     while ($tlvlen > 0) {
	my ($tlv, $len) = unpack("Cv", $tlvs);
	$ret->{'tlvs'}{$tlv} = [ unpack("C*", substr($tlvs, 3, $len)) ];
	$tlvlen -= $len + 3;
	$tlvs = substr($tlvs, $len + 3);
     }
    return $ret;
}

sub qmiver {
    my $qmi = shift;

    # decode the list of supported systems in TLV 0x01
    my @data = @{$qmi->{'tlvs'}{0x01}};
    my $n = shift(@data);
    my $data = pack("C*", @data);
    print "supports $n QMI subsystems:\n";
    for (my $i = 0; $i < $n; $i++) {
	my ($sys, $maj, $min) = unpack("Cvv", $data);
	my $system = $sysname{$sys} || sprintf("%#04x", $sys);
	print "  $system ($maj.$min)\n";
	$data = substr($data, 5);
    }
}

sub qmiok {
    my $qmi = shift;
    return exists($qmi->{tlvs}{0x02}) && (unpack("v", pack("C*", @{$qmi->{tlvs}{0x02}}[2..3])) == 0);
}

sub do_qmi {
    my $msgid = shift;
    my $qmi = shift;

    printf "QMI>: " . "%02x " x length($qmi) . "\n", unpack("C*", $qmi) if $debug;
    print F &mk_command_msg('EXT_QMUX', 1, 1, $qmi);
    my $count = 5; # seconds timeout
    while (!($lastmbim == 0x80000003 && ref($lastqmi) && ($lastqmi->{'msgid'} == $msgid))) {
	sleep(1);
	return undef if (!$count--); # timeout
    }
    my $status = &qmiok($lastqmi);
    printf "QMI msg '0x%04x' returned status = $status\n", $msgid if $verbose;
    print to_json($lastqmi) if ($debug && !$status);
    return $status;
}


## Sierra USB comp
my %comps = (
    0  => 'HIP  DM    NMEA  AT    MDM1  MDM2  MDM3  MS',
    1  => 'HIP  DM    NMEA  AT    MDM1  MS',
    2  => 'HIP  DM    NMEA  AT    NIC1  MS',
    3  => 'HIP  DM    NMEA  AT    MDM1  NIC1  MS',
    4  => 'HIP  DM    NMEA  AT    NIC1  NIC2  NIC3  MS',
    5  => 'HIP  DM    NMEA  AT    ECM1  MS',
    6  => 'DM   NMEA  AT    QMI',
    7  => 'DM   NMEA  AT    RMNET1 RMNET2 RMNET3',
    8  => 'DM   NMEA  AT    MBIM',
    9  => 'MBIM',
    10 => 'NMEA MBIM',
    11 => 'DM   MBIM',
    12 => 'DM   NMEA  MBIM',
    13 => 'Config1: comp6    Config2: comp8',
    14 => 'Config1: comp6    Config2: comp9',
    15 => 'Config1: comp6    Config2: comp10',
    16 => 'Config1: comp6    Config2: comp11',
    17 => 'Config1: comp6    Config2: comp12',
    18 => 'Config1: comp7    Config2: comp8',
    19 => 'Config1: comp7    Config2: comp9',
    20 => 'Config1: comp7    Config2: comp10',
    21 => 'Config1: comp7    Config2: comp11',
    22 => 'Config1: comp7    Config2: comp12',
);

### main ###

# verify that the $mgmt device is a chardev provided by the cdc_mbim driver
my ($mode, $rdev) = (stat($mgmt))[2,6];
die "'$mgmt' is not a character device\n" unless S_ISCHR($mode);
my $driver = basename(readlink(sprintf("/sys/dev/char/%u:%u/device/driver", $rdev >> 8, $rdev & 0xff)));
die "'$mgmt' is provided by '$driver' - only MBIM devices are supported\n" unless ($driver eq "cdc_mbim");

# open device now and keep it open until exit
open(F, "+<", $mgmt) || die "open $mgmt: $!\n";
autoflush F 1;
autoflush STDOUT 1;

# check message size
require 'sys/ioctl.ph';
eval 'sub IOCTL_WDM_MAX_COMMAND () { &_IOC( &_IOC_READ, ord(\'H\'), 0xa0, 2); }' unless defined(&IOCTL_WDM_MAX_COMMAND);
my $foo = '';
my $r = ioctl(F, &IOCTL_WDM_MAX_COMMAND, $foo);
if ($r) {
    $maxctrl = unpack("s", $foo);
} else {
    warn("ioctl failed: $!\n") if $debug;
}
print "MaxMessageSize=$maxctrl\n"  if $debug;

# fork the reader
my $pid = fork();
if ($pid == 0) { # child

    # allow writer to see the last MBIM message
    tie $lastmbim, 'IPC::Shareable', 'mbim', { create => 1, destroy => 0 } || die "tie failed\n";
    tie $lastqmi, 'IPC::Shareable', 'qmi', { create => 1, destroy => 0 } || die "tie failed\n";

    # reset to avoid inheriting old values...
    $lastmbim = 0;

    # loop until CLOSE_DONE...
    while ($lastmbim != 0x80000002) {
	&read_mbim(60);
    }
    $lastmbim = 0x80000002; # in case of timeout...
    print "exiting reader\n" if $debug;
    exit 0;
} elsif (!$pid) {
    die "fork() failed: $!\n";
}

# watch reader status
tie $lastmbim, 'IPC::Shareable', 'mbim', { create => 1, destroy => 1 } || die "tie failed\n";
tie $lastqmi, 'IPC::Shareable', 'qmi', { create => 1, destroy => 1 } || die "tie failed\n";

# reset to avoid inheriting old values...
$lastmbim = 0;

# send OPEN and wait until reader has seen the OPEN_DONE message
print F &mk_open_msg;

# wait for OPEN_DONE
while ($lastmbim != 0x80000001) {
    sleep(1);
}
print "MBIM OPEN succeeded\n" if $verbose;

# verify QMI channel support with QMI_CTL_MESSAGE_GET_VERSION_INFO
unless (&do_qmi(0x0021, &mk_qmi(0, 0, 0x0021, { 0x01 => pack("C", 255), }))) {
    print "Failed to verify QMI vendor specific MBIM service\n";
    &quit;
}
print "MBIM QMI support verified\n";
&qmiver($lastqmi) if $verbose;

# allocate a DMS CID (or just reuse the one allocated by the MBIM firmware application?)
# QMI_CTL_GET_CLIENT_ID, TLV 0x01 => 2 (DMS)
unless (&do_qmi(0x0022, &mk_qmi(0, 0, 0x0022, { 0x01 => pack("C", 2), }))) {
    print "Failed to get QMI DMS client ID\n";
    &quit;
}
$dmscid = $lastqmi->{'tlvs'}{0x01}[1]; # save the DMS CID
print "Got QMI DMS client ID '$dmscid'\n" if $verbose;

#QMI_DMS_SWI_SETUSBCOMP (or whatever)
# get USB comp = 0x555B
# set USB comp = 0x555C
# "Set FCC Authentication" =  0x555F
##print F &mk_command_msg('EXT_QMUX', 1, 1,  &mk_qmi(2, $dmscid, 0x555c, { 0x01 => $usbcomp}));
# wait for response and decode

# always get first.  We need the list of supported settings to allow set
&do_qmi(0x555b, &mk_qmi(2, $dmscid, 0x555b, {})) || &quit;
my $current = $lastqmi->{'tlvs'}{0x10}[0];
my @supported = @{$lastqmi->{'tlvs'}{0x11}};
my $count = shift(@supported);

# basic sanity:
if ($count != $#supported + 1) {
    print "ERROR: array length mismatch, $count != $#supported\n";
    print to_json(\@supported),"\n";
    &quit;
}


&quit unless (grep { $current == $_ } @supported); # verify that the current comp is supported

# dump current settings
printf "Current USB composition: %d\n", $current;
if ($verbose) {
    print "USB compositions:\n";
    for my $i (sort { $a <=> $b } keys %comps) {
	printf "%s %2i - %-48s %sSUPPORTED\n", $i == $current ? '*' : ' ', $i, $comps{$i}, (grep { $i == $_ } @supported) ? '' : 'NOT ';
    }
}

# want a new setting?
&quit unless defined($usbcomp);

# no need to change to the current setting
if ($usbcomp == $current) {
    print "Current setting is already '$usbcomp'\n";
    &quit;
}

# verify that the new setting is supported
unless (grep { $usbcomp == $_ } @supported) {
    print "USB composition '$usbcomp' is not supported\n";
    &quit;
}

# attempt to change USB comp
if (!&do_qmi(0x555c, &mk_qmi(2, $dmscid, 0x555c, { 0x01 => pack("C", $usbcomp)}))) {
    print "Failed to change USB composition to '$usbcomp'\n";
}

&quit;

sub quit {
    if ($dmscid) {
	# release DMS CID
	# QMI_CTL_RELEASE_CLIENT_ID
	&do_qmi(0x0023, &mk_qmi(0, 0, 0x0023, { 0x01 =>  pack("C*", 2, $dmscid)}));
    }

    # send CLOSE
    print F &mk_close_msg;

    # wait for the reader to exit (on CLOSE_DONE)
    waitpid($pid, 0);

    close(F);
    exit 0; # will exit parent
}
    
sub usage {
    print STDERR <<EOH
Usage: $0 [options]  

Where [options] are
  --device=<mbimdev>    use <mbimdev> (default: '$mgmt')
  --usbcomp=<num>	change USB composition setting
  --debug		enable verbose debug output
  --help		this help text

  The current setting and supported modes will always be displayed
  

EOH
    ;
    exit;
}
