#!/usr/bin/perl -w
# Copyrigt Denis Immoos <denisimmoos@gmail.com>
use strict;
use Net::SNMP;
use Getopt::Long;
#use Data::Dumper;
# Nagios specific
my $TIMEOUT = 15;
#################################### Globals
##############################""
# global variable definitions for check_options
our $o_host = undef;
our $o_port = 161;
our $o_community = undef;
our $o_login = undef;
our $o_passwd = undef;
our $o_privpasswd = $o_passwd;
our $o_authprotocol = "md5";
our $o_privprotocol = "md5";
our $o_verb = undef;
our $o_warn;
our $o_crit;
our $o_unit;
our $o_label;
our $o_oid;
our $o_calc;
our $o_warning;
our $o_critical;
my $o_help = undef;
my $global_status=1; # global status : 0=OK, 1=Warn, 2=Crit
my $snmpv2;
# functions
sub help {
print "\ncheck-snmp-numeracy Nagios check-script to check an OID and
give it a label and unit string and perform some optional calculation.\n";
print "\n\nCopyright (c) 2012 - Denis Immoos (d.immoos\@gmail.com)\n\n";
print_usage();
print <<EOT;
-v, --verbose
print extra debugging information (including interface list on the system)

-h, --help
print this help message

-H, --hostname=HOST
name or IP address of host to check

-C, --community=COMMUNITY NAME
community name for the host's SNMP agent (implies v1 protocol)

-2 use snmp v2c instead of v1

-l, --login=LOGIN
Login for snmpv3 authentication (implies v3 protocol with MD5)

-a, --passwd=PASSWD
Password for snmpv3 authentication

-A, --authprotocol
Protocol for authentication (md5|sha1), for snmpv3 only

-x, --privpasswd
Password for snmpv3 encryption

-X, --privprotocol
Protocol for encryption (des|aes), for snmpv3 only

-P, --port=PORT
SNMP port (Default 161)

-t, --timeout=INTEGER
timeout for SNMP (Default: Nagios default)

-o, --oid=OID[,OID,...]
OID for SNMP (OBLIGATORY)

Note: If multiple OID's are selected an average will be calculated
automatically.
-u, --unit=UNIT

unit string [V,Mb,Gb,b,Pa, ... ] (OBLIGATORY)

--label=LABEL
label string [Volts,Megabytes,Gigabytes,bytes,Pressure, ... ]
(OBLIGATORY)

--calc=CALCULATION
calculation string (OPTIONAL)

EXAMPLES:

# the received OID value * 1000
--calc='#oid0# * 1000'
# the received OID value ^2
--calc='#oid0# ** 2'
# square root of the multiplication of two OID's
--calc='sqrt( #oid0# + #oid1# )'
# absolut of the received OID value
# if a singel value is selected you can use #oid# instead of #oid0#
--calc='abs(#oid#)'
--calc='abs(#oid0#)'

# stupid example of what you can do with the received OID value
--calc='sqrt(#oid3# ** 2)'

EOT
}

# For verbose output
sub verb { my $t=shift; print $t,"\n" if defined($o_verb) ; }

# check options
sub check_options {

Getopt::Long::Configure ("bundling");
GetOptions(
'H:s' 		=> \$o_host, 			'hostaddr:s' 		=> \$o_host,
'p:i' 		=> \$o_port, 			'port:i' 			=> \$o_port,
'C:s' 		=> \$o_community, 		'community:s' 		=> \$o_community,
'l:s' 		=> \$o_login, 			'login:s' 			=> \$o_login,
'a:s' 		=> \$o_passwd, 			'passwd:s' 			=> \$o_passwd,
'A:s' 		=> \$o_authprotocol, 	'authprotocol:s' 	=> \$o_authprotocol,
'x:s' 		=> \$o_privpasswd, 		'privpasswd:s' 		=> \$o_privpasswd,
'X:s' 		=> \$o_privprotocol, 	'privprotocol:s' 	=> \$o_privprotocol,
't:i' 		=> \$TIMEOUT, 			'timeout:i' 		=> \$TIMEOUT,
'v' 		=> \$o_verb, 			'verbose' 			=> \$o_verb,
'h' 		=> \$o_help, 			'help' 				=> \$o_help,
'2' 		=> \$snmpv2, 
'w:s' 		=> \$o_warn, 			'warn:s' 			=> \$o_warn, 
'c:s' 		=> \$o_crit, 			'crit:s' 			=> \$o_crit,
'oid:s' 	=> \$o_oid, 
'label:s' 	=> \$o_label,
'u:s' 		=> \$o_unit, 			'unit:s'		 	=> \$o_unit,
'calc:s'  	=> \$o_calc,
);

if (defined ($o_help) ) { help(); exit 3};
if (! defined ($o_host)) { print "\nYou must supply host address\n"; print_usage(); exit 3}

if ( !defined($o_community) && 
	(!defined($o_login) || 
	!defined($o_passwd)) ) { 
		print "You must supply snmp login info!\n"; 
		print_usage();
		exit 3;
}

if (! defined ($o_unit)) { 
	print "\n[-u|--unit] is obligatory \n";
	print_usage(); 
	exit 3;
}
if (! defined ($o_label)) { 
	print "\n[--label] is obligatory.\n";
	print_usage(); 
	exit 3;
}

if (! defined ($o_oid)) { 
	print "\n[-o|--oid] is obligatory.\n";
	print_usage(); 
	exit 3;
}

if (! defined ($o_crit) or ! defined ($o_warn)) { print "\nWARNING and
	CRITICAL thresholds are obligatory\n"; print_usage(); exit 3 }
}

sub end_script {
	my $exit_status = shift;
	my $output = shift;
	print "$output\n";
	exit $exit_status;
}



sub print_usage {
	print "\nUsage: $0 [-v] -H <host> -C <snmp_community> -o <oid> -u <unit> --label=<label> [ --calc='<calculation>' ] | (-l login -a passwd [-A md5|sha1] [-x privpasswd] [-X des|aes]) [-p <port>] [-t <timeout>]\n\n";
}


sub doSNMP {
	my $OID = shift;


eval {
	local $SIG{ALRM} = sub { die "Alarm" };
	alarm($TIMEOUT);
	verb("logging in to $o_host");
	#
	# Connect to host
	#
	my ($session,$error);
	if ( defined($o_login) && defined($o_passwd)) {
		# SNMPv3 login
		verb("SNMPv3 login");
		($session, $error) = Net::SNMP->session(
			-hostname => $o_host,
			-version => '3',
			-username => $o_login,
			-authpassword => $o_passwd,
			-authprotocol => $o_authprotocol,
			-privpassword => $o_privpasswd,
			-privprotocol => $o_privprotocol
		);
	} else {
		if (defined($snmpv2)) {
			#SNMPV2c login
			($session, $error) = Net::SNMP->session(
				-hostname => $o_host,
				-community => $o_community,
				-port => $o_port,
				-timeout => $TIMEOUT,
				-version => '2c'
			);
	} else {
		# SNMPV1 login
		($session, $error) = Net::SNMP->session(
			-hostname => $o_host,
			-community => $o_community,
			-port => $o_port,
			-timeout => $TIMEOUT
		);
	}
}


if (!defined($session)) {
	
	printf("ERROR opening session: %s.\n", $error);
	end_script(3,"ERROR opening snmp session to $o_host");
}


my ($resultat,$key)=(undef,undef);

my @checks = ($OID);
verb("Doing snmp get with OID: $OID");
$resultat = $session->get_request( varbindlist => \@checks);
if (defined($resultat)) {
	chomp($$resultat{$OID});
	return $$resultat{$OID};
} else {
	end_script(3,"UNKNOWN: cannot get anything, check
	connection and OID");
}
$session->close;
alarm (0);
};
}

########## MAIN #######

check_options();

my @OIDS = split(/\,/,$o_oid);
my $oid;
my $count = 0;
my $oid_value;
my @OID_VALUES;
my $total = 0;
my $divisor = 1;
# Due to compatibility
if ( $o_calc ) { $o_calc =~ s/#oid#/#oid0#/g; }
foreach $oid (@OIDS) {
      my $oid_value = doSNMP($oid);
      if (!defined($oid_value)) {
         end_script(3, "UNKNOWN SNMP: no value for oid $oid got!");
      }

# Mathemagics ;)
if ( $o_calc ) {
	$o_calc =~ s/#oid$count#/$oid_value/g or end_script(3, "You used --calc please define #oid$count# ...");
	verb("replaced #oid$count#: " . $o_calc );
} else {
	push(@OID_VALUES,$oid_value);
}
	verb("#oid$count#: " . $oid_value);
	$count++;
}



# -1
$count--;
#
# Mathemagics II ;)
#
if ( $o_calc ) {
# eval ain't evil at this point
$oid_value = eval($o_calc);
if ( not defined($oid_value) ) { end_script(3, "Wrong calculation syntax please check your calculation (Missing: $o_calc) ..."); }
	verb("calculated \$oid_value [ $o_calc ] : " . $oid_value );
} else {
	#default Mittelwert

	foreach (@OID_VALUES) { $total += $_; }
		$divisor = @OID_VALUES;
		$oid_value = $total / $divisor;
		verb("calculated \$oid_value [ average ] : " . $oid_value );
}

# threshold handling
my ($o_crit_min, $o_crit_max) = split(":", $o_crit) or end_script(3, "critical threshold syntax is wrong");
my ($o_warn_min, $o_warn_max) = split(":", $o_warn) or end_script(3, "warning threshold syntax is wrong");

# build perfdata string
# customer specific EBM: instead of $o_warn_max we submit $o_crit_min for "[warn]" perfdata field
#check http://nagiosplug.sourceforge.net/developer-guidelines.html#AEN201 for more info
my $perfdata = $o_label . "=" . $oid_value . $o_unit . ";" . $o_crit_min .  ";" . $o_crit_max;
my $outputmsg = "($o_oid): " . $oid_value . " " . $o_unit;
my $output;

if ($oid_value < $o_crit_min or $oid_value > $o_crit_max) {
	$output = "CRITICAL - " . $outputmsg . "|" . $perfdata;
	end_script(2, $output);
} elsif ($oid_value < $o_warn_min or $oid_value > $o_warn_max) {
	$output = "WARNING - " . $outputmsg . "|" . $perfdata;
	end_script(1, $output);
} else {
	$output = "OK - " . $outputmsg . "|" . $perfdata;
	end_script(0, $output);
}


