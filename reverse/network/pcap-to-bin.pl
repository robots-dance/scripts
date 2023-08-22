use strict;

use Net::Pcap;
# ppm install http://www.bribes.org/perl/ppm/Net-Pcap.ppd
# Note: only for Perl x86

use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::TCP;
# ppm install NetPacket

use constant
{
	USAGE => "Usage: pcap-to-bin.pl <pcap-file-path> <output-file-path> " .
		"<client-address> [bin|html] [glue] [cut <header-size>]\n",
	CLIENT => "[client]",
	SERVER => "[server]",
	BYTE_LINE_SIZE => 32
};

my $g_curHtmlLinePos = 0;
my $g_senderIsClient = -1;

sub headerNeeded( $$ )
# @1: sender is client ( bool )
# @2: glue needed ( bool )
{
	my ( $senderIsClient, $glueNeeded ) = @_;
	my $headerNeeded = 0;
	if ( $glueNeeded )
	{
		$headerNeeded = 1 if ( -1 == $g_senderIsClient ||
			$senderIsClient != $g_senderIsClient );
	}
	else {
		$headerNeeded = 1;
	}
	return $headerNeeded;
}

sub printBufferToHtml( $$ )
# @1: data buffer ( binary string )
# @2: header needed ( bool )
{
	my ( $data, $headerNeeded ) = @_;
	
	if ( $headerNeeded )
	{
		$g_curHtmlLinePos = 0;
	}
	
	my $byteIndex = 0;
	my $dataSize = length( $data );
	while ( $byteIndex < $dataSize )
	{
		if ( 0 == $g_curHtmlLinePos )
		{
			print OUTPUT_FILE "<br>";
		}
		my $selectionNeeded = ( 0 == $byteIndex and not $headerNeeded );
		if ( $selectionNeeded )
		{
			print OUTPUT_FILE "<b style='color: green'>";
		}
		printf OUTPUT_FILE "<tt>%02x</tt>", ( unpack( "W", substr( $data,
			$byteIndex, 1 ) ) )[ 0 ];
		if ( $selectionNeeded )
		{
			print OUTPUT_FILE "</b>";
		}
		
		$g_curHtmlLinePos = 0 if ( $g_curHtmlLinePos++ >= BYTE_LINE_SIZE );
		if ( $g_curHtmlLinePos > 0 )
		{
			print OUTPUT_FILE "&nbsp;";
		}
		
		$byteIndex++;
	}
}

sub writeToBinary( $$$$$ )
# @1: client ip address ( string )
# @2: source ip address from a package ( string )
# @3: tcp payload ( binary string )
# @4: glue needed ( bool ) 
{
	my ( $pkgNum, $clientAddress, $srcIp, $tcpData, $glueNeeded ) = @_;
	my $senderIsClient = $srcIp eq $clientAddress;
	
	if ( headerNeeded( $senderIsClient, $glueNeeded ) )
	{
		if ( $senderIsClient )
		{
			syswrite( OUTPUT_FILE, CLIENT, length( CLIENT ) );
		}
		else
		{
			syswrite( OUTPUT_FILE, SERVER, length( SERVER ) );
		}
		$g_senderIsClient = $senderIsClient;
	}
	
	syswrite( OUTPUT_FILE, $tcpData, length( $tcpData ) );	
}

sub writeToHtml( $$$$$ )
# see writeToBinary
{
	my ( $pkgNum, $clientAddress, $srcIp, $tcpData, $glueNeeded ) = @_;
	my $senderIsClient = $srcIp eq $clientAddress;
	
	my $headerNeeded = 0;
	if ( headerNeeded( $senderIsClient, $glueNeeded ) )
	{
		if ( $pkgNum > 0 )
		{
			print OUTPUT_FILE "</div><br><br>";
		}
		
		if ( $senderIsClient )
		{
			print OUTPUT_FILE "<b style='color: red;'>client</b>";
		}
		else
		{
			print OUTPUT_FILE "<b style='color: blue;'>server</b>";
		}
		
		print OUTPUT_FILE "<br><i>";
		print OUTPUT_FILE "pkg num = $pkgNum, size = " . length( $tcpData );
		print OUTPUT_FILE "</i>&nbsp;&nbsp;";
		print OUTPUT_FILE "<a href='javascript:void(0);' onclick=" .
			"'ManagePkgFold( $pkgNum )'>";
		print OUTPUT_FILE "<span id='link_$pkgNum'>open</span></a>";
		print OUTPUT_FILE "<div style='display: none' id='pkg_$pkgNum'>";
		
		$headerNeeded = 1;
		$g_senderIsClient = $senderIsClient;
	}
	
	printBufferToHtml( $tcpData, $headerNeeded );
}

sub processPacket( $$$ )
{
	my ( $userData, $header, $packet ) = @_;
	
	# extract params
	my $clientAddress = $userData->{ 'addr' };
	my $format = ( $userData->{ 'format' } or "bin" );
	
	my $glue = ( $userData->{ 'glue' } or "" );
	my $glueNeeded = $glue eq "glue";
	
	my $cut = ( $userData->{ 'cut' } or "" );
	my $cutNeeded = $cut eq "cut";
	my $headerSize = $cutNeeded ? $userData->{ 'headerSize' } : 0;
	
	# extract packages
	my $etherPkg = NetPacket::Ethernet->decode( $packet );
	my $ipPkg = NetPacket::IP->decode( $etherPkg->{ 'data' } );
	my $tcpPkg = NetPacket::TCP->decode( $ipPkg->{ 'data' } );
	my $tcpData = substr( $tcpPkg->{ 'data' }, $headerSize );
	my $payloadSize = length( $tcpData );
	
	if ( $payloadSize > 0 )
	{
		my $srcIp = $ipPkg->{ 'src_ip' };
		my $pkgNum = $userData->{ 'pkgNum' };
		if ( $format eq "bin" )
		{
			writeToBinary( $pkgNum, $clientAddress, $srcIp,
				$tcpData, $glueNeeded );
		}
		elsif ( $format eq "html" )
		{
			writeToHtml( $pkgNum, $clientAddress, $srcIp,
				$tcpData, $glueNeeded );
		}
		
		printf "src = %s, dst = %s, size = %d\n",
			$srcIp,
			$ipPkg->{ 'dest_ip' },
			$payloadSize;
		
		$userData->{ 'pkgNum' }++;
	}
}

die USAGE if ( @ARGV < 3 );

my $err = undef;

# try to open an input pcap file
my $pcapPath = $ARGV[ 0 ];
my $pcapFile = pcap_open_offline( $pcapPath, \$err ) or
	die "can't read pcap file: $err\n";

# try to open an output file
my $outFilePath = $ARGV[ 1 ];
if ( not open OUTPUT_FILE, ">$outFilePath" )
{
	pcap_close( $pcapFile );
	die "can't open an output file\n";
}

# prepare parameters for processPacket sub
my %userData = ( 'addr' => $ARGV[ 2 ] );
my $format = "";
$format = $ARGV[ 3 ] if ( @ARGV > 3 );
if ( $format eq "bin" ) {
	binmode OUTPUT_FILE;
}
elsif ( $format eq "html" )
{
	print OUTPUT_FILE "<html>";
	print OUTPUT_FILE "<head><title>session dump</title></head>";
	print OUTPUT_FILE "<body>";
	print OUTPUT_FILE "<script language='JavaScript'>";
	print OUTPUT_FILE <<"END";
	function ManagePkgFold( number )
	{
		var pkgElem = document.getElementById( 'pkg_' + number );
		var linkElem = document.getElementById( 'link_' + number );
		if ( pkgElem.style.display == 'none' )
		{
			pkgElem.style.display = '';
			linkElem.innerHTML = 'close';
		}
		else
		{
			pkgElem.style.display = 'none';
			linkElem.innerHTML = 'open';
		}
	}
END
	print OUTPUT_FILE "</script>";
	print OUTPUT_FILE "<h2>Session</h2>";
}
elsif ( length( $format ) > 0 )
{
	close OUTPUT_FILE;
	pcap_close( $pcapFile );
	die "unsupported output format\n";
}

$userData{ 'format' } = $format;
$userData{ 'glue' } = $ARGV[ 4 ] if ( @ARGV > 4 );
$userData{ 'pkgNum' } = 0;
if ( @ARGV > 6 )
{
	$userData{ 'cut' } = $ARGV[ 5 ];
	my ( $headerSize ) = $ARGV[ 6 ] =~ /([\d]+)/;
	die "incorrect header size to skip\n" if ( $headerSize < 0 );
	$userData{ 'headerSize' } = $headerSize;
}

pcap_loop( $pcapFile, -1, \&processPacket, \%userData );

pcap_close( $pcapFile );

if ( $format eq "html" )
{
	print OUTPUT_FILE "</body>";
	print OUTPUT_FILE "</html>";
}

close OUTPUT_FILE;
