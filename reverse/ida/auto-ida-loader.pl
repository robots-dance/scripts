use strict;

use constant {
	USAGE => "Usage: auto-ida-loader.pl <ida-path> <script-path> " .
		 "<dir> [<module-regex>]",
	
	SCRIPT_STARTED => "auto_script_started",
	
	SCRIPT_FINISHED => "auto_script_finished"
};

die USAGE if ( @ARGV < 3 );

my $idaPath = $ARGV[ 0 ];
my $scriptPath = $ARGV[ 1 ];
my $dirPath = $ARGV[ 2 ];
my $moduleRgx = "";
$moduleRgx = $ARGV[ 3 ] if ( @ARGV > 3 );

die "bad ida path" if ( ! -f $idaPath );
die "bad script path" if ( ! -f $scriptPath );
die "bad dir path" if ( ! -d $dirPath );

chdir $dirPath or die "can't change current directory";
opendir my ( $dirHandle ), "." or die "can't open the current directory";
my @files = readdir $dirHandle;
closedir $dirHandle;

my $logFileName = "ida.log";
my $selfLogFileName = "ida-fin.log";
open SELF_LOG, ">$selfLogFileName" or die "can't open output file";
foreach my $fileName ( @files )
{
	next if ( $fileName eq "." or $fileName eq ".." );
	next if ( -d $fileName );
	$fileName = lc $fileName;
	next if ( ! ( $fileName =~ /\.(exe|dll)$/ ) );
	if ( length( $moduleRgx ) > 0 )
	{
		next if ( ! ( $fileName =~ $moduleRgx ) );
	}
	
	print $fileName, "...\n";
	unlink $logFileName if ( -f $logFileName );
	`"$idaPath" -L$logFileName -A -S"$scriptPath batch" "$fileName"`;
	
	my $started = 0;
	my @scriptOutput = ();
	my $outputNoEmpty = 0;
	
	open LOG_FILE, $logFileName or die "can't open log file name";
	while ( <LOG_FILE> )
	{
		chomp;
		if ( $started )
		{
			last if ( $_ eq SCRIPT_FINISHED );
			$outputNoEmpty = 1 if ( length( $_ ) > 0 );
			push @scriptOutput, $_;
		}
		$started = 1 if ( $_ eq SCRIPT_STARTED );
	}
	close LOG_FILE;
	
	if ( $outputNoEmpty )
	{
		print SELF_LOG $fileName, "\n======== ========\n";
		foreach my $outputLine ( @scriptOutput )
		{
			print SELF_LOG $outputLine, "\n";
		}
		print SELF_LOG "++++++++ ++++++++\n";
	}
	
	print "done.\n\n";
}
close SELF_LOG;
