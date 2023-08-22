use Fcntl qw ( SEEK_SET SEEK_CUR );
use File::Path qw( remove_tree );
use strict;

# sizes
use constant {
	REC_BASE_SIZE => 3,
	REC_TYPE_SIZE => 1,
	REC_LEN_SIZE => 2
};

# error codes
use constant {
	UNKNOWN_ERROR => 0,
	UNSUPPORTED_PAGE_SIZE => -1,
	CANT_CREATE_OBJ => -2,
	LIB_STRUC_ERROR => -3,
	IO_ERROR => -4
};

sub ParseObjectHeader( $$ )
{
	my ( $pageData, $objectName ) = @_;
	my $recordSize = unpack( "v", substr( $pageData,
		REC_TYPE_SIZE, REC_LEN_SIZE ) );
	my $objNameSize = unpack( "C", substr( $pageData,
		REC_BASE_SIZE, 1 ) );
	if ( $recordSize != $objNameSize + 2 or
		$recordSize >= length( $pageData ) )
	{
		return 0;
	}
	$$objectName = substr( $pageData, REC_BASE_SIZE + 1, $objNameSize );
	return 1;
}

sub WriteObjectData( $$ )
{
	my ( $objFile, $data ) = @_;
	if ( defined $objFile )
	{
		syswrite( $objFile, $data );
		return 1;
	}
	else {
		return 0;
	}
}

sub UnpackLibrary( $$ )
{
	my ( $libPath, $objDirPath ) = @_;
	open( my $libFile, "<", $libPath ) or return 0;
	binmode $libFile;
	
	my $curLibOff = 0;
	my $recordType = "";
	my $recordSizeBuff = "";
	my $recordSize = 0;
	my $recordData = "";
	my $pageSize = 0;
	my $pageData = "";
	
	# check quickly a library type
	if ( read( $libFile, $recordType, REC_TYPE_SIZE ) !=
		REC_TYPE_SIZE or not $recordType eq "\xf0" )
	{
		return 0;
	}
	else {
		$curLibOff += REC_TYPE_SIZE;
	}
	
	# read a record size
	seek( $libFile, $curLibOff, SEEK_SET );
	if ( read( $libFile, $recordSizeBuff, REC_LEN_SIZE ) != REC_LEN_SIZE )
	{
		return 0;
	}
	else {
		$curLibOff += REC_LEN_SIZE;
	}
	$recordSize = unpack( "v", $recordSizeBuff );
	$pageSize = $recordSize + REC_BASE_SIZE;
	# printf "%s = %x\n", $libPath, $recordSize;
	if ( $pageSize != 0x80 ) {
		return UNSUPPORTED_PAGE_SIZE;
	}
	
	# skip remain bytes of the first library record
	seek( $libFile, $curLibOff, SEEK_SET );
	if ( read( $libFile, $recordData, $recordSize ) != $recordSize )
	{
		return 0;
	}
	else {
		$curLibOff += $recordSize;
	}
	
	# read object files page by page
	my $endFinded = 0;
	my $parseError = 0;
	my $ioError = 0;
	my $curObjFile = undef;
	while ( !$endFinded and !$parseError and !$ioError )
	{
		seek( $libFile, $curLibOff, SEEK_SET );
		if ( read( $libFile, $pageData, $pageSize ) != $pageSize )
		{
			close $curObjFile if ( defined $curObjFile );
			$ioError = 1;
			last;
		}
		$recordType = substr( $pageData, 0, REC_TYPE_SIZE ); 
		if ( $recordType eq "\x80" or $recordType eq "\x82" )
		{
			my $objectName = "";
			if ( ParseObjectHeader( $pageData, \$objectName ) and \
				length( $objectName ) > 0 )
			{
				close $curObjFile if ( defined $curObjFile );
				# process .c, .C, .cpp, .asm extensions
				my ( $objectName ) = $objectName =~ /\\([^\\]+)\.(c|a)/i;
				my $fullObjPath = "$objDirPath/$objectName.obj";
				my $pathCounter = 0;
				while ( -f $fullObjPath )
				{
					$fullObjPath = "$objDirPath/${objectName}_$pathCounter";
					$fullObjPath .= ".obj";
					$pathCounter++;
				}
				if ( !open( $curObjFile, ">", $fullObjPath ) )
				{
					print "can't open an output file\n";
					$ioError = 1;
				}
				else
				{
					binmode $curObjFile;
					syswrite( $curObjFile, $pageData );
				}
				print "\t$objectName\n";
			}
			elsif ( !$parseError )
			{
				$parseError = !WriteObjectData( $curObjFile, $pageData );
			}
		}
		elsif ( $recordType eq "\xf1" )
		{
			$recordSize = unpack( "v", substr( $pageData, REC_TYPE_SIZE,
				REC_LEN_SIZE ) );
			if ( ( $recordSize + REC_BASE_SIZE )% $pageSize == 0 )
			{
				$endFinded = 1;
			}
			else
			{
				$parseError = !WriteObjectData( $curObjFile, $pageData );
			}
		}
		else
		{
			$parseError = !WriteObjectData( $curObjFile, $pageData );
		}
		$curLibOff += $pageSize;
	}
	
	# check for some errors
	if ( $parseError )
	{
		printf "current library offset: %x\n", $curLibOff;
		return LIB_STRUC_ERROR; 
	}
	elsif ( $ioError )
	{
		return IO_ERROR;
	}
	
	close $libFile;
	return 1;
}

die "Usage: extract-objects.pl <libraries-path>" if ( @ARGV < 1 );
my $librariesPath = $ARGV[ 0 ];

opendir my $libsDir, $librariesPath or die "can't open the specified dir";
while ( my $fileName = readdir( $libsDir ) )
{
	if ( $fileName =~ /\.lib$/ )
	{
		my $objDirName = substr( $fileName, 0, length(
			$fileName ) - 4 ) . "_objects";
		my $fullObjDirPath = "$librariesPath/$objDirName";
		remove_tree( $fullObjDirPath ) if ( -d $fullObjDirPath );
		if ( -d $fullObjDirPath or !mkdir( $fullObjDirPath ) )
		{
			print "can't prepare a directory for $fileName\n";
			next;
		}
		
		my $fullLibPath = "$librariesPath/$fileName"; 
		print "library $fileName processing start...\n";
		if ( ( my $errorCode = UnpackLibrary( $fullLibPath,
			$fullObjDirPath ) ) <= 0 )
		{
			$errorCode = UNKNOWN_ERROR if ( 0 == $errorCode );
			printf "error %d occured during processing the %s library",
				$errorCode, $fileName;
			last;
		}
		print "finish.\n\n";
	}
	next if ( $fileName eq "." or $fileName eq ".." );
}
closedir $libsDir;
