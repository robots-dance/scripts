#include <idc.idc>

#define BAD_SEGMENT_NAME 1
#define BAD_SEGMENT 2
#define BAD_STRUCT_SIZE 3

#define PRINT_ASCII 0
#define STRONG_ASCII_CHECK 1

#define PRINT_DISASM_LINE 1

#define OUTPUT_FILE_NAME "blocks-list.txt"

static DataToXrefsCount(ea)
{
	auto counter = 0;
	auto xr;
	for ( xr = DfirstB( ea ); xr != BADADDR; xr = DnextB( ea, xr ) )
	{
		counter++;
	}
	return counter;
}

static main()
/*
	This script find all data structures from supplied segment
	You can specify also and a structure size for filtering
	(or input -1 if it's not needed)
*/
{
	// get a segment
	auto segName = AskStr( ".rdata", "enter a segment name:" );
	auto segSel = SegByName( segName );
	if ( BADSEL == segSel )
	{
		Message("bad segment name\n");
		return BAD_SEGMENT_NAME;
	}
	auto segAddr = SegByBase( segSel );
	if ( BADADDR == segAddr )
	{
		Message("bad segment\n");
		return BAD_SEGMENT;
	}
	
	// get structure size
	auto structSize = AskLong( -1,
		"enter a structure size (optional, for filter):" );
	if ( !IsLong( structSize ) )
	{
		Message("bad structure size\n");
		return BAD_STRUCT_SIZE;
	}
	
	// process segment
	auto nextSegAddr = NextSeg( segAddr );
	auto ea = segAddr;
	auto blockSize = 0;
	auto blockAddr = 0;
	auto equalsCounter = 0;
	auto asciiCounter = 0;
	auto kFilePath = GetIdaDirectory() + "\\output\\" + OUTPUT_FILE_NAME;
	auto outputFile = fopen( kFilePath, "w" );
	while ( ea != nextSegAddr )
	{
		if ( DataToXrefsCount( ea ) > 0 )
		{
			auto isCorrectBlSize = blockSize == structSize || -1 == structSize;
			auto isAsciiStr;
			if ( STRONG_ASCII_CHECK )
			{
				isAsciiStr = ( blockSize - asciiCounter ) == 1 &&
					Byte( ea - 1 ) == 0;
			}
			else
			{
				isAsciiStr = ( asciiCounter >= blockSize / 2 );
			}
			if ( blockSize > 0 && isCorrectBlSize )
			{
				if ( !isAsciiStr || PRINT_ASCII )
				{
					fprintf( outputFile, "%x %d\n", blockAddr, blockSize );
					Message("block at %x = %d", blockAddr, blockSize);
					if ( PRINT_DISASM_LINE )
					{
						Message( "; // %s", GetDisasm( blockAddr ) );
					}
					Message("\n");
					equalsCounter++;
				}
			}
			asciiCounter = 0;
			blockAddr = ea;
			blockSize = 1;
		}
		else {
			blockSize++;
		}
		auto byte = Byte( ea );
		auto isAsciiCh = byte >= 32 && byte <= 126;
		if ( isAsciiCh ) {
			asciiCounter++;
		}
		ea++;
	}
	fclose( outputFile );
	
	Message("equals: %d\n", equalsCounter);
	
	return 0;
}
