from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError
import struct
import sys

class ErrorCode:
	BAD_USAGE = 1
	BAD_NEW_ENTRY = 2
	CANT_OPEN_FILE = 3
	CANT_PARSE_ELF = 4
	BAD_BYTES_ORDER = 5

argsCount = len( sys.argv )
if argsCount < 3:
	print "Usage: patch-elf-entry <file-path> <new-entry> [bytes-order:l|b]"
	sys.exit( ErrorCode.BAD_USAGE )

bytesOrder = "l"
if argsCount > 3:
	bytesOrder = sys.argv[ 3 ]
	if bytesOrder != "l" and bytesOrder != "b":
		print "incorrect bytes order"
		sys.exit( ErrorCode.BAD_BYTES_ORDER )

filePath = sys.argv[ 1 ]
try:
	newEntry = int( sys.argv[ 2 ], 16 )
	if newEntry > 0xFFFFFFFF:
		raise ValueError()
except ValueError:
	print "incorrect entry point"
	sys.exit( ErrorCode.BAD_NEW_ENTRY )

try:
	inpFile = open( filePath, "r+b" )
except IOError:
	print "can't open an input file" 
	sys.exit( ErrorCode.CANT_OPEN_FILE )

try:
	elfFile = ELFFile( inpFile )
except ELFError:
	print "can't open this ELF file"
	sys.exit( ErrorCode.CANT_PARSE_ELF )

oldEntry = elfFile[ "e_entry" ]
sctTableOff = elfFile[ "e_shoff" ]
print "old addr   new addr"
print "=======    ========"
if sctTableOff != 0:
	sctIndex = 0
	sctSize = 40
	addrOff = 12
	for sct in elfFile.iter_sections():
		oldSctAddr = sct.header[ "sh_addr" ]
		newSctAddr = ( oldSctAddr - oldEntry ) + newEntry
		fieldOffset = sctTableOff + sctIndex * sctSize + addrOff
		print "%08x   %08x" % ( oldSctAddr, newSctAddr )
		inpFile.seek( fieldOffset )
		fmtStr = "<I" if bytesOrder == "l" else ">I"
		inpFile.write( struct.pack( fmtStr, newSctAddr ) )
		sctIndex += 1
else:
	print "can't find any sections"

inpFile.close()
