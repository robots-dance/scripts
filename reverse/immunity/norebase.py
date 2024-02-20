import immlib
import pelib
import struct

def usage( imm ):
	imm.log( "!norebase <address>" )

def main( args ):
	imm = immlib.Debugger()
	
	addr = 0
	if not args or len( args ) == 0:
		addr = imm.getCurrentAddress()
		print "no args supplied, use current address"
	else:
		try:
			addr = int( args[ 0 ], 16 )
		except ValueError:
			print "incorrect input address"
	
	module = imm.getModuleByAddress( addr )
	if module == None:
		return "[*] no modules contain this address!"
	
	base = module.getBase()
	
	# get an offset to an optional header
	mzHdr = pelib.MZ()
	mzHdrData = imm.readMemory( base, struct.calcsize( mzHdr.fmt ) )
	mzHdr.get( mzHdrData )
	pehdrAddr = base + mzHdr.getPEOffset() + pelib.IMAGE_SIZEOF_FILE_HEADER + 4
	
	# extract original base
	optHdr = pelib.IMGOPThdr()
	optHdrData = ( imm.readMemory( pehdrAddr, struct.calcsize(
		optHdr.optionalfmt ) ) )
	optHdr.get( optHdrData )
	originalBase = optHdr.ImageBase
	
	# get a result address
	norebaseAddr = addr - base + originalBase
	imm.log( "no-rebase address: 0x%x" % norebaseAddr )
	return "[*] 0x%x" % norebaseAddr
