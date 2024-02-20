from zlib import decompress
import sys

if len( sys.argv ) < 2:
	sys.exit( "incorrect params" )

inpFileName = sys.argv[ 1 ]
inpFile = open( inpFileName, 'rb' )
inpData = inpFile.read()
inpFile.close()

signPos = inpData.find( '\x78\x9c' )

outFileName = inpFileName + ".unzl"
outFile = open( outFileName, 'wb' )

while signPos != -1:
	prevSignPos = signPos
	signPos = inpData.find( '\x78\x9c', signPos + 2 )
	try:
		if signPos != -1:
			data = decompress( inpData[ prevSignPos: signPos ] )
		else:
			data = decompress( inpData[ prevSignPos: ] )
		outFile.write( data )
		print "decompression ok\n"
	except:
		print "error occured during decompressing\n"

outFile.close()
