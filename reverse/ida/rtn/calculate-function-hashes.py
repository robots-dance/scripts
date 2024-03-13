import hashlib
import pickle
import struct

ARM32_INST_SIZE = 4

def DumpFunctionsInfo( outputFile ):
	functions = Functions()
	hashes = {}
	uniqueDublicates = {}
	for func in functions:
		funcStart = func
		funcEnd = GetFunctionAttr( func, FUNCATTR_END )
		if not funcEnd:
			continue
		
		# get the function body
		funcData = ""
		ea = funcStart
		while ea < funcEnd:
			funcData += struct.pack( "B", Byte( ea ) )
			ea += 1
		
		# get the function instructions count
		instsCount = 0
		ea = funcStart
		while ea < funcEnd:
			if DecodeInstruction( ea ):
				instsCount += 1
			ea += ARM32_INST_SIZE
		
		# calculate and add a hash
		hashObj = hashlib.sha1( funcData )
		strRepr = hashObj.hexdigest()
		if strRepr in hashes:
			print "dublicate at %x of %x, %d" % ( func,
				hashes[ strRepr ][ 0 ], instsCount )
			if not hashes[ strRepr ][ 3 ]:
				uniqueDublicates[ strRepr ] = ( func, instsCount )
				hashes[ strRepr ][ 3 ] = True
		else:
			hashes[ strRepr ] = [ func, instsCount,
				GetFunctionName( func ), False ]
	
	if len( uniqueDublicates ) > 0:
		print "\n",
	
	for dublHash in uniqueDublicates.keys():
		dublicate = uniqueDublicates[ dublHash ]
		print "%x = %d" % ( dublicate[ 0 ], dublicate[ 1 ] )
	
	pickle.dump( hashes, outputFile )

filePath = AskFile( True, "*.pic", "select an output file name:" )
if filePath:
	try:
		outputFile = open( filePath, "wb" )
		DumpFunctionsInfo( outputFile )
		outputFile.close()
	except IOError:
		pass
