import hashlib
import pickle
import struct

ARM32_INST_SIZE = 4
MIN_INSTS_COUNT = 6

def LoadFunctions( inputFile ):
	curHashes = {}
	
	# calculate hashes for functions from the current db
	for func in Functions():
		funcStart = func
		funcEnd = GetFunctionAttr( func, FUNCATTR_END )
		if not funcEnd:
			continue
		
		# get a function body
		funcData = ""
		ea = funcStart
		while ea < funcEnd:
			funcData += struct.pack( "B", Byte( ea ) )
			ea += 1
		
		# calculate and add a hash
		hashObj = hashlib.sha1( funcData )
		strRepr = hashObj.hexdigest()
		if strRepr in curHashes:
			if not curHashes[ strRepr ][ 1 ]:
				curHashes[ strRepr ][ 1 ] = True
		else:
			curHashes[ strRepr ] = [ func, False ]
	
	# search equal functions from the other db and add symbols
	symbHashes = pickle.load( inputFile )
	for funcHash in curHashes.keys():
		funcInfo = curHashes[ funcHash ]
		if funcInfo[ 1 ]: # no-unique 
			continue
		if not funcHash in symbHashes:
			continue	
		symFuncInfo = symbHashes[ funcHash ]
		if symFuncInfo[ 3 ]: # no-unique
			continue
		instsCount = symFuncInfo[ 1 ]
		symName = symFuncInfo[ 2 ]
		if symName[ : 4 ] == "sub_":
			continue
		if instsCount < MIN_INSTS_COUNT:
			continue
		func = curHashes[ funcHash ][ 0 ]
		makeStatus = MakeNameEx( func, symName, SN_NOWARN | SN_CHECK )
		printParams = ( symName, func )
		if makeStatus:
			print "name %s for %x created" % printParams
		else:
			print "can't create name %s for %x" % printParams

filePath = AskFile( False, "*.pic", "select an input file name:" )
if filePath:
	try:
		inputFile = open( filePath, "rb" )
		LoadFunctions( inputFile )
		inputFile.close()
	except IOError:
		pass
