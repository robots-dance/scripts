import hashutils
import idaapi
import os.path
import pickle
import struct

class RefObjectType:
	Unknown = -1
	Code = 0
	String = 1
	Data = 2

class ErrorCode:
	CANT_READ_REPR_FILE = 1
	CANT_WRITE_REPR_FILE = 2

kReprFileName = "object-xrefs.pic"

def UpdateXrefs( xrefsInfo ):
	for entry in Entries():
		beginEa = entry[ 2 ]
		entryName = entry[ 3 ]
		
		if GetFunctionAttr( beginEa, FUNCATTR_START ) == BADADDR:
			print "data export %s is skipped\n" % entryName 
			continue
		
		endEa = GetFunctionAttr( beginEa, FUNCATTR_END )
		
		hashObj = hashutils.CalcFunctionHash( beginEa, endEa )
		funcHash = hashObj.digest()
		
		if entryName in xrefsInfo.keys() and funcHash in \
			xrefsInfo[ entryName ].keys():
		# -------- --------
			print "the %s/%s name already exists\n" % ( entryName,
				hashObj.hexdigest() )
			continue
		
		print entryName
		
		# process all potential named referencies from the current function
		curEa = beginEa
		while curEa != BADADDR:
			name = ""
			addr = 0
			for xref in XrefsFrom( curEa, 1 ):
				xrefName = Name( xref.to )
				if xrefName == "":
					continue
				
				# filter all auto-created names
				prefixes = ( "sub", "loc", "dword", "word",
					"byte", "off", "unk", "locret" )
				prefixFinded = False
				for pref in prefixes:
					if xrefName.find( pref + "_" ) == 0:
						prefixFinded = True	
						break
				if prefixFinded:
					break
				else:
					name = xrefName
					addr = xref.to
			
			if len( name ) > 0 and GetDisasm( curEa ).find( name + "+" ) == -1:
				xrefOff = curEa - beginEa
				
				# detect an object type
				objType = RefObjectType.Unknown 
				addrFlags = GetFlags( addr )
				if isCode( addrFlags ):
					objType = RefObjectType.Code
				elif isData( addrFlags ):
					objType = RefObjectType.Data
					if GetStringType( addr ) != None:
						objType = RefObjectType.String
				
				refObject = ( objType, name )
				# update the xrefs information 
				if entryName in xrefsInfo.keys():
					entries = xrefsInfo[ entryName ]
					if funcHash in entries.keys():
						entries[ funcHash ][ xrefOff ] = refObject 
					else:
						entries[ funcHash ] = { xrefOff: refObject }
				else:
					entries = { funcHash: { xrefOff: refObject } }
					xrefsInfo[ entryName ] = entries
				
				print "\t%s" % name
			
			curEa = NextHead( curEa, endEa )
		
		if not entryName in xrefsInfo.keys():
			xrefsInfo[ entryName ] = { funcHash: {} }
		else:
			if not funcHash in xrefsInfo[ entryName ].keys():
				xrefsInfo[ entryName ][ funcHash ] = {}
		print "\n",


# ===== Entry Point ====

idaapi.autoWait()

xrefsInfo = None

print "auto_script_started"

if os.path.isfile( kReprFileName ):
	# try to read a names file
	try:
		xrefsFile = open( kReprFileName, "rb" )
	except IOError:
		print "can't open an input file"
		Exit( ErrorCode.CANT_READ_REPR_FILE )			
	
	xrefsInfo = pickle.load( xrefsFile )
	xrefsFile.close()
else:
	xrefsInfo = {}	

# update names
UpdateXrefs( xrefsInfo )

# try to write the names file
try:
	xrefsFile = open( kReprFileName, "wb" )
except IOError:
	print "can't open an output file"
	Exit( ErrorCode.CANT_WRITE_REPR_FILE )

pickle.dump( xrefsInfo, xrefsFile )
xrefsFile.close()

print "auto_script_finished"

Exit( 0 )
