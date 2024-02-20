import os
import pefile
import sys

USAGE_ERR = 1
FILE1_NO_EXISTS = 2
FILE2_NO_EXISTS = 3
BAD_PE_FILE = 4
SECTION_NO_FINDED = 5

def SearchSectionByName( peImage, sctName ):
	"""
	return a section index if finded or -1 otherwise
	"""
	finded = False
	sctIndex = 0
	for section in peImage.sections:
		curSctName = section.Name.replace( '\0', '' )
		if curSctName == sctName:
			finded = True
			break
		sctIndex += 1
	if not finded:
		sctIndex = -1
	return sctIndex

USAGE = "compare-sections.py <file1> <file2> <section-name>"
argsCount = len( sys.argv )
if argsCount < 4:
	print USAGE
	sys.exit( USAGE_ERR )

# check input arguments
file1Path = sys.argv[ 1 ]
file2Path = sys.argv[ 2 ]
sectionName = sys.argv[ 3 ]
if not os.path.isfile( file1Path ):
	print "file1 no exists"
	sys.exit( FILE1_NO_EXISTS )
if not os.path.isfile( file2Path ):
	print "file2 no exists"
	sys.exit( FILE2_NO_EXISTS )

# open pe files
peFile1 = None
peFile2 = None
try:
	peFile1 = pefile.PE( file1Path )
	peFile2 = pefile.PE( file2Path )
except:
	errorInfo = "file1" if not peFile1 else "file2"
	print "can't open " + errorInfo + " as a pe file"
	sys.exit( BAD_PE_FILE )

# search sections
file1SctIndex = SearchSectionByName( peFile1, sectionName )
if file1SctIndex >= 0:
	file2SctIndex = SearchSectionByName( peFile2, sectionName )
if file1SctIndex == -1 or file2SctIndex == -1:
	errorInfo = "file1" if file1SctIndex == -1 else "file2"
	print "can't find the specified section in " + errorInfo
	sys.exit( SECTION_NO_FINDED )

# get sections
file1Sct = peFile1.sections[ file1SctIndex ]
file2Sct = peFile2.sections[ file2SctIndex ]

# get addresses of the sections
file1SctAddr = file1Sct.VirtualAddress
file2SctAddr = file2Sct.VirtualAddress

# extract data from the sections
file1SctData = peFile1.get_memory_mapped_image()[ file1SctAddr: \
	file1SctAddr + file1Sct.Misc_VirtualSize ]
file2SctData = peFile2.get_memory_mapped_image()[ file2SctAddr: \
	file2SctAddr + file2Sct.Misc_VirtualSize ]

if file1SctData != file2SctData:
	print "sections are different"
else:
	print "sections are equal"
