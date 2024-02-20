def GetSegment( name ):
	'''
	return a tuple with start and end addresses of
	a segment with the supplied name or False if
	it no exists
	'''
	segSel = SegByName( name )
	if BADSEL == segSel:
		return False
	segStart = SegByBase( segSel )
	segEnd = SegEnd( segStart )
	if BADADDR == segStart or BADADDR == segEnd:
		return False
	return ( segStart, segEnd )

segAddresses = GetSegment( ".text" )
if segAddresses != False:
	ea = segAddresses[ 0 ]
	end = segAddresses[ 1 ]
	counter = 0
	print "start..."
	while ea != BADADDR:
		inst = DecodeInstruction( ea )
		if inst is not None:
			ist_type = inst.itype
			isIndirectCall = idaapi.NN_callfi == ist_type or \
				idaapi.NN_callni == ist_type
			isRegOper = inst.Op1.type == idaapi.o_reg 
			if isIndirectCall and isRegOper:
				counter += 1
				print( "%d: 0x%x" % ( counter, ea ) )
		ea = NextHead( ea, end )
	print "end"
else:
	Message( "Cannot get code segment" )
