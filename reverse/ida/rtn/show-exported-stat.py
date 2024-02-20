def calculate_params_count( callAddr ):
	'''
		@note: it works for x86 only and believes, that
		every function argument transmitted to function
		by one push command
	'''
	funcStartAddr = GetFunctionAttr( callAddr, FUNCATTR_START )
	ea = PrevHead( callAddr, funcStartAddr )
	prevCallFinded = False
	paramsCount = 0
	while ea > funcStartAddr and not prevCallFinded:
		inst = DecodeInstruction( ea )
		if inst is None:
			continue
		instType = inst.itype
		isCall = idaapi.NN_call == instType or \
			idaapi.NN_callfi == instType or \
			idaapi.NN_callni == instType
		if not isCall:
			if instType >= idaapi.NN_push and instType <= idaapi.NN_pushfq:
				paramsCount += 1
		else:
			prevCallFinded = True
		ea = PrevHead( ea, funcStartAddr )
	return paramsCount

def find_indirect_calls( funcStartAddr, byRegOnly = False, \
	byMemRefOnly = False ):
	'''
	'''
	if byRegOnly and byMemRefOnly:
	# these parameters are exlusive
		return None
	result = []
	funcEndAddr = GetFunctionAttr( funcStartAddr, FUNCATTR_END )
	if funcEndAddr is None:
		return None
	ea = funcStartAddr
	while ea < funcEndAddr:
		inst = DecodeInstruction( ea )
		if inst is not None:
			instType = inst.itype
			isIndirectCall = idaapi.NN_callfi == instType or \
				idaapi.NN_callni == instType
			instOp1Type = inst.Op1.type
			
			if byRegOnly:
				isRegOper = instOp1Type == idaapi.o_reg
			else:
				isRegOper = True
			
			if byMemRefOnly:
				isMemRef = instOp1Type == idaapi.o_phrase or \
					instOp1Type == idaapi.o_displ
			else:
				isMemRef = True
			if isIndirectCall and isRegOper and isMemRef:
				result.append( ea )
		ea = NextHead( ea, funcEndAddr )
	return result

def get_mem_ref_value( instAddr ):
	return DecodeInstruction( instAddr ).Op1.addr

def iterate_locals( frame, handler ):
	'''
		@frame: a function frame
		@handler: called by this function for every argument,
			a prototype is ( isArg, argOffset, argName )
		@ret: the function arguments count
	'''
	argsCount = 0
	argsStarted = False
	memberOffset = GetFirstMember( frame )
#	lastMbrOffset = GetLastMember( frame )
	memberIndex = 0
	membersCount = GetMemberQty( frame )
	while memberIndex < membersCount:
		memberSize = None
		while memberSize == None:
			memberSize = GetMemberSize( frame, memberOffset )
			if memberSize == None:
				memberOffset += 1
		memberName = GetMemberName( frame, memberOffset )
		handler( argsStarted, memberOffset, memberName )
		if argsStarted:
			argsCount += 1
		if memberName == " r":
			argsStarted = True
		memberOffset += memberSize
		memberIndex += 1
	return argsCount

def process_frame_member( isArg, offset, name ):
	if isArg:
		print "%s: %d" % ( name, offset )

virtMethodsStat = {}
exportedCount = GetEntryPointQty()
for exportedIndex in range( 0, exportedCount ):
	exportedNum = GetEntryOrdinal( exportedIndex )
	if 0 == exportedNum or exportedNum > exportedCount:
		print "bad exported number\n"
		continue
	exportedAddr = GetEntryPoint( exportedNum )
	if -1 == exportedAddr:
		print "bad exported address\n"
		continue
	exportedName = GetEntryName( exportedNum )
	frame = GetFrame( exportedAddr )
	if frame is None:
		print "bad exported frame for: %x\n" % exportedAddr
		continue
	membersCount = GetMemberQty( frame )
	
	print "number: %d" % exportedNum
	print "addr: %x" % exportedAddr
	print "name: %s" % exportedName
	print "members: %d" % membersCount
	if membersCount > 0:
		argsCount = iterate_locals( frame, process_frame_member )
	else:
		argsCount = 0
	print "args count: %d" % argsCount
	
	calls = find_indirect_calls( exportedAddr, False, True )
	if calls is None:
		"print calls: can't iterate the function\n"
		continue
	for callIndex in range( 0, len( calls ) ):
		addr = calls[ callIndex ]
		refOffset = get_mem_ref_value( addr )
		if refOffset & 0x10000000:
			continue
		paramsCount = calculate_params_count( addr )
		if virtMethodsStat.has_key( refOffset ):
			virtMethodsStat[ refOffset ].append( paramsCount )
		else:
			virtMethodsStat[ refOffset ] = [ paramsCount ]
		print "    %x: %s; ps=%d" % ( addr, GetDisasm( addr ), paramsCount )
	print "\n",

print "\n========================\n"
print "offset | statSize | paramsCount | frequency\n"

for memberOffset in sorted( virtMethodsStat.keys() ):
	paramsStat = virtMethodsStat[ memberOffset ]
	paramsStat = sorted( paramsStat )
	
	print "%-7x %-10d" % ( memberOffset, len( paramsStat ) ),
	
	maxVal = paramsStat[ 0 ]
	maxCount = 1
	
	previousVal = maxVal
	maxCounter = 1
	
	for index in range( 1, len( paramsStat ) ):
		paramsCount = paramsStat[ index ]
		if paramsCount == previousVal:
			maxCounter += 1
		else:
			if maxCounter > maxCount:
				maxVal = previousVal
				maxCount = maxCounter
			previousVal = paramsCount
			maxCounter = 1
	if maxVal == previousVal:
		maxCount = maxCounter
	print "%-13d %d" % ( maxVal, maxCount )
