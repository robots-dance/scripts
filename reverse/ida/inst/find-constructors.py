# this script searches pseudo-contructors,
# which init some structure with function pointers
# ( and maybe other number stuff )
#

from idaapi import *

CTOR_MIN_ASSIGN_COUNT = 4

class ContinueExcept:
	pass

def main():
	offset = AskStr( "0C", "Enter offset to search" ).strip()
	allAllowed = False
	if offset == "*":
		allAllowed = True
	else:
		try:
			offset = int( offset, 16 )
		except ValueError:
			Warning( "Incorrect offset value!" )
			return
	
	ctors = []
	for func in Functions():
		funcEnd = GetFunctionAttr( func, FUNCATTR_END )
		ea = func
		initCounter = 0
		ctorAdded = False
		while ea != BADADDR:
			inst = DecodeInstruction( ea )
			
			try:
				if inst == None:
					print "can't get instruction at 0x%x" % ( ea, )
					raise ContinueExcept()
				
				if inst.itype != idaapi.NN_mov:
					raise ContinueExcept()
				
				op1Type = inst.Op1.type
				if op1Type != o_displ and op1Type != o_phrase:
					raise ContinueExcept()
				
				if op1Type == o_phrase and ( offset > 0 or not allAllowed ):
					raise ContinueExcept()
			
			except ContinueExcept:
				initCounter = 0
				ea = NextHead( ea, funcEnd )
				continue
			
			displ = 0
			if op1Type == o_displ:
				displ = GetOperandValue( ea, 0 )
			
			equatedValue = GetOperandValue( ea, 1 )
			isSubPtrAssignment = DecodeInstruction( equatedValue ) != None
			if not ctorAdded:
				if isSubPtrAssignment:
					initCounter += 1
				else:
					initCounter = 0
				
				if initCounter >= CTOR_MIN_ASSIGN_COUNT:
					ctors.append( func )
					ctorAdded = True
			
			if ( allAllowed or offset == displ ) and isSubPtrAssignment:
					print "0x%x: %s" % ( ea, GetDisasm( ea ) )
			
			ea = NextHead( ea, funcEnd )
	
	print "================\n"
	print "Constructors:\n--"
	
	for ctor in ctors:
		print "0x%x" % ctor

main()
