# This script is part of the IDA IOS Toolkit
# (C) Copyright 2011 Stefan Esser

# This script searches the iOS syscall table within the iOS kernelcache 
# without relying on symbols because Apple loves to either remove them 
# or to move them around


from idaapi import *
from idc import *
import idautils
import re


def parsesyscallsmaster(filename):
	'''
	parsesyscallsmaster: filename
	
	Parses the syscalls.master file to retrieve names and arguments 
	for syscalls.
	'''
	
	syscallinfo = {}
	
	syscalldef_re = re.compile('(?P<num>[0-9]+)\s+([a-zA-Z0-9_]+)\s+([a-zA-Z0-9_]+)\s+\{\s+([a-zA-Z0-9_]+)\s+([a-zA-Z0-9_]+)\s*\(([^)]+)\)')
	
	try:
		with open(filename) as f:
			for line in f:
				m = syscalldef_re.match(line)
				if m:
					num = int(m.group(1))
					name = m.group(5)
					params = m.group(6)
					if not syscallinfo.has_key(num):
						syscallinfo[num] = { "name" : name, "params" : params }
					else:
						# Overwrite if not nosys
						if name != "nosys":
							syscallinfo[num] = { "name" : name, "params" : params }
	except IOError, err:
		pass

	return syscallinfo
	

def registersysentstruct():
	'''
	registersysentstruct:
	
	Registers the 'sysent' struct type in IDA.
	'''

	strsysent = """

struct sysent {
	unsigned short sy_narg;
	unsigned char sy_resv;
	unsigned char sy_flags;
	void (*sy_call)();
	void (*sy_arg_munge32)();
	void (*sy_arg_munge64)();
	unsigned int sy_return_types;
	unsigned short sy_arg_bytes;
};

"""
	r = idc.SetLocalType(-1, strsysent, 0)
	r = Til2Idb(-1, "sysent")
	

def findsyscalltable(syscallinfo):
	'''
	findsyscalltable: syscallinfo
	
	Searches for the syscall table inside the iOS kernel
	binary. Search is performed inside the __data segment
	and syscall table is recognized by a combination of
	a pattern match for the first syscall handler and the
	assumption that the syscall table is immediately 
	followed by the nsysent variable that contains the
	number of syscall handlers.
	'''
	
	# retrieve information about 'sysent' struct
	sid = get_struc_id("sysent")
	ssize = get_struc_size(sid)
	if ssize == 0:
		print "Could not load information about 'sysent' struct"
		return
	
	# text segment
	textsegment = get_segm_by_name("__text")
	if not textsegment:
		print "Could not find __text segment"
		return
		
	# syscall table is assumed to be found in section ''
	syscalltablesegment = get_segm_by_name("__data")
	if not syscalltablesegment:
		print "Could not find segment __data"
		return

	curEA = syscalltablesegment.startEA
	endEA = syscalltablesegment.endEA
	
	while curEA < endEA:	
		
		# signature of first syscall entry
		#
		# 0x00000000
		# handler
		# 0x00000000
		# 0x00000000
		# 0x00000001
		# 0x00000000
		
		curEA += 4
		
		if idc.Dword(curEA) != 0:
			continue
		handler = idc.Dword(curEA+4)
		if handler < textsegment.startEA:
			continue
		if handler > textsegment.endEA:
			continue
		if idc.Dword(curEA+8) != 0:
			continue
		if idc.Dword(curEA+12) != 0:
			continue
		if idc.Dword(curEA+16) != 1:
			continue
		if idc.Dword(curEA+20) != 0:
			continue
			
		# Passed signature of syscall handler 0
		# now check if we can find the end
		
		# Assume a syscall table longer than 32 entries
		cnt = 31
		innerEA = curEA + 31 * ssize	
				
		while innerEA < endEA:
			innerEA += ssize
			cnt += 1
			# Assume less than 700 syscalls for now
			if cnt > 700:
				break
				
			nsys = idc.Dword(innerEA)
			if nsys == cnt:
				# Found end of syscall table
				
				# mark nsysent variable
				idc.MakeDword(innerEA)
				idaapi.set_name(innerEA, "_nsysent", 0)
				
				# mark syscall table as an array of struct 'sysent' 
				idaapi.do_unknown_range(curEA, ssize * nsys, DOUNK_DELNAMES)
				idaapi.set_name(curEA, "_sysent", 0)
				idaapi.doStruct(curEA, ssize, sid)
				idc.MakeArray(curEA, nsys)
				idc.SetArrayFormat(curEA, AP_INDEX | AP_IDXDEC, 1, -1)
				
				# loop through all syscall handlers and set functype
				i = 0
				ht = {}
				while i < nsys:
					handler = idc.Dword(curEA + ssize * i + 4)
					
					# We have to support ARM THUMB code
					addr = handler & 0xFFFFFFFE
					
					if syscallinfo.has_key(i):
						si = syscallinfo[i]
					
						# check for name collision
						if not ht.has_key(handler):
							ht[handler] = si["name"]
							
							# set name of syscall
							idaapi.set_name(addr, "_" + si["name"])
							
						if si["params"] == "void":
							typestring = "void"
						else:
							typestring = "struct %s_args" % (si["name"])
							params = si["params"].replace(",", ";")
							print typestring + "{" + params + ";};"
							r = idc.SetLocalType(-1, typestring + "{" + params + ";};", 0)
							Til2Idb(-1, "%s_args" % (si["name"]))
						
						functype = "int xxx(proc_t p, %s *uap, int *retval);" % (typestring)
						r = idc.SetType(addr, functype)
					i = i + 1
				
				# notify user
				print "Found syscall table _sysent at %08x" % (curEA)
				print "Number of entries in syscall table _nsysent = %u" % (nsys)
				print "Syscall number count _nsysent is at %08x" % (innerEA)
				idc.Jump(curEA)
				return


if __name__ == '__main__':
	registersysentstruct()
	fname = idc.AskFile(0, "syscalls.master", "Find /bsd/kern/syscalls.master from XNU source code")
	syscallinfo = parsesyscallsmaster(fname)
	findsyscalltable(syscallinfo)
	print "Done."

# TODO: fix problems with unknown types
