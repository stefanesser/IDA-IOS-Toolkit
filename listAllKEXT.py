# This script is part of the IDA IOS Toolkit
# (C) Copyright 2011 Stefan Esser

# This script searches the iOS kernelcache binary for contained kernel
# extensions. All kernel extensions found are returned with their full
# name, starting address and version number in a selection dialog.
# While searching for the KEXT files in IDA memory, all parsed mach-o
# headers are converted to the appropriate structures and all KEXT
# sections found are created inside the IDA database.


from idc import *
import idaapi
import idautils


def registerstructs():
	"""
	registerstructs:
	
	Registers all the required structures in the IDA database.
	"""
	
	Til2Idb(-1, "kmod_info")
	Til2Idb(-1, "mach_header")
	Til2Idb(-1, "load_command")
	Til2Idb(-1, "segment_command")
	Til2Idb(-1, "symtab_command")
	Til2Idb(-1, "uuid_command")
	Til2Idb(-1, "section")


class MySelectionDialog(Choose2):
	"""
	MySelectionDialog
	
	A selection dialog displaying all the KEXT found, with their
	full name, address and version number. On selection the
	cursor jumps to the mach-o header of the selected KEXT.
	"""
	def __init__(self, title, headers, items):
		Choose2.__init__(self, title, headers, 0)#Choose2.CH_MODAL)
		self.n = 0
		self.items = items
		self.icon = -1
		self.selcount = 0
		self.popup_names = []

	def OnClose(self):
		pass

	def OnEditLine(self, n):
		pass

	def OnInsertLine(self):
		pass

	def OnSelectLine(self, n):
		pass

	def OnGetLine(self, n):
		return self.items[n]

	def OnGetSize(self):
		return len(self.items)

	def OnDeleteLine(self, n):
		pass

	def OnRefresh(self, n):
		return n

	def OnCommand(self, n, cmd_id):
		pass

	def OnGetLineAttr(self, n):
		if n < 0:
			return
		if (n & 1) == 0:
			return [0xFFFFFF, 0]
		else:
			return [0xEEEEEE, 0]


def forceStruct(ea, name):
	"""
	forceStruct: ea, name
	
	Does all the necessary things to force IDA to convert the
	memory starting at address 'ea' into a struct of type 'name'.
	Returns the address after the struct.
	"""

	sid = idaapi.get_struc_id(name)
	ssize = idaapi.get_struc_size(sid)

	idaapi.do_unknown_range(ea, ssize, DOUNK_DELNAMES)
	x = idaapi.doStruct(ea, ssize, sid)
	return ea + ssize

def get_member_from_struct(ea, sname, mname):
	"""
	get_member_from_struct: ea, sname, mname
	
	Retrieves a DWORD member named 'mname' from struct 'sname'
	starting at address 'ea'.
	"""
	
	sid = idaapi.get_struc_id(sname)
	stru = idaapi.get_struc(sid)
	member = idaapi.get_member_by_name(stru, mname)
	
	# TODO check size
	return idc.Dword(ea + member.soff)


def formatKEXTresults(kextlist):
	"""
	formatKEXTresults: kextlist
	
	Converts the supplied kextlist into a format usable by the
	Choose2 dialog.
	"""
	
	strlist = []
	for k in kextlist:
		strlist.append([k["addr"],k["name"],k["version"]])
	return strlist


def formatSECTIONresults(sectionlist):
	"""
	formatSECTIONresults: sectionlist

	Converts the supplied sectionlist into a format usable by the
	Choose2 dialog.
	"""

	strlist = []
	for s in sectionlist:
		strlist.append([s["name"],s["start"],s["end"]])
	return strlist


def findAllKEXT():
	"""
	findAllKEXT:
	
	Finds all KEXT contained in the kernelcache file. The mach-o
	headers will be converted into the appropiate structs, the
	new sections will be defined and the name and version number
	of the KEXT are extracted. In the end a window is shown that
	shows all contained KEXT.
	"""
	
	# Ask the user if he wants to add all the KEXT sections
	# to the IDA database. 
	answer = idc.AskYN(0, """Do you want to add all the KEXT sections to the IDA database?
	
If this was already done before or there was already code or data in the same place in the IDA database, IDA might react very slow, crash or just stop to work.""")
	
	# KEXT cache starts behind the __LINKEDIT segment
	# NOTE: IDA calls the segment __LINKEDIT_hidden
	
	linkedit = idaapi.get_segm_by_name("__LINKEDIT_hidden")
	if not linkedit:
		print "[-] cannot find KEXTCACHE: __LINKEDIT segment not found"
		return
	kextcache = idaapi.get_next_seg(linkedit.endEA)
	if not kextcache:
		print "[-] cannot find KEXTCACHE: __LINKEDIT not followed by any segment"
		return
	
	dummyName = idaapi.get_segm_name(kextcache)
	if dummyName != "__text":
		print "[-] cannot find KEXTCACHE: __LINKEDIT not followed by __text segment"
		return
	
	if answer == 1:
		# Destroy everything in the kextcache area
		idaapi.do_unknown_range(kextcache.startEA, kextcache.endEA-kextcache.startEA, DOUNK_DELNAMES)
	
	startEA = kextcache.startEA
	kextlist = []
	while True:
		sig = idc.Dword(startEA)
		if sig != 0xfeedface:
			"[-] expected the next KEXT but did not find correct signature"
			break
		
		seg_lc = None
		
		sections = []
		added = 0
		
		next = forceStruct(startEA, "mach_header")
		ncmds = get_member_from_struct(startEA, "mach_header", "ncmds")
		for i in range(ncmds):
			lc_addr = next
			cmd = get_member_from_struct(next, "load_command", "cmd")
			if cmd == 1:
				seg_lc = next
				next = forceStruct(seg_lc, "segment_command")
				nsecs = get_member_from_struct(seg_lc, "segment_command", "nsects")
				for j in range(nsecs):
					section = next
					next = forceStruct(section, "section")
					
					# Get basic information about segment (needed for ALL the code below)
					secStart = get_member_from_struct(section, "section", "addr")
					secEnd = secStart + get_member_from_struct(section, "section", "size")
					secname = idc.GetString(section)
					
					# We should tell IDA about what this section is
					s = idaapi.segment_t()
					s.startEA	  = secStart
					s.endEA		  = secEnd
					s.sel		  = idaapi.setup_selector(0)
					if secname == "__text":
						s.bitness = 0
					else:
						s.bitness = 1
					s.align		  = get_member_from_struct(section, "section", "align")
					s.comb		  = 0 # ???
					
					if secname == "__text" or secname == "stubs":
						sclass = "CODE"
					elif secname == "__bss":
						sclass = "BSS"
					else:
						sclass = "DATA"
					
					if len(sections) == 0:
						sec = {}
						sec["name"] = "MACH-O HEADER"
						sec["start"] = "%08X" % (startEA)
						sec["end"] = "%08X" % (secStart-1)
						sections.append(sec)
					
					sec = {}
					sec["name"] = secname
					sec["start"] = "%08X" % (secStart)
					sec["end"] = "%08X" % (secEnd-1)
					sections.append(sec)
					
					if answer == 1:
						# Destroy everything inside the segment
						idaapi.do_unknown_range(secStart, secEnd-secStart, DOUNK_DELNAMES)
					
						# Ensure that the whole section is undefined
						idaapi.add_segm_ex(s, secname, sclass, idaapi.ADDSEG_NOSREG|idaapi.ADDSEG_QUIET)
					
					if secname == "__text":
						idc.SetRegEx(secStart, "T", 1, 0)

					# special handling of constructor and destructor
					if secname == "__constructor" or secname == "__destructor":
						for z in range(secStart, secEnd, 4):
							idc.OpOffEx(z, -1, REF_OFF32, 0xFFFFFFFF, 0, 0)
					
					# We have to check for __data section because we want
					# to find the kmod_info structure
					if secname != "__data":
						continue
						
					kextName = None
					for z in range(secStart, secEnd, 4):
						k = z
						# We assume that all KEXT name start with "com."
						kextNameSig = idc.Dword(k)
						if kextNameSig == 0x2e6d6f63:
							forceStruct(k-12, "kmod_info")
							kextName = idc.GetString(k)
							kextVersion = idc.GetString(k+64)
							#print "-> %s - version: %s" % (kextName, kextVersion)
							
							dic = {}
							dic["addr"] = "%08X" % (startEA)
							dic["name"] = kextName
							dic["version"] = kextVersion
							kextlist.append(dic)
							added = 1
							break
					if kextName == None:
						print "ERROR COULD NOT FIND NAME"
					
			elif cmd == 0x1b:
				next = forceStruct(lc_addr, "uuid_command")
			elif cmd == 0x2:
				next = forceStruct(lc_addr, "symtab_command")
				#print "Found symbol table KEXT at %08x" % (startEA)
			else:
				print "Unknown load command %08x" % (cmd)
			
			if added:
				kextlist[len(kextlist)-1]["sections"] = sections
			
			next = lc_addr + get_member_from_struct(lc_addr, "load_command", "cmdsize")
		
		if seg_lc == None:
			startEA += 4
			while idc.Dword(startEA) != 0xfeedface:
				startEA += 4
			continue
		
		startEA = get_member_from_struct(seg_lc, "segment_command", "vmaddr")
		startEA += get_member_from_struct(seg_lc, "segment_command", "vmsize")

	c = MySelectionDialog("Retrieved KEXT", [ ["Address", 10], [ "Name", 65 ], ["Version", 65] ], formatKEXTresults(kextlist))
	selected_row = c.Show(True)
	if selected_row >= 0:
		sel = kextlist[selected_row]
		
		c = MySelectionDialog("Sections inside " + sel["name"], [ ["Name", 16], [ "Start", 10 ], ["End", 10] ], formatSECTIONresults(sel["sections"]))
		selected_row = c.Show(True)
		if selected_row >= 0:
			sel = sel["sections"][selected_row]
			
			idc.Jump(int(sel["start"], 16))


if __name__ == '__main__':
	registerstructs()
	findAllKEXT()
	print 'Done.'

