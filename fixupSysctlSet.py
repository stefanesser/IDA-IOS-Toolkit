# This script is part of the IDA IOS Toolkit
# (C) Copyright 2011 Stefan Esser

# This script ensures that all sysctl_oid structures referenced by the
# sysctl_set segment are marked correctly. In addition to that all
# sysctl oid_handlers used get the correct function type.


import idaapi, idc, idautils


def registersysctlstructs():
	'''
	registersysctlstructs:
	
	Registers the 'sysctl_req' and 'sysctl_oid' struct types in IDA.
	'''

	strsysctl_req = """

struct sysctl_req {
	struct proc	*p;
	int         lock;
	void*       oldptr;
	size_t		oldlen;
	size_t		oldidx;
	int		    (*oldfunc)(struct sysctl_req *, const void *, size_t);
	void*       newptr;
	size_t		newlen;
	size_t		newidx;
	int		    (*newfunc)(struct sysctl_req *, void *, size_t);
};

"""
	
	strsysctl_oid = """

struct sysctl_oid {
	void *oid_parent;
	void *oid_link;
	int		oid_number;
	int		oid_kind;
	void		*oid_arg1;
	int		oid_arg2;
	const char	*oid_name;
	int 		(*oid_handler) (struct sysctl_oid *oidp, void *arg1, int arg2, struct sysctl_req *req);
	const char	*oid_fmt;
};
"""

	idc.SetLocalType(-1, strsysctl_req, 0)
	Til2Idb(-1, "sysctl_req")
	idc.SetLocalType(-1, strsysctl_oid, 0)
	Til2Idb(-1, "sysctl_oid")


def fixupSysctlSet():
	'''
	fixupSysctlSet:
	
	Fixes up the '__sysctl_set' segment, ensures the targets are actually
	'sysctl_oid' structures and adds the correct function type to the handler.
	'''
	
	segm = idaapi.get_segm_by_name("__sysctl_set")
	if not segm:
		print "Could not find __sysctl_set segment"
		return
		
	segea = segm.startEA
	segend = segm.endEA

	sid = get_struc_id("sysctl_oid")
	ssize = get_struc_size(sid)
	stru = get_struc(sid)
	if ssize == 0:
		print "Could not load information about 'sysctl_oid' struct"
		return

	# clear whole range of sysctl_set segment
	idaapi.do_unknown_range(segea, segend-segea, DOUNK_DELNAMES)

	# idapython oldschool - we work with the structure offset
	oid_handler = get_member_by_name(stru, "oid_handler")
	
	# loop through sysctl_set segment
	while segea < segend:
		# Ensure pointer is a pointer
		idaapi.op_offset(segea, 0, idaapi.REF_OFF32, 0xffffffff, 0, 0)
		ptr = idc.Dword(segea)
		
		# Mark structure as sysctl_oid structure
		idaapi.do_unknown_range(ptr, ssize, DOUNK_DELNAMES)
		x = doStruct(ptr, ssize, sid)
		handler = idc.Dword(ptr + oid_handler.soff)

		# We have to support ARM THUMB code
		addr = handler & 0xFFFFFFFE
		
		# Set correct function type for oid_handler
		idc.SetType(addr, "int *oid_handler(struct sysctl_oid *oidp, void *arg1, int arg2, struct sysctl_req *req);")

		segea += 4
            
if __name__ == '__main__':
	registersysctlstructs()
	fixupSysctlSet()
	print 'Done.'

# TODO generate names for structures