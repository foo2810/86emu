# x86 utilities (Temporary)

from unicorn import *
from unicorn.x86_const import *
import struct

class GDTMgr(object):
	def __init__(self, mu, base, size):
		self.mu = mu
		self.baseAddr = base
		
		# Allignment
		while size % 8 == 0:
			size += 1
		size -= 1	# cf) x86 manual vol4 3.5.1
		self.size = size
		
		# Memory mapping
		mu.mem_map(base, size)
		
		# Set GDTR
		mu.reg_write(UC_X86_REG_GDTR, createGDTRVal(base, size))
		
			
	def setGDTEntry(self, entry, segSelector):
		idx = (segSelector & 0xfff8) >> 3
		self.mu.mem_write(self.baseAddr + 8 * idx, entry)
		
	
	def createGDTEntry(self, limit, base, flags):
		entry = (base & 0xff000000) >> 24
		entry <<= 16
		flags |= (limit & 0xf0000) >> 8		#((limit 0xf0000) >> 16) << 8
		entry |= flags
		entry <<= 8
		entry |= (base & 0x00ff0000) >> 16
		entry <<= 16
		entry |= (base & 0x0000ffff)
		entry <<= 16
		entry |= (limit & 0xffff)
		#print(bin(entry))
		return struct.pack("<Q", entry)
		
	
	def createGDTEntryFlgs(self, cd, ec, wr, aa,  s, dpl, p, g, avl=0, db=1):
		flags = g
		flags <<= 1
		flags |= db
		flags <<= 2
		flags |= avl
		flags <<= 5
		flags |= p
		flags <<= 2
		flags |= dpl
		flags <<= 1
		flags |= s
		flags <<= 1
		flags |= cd
		flags <<= 1
		flags |= ec
		flags <<= 1
		flags |= wr
		flags <<= 1
		flags |= aa
		
		return flags
		
		
	def createSegSelector(self, index, ti, rpl):
		if ti != 0 and ti != 1:
			raise ValueError
			
		selector = 0
			
		selector |= index
		selector <<= 1
		selector |= ti
		selector <<= 2
		selector |= rpl
		
		return selector
	

def createGDTRVal(base, size):
	return (0, base, size, 0x0)