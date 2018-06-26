#

from peBaseClass import *
from utility import *

class RelocationThunk(BinaryReader):
	def __init__(self, mapData, ptr):
		super().__init__(mapData, ptr)
		thunk = byteToIntLE(super().readBytes(2))
		self.type = (thunk & 0xf000) >> (4 * 3)
		self.offset = thunk & 0x0fff
	
	def printAll(self):
		print("[Relocation Thunk]")
		print("Type: ", self.type)
		print("Offset: ", self.offset)

class ImageBaseRelocation(BinaryReader):
	def __init__(self, mapData, ptr):
		super().__init__(mapData, ptr)
		self.VirtualAddress = byteToIntLE(super().readBytes(4))
		self.SizeOfBlock = byteToIntLE(super().readBytes(4))
		
		self.thunks = list()
		self.numberOfThunk = int((self.SizeOfBlock - 8) / 2)
		
		for i in range(self.numberOfThunk):
			thunk = RelocationThunk(mapData, super().getCurrentPosition())
			self.thunks.append(thunk)
		
		super().shiftPtr(self.numberOfThunk * 2)
	
	def printAll(self):
		print("[ImageBaseRelocation]")
		print("VirtualAddress: ", self.VirtualAddress)
		print("SizeOfBlock: ", self.SizeOfBlock)
		print("Number of Thunk: ", self.numberOfThunk)
		"""
		for thunk in self.thunks:
			thunk.printAll()
		"""
		
class RelocationTable(BinaryReader):
	def __init__(self, mapData, ptr, size):
		super().__init__(mapData, ptr)
		
		# For iteration
		self.i = 0
		self.baseRelocations = list()
		self.size = size
		self.numberOfEntry = 0
		
		if size != 0:
			addr = ptr
			thunk = ImageBaseRelocation(mapData, addr)
			self.baseRelocations.append(thunk)
			self.numberOfEntry += 1
			readSize = 0
			while readSize < size:
				thunk = ImageBaseRelocation(mapData, addr)
				self.baseRelocations.append(thunk)
				addr = thunk.getEndOffset() + 1
				readSize += thunk.getSize()
				self.numberOfEntry += 1
	
	def printAll(self):
		print("[RelocationTable]")
		for item in self.baseRelocations:
			item.printAll()
				
	def __iter__(self):
		return self
		
	def __next__(self):
		if self.i == self.numberOfEntry:
			self.i = 0
			raise StopIteration
		
		item = self.baseRelocations[self.i]
		self.i += 1
		
		return item