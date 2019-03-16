# Relocation Table

# イメージのロードの際、オプショナルヘッダーのImageBaseが指すアドレスにロードできなかった場合、
# このベース再配置テーブルを利用して、アドレスの再配置を行う

from peBaseClass import *
from peConstants import *
from utility import *

class RelocationTarget(BinaryReader):
	def __init__(self, mapData, ptr):
		super().__init__(mapData, ptr)
		thunk = byteToIntLE(super().readBytes(2))
		self.type = (thunk & 0xf000) >> (4 * 3)
		self.offset = thunk & 0x0fff
		self.typeText = ""
		if self.type == IMAGE_REL_BASED_ABSOLUTE:
			self.typeText = "ABSOLUTE"
		elif self.type == IMAGE_REL_BASED_HIGHLOW:
			self.typeText = "HIGHLOW"
		else:
			self.typeText = "Other type"
	
	def printAll(self):
		print("[Relocation Target]")
		print("Type: ", self.typeText)
		print("Offset: ", self.offset)

class ImageBaseRelocation(BinaryReader):
	def __init__(self, mapData, ptr):
		super().__init__(mapData, ptr)
		self.VirtualAddress = byteToIntLE(super().readBytes(4))
		self.SizeOfBlock = byteToIntLE(super().readBytes(4))
		
		self.thunks = list()
		self.numberOfThunk = int((self.SizeOfBlock - 8) / 2)
		
		ptr = super().getCurrentPosition()
		for i in range(self.numberOfThunk):
			thunk = RelocationTarget(mapData, ptr)
			self.thunks.append(thunk)
			ptr += 2
		
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
		
class RelocationTable:
	def __init__(self, mapData, ptr, size):
		
		# For iteration
		self.i = 0
		self.baseRelocations = list()
		self.size = size
		self.numberOfEntry = 0
		
		if size != 0:
			addr = ptr
			thunk = ImageBaseRelocation(mapData, addr)
			
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