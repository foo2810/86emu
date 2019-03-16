# Import Table

from peBaseClass import *
from utility import *

class ImageImportByName(BinaryReader):
	def __init__(self, mapData, ptr):
		super().__init__(mapData, ptr)
		self.Hint = byteToIntLE(super().readBytes(2))
		self.Name = getStringFromBytePtrLE(mapData, super().getCurrentPosition())
		super().shiftPtr(len(self.Name) + 1)
	
	def printAll(self):
		print("[ImageImportByName]")
		print("Hint: ", self.Hint)
		print("Name(", hex(super().getStartOffset()), "): ", self.Name)

class ImageThunkData32(BinaryReader):
	def __init__(self, mapData, ptr):
		IMAGE_ORDINAL_FLAG32 = 0x80000000
		
		super().__init__(mapData, ptr)
		self.Union = super().readBytes(4)
		var = byteToIntLE(self.Union)
		if var & IMAGE_ORDINAL_FLAG32 != 0:
			self.Ordinal = var & 0xffff
		else:
			self.Ordinal = None
		
		self.ForwarderString = getStringFromBytePtrLE(mapData, var)
		self.Function = var
		self.AddressOfData = ImageImportByName(mapData, var)
	
	def getHeadPtr(self):
		return super().getStartOffset()
		
	def getRva(self):
		return super().getStartOffset()
	
	def printAll(self):
		print("[ImageThunkData32]  RVA: ", hex(super().getStartOffset()))
		print("Union: ", self.Union)
		
		print("ForwarderString: ", self.ForwarderString)
		print("Function: ", hex(self.Function))
		print("Ordinal: ", self.Ordinal)
		self.AddressOfData.printAll()
		
		print("-" * 25)

class ImageThunkData64(BinaryReader):
	def __init__(self, mapData, ptr):
		IMAGE_ORDINAL_FLAG64 = 0x8000000000000000

		super().__init__(mapData, ptr)
		
		self.Union = super().readBytes(8)
		var = byteToIntLE(self.Union)
		if var & IMAGE_ORDINAL_FLAG64 != 0:
			self.Ordinal = var & 0xffff
		else:
			self.Ordinal = None
		
		self.ForwarderString = getStringFromBytePtrLE(mapData, var)
		self.Function = var
		self.AddressOfData = ImageImportByName(mapData, var)
	
	def printAll(self):
		print("[ImageThunkData64]")
		print("Union: ", self.Union)
		print("ForwarderString: ", self.ForwarderString)
		print("Function: ", hex(self.Function))
		self.AddressOfData.printAll()
		
		print("-" * 25)

class ImageImportDescriptor(BinaryReader):
	# 20 bytes
	
	def __init__(self, mapData, ptr, magic):
		super().__init__(mapData, ptr)
		
		# For iteration
		self.i = 0
		
		self.Union = byteToIntLE(super().readBytes(4))
		self.TimeDataStamp = byteToIntLE(super().readBytes(4))
		self.ForwarderChain = super().readBytes(4)
		
		self.nameRVA = byteToIntLE(super().readBytes(4))
		self.Name = getStringFromBytePtrLE(mapData, self.nameRVA)
		
		firstThunkRVA = byteToIntLE(super().readBytes(4))
		addr = firstThunkRVA
		self.numberOfEntry = 0
		self.FirstThunk = list()
		if magic == 32:
			step = 4
			thunk = ImageThunkData32(mapData, addr)
			while byteToIntLE(thunk.Union) != 0:
				self.numberOfEntry += 1
				self.FirstThunk.append(thunk)
				addr += step
				thunk = ImageThunkData32(mapData, addr)
			
		elif magic == 64:
			step = 8
			thunk = ImageThunkData64(mapData, addr)
			while byteToIntLE(thunk.Union) != 0:
				self.numberOfEntry += 1
				self.FirstThunk.append(thunk)
				addr += step
				thunk = ImageThunkData64(mapData, addr)
			
		else:
			print("Unknown magic")
			raise Exception
		
	
	def getThunks(self):
		return self.FirstThunk
	
	def __iter__(self):
		return self
	
	def __next__(self):
		if self.i == self.numberOfEntry:
			self.i = 0
			raise StopIteration
		
		entry = self.FirstThunk[self.i]
		self.i += 1
		
		return entry
		
	
	def printAll(self, flg):
		print("[ImageImportDescriptor]")
		print("Union: ", self.Union)
		print("TimeDataStamp: ", self.TimeDataStamp)
		print("ForwarderChain: ", self.ForwarderChain)
		print("Name(", hex(self.nameRVA), "): ", self.Name)
		#print("Thunks: (Ellipsis)")
		print("Thunks:")
		
		if flg == 1:
			for thunk in self.FirstThunk:
				thunk.printAll()
			
		print("-" * 20)
		
	
class ImportTable:
	ImportDescriptorSize = 20
	def __init__(self, mapData, vRva, size, magic):
		#super().__init__(mapData, vRva)
		
		# For iteration
		self.i = 0
		
		self.size = size
		self.ImportTableEntries = list()
		self.numberOfEntry = 0
		
		addr = vRva
		entry = ImageImportDescriptor(mapData, addr, magic)
		while entry.Union != 0:
			self.numberOfEntry += 1
			self.ImportTableEntries.append(entry)
			addr += ImportTable.ImportDescriptorSize
			entry = ImageImportDescriptor(mapData, addr, magic)
	
	def printAll(self, flg):
		print("[ImportTable]")
		for i in range(len(self.ImportTableEntries)):
			self.ImportTableEntries[i].printAll(flg)
	
	def __iter__(self):
		return self
	
	def __next__(self):
		if self.i == self.numberOfEntry:
			self.i = 0
			raise StopIteration
		
		entry = self.ImportTableEntries[self.i]
		self.i += 1
		
		return entry
		
