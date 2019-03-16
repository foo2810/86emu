# Export Table

from peBaseClass import *
from utility import *

# アドレスのサイズが64bitの場合と32bitの場合があるのか？
# おそらくある.　しかしまだ未対応!

class ExportAddressTable(BinaryReader):
	def __init__(self, mapData, vRva, num):
		super().__init__(mapData, vRva)
		
		self.i = 0
		
		self.addrs = list()
		self.numberOfEntry = num
		
		for i in range(num):
			ptr = byteToIntLE(super().readBytes(4))	# アドレスサイズ不明
			self.addrs.append(ptr)
		
	def __iter__(self):
		return self
	
	def __next__(self):
		if self.i == self.numberOfEntry:
			self.i = 0
			raise StopIteration
		
		entry = self.addrs[self.i]
		self.i += 1
		
		return entry
		
	def __getitem__(self, j):
		return self.addrs[j]

class ExportNameTable(BinaryReader):
	def __init__(self, mapData, vRva, num):
		super().__init__(mapData, vRva)
		self.i = 0
		
		self.names = list()
		self.numberOfEntry = num
		
		for i in range(num):
			ptr = byteToIntLE(super().readBytes(4))
			name = getStringFromBytePtrLE(self.rawData, ptr)
			self.names.append(name)
	
	def getSize(self):
		return self.numberOfEntry
	
	def __iter__(self):
		return self
	
	def __next__(self):
		if self.i == self.numberOfEntry:
			self.i = 0
			raise StopIteration
		
		entry = self.names[self.i]
		self.i += 1
		
		return entry
	
	def __getitem__(self, j):
		return self.names[j]

# 名前テーブルと序数テーブルは1対1に対応している
# 例えば、"A"という名前のシンボルを名前テーブルから探し、それと同じインデックスで序数テーブルにアクセスすると、
# エクスポートアドレステーブル上の対応するインデックスがある？
class ExportNamesOrdinalsTable(BinaryReader):
	def __init__(self, mapData, vRva, num):
		super().__init__(mapData, vRva)
		
		self.i = 0
		
		self.namesOrdinals = list()
		self.numberOfEntry = num
		
		for i in range(num):
			n = byteToIntLE(super().readBytes(2))
			#name = getStringFromBytePtrLE(self.rawData, ptr)
			self.namesOrdinals.append(n)
		
	def __iter__(self):
		return self
	
	def __next__(self):
		if self.i == self.numberOfEntry:
			self.i = 0
			raise StopIteration
		
		entry = self.namesOrdinals[self.i]
		self.i += 1
		
		return entry
	
	def __getitem__(self, j):
		return self.namesOrdinals[j]
			
class ImageExportDirectory(BinaryReader):
	def __init__(self, mapData, vRva, size):
		super().__init__(mapData, vRva)
		
		self.Characteristics = byteToIntLE(super().readBytes(4))
		self.TimeDataStamp = byteToIntLE(super().readBytes(4))
		self.MajorVersion = byteToIntLE(super().readBytes(2))
		self.MinorVersion = byteToIntLE(super().readBytes(2))
		self.Name = getStringFromBytePtrLE(mapData, byteToIntLE(super().readBytes(4)))
		self.Base = byteToIntLE(super().readBytes(4))
		self.NumberOfFunctions = byteToIntLE(super().readBytes(4))
		self.NumberOfNames = byteToIntLE(super().readBytes(4))
		self.AddressOfFunctions = byteToIntLE(super().readBytes(4))
		self.AddressOfNames = byteToIntLE(super().readBytes(4))
		self.AddressOfNameOrdinals = byteToIntLE(super().readBytes(4))
		
		#print("vRva + size = {}".format(vRva + size))
		#print("End offset = {}".format(self.getEndOffset()))
		super().moveTo(vRva + size)
		
	def printAll(self):
		print("Characteristics: ", self.Characteristics)
		print("TimeDataStamp: ", self.TimeDataStamp)
		print("MajorVersion: ", self.MajorVersion)
		print("MinorVersion: ", self.MinorVersion)
		print("Name: ", self.Name)
		print("Base: ",  self.Base)
		print("NumberOfFunctions: ", self.NumberOfFunctions)
		print("NumberOfNames: ", self.NumberOfNames)
		print("AddressOfFunctions: ", hex(self.AddressOfFunctions))
		print("AddressOfNames: ", hex(self.AddressOfNames))
		print("AddressOfNameOrdinals: ", hex(self.AddressOfNameOrdinals))
		
		
class ExportTable:
	def __init__(self, mapData, vRva, size):
		
		# For iteration
		self.i = 0
		
		self.mapData = mapData
		self.selfOffset = vRva
		self.size = size
		#self.ExportTableEntries = list()
		
		
		#addr = vRva
		
		self.exportDir = ImageExportDirectory(mapData, vRva, size)
		self.exportAddressTable = ExportAddressTable(mapData, self.exportDir.AddressOfFunctions, self.exportDir.NumberOfFunctions)
		self.exportNameTable = ExportNameTable(mapData, self.exportDir.AddressOfNames, self.exportDir.NumberOfNames)
		self.exportNameOrdinalTable = ExportNamesOrdinalsTable(mapData, self.exportDir.AddressOfNameOrdinals, self.exportDir.NumberOfNames)
		
		self.numberOfEntry = self.exportDir.NumberOfNames
	
	def getAddressByName(self, name):
		ord = None
		for idx in range(self.numberOfEntry):
			if self.exportNameTable[idx] == name:
				ord = self.exportNameOrdinalTable[idx]
				break
		if ord is None:
			return None
			
		return self.exportAddressTable[ord]
	
	def isExported(self, addr):
		return addr >= self.selfOffset and addr < self.selfOffset + self.size
		#return addr >= self.getStartOffset() and addr < self.getStartOffset() + self.size
		
	def getExportName(self, addr):
		return getStringFromBytePtrLE(self.mapData, addr)
		
	def __iter__(self):
		return self
	
	def __next__(self):
		if self.i == self.numberOfEntry:
			self.i = 0
			raise StopIteration
		
		entry = (self.exportNameOrdinalTable[self.i], self.exportNameTable[self.i])
		self.i += 1
		
		return entry
	
	def printAll(self):
		print("\nExportTable")
		print("-" * 35)
		self.exportDir.printAll()
		
		print("-" * 25)
		print("Ordinal\t\tVRVA\t\tName")
		for ord, name in zip(self.exportNameOrdinalTable, self.exportNameTable):
			addr = self.exportAddressTable[ord]
			print("%7d\t\t0x%x\t\t%s" % (ord, addr, name), end="")
			if self.isExported(addr):
				print("(Exported to {})".format(self.getExportName(addr)))
			else:
				print("")
		
		print("\n\n")
		