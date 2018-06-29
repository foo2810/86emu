# Export Table

from peBaseClass import *
from utility import *

class ImageExportDirectory(BinaryReader):
	def __init__(self, mapData, vRva, size):
		super().__init__(mapData, vRva)
		
		self.Characteristics = byteToIntLE(super().readBytes(4))
		self.TimeDataStamp = byteToIntLE(super().readBytes(4))
		self.MajorVersion = byteToIntLE(super().readBytes(2))
		self.MinorVersion = byteToIntLE(super().readBytes(2))
		self.Name = getStringFromBytePtrLE(mapData, byteToIntLE(super().readBytes(4)))
		self.NumberOfFunctions = byteToIntLE(super().readBytes(4))
		self.NumberOfNames = byteToIntLE(super().readBytes(4))
		self.AddressOfFunctions = byteToIntLE(super().readBytes(4))
		self.AddressOfNames = byteToIntLE(super().readBytes(4))
		self.AddressOfNameOrdinals = byteToIntLE(super().readBytes(4))
		
	def printAll(self):
		print("Characteristics: ", self.Characteristics)
		print("TimeDataStamp: ", self.TimeDataStamp)
		print("MajorVersion: ", self.MajorVersion)
		print("MinorVersion: ", self.MinorVersion)
		print("Name: ", self.Name)
		print("NumberOfFunctions: ", self.NumberOfFunctions)
		print("NumberOfNames: ", self.NumberOfNames)
		print("AddressOfFunctions: ", hex(self.AddressOfFunctions))
		print("AddressOfNames: ", hex(self.AddressOfNames))
		print("AddressOfNameOrdinals: ", hex(self.AddressOfNameOrdinals))
		
		
class ExportTable:
	def __init__(self, mapData, vRva, size):
		
		# For iteration
		self.i = 0
		
		self.size = size
		self.ExportTableEntries = list()
		self.numberOfEntry = 0
		
		addr = vRva
		
		self.exportDir = ImageExportDirectory(mapData, vRva, size)
	
	def printAll(self):
		print("\nExportTable(Test)")
		print("--------------------")
		self.exportDir.printAll()
		print("\n\n")
		
	def __iter__(self):
		return self
	
	def __next__(self):
		if self.i == self.numberOfEntry:
			self.i = 0
			raise StopIteration
		
		entry = self.ExportTableEntries[self.i]
		self.i += 1
		
		return entry
		