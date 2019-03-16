# PE Header

from array import array
from peBaseClass import *
from utility import *

# BYTE: 8bits unsigned
# WORD: 16bits unsigned
# DWORD: 32bits unsigned
# LONG: 32bits signed


class ROMImage(Exception):
	description = "This PE format file is ROM image"
	def __init__(self, info=""):
		import sys
		print(ROMImage.description + " - " + info, file=sys.stderr)

class UnknownMagic(Exception):
	def __init__(self, desc):	
		super().__init__(desc)

class MSDOSHeader(BinaryReader):
	# 64bytes
	def __init__(self, bData):
		super().__init__(bData, 0)
		
		self.e_magic = super().readBytes(2)
		self.e_cblp = byteToIntLE(super().readBytes(2))
		self.e_cp = byteToIntLE(super().readBytes(2))
		self.e_crlc = byteToIntLE(super().readBytes(2))
		self.e_cparhdr = byteToIntLE(super().readBytes(2))
		self.e_minalloc = byteToIntLE(super().readBytes(2))
		self.e_maxalloc = byteToIntLE(super().readBytes(2))
		self.e_ss = byteToIntLE(super().readBytes(2))
		self.e_sp = byteToIntLE(super().readBytes(2))
		self.e_csum = byteToIntLE(super().readBytes(2))
		self.e_ip = byteToIntLE(super().readBytes(2))
		self.e_cs = byteToIntLE(super().readBytes(2))
		self.e_lfarlc = byteToIntLE(super().readBytes(2))
		self.e_ovno = byteToIntLE(super().readBytes(2))
		self.e_res = array("I", range(4))
		super().shiftPtr(2 * 4)	# 2bytes * 4
		self.e_oemid = byteToIntLE(super().readBytes(2))
		self.e_oeminfo = byteToIntLE(super().readBytes(2))
		self.e_res2 = array("I", range(10))
		super().shiftPtr(2 * 10)
		self.e_lfanew = byteToIntLE(super().readBytes(4))
		

	def printAll(self):
		print("[MSDOSHeader]")
		print("e_magic: ", self.e_magic)
		print("e_cblp: ", self.e_cblp)
		print("e_cp: ", self.e_cp)
		print("e_crlc: ", self.e_crlc)
		print("e_cparhdr: ", self.e_cparhdr)
		print("e_minalloc: ", self.e_minalloc)
		print("e_ss: ", self.e_ss)
		print("e_sp: ", self.e_sp)
		print("e_csum: ", self.e_csum)
		print("e_ip: ", self.e_ip)
		print("e_cs: ", self.e_cs)
		print("e_lfarlc: ", self.e_lfarlc)
		print("e_ovno: ", self.e_ovno)
		print("e_res: ", self.e_res)
		print("e_oemid: ", self.e_oemid)
		print("e_oeminfo: ", self.e_oeminfo)
		print("e_res2: ", self.e_res2)
		print("e_lfanew: ", self.e_lfanew)
		
		print("-" * 50)

class ImageFileHeader(BinaryReader):
	# 22bytes
	
	def __init__(self, bData, ptr):
		super().__init__(bData, ptr)
		
		self.Machine = super().readBytes(2)
		self.NumberOfSections = byteToIntLE(super().readBytes(2))
		self.TimeDataStamp = byteToIntLE(super().readBytes(4))
		self.PointerToSymbolTable = byteToIntLE(super().readBytes(4))
		self.NumberOfSymbols = byteToIntLE(super().readBytes(4))
		self.SizeOfOptionalHeader = byteToIntLE(super().readBytes(2))
		self.Characteristics = byteToIntLE(super().readBytes(2))
		
	def printAll(self):
		print("[ImageFileHeader]")
		print("Machine: ", self.Machine)
		print("NumberOfSections: ", self.NumberOfSections)
		print("TimeDataStamp: ", self.TimeDataStamp)
		print("PointerToSymbolTable: ", self.PointerToSymbolTable)
		print("NumberOfSymbols: ", self.NumberOfSymbols)
		print("SizeOfOptionalHeader: ", self.SizeOfOptionalHeader)
		print("Characteristics: ", hex(self.Characteristics))
		
		print("-" * 30)

class ImageDataDirectoryEntry:
	def __init__(self, vAddr, size):
		self.VirtualAddress = vAddr
		self.Size = size
		
class ImageOptionalHeader32(BinaryReader):
	# 96bytes
	
	def __init__(self, bData, ptr):
		super().__init__(bData, ptr)
		
		self.Magic = super().readBytes(2)
		self.MajorLinkerVersion = byteToIntLE(super().readBytes(1))
		self.MinorLinkerVersion = byteToIntLE(super().readBytes(1))
		self.SizeOfCode = byteToIntLE(super().readBytes(4))
		self.SizeOfInitializedData = byteToIntLE(super().readBytes(4))
		self.SizeOfUninitializedData = byteToIntLE(super().readBytes(4))
		self.AddressOfEntryPoint = byteToIntLE(super().readBytes(4))
		self.BaseOfCode = byteToIntLE(super().readBytes(4))
		self.BaseOfData = byteToIntLE(super().readBytes(4))
		
		self.ImageBase = byteToIntLE(super().readBytes(4))
		self.SectionAlignment = byteToIntLE(super().readBytes(4))
		self.FileAlignment = byteToIntLE(super().readBytes(4))
		self.MajorOperatingSystemVersion = byteToIntLE(super().readBytes(2))
		self.MinorOperatingSystemVersion = byteToIntLE(super().readBytes(2))
		self.MajorImageVersion = byteToIntLE(super().readBytes(2))
		self.MinorImageVersion = byteToIntLE(super().readBytes(2))
		self.MajorSubsystemVersion = byteToIntLE(super().readBytes(2))
		self.MinorSubsystemVersion = byteToIntLE(super().readBytes(2))
		self.Win32VersionValue = byteToIntLE(super().readBytes(4))
		self.SizeOfImage = byteToIntLE(super().readBytes(4))
		self.SizeOfHeaders = byteToIntLE(super().readBytes(4))
		self.CheckSum = byteToIntLE(super().readBytes(4))
		self.Subsystem = byteToIntLE(super().readBytes(2))
		self.DllCharacteristics = byteToIntLE(super().readBytes(2))
		self.SizeOfStackReserve = byteToIntLE(super().readBytes(4))
		self.SizeOfStackCommit = byteToIntLE(super().readBytes(4))
		self.SizeOfHeapReserve = byteToIntLE(super().readBytes(4))
		self.SizeOfHeapCommit = byteToIntLE(super().readBytes(4))
		self.LoaderFlags = byteToIntLE(super().readBytes(4))
		self.NumberOfRvaAndSizes = byteToIntLE(super().readBytes(4))
		
		self.DataDirectory = list()    #array("L", range(self.NumberOfRvaAndSizes))
		for i in range(self.NumberOfRvaAndSizes):
			vAddr = byteToIntLE(super().readBytes(4))
			size = byteToIntLE(super().readBytes(4))
			dataDirectoryEntry = ImageDataDirectoryEntry(vAddr, size)
			self.DataDirectory.append(dataDirectoryEntry)
			
		#super().shiftPtr(self.NumberOfRvaAndSizes)
		#super().shiftPtr(4 * self.NumberOfRvaAndSizes)
		
	def printAll(self):
		print("[ImageOptionalHeader32]")
		print("Magic: ", self.Magic)
		print("MajorLinkerVersion: ", self.MajorLinkerVersion)
		print("MinorLinkerVersion: ", self.MinorLinkerVersion)
		print("SizeOfCode: " + hex(self.SizeOfCode), "(", (self.SizeOfCode), ")")
		print("SizeOfInitializedData: " + hex(self.SizeOfInitializedData), "(", (self.SizeOfInitializedData), ")")
		print("SizeOfUninitializedData: " + hex(self.SizeOfUninitializedData), "(", (self.SizeOfUninitializedData), ")")
		print("AddressOfEntryPoint: ", self.AddressOfEntryPoint, "(", hex(self.AddressOfEntryPoint), ")")
		print("BaseOfCode: ", self.BaseOfCode)
		print("BaseOfData: ", self.BaseOfData)
		
		print("ImageBase: ", hex(self.ImageBase))
		print("SectionAlignment: ", hex(self.SectionAlignment))
		print("FileAlignment: ", hex(self.FileAlignment))
		print("MajorOperatingSystemVersion: ", self.MajorOperatingSystemVersion)
		print("MinorOperatingSystemVersion: ", self.MinorOperatingSystemVersion)
		print("MajorImageVersion: ", self.MajorImageVersion)
		print("MinorImageVersion: ", self.MinorImageVersion)
		print("MajorSubsystemVersion: ", self.MajorSubsystemVersion)
		print("MinorSubsystemVersion: ", self.MinorSubsystemVersion)
		print("Win32VersionValue: ", self.Win32VersionValue)
		print("SizeOfImage: ", hex(self.SizeOfImage))
		print("SizeOfHeaders: ", hex(self.SizeOfHeaders))
		print("CheckSum: ", self.CheckSum)
		print("Subsystem: ", self.Subsystem)
		print("DllCharacteristics: ", self.DllCharacteristics)
		print("SizeOfStackReserve: ", self.SizeOfStackReserve)
		print("SizeOfStackCommit: ", self.SizeOfStackCommit)
		print("SizeOfHeapReserve: ", self.SizeOfHeapReserve)
		print("SizeOfHeapCommit: ", self.SizeOfHeapCommit)
		print("LoaderFlags: ", self.LoaderFlags)
		print("NumberOfRvaAndSizes: ", self.NumberOfRvaAndSizes)
		print("DataDirectory: DATADIRECTORY_DUMMY")
		
		for i in range(self.NumberOfRvaAndSizes):
			print("%d:" % i)
			print("\tVirtualAddress:", hex(self.DataDirectory[i].VirtualAddress))
			print("\tSize:", self.DataDirectory[i].Size)
		
		print("-" * 30)

class ImageOptionalHeader64(BinaryReader):
	# 96bytes
	
	def __init__(self, bData, ptr):
		super().__init__(bData, ptr)
		
		self.Magic = super().readBytes(2)
		self.MajorLinkerVersion = byteToIntLE(super().readBytes(1))
		self.MinorLinkerVersion = byteToIntLE(super().readBytes(1))
		self.SizeOfCode = byteToIntLE(super().readBytes(4))
		self.SizeOfInitializedData = byteToIntLE(super().readBytes(4))
		self.SizeOfUninitializedData = byteToIntLE(super().readBytes(4))
		self.AddressOfEntryPoint = byteToIntLE(super().readBytes(4))
		self.BaseOfCode = byteToIntLE(super().readBytes(4))
		#self.BaseOfData = byteToIntLE(super().readBytes(4))		# In 64bit PE format, there is not this item
		
		self.ImageBase = byteToIntLE(super().readBytes(8))
		self.SectionAlignment = byteToIntLE(super().readBytes(4))
		self.FileAlignment = byteToIntLE(super().readBytes(4))
		self.MajorOperatingSystemVersion = byteToIntLE(super().readBytes(2))
		self.MinorOperatingSystemVersion = byteToIntLE(super().readBytes(2))
		self.MajorImageVersion = byteToIntLE(super().readBytes(2))
		self.MinorImageVersion = byteToIntLE(super().readBytes(2))
		self.MajorSubsystemVersion = byteToIntLE(super().readBytes(2))
		self.MinorSubsystemVersion = byteToIntLE(super().readBytes(2))
		self.Win32VersionValue = byteToIntLE(super().readBytes(4))
		self.SizeOfImage = byteToIntLE(super().readBytes(4))
		self.SizeOfHeaders = byteToIntLE(super().readBytes(4))
		self.CheckSum = byteToIntLE(super().readBytes(4))
		self.Subsystem = byteToIntLE(super().readBytes(2))
		self.DllCharacteristics = byteToIntLE(super().readBytes(2))
		self.SizeOfStackReserve = byteToIntLE(super().readBytes(8))
		self.SizeOfStackCommit = byteToIntLE(super().readBytes(8))
		self.SizeOfHeapReserve = byteToIntLE(super().readBytes(8))
		self.SizeOfHeapCommit = byteToIntLE(super().readBytes(8))
		self.LoaderFlags = byteToIntLE(super().readBytes(4))
		self.NumberOfRvaAndSizes = byteToIntLE(super().readBytes(4))
		self.DataDirectory = list()
		for i in range(self.NumberOfRvaAndSizes):
			vAddr = byteToIntLE(super().readBytes(4))
			size = byteToIntLE(super().readBytes(4))
			dataDirectoryEntry = ImageDataDirectoryEntry(vAddr, size)
			self.DataDirectory.append(dataDirectoryEntry)
		
		#self.DataDirectory = array("L", range(self.NumberOfRvaAndSizes))
		#super().shiftPtr(self.NumberOfRvaAndSizes)
		#super().shiftPtr(4 * self.NumberOfRvaAndSizes)
		
	def printAll(self):
		print("[ImageOptionalHeader64]")
		print("Magic: ", self.Magic)
		print("MajorLinkerVersion: ", self.MajorLinkerVersion)
		print("MinorLinkerVersion: ", self.MinorLinkerVersion)
		print("SizeOfCode: ", self.SizeOfCode)
		print("SizeOfInitializedData: ", self.SizeOfInitializedData)
		print("SizeOfUninitializedData: ", self.SizeOfUninitializedData)
		print("AddressOfEntryPoint: ", self.AddressOfEntryPoint, "(", hex(self.AddressOfEntryPoint), ")")
		print("BaseOfCode: ", self.BaseOfCode)
		#print("BaseOfData: ", self.BaseOfData)
		
		print("ImageBase: ", hex(self.ImageBase))
		print("SectionAlignment: ", hex(self.SectionAlignment))
		print("FileAlignment: ", hex(self.FileAlignment))
		print("MajorOperatingSystemVersion: ", self.MajorOperatingSystemVersion)
		print("MinorOperatingSystemVersion: ", self.MinorOperatingSystemVersion)
		print("MajorImageVersion: ", self.MajorImageVersion)
		print("MinorImageVersion: ", self.MinorImageVersion)
		print("MajorSubsystemVersion: ", self.MajorSubsystemVersion)
		print("MinorSubsystemVersion: ", self.MinorSubsystemVersion)
		print("Win32VersionValue: ", self.Win32VersionValue)
		print("SizeOfImage: ", hex(self.SizeOfImage))
		print("SizeOfHeaders: ", hex(self.SizeOfHeaders))
		print("CheckSum: ", self.CheckSum)
		print("Subsystem: ", self.Subsystem)
		print("DllCharacteristics: ", self.DllCharacteristics)
		print("SizeOfStackReserve: ", self.SizeOfStackReserve)
		print("SizeOfStackCommit: ", self.SizeOfStackCommit)
		print("SizeOfHeapReserve: ", self.SizeOfHeapReserve)
		print("SizeOfHeapCommit: ", self.SizeOfHeapCommit)
		print("LoaderFlags: ", self.LoaderFlags)
		print("NumberOfRvaAndSizes: ", self.NumberOfRvaAndSizes)
		print("DataDirectory: DATADIRECTORY_DUMMY")
		"""
		for i in range(self.NumberOfRvaAndSizes):
			print("%d:" % i)
			print("\tVirtualAddress:", hex(self.DataDirectory[i].VirtualAddress))
			print("\tSize:", self.DataDirectory[i].Size)
		#print("DataDirectory: DATADIRECTORY_SAMPLE")
		#print("DataDirectory: ", self.DataDirectory)
		"""
		print("-" * 30)
		
class NTHeader(BinaryReader):
	# 4 + 20 + 96 + alpha = 120 + alpha bytes
	
	def __init__(self, bData, ptr):
		super().__init__(bData, ptr)
		
		self.Signature = super().readBytes(4)
		self.FileHeader = ImageFileHeader(self.rawData, self.cPtr)
		super().shiftPtr(20)
		
		if super().checkMagic(2) == b"\x0b\x01":
			self.OptionalHeader = ImageOptionalHeader32(self.rawData, self.cPtr)
		elif super().checkMagic(2) == b"\x0b\x02":
			self.OptionalHeader = ImageOptionalHeader64(self.rawData, self.cPtr)
		elif super().checkMagic(2) == b"\x07\x01":
			raise ROMImage
		else:
			raise UnknownMagic("Unknown Magic")
			
			
		super().shiftPtr(self.FileHeader.SizeOfOptionalHeader)

	def printAll(self):
		print("[NTHeader]")
		print("Signature: ", self.Signature)
		self.FileHeader.printAll()
		self.OptionalHeader.printAll()
		
		print("-" * 50)



class ImageSectionHeader(BinaryReader):
	# Size: 40
	
	nameLength = 8
	# Alloc magic
	allocMagic = 0xE0000000
	
	def __init__(self, bData, ptr):
		super().__init__(bData, ptr)
		
		self.name = super().readBytes(8)
		self.Misc = super().readBytes(4)
		self.VirtualAddress = byteToIntLE(super().readBytes(4))
		self.SizeOfRawData = byteToIntLE(super().readBytes(4))
		self.PointerToRawData = byteToIntLE(super().readBytes(4))
		self.PointerToRelocations = byteToIntLE(super().readBytes(4))
		self.PointerToLinenumbers = byteToIntLE(super().readBytes(4))
		self.NumberOfRelocations = byteToIntLE(super().readBytes(2))
		self.NumberOfLinenumbers = byteToIntLE(super().readBytes(2))
		self.Characteristics = byteToIntLE(super().readBytes(4))
	
	def getRawData(self):
		savePtr = super().getCurrentPosition()
		super().moveTo(self.PointerToRawData)
		#print("Name: ", self.name)
		#print("Ptr: ", self.PointerToRawData)
		#print("Size: ", self.SizeOfRawData)
		rawData = super().readBytes(self.SizeOfRawData)
		#print(rawData)
		super().moveTo(savePtr)
		
		return rawData
	
	def isAlloced(self):
		return self.Characteristics & ImageSectionHeader.allocMagic != 0

	def printAll(self):
		print("[SectionHeader]")
		print("FileOffset(Not member variable): ", self.selfOffset)	# Not member varialbe
		print("Name: ", self.name)
		print("Misc: ", self.Misc)
		print("VirtualAddress: ", hex(self.VirtualAddress))
		print("SizeOfRawData: ", self.SizeOfRawData, "(", hex(self.SizeOfRawData), ")")
		print("PointerToRawData: ", self.PointerToRawData, "(", hex(self.PointerToRawData), ")")
		print("PointerToRelocations: ", self.PointerToRelocations)
		print("PointerToLinenumbers: ", self.PointerToLinenumbers)
		print("NumberOfRelocations: ", self.NumberOfRelocations)
		print("NumberOfLinenumbers: ", self.NumberOfLinenumbers)
		print("Characteristics: ", hex(self.Characteristics))
		if self.Characteristics & ImageSectionHeader.allocMagic != 0:
			print("\tThis section is alloced.")
		
		print("-" * 30)


class SectionTable(BinaryReader):
	def __init__(self, bData, ptr, nsec):
		super().__init__(bData, ptr)
		
		# For iteration
		self.i = 0
		
		self.numberOfSection = nsec
		self.sectionHeaders = list()
		addr = ptr
		for i in range(self.numberOfSection):
			sectionHeader = ImageSectionHeader(bData, addr)
			self.sectionHeaders.append(sectionHeader)
			addr = sectionHeader.getEndOffset()+1
	
	def getSectionData(self, index):
		return self.sectionHeaders[index].getRawData()
	
	def printAll(self):
		print("[SectionTable]")
		for i in range(self.numberOfSection):
			self.sectionHeaders[i].printAll()
			
		print("-" * 30)
	
	def __iter__(self):
		return self
		
	def __next__(self):
		if self.i == self.numberOfSection:
			self.i = 0
			raise StopIteration
		sectionH = self.sectionHeaders[self.i]
		self.i += 1
		return sectionH
		
class PEHeaders:
	def __init__(self, bData):
		self.bData = bData
		self.msDosHeader = MSDOSHeader(self.bData)
		self.ntHeader = NTHeader(self.bData, self.msDosHeader.e_lfanew)
		self.fileHeader = self.ntHeader.FileHeader
		self.optionalHeader = self.ntHeader.OptionalHeader
		self.dataDirectory = self.optionalHeader.DataDirectory	# List
		self.sectionTable = SectionTable(self.bData, self.ntHeader.getEndOffset()+1, self.ntHeader.FileHeader.NumberOfSections)
	
	def getMSDosHeader(self):
		return self.msDosHeader
		
	def getNTHeader(self):
		return self.ntHeader
		
	def getFileHeader(self):
		return self.fileHeader
	
	def getOptionalHeader(self):
		return self.optionalHeader
	
	def getDataDirectory(self):
		return self.dataDirectory
	
	def getSectionTable(self):
		return self.sectionTable
	
	def printAll(self):
		print("[PE File Info]")
		self.msDosHeader.printAll()
		self.ntHeader.printAll()
		self.sectionTable.printAll()

		