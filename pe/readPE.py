# PE Reader

##########################################################################
# c.f.                                                                   #
# https://en.wikibooks.org/wiki/X86_Disassembly/Windows_Executable_Files #
# http://hp.vector.co.jp/authors/VA050396/tech_06.html                   #
#                                                                        #
##########################################################################

# -*- coding: utf-8 -*-

from array import array
from pathlib import Path

from peHeader import *
from importTable import *
from exportTable import *
from relocationTable import *
from utility import *


class PEReader:
	def __init__(self, path):
		if not path.exists():
			raise FileNotFoundError
		
		st = path.open("rb")
		self.bData = st.read()
		
		self.peHeaders = PEHeaders(self.bData)
		
		st.close()
		
		self.importTable = None
		self.exportTable = None
		self.relocationTable = None
		
		self.filename = str(path.resolve())
	
	def getMSDosHeader(self):
		return self.peHeaders.msDosHeader
		
	def getNTHeader(self):
		return self.peHeaders.ntHeader
		
	def getFileHeader(self):
		return self.peHeaders.fileHeader
	
	def getOptionalHeader(self):
		return self.peHeaders.optionalHeader
	
	def getDataDirectory(self):
		return self.peHeaders.dataDirectory
	
	def getSectionTable(self):
		return self.peHeaders.sectionTable
		
	def getImportTable(self, mapData):
		if self.importTable is not None:
			return self.importTable
	
		importTableVRva = self.peHeaders.optionalHeader.DataDirectory[1].VirtualAddress
		importTableSize = self.peHeaders.optionalHeader.DataDirectory[1].Size
		if self.peHeaders.optionalHeader.Magic == b"\x0b\x01":
			magic = 32
		elif self.peHeaders.optionalHeader.Magic == b"\x0b\x02":
			magic = 64
		else:
			raise ROMImage("in dumpImportTable")
			
		self.importTable = ImportTable(mapData, importTableVRva, importTableSize, magic)
		return self.importTable
	
	def getExportTable(self, mapData):
		if self.exportTable is not None:
			return self.exportTable
		
		exportTableVRva = self.peHeaders.optionalHeader.DataDirectory[0].VirtualAddress
		exportTableSize = self.peHeaders.optionalHeader.DataDirectory[0].Size
		self.exportTable = ExportTable(mapData, exportTableVRva, exportTableSize)
		
		return self.exportTable
	
	def getRelocationTable(self, mapData):
		if self.relocationTable is not None:
			return self.relocationTable
		
		relocationTableVRva = self.peHeaders.optionalHeader.DataDirectory[5].VirtualAddress
		relocationTableSize = self.peHeaders.optionalHeader.DataDirectory[5].Size
		self.relocationTable = RelocationTable(mapData, relocationTableVRva, relocationTableSize)
		
		return self.relocationTable
		
	def dumpImportTable(self, mapData, flg=1):
		self.importTable = self.getImportTable(mapData)
		self.importTable.printAll(flg)
	
	def dumpExportTable(self, mapData):
		self.exportTable = self.getExportTable(mapData)
		self.exportTable.printAll()
	
	def dumpRelocationTable(self, mapData):
		self.relocationTable = self.getRelocationTable(mapData)
		self.relocationTable.printAll()
	
	def printAll(self):
		self.peHeaders.printAll()

