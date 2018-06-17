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

from peBaseClass import *
from peHeader import *
from importTable import *
from utility import *


class PEReader:
	def __init__(self, path):
		if not path.exists():
			raise FileNotFoundError
		
		st = path.open("rb")
		self.bData = st.read()
		
		self.peHeaders = PEHeaders(self.bData)
		
		st.close()
		
	def dumpImportTable(self, mapData):
		importTableVRva = self.peHeaders.optionalHeader.DataDirectory[1].VirtualAddress
		importTableSize = self.peHeaders.optionalHeader.DataDirectory[1].Size
		if self.peHeaders.optionalHeader.Magic == b"\x0b\x01":
			magic = 32
		elif self.peHeaders.optionalHeader.Magic == b"\x0b\x02":
			magic = 64
		else:
			raise ROMImage("in dumpImportTable")
			
		self.importTable = ImportTable(mapData, importTableVRva, importTableSize, magic)
		self.importTable.printAll()
		
		
	
	def printAll(self):
		self.peHeaders.printAll()

