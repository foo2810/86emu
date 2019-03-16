import sys
from pathlib import Path
from readPE import *
from loadPE import *
from relocationTable import *
from utility import *
from peMap import *

class DynamicLinker:
	def __init__(self, mapMgr, mapper, peReader):
		self.dllPath = Path("./DLL/32/tmp/")
		self.mapMgr = mapMgr
		self.mapper = mapper
		self.reader = peReader
		self.mapping = self.mapper.getMap()
		
		fName = peReader.filename
		self.loader = PEFileLoader(Path(fName))
		self.__dump = self.loader.dump()
	
	def link(self):
		print("Exec Name: {}\n".format(self.reader.filename))
		# Import-Table of exe
		importedDllList = list()
		importTable = self.reader.getImportTable(self.__dump)
		for desc in importTable:
			importedDllList.append(desc.Name)
			print("    >>> Import {}".format(desc.Name))
		print("")
		for impDll in importedDllList:
			self._linkImportFunc(impDll)
		
		self.__dump = None
	
	def _linkImportFunc(self, dllName):
		dllName = dllName.lower()
		headAddr = self.mapMgr.getDllHead(dllName)
		if headAddr is None:
			print("{} not mapped".format(dllName))
			return
		
		dllReader = dllLoader = None
		dllName = dllName.lower()
		print("{}".format(dllName))
		try:
			path = self.dllPath / (dllName)
			path = path.resolve()
			dllReader = PEReader(path)
			dllLoader = PEFileLoader(path)
		except FileNotFoundError as e:
			if dllName not in self.notfoundList:
				self.notfoundList.append(dllName)
			print("    >>> not found\n".format(dllName))
			"""
			yn = input("Continue? : ")
			if yn != "y":
				sys.exit(1)
			else:
				print("       continue")
				return
			"""
			return
		except ROMIMage as e:
			print("    >>> ROM Image : {}\n".format(dllName))
			sys.exit(1)
		except UnknownImage as e:
			print("    >>> Unknown Image : {}\n".format(dllName))
			sys.exit(1)
		
		dump = self.mapMgr.getDllData(dllName)
		if dump is None:
			return
		
		iTable = dllReader.getImportTable(dump)
		
		for ent in iTable:
			dll = ent.Name.lower()
			for thnk in ent:
				rva = thnk.AddressOfData.getRva()
				func = thnk.AddressOfData.Name
				
				if self.mapMgr.isMappedDll(dll):
					#print("{} - {} can be imported now".format(dll, func))
					pass
				else:
					#print("{} - {} cannot be imported now".format(dll, func))
					self.mapper._traceExportFunc(dll)
					