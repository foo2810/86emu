
import sys
from pathlib import Path
from readPE import *
from loadPE import *
from relocationTable import *
from utility import *

class PEMapMgr:
	def __init__(self, mu, sPos):
		self.mu = mu
		self.headAddr = sPos
		self.dllList = dict()
	
	def map(self, reader, bData, head=None):
		peName = Path(reader.filename).name.lower()
		size = len(bData)
		self.mu.mem_map(self.headAddr, size)
		self.mu.mem_write(self.headAddr, bData)
		
		
		relocTable = reader.getRelocationTable(bData)
		diffAddr = self.headAddr - reader.getOptionalHeader().ImageBase
		for relocBlk in relocTable:
			bRva = relocBlk.VirtualAddress
			for relocEnt in relocBlk.thunks:
				if relocEnt.type == 3:
					addr = self.headAddr + bRva + relocEnt.offset
					val = byteToIntLE(self.mu.mem_read(addr, 4))
					val += diffAddr
					try:
						valCode = val.to_bytes(4, "little")
					except:
						print(peName)
						print("bRva: ", bRva)
						print("ImageBase: ", reader.getOptionalHeader().ImageBase)
						print("diffAddr: ", diffAddr)
						print("val: ", val - diffAddr)
						continue
						
					self.mu.mem_write(addr, valCode)
		
		ret = self.headAddr
		self.dllList[peName] = (self.headAddr, size)
		self.headAddr += size
		
		return ret
	
	def read(self, addr, size):
		return self.mu.mem_read(addr, size)
	
	def write(self, dllName, vrva, size, data):
		# size は念のため
		addr = self.dllList[dllName.lower()][0] + vrva
		self.mu.mem_write(addr, data)
	
	def getHeadAddr(self):
		return self.headAddr
	
	def getHeadList(self):
		return [d[0] for d in self.dllList]
	
	def getDllHead(self, dll):
		if dll in self.dllList:
			return self.dllList[dll][0]
		else:
			return None
	
	def getDllData(self, dll):
		if dll in self.dllList:
			return self.mu.mem_read(self.dllList[dll][0], self.dllList[dll][1])
	
	def isMappedDll(self, dll):
		if dll.lower() in self.dllList:
			return True
		else:
			return False

# 実行形式が関数をエクスポートする場合があれば、その処理には未対応
# 実行形式が関数を転送する場合があれば、その処理には未対応	たぶんない
class PEEXPFMapper:
	def __init__(self, mapMgr, peReader):
		self.dllPath = Path("./DLL/32/tmp/")
		#self.sampDlls = ['kernelbase.dll', 'version.dll', 'user32.dll', 'ole32.dll', 'kernel32.dll', 'ucrtbase.dll', 'ntdll.dll', 'cfgmgr32.dll', 'advapi32.dll', 'shlwapi.dll']
		self.sampDlls = ["kernelbase.dll"]
		self.mapping = dict()
		self.efList = list()
		self.notfoundList = list()
		self.expFailList = dict()
		self.impFailList = dict()
		self.reader = peReader
		
		#sPos = self.reader.getOptionalHeader().ImageBase
		self.mapMgr = mapMgr
		
		fName = peReader.filename
		self.loader = PEFileLoader(Path(fName))
		self.__dump = self.loader.dump()
		
		headAddr = self.mapMgr.map(self.reader, self.__dump)
		
		for dll in self.sampDlls:
			if dll not in self.mapping:
				self._traceExportFunc(dll)
		"""
		for dll, func, vrva in self.efList:
			try:
				self.mapMgr.write(dll, vrva, 4, self.mapping[dll][func].to_bytes(4, "little"))
			except KeyError as e:
				print("{} - {} is not found in kernelbase".format(dll, func))
		"""
		
		# 簡略化のためExportTableの処理はとりあえずpass 必要ないかもしれない
		"""
		exportTable = self.reader.getExportTable(dump)
		for ord, name in exportTable:
			vrva = exportTable.exportAddressTable[ord]
			if exportTable.isExported(vrva):
				pass	# Basically, exe file doesn't export functions
			else:
				pass
		"""
		
	
	def map(self):
		print("Exec Name: {}\n".format(self.reader.filename))
		# Import-Table of exe
		importedDllList = list()
		importTable = self.reader.getImportTable(self.__dump)
		for desc in importTable:
			importedDllList.append(desc.Name.lower())
			print("    >>> Import {}".format(desc.Name))
		print("")
		
		for impDll in importedDllList:
			if impDll not in self.mapping:
				self._traceExportFunc(impDll.lower())
		
		#print("Not found in KERNELBASE.DLL:")
		"""
		for dll, func, vrva in self.efList:
			try:
				self.mapMgr.write(dll, vrva, 4, self.mapping[dll][func].to_bytes(4, "little"))
			except KeyError as e:
				print("{} - {} is not found in kernelbase".format(dll, func))
		"""
		
		self.__exeLink()
		
		self.__dump = None
		
		print("AAAA {}".format(hex(byteToIntLE(self.mapMgr.read(0x99014c, 4)))))
	
	def __exeLink(self):
		exeName = str(Path(self.reader.filename).name).lower()
		
		importTable = self.reader.getImportTable(self.__dump)
		for ent in importTable:
			dll = ent.Name.lower()
			if dll == "":
				continue
			
			# 常にFalseであるはず
			"""
			if not self.mapMgr.isMappedDll(dll):
				self._traceExportFunc(dll)
			
				if not self.mapMgr.isMappedDll(dll):
					continue
			"""
			
			for thnk in ent:
				rva = thnk.getRva()
				func = thnk.AddressOfData.Name
				
				if func == "":
					continue
					
				try:
					self.mapMgr.write(exeName, rva, 4, self.mapping[dll][func].to_bytes(4, "little"))
				except KeyError as e:
					if dll not in self.impFailList:
						self.impFailList[dll] = list()
					
					flg = True
					
					for d in self.sampDlls:				
						"""
						# 常にFalseであるはず
						if d not in self.mapping:
							self._traceExportFunc(d)
						"""
							
						for f in self.mapping[d].keys():
							
							if func == f:									
								flg = False
								#print("    HIT Altanatively: {} - {}".format(d, f))
								self.mapMgr.write(exeName, rva, 4, self.mapping[d][f].to_bytes(4, "little"))
					
					if flg:
						self.impFailList[dll].append(func)
		
	def _traceExportFunc(self, dllName):
		dllReader = dllLoader = None
		dllName = dllName.lower()
		
		if dllName in self.mapping:
			return
		
		#print("{}".format(dllName))
		try:
			path = self.dllPath / (dllName)
			path = path.resolve()
			dllReader = PEReader(path)
			dllLoader = PEFileLoader(path)
		except FileNotFoundError as e:
			if dllName not in self.notfoundList:
				self.notfoundList.append(dllName)
			#print("    >>> not found\n".format(dllName))
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
		
		print(dllName)
		
		dump = dllLoader.dump()
		
		headAddr = self.mapMgr.map(dllReader, dump)
		
		self.mapping[dllName] = dict()
		
		exportTable = dllReader.getExportTable(dump)
		expList = list()
		expFuncList = list()
		for ord, name in exportTable:
			vrva = exportTable.exportAddressTable[ord]
			if exportTable.isExported(vrva):
				exp = exportTable.getExportName(vrva)
				items = exp.split(".")
				expDllName = (items[0] + ".dll").lower()
				expFuncName = items[1]
				
				#self.mapping[dllName][name] = headAddr + vrva	#とりあえず自身のアドレスを入れておく
				
				if expDllName not in self.mapping:
					self._traceExportFunc(expDllName)
					"""
					expList.append(exp)
					expFuncList.append(name)									# expListに対応
					self.efList.append((dllName, name, vrva))
					"""
					
				#+#
				expFuncList.append((name, vrva))
				
				try:
					self.mapping[dllName][name] = self.mapping[expDllName][expFuncName]
				except KeyError as e:
					if dllName not in self.expFailList:
						self.expFailList[dllName] = list()
						
						flg = True
						
					for dll in self.sampDlls:
						"""
						if dll not in self.mapping:
							continue
						"""
						for func in self.mapping[dll].keys():
							if name == func:
								flg = False
								self.mapping[dllName][name] = self.mapping[dll][func]
								break
						if not flg:
							break
						
					if flg:
						self.expFailList[dllName].append(name)
			else:
				self.mapping[dllName][name] = headAddr + vrva
				
		
		#
		"""
		for exp in expList:
			items = exp.split(".")
			expDllName = (items[0] + ".dll").lower()
			if not (expDllName in self.mapping):
				self._traceExportFunc(expDllName)
		"""
		
		for idx in range(len(expFuncList)):
			funcName = expFuncList[idx][0]
			#items = expList[idx].split(".")
			#expDllName = (items[0] + ".dll").lower()
			#expFuncName = items[1]
			try:
				#self.mapping[dllName][funcName] = self.mapping[expDllName][expFuncName]
				vrva = expFuncList[idx][1]
				self.mapMgr.write(dllName, vrva, 4, self.mapping[dllName][funcName].to_bytes(4, "little"))
			except KeyError as e:
				pass
				"""
				print("{} - {}".format(dllName, funcName))
				flg = False
				if expDllName not in self.mapping:
					if dllName not in self.expFailList:
						self.expFailList[dllName] = list()
						flg = True
					print("    >>> {} not loaded\n".format(expDllName))
				if expDllName in self.mapping:
					if expFuncName not in self.mapping:
						if dllName not in self.expFailList:
							self.expFailList[dllName] = list()
						flg = True
						print("    >>> {} not in {}\n".format(expFuncName, expDllName))
				
				for dll in self.sampDlls:
					for func in self.mapping[dll].keys():
						if funcName == func:
							flg = False
							print("    HIT Altanatively: {} - {}".format(dll, func))
							self.mapping[dllName][funcName] = self.mapping[dll][func]
							#self.mapMgr.write(dllName, rva, 4, self.mapping[dll][func].to_bytes(4, "little"))
				
				if flg:
					self.expFailList[dllName].append(funcName)
				"""
		
		importTable = dllReader.getImportTable(dump)
		if dllName == "kernel32.dll":
			yn = input()
			for ent in importTable:
				dll = ent.Name.lower()
				print(dll)
				for thnk in ent:
					func = thnk.AddressOfData.Name
					print("\t{}".format(func))
			yn = input()	
		
			
		importTable = dllReader.getImportTable(dump)
		for ent in importTable:
			dll = ent.Name.lower()
			
			if not self.mapMgr.isMappedDll(dll):
				self._traceExportFunc(dll)
			
				if not self.mapMgr.isMappedDll(dll):
					pass	# dllが存在しない
			
			for thnk in ent:
				rva = thnk.getRva()
				func = thnk.AddressOfData.Name
				
				if func == "":
					continue
				
				try:
					self.mapMgr.write(dllName, rva, 4, self.mapping[dll][func].to_bytes(4, "little"))
				except KeyError as e:
					if dll not in self.impFailList:
						self.impFailList[dll] = list()
					
					flg = True
					
					for d in self.sampDlls:
						for f in self.mapping[d].keys():							
							if func == f:									
								flg = False
								#print("    HIT Altanatively: {} - {}".format(d, f))
								self.mapMgr.write(dllName, rva, 4, self.mapping[d][f].to_bytes(4, "little"))
								break
						
						if not flg:
							break
					
					if flg:
						self.impFailList[dll].append(func)
					
				
	def getMap(self):
		self.mapping
	
	def getNextHead(self):
		return self.mapMgr.getHeadAddr()
	
	def getExpFailList(self):
		return self.expFailList
	
	def getImpFailList(self):
		return self.impFailList
	
	def getNotFoundList(self):
		return self.notfoundList
	
	def dumpMap(self, fname):
		with open(fname, "w") as st:
			for dll in self.mapping.keys():
				st.write("{}:\n".format(dll))
				for func in self.mapping[dll].keys():
					st.write("\t- {}\t{}\n".format(func, hex(self.mapping[dll][func])))