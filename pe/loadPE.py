# Memory map pe format file

from readPE import *
from pathlib import Path
from mmap import *

class PEFileLoader:
	def __init__(self, path, printOn=False):
		self.peHeader = None
		self.mapData = None
		
		if not path.exists():
			raise FileNotFoundError
	
		st = path.open("rb")
		bData = st.read()
		self.peHeader = PEHeaders(bData)
		st.close()
		
		#self.isLoaded = False
		#self.peHeader.printAll()
		self.__loadToMemory(printOn)
		
	def __del__(self):
		self.mapData.close()
		
	# Not Complete!!!!!!!!!!!!
	# セグメントに対するアクセス制限は考慮していない
	# ...etc
	def __loadToMemory(self, printOn=False):
		alignment = self.peHeader.ntHeader.OptionalHeader.SectionAlignment
		baseAddr = self.peHeader.ntHeader.OptionalHeader.ImageBase
		mapSize = self.peHeader.ntHeader.OptionalHeader.SizeOfImage
		#entryPoint = self.peHeader.ntHeader.OptionalHeader.AddressOfEntryPoint
		
		if printOn:
			print("[Caution] loadToMemory is not COMPLETED!!!!!!!!!!\n")
			print("[LOAD PE FORMAT FILE]")
			print("BaseAddress: ", hex(baseAddr))
			print("Alignment: ", hex(alignment))
			#print("EntryPoint: ", hex(entryPoint))
		
		
		self.mapData = mmap(-1, mapSize, None, ACCESS_WRITE)
		
		if printOn:
			print("[Sections]")
		for section in self.peHeader.sectionTable:
			if not section.isAlloced:
				continue
			
			name = section.name
			vRva = section.VirtualAddress
			size = section.SizeOfRawData
			
			if printOn:
				print("\tName: ", name)
				print("\tSize: ", hex(size))
				print("\tVirtualAddress(RVA): ", hex(vRva))
			
			
			# Padding (alignment)
			"""
			if self.mapData.tell() % alignment != 0:
				cnt = alignment - (self.mapData.tell() % alignment)
				for i in range(cnt):
					self.mapData.write_byte(0)
			"""
			
			curPosB = self.mapData.tell()
			if vRva > curPosB:
				self.mapData.write(b"\x00" * (vRva - curPosB))
			
			if printOn:
				curPosA = self.mapData.tell()
				print("\tHead Position of MemoryMap: ", hex(curPosA))
			
			rawData = section.getRawData()
			res = self.mapData.write(rawData)
			self.mapData.flush()
			
			if printOn:
				print("\tRes from write(): ", hex(res))
				print("")
		
		#self.isLoaded = True
		self.mapData.seek(0)
	
	def getMapData(self):
		return self.mapData
			
	
	def dump(self, filename=""):
		"""
		if not self.isLoaded:
			print("Pe format file has not mapped yet")
			return
		"""
		
		dumpData = self.mapData.read()
		self.mapData.seek(0)
			
		if filename != "":
			st = open(filename, "wb")
			
			st.write(dumpData)
			st.flush()
			st.close()
		
		return dumpData
