# Memory map pe format file

from readPE import *
from pathlib import Path
from mmap import *

class PEFileLoader:
	def __init__(self, path):
		if not path.exists():
			raise FileNotFoundError
	
		st = path.open("rb")
		bData = st.read()
		self.peHeader = PEHeaders(bData)
		st.close()
		
		self.isLoaded = False
		#self.peHeader.printAll()
		self.__loadToMemory()
		
	def __del__(self):
		self.mapData.close()
		
	# Not Complete!!!!!!!!!!!!
	# セグメントに対するアクセス制限は考慮していない
	# ...etc
	def __loadToMemory(self):
		if not self.isLoaded:
			print("[Caution] loadToMemory is not COMPLETED!!!!!!!!!!\n")
			
			alignment = self.peHeader.ntHeader.OptionalHeader.SectionAlignment
			baseAddr = self.peHeader.ntHeader.OptionalHeader.ImageBase
			mapSize = self.peHeader.ntHeader.OptionalHeader.SizeOfImage
			#entryPoint = self.peHeader.ntHeader.OptionalHeader.AddressOfEntryPoint
			
			print("[LOAD PE FORMAT FILE]")
			print("BaseAddress: ", hex(baseAddr))
			print("Alignment: ", hex(alignment))
			#print("EntryPoint: ", hex(entryPoint))
			
			
			self.mapData = mmap(-1, mapSize, None, ACCESS_WRITE)
			
			print("[Sections]")
			for section in self.peHeader.sectionTable:
				if not section.isAlloced:
					continue
				
				name = section.name
				vRva = section.VirtualAddress
				size = section.SizeOfRawData
				
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
				
				curPosA = self.mapData.tell()
				print("\tHead Position of MemoryMap: ", hex(curPosA))
				
				rawData = section.getRawData()
				self.mapData.flush()
				print("\tRes from write(): ", hex(self.mapData.write(rawData)))
				print("")
			
			self.isLoaded = True
			self.mapData.seek(0)
			
	
	def dump(self, filename):
		if not self.isLoaded:
			print("Pe format file has not mapped yet")
			return
			
		st = open(filename, "wb")
		dumpData = self.mapData.read()
		self.mapData.seek(0)
		st.write(dumpData)
		st.flush()
		st.close()
