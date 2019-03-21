# Sample emulation of x86

from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *
from capstone import *
from pathlib import *
from readPE import *
from loadPE import *
from importTable import *
from exportTable import *
import x86UtilTemp
from utility import *
import sys
from peMap import *
from dynamicLinker import *


class SimpleEngine:
	def __init__(self, addr):
		self.capmd = Cs(CS_ARCH_X86, CS_MODE_32)
		self.address = addr
	
	def disas_single(self, data):
		for i in self.capmd.disasm(data, self.address):
			print("\t%s\t%s" % (i.mnemonic, i.op_str))
			break

disasm = None

def printReg(mu):
	r_eax = mu.reg_read(UC_X86_REG_EAX)
	r_ebx = mu.reg_read(UC_X86_REG_EBX)
	r_ecx = mu.reg_read(UC_X86_REG_ECX)
	r_edx = mu.reg_read(UC_X86_REG_EDX)
	r_ebp = mu.reg_read(UC_X86_REG_EBP)
	r_esp = mu.reg_read(UC_X86_REG_ESP)
	r_edi = mu.reg_read(UC_X86_REG_EDI)
	r_esi = mu.reg_read(UC_X86_REG_ESI)
	r_eip = mu.reg_read(UC_X86_REG_EIP)
	r_eflags = mu.reg_read(UC_X86_REG_EFLAGS)
	r_CS = mu.reg_read(UC_X86_REG_CS)
	r_SS = mu.reg_read(UC_X86_REG_SS)
	r_DS = mu.reg_read(UC_X86_REG_DS)
	r_ES = mu.reg_read(UC_X86_REG_ES)
	r_FS = mu.reg_read(UC_X86_REG_FS)
	r_GS = mu.reg_read(UC_X86_REG_GS)
	r_GDTR = mu.reg_read(UC_X86_REG_GDTR)
	r_LDTR = mu.reg_read(UC_X86_REG_LDTR)
	r_IDTR = mu.reg_read(UC_X86_REG_IDTR)
	r_TR = mu.reg_read(UC_X86_REG_TR)	# task register	
	print(">>> EAX = 0x%x" % r_eax)
	print(">>> EBX = 0x%x" % r_ebx)
	print(">>> ECX = 0x%x" % r_ecx)
	print(">>> EDX = 0x%x" % r_edx)
	print(">>> EBP = 0x%x" % r_ebp)
	print(">>> ESP = 0x%x" % r_esp)
	print(">>> EDI = 0x%x" % r_edi)
	print(">>> ESI = 0x%x" % r_esi)
	print(">>> EIP = 0x%x" % r_eip)
	print(">>> CS = 0x%x" % r_CS)
	print(">>> SS = 0x%x" % r_SS)
	print(">>> DS = 0x%x" % r_DS)
	print(">>> ES = 0x%x" % r_ES)
	print(">>> FS = 0x%x" % r_FS)
	print(">>> GS = 0x%x" % r_GS)
	print(">>> GDTR = ", r_GDTR)
	print(">>> LDTR = ", r_LDTR)
	print(">>> IDTR = ", r_IDTR)
	print(">>> TR = ", r_TR)
	
def hook_block(uc, address, size, user_data):
	print(">>> Tracing basic block at 0x%x, block size = 0x%x" % (address, size))
	
def hook_code(uc, address, size, user_data):
	print(">>> Tracing instruction at 0x%x, instruction size = %u" % (address, size))
	instruction = uc.mem_read(address, size)
	data = b""
	for n in instruction:
		data = data + n.to_bytes(1, "little")
	disasm.disas_single(data)
	#printReg(uc)
	


def main():
	global disasm
	
	exeFile = Path("./sampledata/sample.exe")
	peReader = PEReader(exeFile)
	loader = PEFileLoader(exeFile)
	dumpData = loader.dump()
	
	mu = None
	ADDRESS = peReader.getOptionalHeader().ImageBase
	ENTRYPOINT = ADDRESS + peReader.getOptionalHeader().AddressOfEntryPoint
	SIZEOFCODE = peReader.getOptionalHeader().SizeOfCode
	DATAADDR = None
	DATASIZE = 0x250000
	
	disasm = SimpleEngine(ENTRYPOINT)
	
	
	
	try:
		# Initialize emulator in X86-32bit mode
		mu = Uc(UC_ARCH_X86, UC_MODE_32)
		
		#mu.hook_add(UC_HOOK_BLOCK, hook_block)
		mu.hook_add(UC_HOOK_CODE, hook_code)
		
		mapMgr = PEMapMgr(mu, ADDRESS)
		mapper = PEEXPFMapper(mapMgr, peReader)
		mapper.map()
		f = mapper.getExpFailList()
		f2 = mapper.getImpFailList()
		nf = mapper.getNotFoundList()
		print("\n\nExpFailList:")
		for dll in f.keys():
			for func in f[dll]:
				print("{} - {}".format(dll, func))
		print("\n\n")
		
		print("ImpFailList:")
		for dll in f2.keys():
			for func in f2[dll]:
				print("{} - {}".format(dll, func))
		print("\n\n")
		
		print("Not Found DLL:")
		for f in nf:
			print(f)
		
		print("\n")
		
		mapper.dumpMap("mapping.txt")
		
		DATAADDR = mapper.getNextHead()
		mu.mem_map(DATAADDR, DATASIZE)
		
		# Initialize machine registers
		gdtBase = DATAADDR + DATASIZE
		gdtSize = 8192
		#mu.mem_map(gdtBase, gdtSize)
		
		gdtMgr = x86UtilTemp.GDTMgr(mu, gdtBase, gdtSize)
		
		# CS
		selector = gdtMgr.createSegSelector(4, 0, 3)
		flgs = gdtMgr.createGDTEntryFlgs(s=1, dpl=3, p=1, g=1, cd=1, ec=0, wr=1, aa=1)
		entry = gdtMgr.createGDTEntry(0xffffffff, 0x0, flgs)
		gdtMgr.setGDTEntry(entry, selector)
		
		# ES DS GS
		selector = gdtMgr.createSegSelector(5, 0, 3)
		flgs = gdtMgr.createGDTEntryFlgs(s=1, dpl=3, p=1, g=1, cd=1, ec=0, wr=1, aa=1)
		entry = gdtMgr.createGDTEntry(0xffffffff, 0x0, flgs)
		gdtMgr.setGDTEntry(entry, selector)
		
		# SS
		selector = gdtMgr.createSegSelector(6, 0, 0)
		flgs = gdtMgr.createGDTEntryFlgs(s=1, dpl=0, p=1, g=1, cd=0, ec=1, wr=1, aa=1)
		entry = gdtMgr.createGDTEntry(0xffffffff, 0x0, flgs)
		gdtMgr.setGDTEntry(entry, selector)
		
		# FS
		selector = gdtMgr.createSegSelector(10, 0, 3)
		flgs = gdtMgr.createGDTEntryFlgs(s=1, dpl=3, p=1, g=0, cd=0, ec=0, wr=1, aa=1)
		#entry = gdtMgr.createGDTEntry(0xffffffff, 0x0, flgs)
		entry = gdtMgr.createGDTEntry(0xfff, 0x0, flgs)
		gdtMgr.setGDTEntry(entry, selector)
		
		
		
		print("SET SEGMENT REGISTER")
		mu.reg_write(UC_X86_REG_ES, 0x002b)
		print("ES")
		mu.reg_write(UC_X86_REG_CS, 0x0023)
		print("CS")
		mu.reg_write(UC_X86_REG_SS, 0x0030)	#0x002b
		print("SS")
		mu.reg_write(UC_X86_REG_DS, 0x002b)
		print("DS")
		mu.reg_write(UC_X86_REG_FS, 0x0053)
		print("FS")
		mu.reg_write(UC_X86_REG_GS, 0x002b)
		print("GS")
		
		#mu.reg_write(UC_X86_REG_EBP, DATAADDR + DATASIZE)
		mu.reg_write(UC_X86_REG_ESP, DATAADDR + DATASIZE)
		
		
		"""
		peImportTable = peReader.getImportTable(dumpData)
		for ent in peImportTable:
			thunks = ent.getThunks()
			for thunk in thunks:
				name = thunk.AddressOfData.Name
				nameList = kernel32ExportTable.exportNameTable
				ordList = kernel32ExportTable.exportNameOrdinalTable
				funcList = kernel32ExportTable.exportAddressTable
				for j in range(nameList.getSize()):
					if name == nameList[j]:
						ord = ordList[j]
						funcAddr = funcList[ord]
						#print(name + ", ", hex(funcAddr))
						mu.mem_write(ADDRESS + thunk.getHeadPtr(), (addr + funcAddr).to_bytes(4, "little"))
		"""
		
		
		# Emulation
		print("[Emulation start]")
		mu.emu_start(ENTRYPOINT, ENTRYPOINT + SIZEOFCODE)
		
	
	except UcError as e:
		print(e)
		printReg(mu)
		printStackTrace()
		
	
	except Exception as e:
		printStackTrace()
		#print(e)

	

if __name__ == "__main__":
	main()