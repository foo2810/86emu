# Sample emulation of x86

from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *
from capstone import *
from pathlib import *
from readPE import *
from loadPE import *

class SimpleEngine:
	def __init__(self, addr):
		self.capmd = Cs(CS_ARCH_X86, CS_MODE_32)
		self.address = addr
	
	def disas_single(self, data):
		for i in self.capmd.disasm(data, self.address):
			print("\t%s\t%s" % (i.mnemonic, i.op_str))
			break

disasm = None

def hook_block(uc, address, size, user_data):
	print(">>> Tracing basic block at 0x%x, block size = 0x%x" % (address, size))
	

def hook_code(uc, address, size, user_data):
	print(">>> Tracing instruction at 0x%x, instruction size = %u" % (address, size))
	instruction = uc.mem_read(address, size)
	data = b""
	for n in instruction:
		data = data + n.to_bytes(1, "little")
	disasm.disas_single(data)
	
def main():
	global disasm
	
	exeFile = Path("./sampledata/sample.exe")
	peReader = PEReader(exeFile)
	loader = PEFileLoader(exeFile)
	loader.dump("dump.bin")
	dumpFile = Path("./dump.bin")
	st = dumpFile.open("rb")
	dumpData = st.read()
	st.close()
	
	
	
	# INC ecx; DEC edx
	#sampCode = b"\x41\x4a"
	
	ADDRESS = peReader.peHeaders.optionalHeader.ImageBase
	ENTRYPOINT = ADDRESS + peReader.peHeaders.optionalHeader.AddressOfEntryPoint
	SIZEOFCODE = peReader.peHeaders.optionalHeader.SizeOfCode
	DATAADDR = 0x600000
	print("Base Address: " + hex(ADDRESS))
	print("Entry Point: " + hex(ENTRYPOINT))
	print("Size of Code: " + hex(SIZEOFCODE))
	print("Data address: " + hex(DATAADDR))
	
	disasm = SimpleEngine(ADDRESS)
	
	"""
	print("Emulate i386 code")
	print("-----------------")
	print("[Sample Code]")
	print("INC ecx\nDEC edx")
	print("----------------")
	"""
	
	mu = None
	
	try:
		# Initialize emulator in X86-32bit mode
		mu = Uc(UC_ARCH_X86, UC_MODE_32)
		
		# map 2MB for this emulation
		mu.mem_map(ADDRESS, 2 * 1024 * 1024)
		mu.mem_map(DATAADDR, 256 * 1024 * 1024)
		
		mu.mem_write(ADDRESS, dumpData)
		
		#mu.hook_add(UC_HOOK_BLOCK, hook_block)
		mu.hook_add(UC_HOOK_CODE, hook_code)
		
		# Initialize machine registers
		#mu.reg_write(UC_X86_REG_ECX, 0x1234)
		#mu.reg_write(UC_X86_REG_EDX, 0x7890)
		mu.reg_write(UC_X86_REG_EBP, DATAADDR + 256 * 1024 * 1024)
		mu.reg_write(UC_X86_REG_ESP, DATAADDR + 256 * 1024 * 1024)
		
		# Emulate sampCode
		print("[Emulation start]")
		mu.emu_start(ENTRYPOINT, ENTRYPOINT + SIZEOFCODE)
		
		
		
		#print("ECX: ", hex(rECX))
		#print("EDX: ", hex(rEDX))
	
	except UcError as e:
		print(e)
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
		print(">>> EAX = 0x%x" % r_eax)
		print(">>> EBX = 0x%x" % r_ebx)
		print(">>> ECX = 0x%x" % r_ecx)
		print(">>> EDX = 0x%x" % r_edx)
		print(">>> EBP = 0x%x" % r_ebp)
		print(">>> ESP = 0x%x" % r_esp)
		print(">>> EDI = 0x%x" % r_edi)
		print(">>> ESI = 0x%x" % r_esi)
		print(">>> EIP = 0x%x" % r_eip)
		print(">>> EFLAGS = 0x%x" % r_eflags)

	

if __name__ == "__main__":
	main()