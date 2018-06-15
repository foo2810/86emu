# Sample emulation of x86

from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *
from readPE import *

def main():
	# INC ecx; DEC edx
	sampCode = b"\x41\x4a"
	
	ADDRESS = 0x1000000
	
	print("Emulate i386 code")
	print("-----------------")
	print("[Sample Code]")
	print("INC ecx\nDEC edx")
	print("----------------")
	
	try:
		# Initialize emulator in X86-32bit mode
		mu = Uc(UC_ARCH_X86, UC_MODE_32)
		
		# map 2MB for this emulation
		mu.mem_map(ADDRESS, 2 * 1024 * 1024)
		
		mu.mem_write(ADDRESS, sampCode)
		
		# Initialize machine registers
		mu.reg_write(UC_X86_REG_ECX, 0x1234)
		mu.reg_write(UC_X86_REG_EDX, 0x7890)
		
		# Emulate sampCode
		mu.emu_start(ADDRESS, ADDRESS + len(sampCode))
		
		rECX = mu.reg_read(UC_X86_REG_ECX)
		rEDX = mu.reg_read(UC_X86_REG_EDX)
		
		print("ECX: ", hex(rECX))
		print("EDX: ", hex(rEDX))
	
	except UcError as e:
		print(e)
	

if __name__ == "__main__":
	main()