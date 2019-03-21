# Main

import sys
from readPE import *
from loadPE import *

def main():
	dllDir = Path("./DLL/32/tmp/")
	dlls = set()
	for dll in dllDir.glob("api-ms*.dll"):
		#print("[{}]".format(str(dll)))
		
		reader = PEReader(dll)
		
		dump = None
		loader = PEFileLoader(dll, printOn=False)
		loader.dump("dump.bin")
		with open("dump.bin", "rb") as st:
			dump = st.read()
		
		eTable = reader.getExportTable(dump)
		
		for ord, name in zip(eTable.exportNameOrdinalTable, eTable.exportNameTable):
			addr = eTable.exportAddressTable[ord]
			if eTable.isExported(addr):
				print("{} - {} exported".format(dll, name))
				
				desc = eTable.getExportName(addr).lower()
				items = desc.split(".")
				expDllName = items[0]
				expFuncName = items[1]
				dlls.add(expDllName)
				print("    {}.{}".format(expDllName, expFuncName))
				print("")
		
	print(dlls)
				
if __name__ == "__main__":
	main()
