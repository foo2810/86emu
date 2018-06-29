# Main

import sys
from readPE import *
from loadPE import *

def main():
	args = sys.argv
	argc = len(args)
	if argc < 2:
		print("Usage: %s <file>\n" % args[0])
		print("[Option]")
		print("h: Show header Info")
		print("l: Map file and dump the data")
		print("I: Show import table")
		print("R: Show relocation table")
		print("a: Do everything")
		print("")
		exit(1)
	elif argc == 2:
		option = "h"
	else:
		option = args[2]
		
	filename = args[1]
	path = Path(filename)
	if not path.exists():
		print("Error: FileNotFound")
		exit(1)
	
	peReader = PEReader(path)
	
	## Reader
	if option in "h" or option in "a":		
		peReader.printAll()
		
	## Loader
	if "l" in option or "I" in option or "R" in option or "a" in option:
		loader = PEFileLoader(path)
		loader.dump("dump.bin")
	
		dumpFile = Path("dump.bin")
		st = dumpFile.open("rb")
		dump = st.read()
		st.close()
	
	## ImportTable
	if "I" in option or "a" in option:
		peReader.dumpImportTable(dump)
	
	## RelocationTable
	if "R" in option or "a" in option:
		peReader.dumpRelocationTable(dump)
		
	## [Test] ExportTable
	if "t" in option:
		peReader.dumpExportTable(dump)
	
if __name__ == "__main__":
	main()
