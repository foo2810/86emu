# Main

import sys
from readPE import *
from loadPE import *

def main():
	args = sys.argv
	argc = len(args)
	if argc < 2:
		print("Usage: %s <file>" % args[0])
		exit(1)
	filename = args[1]
	option = args[2]
	path = Path(filename)
	if not path.exists():
		print("Error: FileNotFound")
		exit(1)
	
	peReader = PEReader(path)
	
	## Reader
	if option in "r" or option in "a":		
		peReader.printAll()
	
	## Loader
	if option in "l" or option in "a":
		loader = PEFileLoader(path)
		loader.dump("dump.bin")
	
		dumpFile = Path("dump.bin")
		st = dumpFile.open("rb")
		dump = st.read()
		st.flush()
		st.close()
		peReader.dumpImportTable(dump)
	
	
if __name__ == "__main__":
	main()
