# Main

import sys
from readPE import *
from loadPE import *

def main():
	args = sys.argv
	argc = len(args)
	if argc != 2:
		print("Usage: %s <file>" % args[0])
		exit(1)
	filename = args[1]
	path = Path(filename)
	if not path.exists():
		print("Error: FileNotFound")
		exit(1)
		
	## Reader
	peReader = PEReader(path)
	peReader.printAll()
	
	## Loader
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
