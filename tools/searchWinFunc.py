import sys
import re
import shutil
from pathlib import Path
from readPE import *
from loadPE import *

#root = "C:\\Windows\\WinSxS\\"
root = "C:\\Windows\\System32\\"
#root = "C:\\Windows\\SysWOW64\\"



def createDirList(root):
	dList = list()
	
	dList.extend(Path(root).glob("*"))
	
	return dList

def getFileListIter(dirList, fList):
	fl = None

	for path in dirList:
		if path.is_dir():
			fl = getFileListIter(path.glob("*"), fList)
		else:
			fList.append(str(path))
	
	return fList
	
def getFileList(root):
	dirList = createDirList(root)
	fList = list()
	
	getFileListIter(dirList, fList)
	
	return fList


def main():
	global searchPathList, root

	args = sys.argv
	argc = len(args)
	
	if argc < 2:
		sys.stderr.write("Usage: {} <Function Name>\n".format(args[0]))
		sys.exit(1)
	
	funcName = args[1]
	
	rootPath = Path(root)
	
	if not rootPath.exists():
		sys.stderr.write(" >>> Error: Root derectory not found")
		sys.exit(1)
	
	fList = getFileList(root)
	
	print("Search directory: {}".format(root))
	print("Number of files: {}".format(len(fList)))
	print("")
	
	dllPat = re.compile(r"^.+\.(?:dll|DLL)$")
	
	for f in fList:
		if dllPat.fullmatch(f):
			path = Path(f)
			try:
				reader = PEReader(path)
			except (UnknownMagic, ROMImage) as e:
				continue
				
			loader = PEFileLoader(path, printOn=False)
			loader.dump("dump.bin")
			dump = None
			with open("dump.bin", "rb") as st:
				dump = st.read()
			
			eTable = reader.getExportTable(dump)
			for ord, name in eTable:
				addr = eTable.exportAddressTable[ord]
				if eTable.isExported(addr):
					continue
					
				if funcName == name:
					print(path)
		
	
if __name__ == "__main__":
	main()
