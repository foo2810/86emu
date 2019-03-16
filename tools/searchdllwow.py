import sys
import shutil
from pathlib import Path
from readPE import *
from loadPE import *

#root = "C:\\Windows\\WinSxS\\"
#root = "C:\\Windows\\System32\\"
root = "C:\\Windows\\SysWOW64\\"

#root = "C:\\Program Files (x86)\\"
#root = "C:\\Program Files\\"

searchPathList = [
"C:\\Windows\\WinSxS\\x86_microsoft-windows-m..namespace-downlevel_31bf3856ad364e35_10.0.17134.1_none_50c6cb8431e7428f\\",
"C:\\Windows\\WinSxS\\x86_microsoft-windows-m..namespace-downlevel_31bf3856ad364e35_10.0.17134.1_none_c4f50889467f081d\\",
"C:\\Windows\\WinSxS\\x86_microsoft-windows-m..namespace-downlevel_31bf3856ad364e35_10.0.17134.1_none_faa460298aa31e4a\\"
]

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
	
	cpFlg = False
	saveDir = Path("./tmp")
	
	if argc < 2:
		sys.stderr.write("Usage: {} <file> (options)\n".format(args[0]))
		sys.stderr.write("[Options]\n")
		sys.stderr.write("c: Copy to ./tmp\n")
		sys.exit(1)
	elif argc == 3:
		cpFlg = True
		
		if not saveDir.exists():
			sys.stderr.write("tmp/ not found\n")
			sys.stderr.write("Create tmp/ directory?(y/n) : ")
			yn = input()
			if yn == "y" or yn == "Y":
				saveDir.mkdir()
			else:
				sys.stderr.write("Now exiting\n")
				sys.exit(1)
	
	rootPath = Path(args[1])
	
	if not rootPath.exists():
		sys.stderr.write(" >>> Error: Root derectory not found")
		sys.exit(1)
	
	peReader = PEReader(rootPath)
	
	## Loader
	loader = PEFileLoader(rootPath, printOn=False)
	loader.dump("dump.bin")
	st = open("dump.bin", "rb")
	dump = st.read()
	st.close()
	
	fList = getFileList(root)
	itable = peReader.getImportTable(dump)
	
	print("Search directory: {}".format(root))
	print("Number of files: {}".format(len(fList)))
	print("")
	
	path = None
	for i in itable:
		dllName = i.Name
		flg = True
		print("[{}]".format(dllName))
		for j in range(len(fList)):
			path = Path(fList[j])
			if dllName.lower() == str(path.name).lower():
				print("Detected in {}".format(path))
				try:
					shutil.copyfile(str(path), str(saveDir / dllName))
				except PermissionError as e:
					pass
				flg = False
		if flg:
			print("Not detected")
		
		print("")
			
		
	
if __name__ == "__main__":
	main()
