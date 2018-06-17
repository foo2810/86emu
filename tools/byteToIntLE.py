#byteToIntLE

import sys, os
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + './../')

from utility import *

def main():
	args = sys.argv
	argc = len(args)
	
	if argc != 2:
		print("Usage: %s <hex>" % args[0])
		exit(1)
		
	strLE = args[1]
	
	if len(strLE) % 2 != 0:
		strLE = strLE + "0"
		
	byteLE = b""
	for i in range(0, len(strLE), 2):
		num = int(strLE[i:i+2], 16)
		byteLE = byteLE + num.to_bytes(1, "little")
	
	num = byteToIntLE(byteLE)
	print("dec: %d, hex: 0x%x" % (num, num))

if __name__ == "__main__":
	main()
