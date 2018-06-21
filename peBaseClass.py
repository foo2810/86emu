# Base class for PE Format

class HeaderBase:
	def __init__(self, bData, selfOffset_):
		self.rawData = bData
		self.cPtr = selfOffset_
		self.selfOffset = selfOffset_
		
	def readBytes(self, size):
		readData = self.rawData[self.cPtr:self.cPtr+size]
		self.cPtr += size
		return readData
	
	def moveTo(self, ptr):
		self.cPtr = ptr
		
	def shiftPtr(self, size):
		self.cPtr += size
	
	def getCurrentPosition(self):
		return self.cPtr
		
	def getStartOffset(self):
		return self.selfOffset
	
	def getEndOffset(self):
		return self.cPtr - 1
	
	def getSize(self):
		return self.cPtr - self.selfOffset
	
	def checkMagic(self, size):
		readData = self.readBytes(size)
		self.shiftPtr(-size)
		return readData

