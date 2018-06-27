# Export Table

from peBaseClass import *
from utility import *

class ImageExportDirectory(BinaryReader):
	def __init__(self, mapData, ptr, size):
		super().__init__(mapData, ptr)