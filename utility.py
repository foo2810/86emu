# Utilities


def byteToIntLE(byte_data):
	"""
	value_str = ""
	
	for b in byte_data:
		b_str = hex(b)
		if len(b_str) < 4:
			value_str = "0" + b_str[2:] + value_str
		else:
			value_str = b_str[2:] + value_str
	
	#print("value_str", value_str)
	value = int(value_str, 16)
	
	return value
	"""
	return int.from_bytes(byte_data, "little")

# C string
def getStringFromBytes(byte_data, ptr):
	bStr = b""
	for b in byte_data[ptr:]:
		if b == 0:
			break
		bStr = bStr + b.to_bytes(1, "little")
	
	return bStr.decode("utf-8", errors="ignore")