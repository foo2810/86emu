#PE Format Constants

# Signature of member of Optional Header in NT Header
NT_OPTIONAL_HEADER32_MAGIC = 0x10b
NT_OPTIONAL_HEADER64_MAGIC = 0x20b
ROM_OPTIONAL_HEADER_MAGIC = 0x107

# Subsystem of member of Optional Header in NT Header
SUBSYSTEM_UNKNOWN = 0					# Unknown subsystem
SUBSYSTEM_NATIVE = 1					# No subsystem required (device drivers and native system processes)
SUBSYSTEM_WINDOWS_GUI = 2				# Windows graphical user interface (GUI) subsystem
SUBSYSTEM_WINDOWS_CUI = 3				# Windows character-mode user interface (CUI) subsystem
SUBSYSTEM_OS2_CUI = 5					# OS/2 CUI subsystem
SUBSYSTEM_POSIX_CUI = 7					# POSIX CUI subsystem
SUBSYSTEM_WINDOWS_CE_GUI = 9			# Windows CE system
SUBSYSTEM_EFI_APPLICATION = 10			# Extensible Firmware Interface (EFI) application
SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11	# EFI driver with boot services
SUBSYSTEM_EFI_RUNTIME_DRIVER = 12		# EFI driver with run-time services
SUBSYSTEM_EFI_ROM = 13					# EFI ROM image
SUBSYSTEM_XBOX = 14						# Xbox system
SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 16 # Boot application


# DLL Characteristics
#No constant name 	0x0001 	Reserved
#No constant name 	0x0002 	Reserved
#No constant name 	0x0004 	Reserved
#No constant name 	0x0008 	Reserved
DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040			# The DLL can be relocated at load time
DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x0080			# Code integrity checks are forced
DLLCHARACTERISTICS_NX_COMPAT = 0x0100				# The image is compatible with data execution prevention (DEP)
DLLCHARACTERISTICS_NO_ISOLATION = 0x0200			# The image is isolation aware, but should not be isolated
DLLCHARACTERISTICS_NO_SEH = 0x0400					# The image does not use structured exception handling (SEH). No handlers can be called in this image
DLLCHARACTERISTICS_NO_BIND = 0x0800					# Do not bind the image
DLLCHARACTERISTICS_APPCONTAINER = 0x1000			# The image must be executed within an App container
DLLCHARACTERISTICS_WDM_DRIVER = 0x2000				# A WDM driver
#No constant name 	0x4000 	Reserved
DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000	# The image is terminal server aware

# DataDirectory Entry					# Discription		Offset32	Offset64
DIRECTORY_ENTRY_EXPORT = 0				# Export Directory 	96 	112
DIRECTORY_ENTRY_IMPORT = 1				# Import Directory 	104 	120
DIRECTORY_ENTRY_RESOURCE = 2			# Resource Directory 	112 	128
DIRECTORY_ENTRY_EXCEPTION = 3			# Exception Directory 	120 	136
DIRECTORY_ENTRY_SECURITY = 4			# Security Directory 	128 	144
DIRECTORY_ENTRY_BASERELOC = 5			# Base Relocation Table 	136 	152
DIRECTORY_ENTRY_DEBUG = 6				# Debug Directory 	144 	160
DIRECTORY_ENTRY_ARCHITECTURE = 7		# Architecture specific data 	152 	168
DIRECTORY_ENTRY_GLOBALPTR = 8			# Global pointer register relative virtual address 	160 	176
DIRECTORY_ENTRY_TLS = 9					# Thread Local Storage directory 	168 	184
DIRECTORY_ENTRY_LOAD_CONFIG = 10		# Load Configuration directory 	176 	192
DIRECTORY_ENTRY_BOUND_IMPORT = 11		# Bound Import directory 	184 	200
DIRECTORY_ENTRY_IAT = 12				# Import Address Table 	192 	208
DIRECTORY_ENTRY_DELAY_IMPORT = 13		# Delay Import table 	200 	216
DIRECTORY_ENTRY_COM_DESCRIPTOR = 14		# COM descriptor table 	208 	224
#No constant name 	15 	Reserved 	216 	232

# Section Characteristics
SCN_MEM_EXECUTE = 0x20000000	# The section can be executed as code
SCN_MEM_READ = 0x40000000		# The section can be read
SCN_MEM_WRITE = 0x80000000		# The section can be written to