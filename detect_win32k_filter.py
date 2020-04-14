import pykd
import sys
import struct

def main(argv):
	
	if len(argv) == 0:
		print "Usage: !py filter.py from_level to_level filtered"
		print "Filtered syscalls for 5th level: !py filter.py 5 5 1"
		exit(-1)
		
	ntMod = pykd.module("nt")
	KeServiceDescriptorTableFilter = int(ntMod.KeServiceDescriptorTableFilter)

	win32Mod = pykd.module("win32k")
	W32pServiceTableFilter = int(win32Mod.W32pServiceTableFilter)
	W32pServiceLimitFilter = pykd.loadDWords(win32Mod.W32pServiceLimitFilter, 1)[0] + 0x1000
	print '[*]W32pServiceTableFilter Address:'
	print '[*]'+str(hex(W32pServiceTableFilter))
	
	win32BaseMod = pykd.module("win32kbase")
	gaWin32KFilterBitmap = int(win32BaseMod.gaWin32KFilterBitmap)
	print '[*]gaWin32KFilterBitmap Address:'
	print '[*]'+str(hex(gaWin32KFilterBitmap))
	
	start_level = int(argv[0])
	end_level = int(argv[1])
	filter = int(argv[2])
	sum = 0
	syscallsLimit = W32pServiceLimitFilter - 0x1000
	
	for i in range(start_level, end_level + 1):
		bitmap = pykd.loadQWords(gaWin32KFilterBitmap + i * 8, 1)[0]
		
		print '[*]=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-='
		print '[*]Bitmap filter level ' + str(hex(i))
		if filter:
			print '[*]Show Filtered'
		else:
			print '[*]Show Unfiltered'
		if not bitmap:
			print '[*] None'
			continue
		  
		# Check SSSDT ID for 0x1000
		for j in range(0x1000, W32pServiceLimitFilter):
			# bit index in byte
			syscallNum = j & 0xfff  
			# function offset in W32pServiceTableFilter
			offset =  pykd.loadDWords(W32pServiceTableFilter + syscallNum * 4, 1)[0]
			offset = (0xfffffffff0000000 | (offset >> 4))
			# function address
			syscall = W32pServiceTableFilter + offset
			syscall = syscall % 2**64
			# check
			check_byte = pykd.loadBytes(bitmap + (syscallNum >> 3), 1)[0]
			filtered = check_byte & (1 << (syscallNum & 7))
			filtered = filtered != 0
			
			# 1 is filtered,0 is unfiltered
			if filtered == filter:
				sum = sum + 1
				print '[*]'+pykd.findSymbol(syscall) + ' ' + hex(j)
		
		if filter:
			print "[*]number of filtered system calls"
		else:
			print "[*]number of allowed system calls"
		print '[*]'+str(syscallsLimit) + "/" + str(sum)

	exit(0)
	
		
if __name__ == "__main__":
	main(sys.argv[1:])