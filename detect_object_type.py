import pykd

def main():
	nt_module = pykd.module("nt")
	ObpTypeDirectoryObject_addr = int(nt_module.ObpTypeDirectoryObject)
	ObpTypeDirectoryObject_value = pykd.loadQWords(ObpTypeDirectoryObject_addr, 1)[0]
	dict_entry_list = pykd.loadQWords(ObpTypeDirectoryObject_value, 37)
	print 'TypeName    PoolTag    PoolType'
	
	for dict_entry in dict_entry_list:
		if dict_entry == 0:
			continue
		type_obj_addr = pykd.loadQWords(dict_entry+8, 1)[0]
		name_str      = pykd.loadUnicodeString(type_obj_addr+0x10)
		key_str       = pykd.loadCStr(type_obj_addr+0xc0)
		pool_type     = pykd.loadDWords(type_obj_addr+0x40+0x24,1)[0]
		if pool_type == 1:
			pool_type = 'PagedPool'
		elif pool_type == 0x200:
			pool_type = 'NonPagedPoolNx'
		print '%s\n%s\n%s\n'%(name_str,key_str,pool_type)
	
if __name__ == "__main__":
	main()
	exit(0)