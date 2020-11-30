import idaapi
import ida_kernwin
import ida_struct
import ida_nalt

class MainClass(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Structure Initialization"
    help = "Structure Initialization"
    wanted_name = "StructInit"
    wanted_hotkey = "ALT+F9"

    def __init__(self):
        super(MainClass, self).__init__()
        self._data = None

    def term(self):
        pass

    def init(self):
        init_str = '''
        ******************************************
        ******************************************
        **Structure Initialization Plugin Loaded**
        ******************************************
        ******************************************
'''
        print(init_str)
        return idaapi.PLUGIN_OK

    def run(self, arg):
        print("Structure Initialization Run...")
        struct_name = ida_kernwin.ask_str('',0,'Target struct name:')
        if struct_name == '':
            return
        struct_id = ida_struct.get_struc_id(struct_name)
        p_struct = ida_struct.get_struc(struct_id)
        struct_size = ida_struct.get_max_offset(p_struct)
        ti = ida_nalt.opinfo_t()
        member_offset = 0
        while member_offset < struct_size:
             p_member = ida_struct.get_member(p_struct,member_offset)
             if p_member is None:
                ida_struct.add_struc_member(p_struct,'field_'+str(hex(member_offset)),member_offset,idaapi.qwrdflag(),None,8)
             member_offset += 8



def PLUGIN_ENTRY():
   return MainClass()


