import idaapi
import ida_kernwin
import ida_xref
import ida_funcs
import ida_bytes
import idc

class TreeNode():
    def __init__(self,func_name,func_addr):
        self.func_name = func_name
        self.func_addr = func_addr
        self.sub_node_num = 0
        self.sub_node_list = []
        self.parent_node_num = 0
        self.parent_node_list = []

    def get_addr(self):
        return self.func_addr

    def get_name(self):
        return self.func_name

    def add_parent(self,parent):
        self.parent_node_list.append(parent)
        self.parent_node_num += 1

    def add_child(self, child):
        self.sub_node_list.append(child)
        self.sub_node_num += 1

class AnalyzExecution():
    def __init__(self,source_list):

        self.source_func_addr_list = source_list
        self.target_func_addr_list = []

        self.module_base = 0

        self.trace_start_node = []

        self.module_iat_dict = {}
        self.last_iat_module_name = ''
        self.target_func_name_dict = {
            "KERNEL32":
            [
                'WriteFile',
                'CreateFileA',
                'CreateFileW'
            ]
        }
        self.path_dict = {}

    def __enum_import_func_cb(self, ea, name, ord):
        self.module_iat_dict[self.last_iat_module_name][name] = ea
        return True

    def __get_image_iat(self):
        import_module_num = idaapi.get_import_module_qty()
        for index in range(import_module_num):
            module_name = idaapi.get_import_module_name(index)
            self.module_iat_dict[module_name] = {}
            self.last_iat_module_name = module_name
            idaapi.enum_import_names(index, self.__enum_import_func_cb)

    def __rebase_source_func(self):
        self.module_base = idaapi.get_imagebase()
        for index in range(len(self.source_func_addr_list)):
            self.source_func_addr_list[index] = self.source_func_addr_list[index] + self.module_base

    def __init_setting(self):
        self.__get_image_iat()
        self.__rebase_source_func()

    def __get_last_ins_addr(self,cur_ins_addr):
        ida_bytes.get_item_size(cur_ins_addr)

    def __get_relative_node(self,src_node,key_name):
        src_node_addr = src_node.get_addr()
        next_node_addr = ida_xref.get_first_cref_to(src_node_addr)
        print('[Debug]next_addr 0x%x' % next_node_addr)
        if next_node_addr ==  idaapi.BADADDR:
            return
        if next_node_addr != idc.PrevHead(src_node_addr):
            new_tree_node = TreeNode(ida_funcs.get_func_name(next_node_addr), next_node_addr)
            new_tree_node.add_parent(src_node)
            src_node.add_child(new_tree_node)
            print('[*]Add node %s 0x%x'%(new_tree_node.get_name(),new_tree_node.get_addr()))
            self.__get_relative_node(new_tree_node,key_name)

        next_node_addr = ida_xref.get_next_cref_to(src_node_addr, next_node_addr)
        print('[Debug]next_addr 0x%x' % next_node_addr)
        while next_node_addr != idaapi.BADADDR:
            if next_node_addr == idc.PrevHead(src_node_addr):
                continue
            new_tree_node = TreeNode(ida_funcs.get_func_name(next_node_addr), next_node_addr)
            new_tree_node.add_parent(src_node)
            src_node.add_child(new_tree_node)
            print('[*]Add node %s 0x%x' % (new_tree_node.get_name(), new_tree_node.get_addr()))
            self.__get_relative_node(new_tree_node,key_name)
            next_node_addr = ida_xref.get_next_cref_to(src_node_addr, next_node_addr)
            print('[Debug]next_addr 0x%x' % next_node_addr)
        return

    def __create_invoke_tree(self):
        # Create tarce start nodes
        for target_image in self.target_func_name_dict.keys():
            if target_image in self.module_iat_dict.keys():
                print('[*]Module %s is imported.' % target_image)
                for target_func_name in self.target_func_name_dict[target_image]:
                    if target_func_name in self.module_iat_dict[target_image]:
                        func_addr = self.module_iat_dict[target_image][target_func_name]
                        print('[*]Func %s at 0x%x' % (target_func_name,func_addr))
                        self.trace_start_node.append(TreeNode(target_func_name,func_addr))

        for start_Node in self.trace_start_node:
            print('[*]Seach for %s'%start_Node.get_name())
            self.path_dict[start_Node.get_name()] = []
            self.__get_relative_node(start_Node,start_Node.get_name())

    def start_analyze(self):
        self.__init_setting()
        self.__create_invoke_tree()

class MainClass(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Execution Path Analyze Plugin"
    help = "Execution Path Analyze Plugin"
    wanted_name = "ExePathAnalyze"
    wanted_hotkey = ""

    def __init__(self):
        super(MainClass, self).__init__()
        self._data = None

    def term(self):
        pass

    def init(self):
        init_str = '''
        ******************************************
        ******************************************
             Execution Path Analyze Plugin
        ******************************************
        ******************************************
'''
        print(init_str)
        return idaapi.PLUGIN_OK

    def run(self, arg):
        print("run")
        input_str = ida_kernwin.ask_text(100, '', 'Input Target Address')
        input_str_list = input_str.split(';')
        addr_list = []
        for addr_str in input_str_list:
            if addr_str == '':
                continue
            addr_list.append(int(addr_str,16))

        DoAnalyze = AnalyzExecution(addr_list)
        DoAnalyze.start_analyze()

def PLUGIN_ENTRY():
   return MainClass()


