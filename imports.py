
def find_import_functions():
    import ida_nalt as api
    imported_function_list = []    
    def imports_names_cb(ea, name, ord):
        if name is not None:
            imported_function_list.append(name)
                
        # True -> Continue enumeration
        # False -> Stop enumeration
        return True

    nimps = api.get_import_module_qty()
    for i in xrange(nimps):
        name = api.get_import_module_name(i)
        api.enum_import_names(i, imports_names_cb)
        
    return imported_function_list

if __name__ == '__main__':
    imports_list = find_import_functions()
    print([i for i in imports_list])