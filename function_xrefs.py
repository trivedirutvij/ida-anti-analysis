def function_xrefs(name):
	import idc
	import idautils
	functions_that_exit = []
	wf_addr = idc.get_name_ea_simple(name)
	print hex(wf_addr), idc.generate_disasm_line(wf_addr, 0)
	for addr in idautils.CodeRefsTo(wf_addr, 0):
		functions_that_exit.append(idc.get_func_name(addr))
	return functions_that_exit

if __name__ == '__main__':
	func_name = input('[+] Enter the name of the import: ')
	xrefs_list = function_xrefs(func_name)

	for i in xrefs_list:
		print('[*] ' + i)