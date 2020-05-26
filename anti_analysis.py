import os
import hashlib
import imports as imp
import idautils
import function_xrefs as fte 

print('-----------------------------------------------')
print('[+] Starting now\n')

'''
Get the name of the file and the file path, combine these two into the absolute file path.
Then, get the hash of the file.
'''
filename = idaapi.get_root_filename()
path = os.getcwd()
path = path + '\\'+ filename
print('[+] Name of file (with path): ' + path)
hasher = hashlib.md5()
with open(path, 'rb') as afile:
    buf = afile.read()
    hasher.update(buf)
print('[+] MD5 hash: ' + hasher.hexdigest())



'''
Begin processing of the disassembly
'''

'''

Check for the text segment (code) and then get its start and end address

'''

for seg in Segments():
	if get_segm_name(seg) == '.text':
		start = get_segm_start(seg)
		end = get_segm_end(seg)

'''

Check imported functions first

'''

imps_list = imp.find_import_functions()
print('[+] Text segment start: \t {}\t Text segment end: \t {}'.format(start,end))

if 'IsDebuggerPresent' in imps_list:
	print('[+] IsDebuggerPresent found')
else:
	print('[-] IsDebuggerPresent not found')

if 'CheckRemoteDebuggerPresent' in imps_list:
	print('[+] CheckRemoteDebuggerPresent found')
else:
	print('[-] CheckRemoteDebuggerPresent not found')

if 'GetTickCount' in imps_list:
	print('[+] GetTickCount found')
else:
	print('[-] GetTickCount not found')

if 'NtQueryInformationProcess' in imps_list:
	print('[+] NtQueryInformationProcess found')
else:
	print('[-] NtQueryInformationProcess not found')

if 'RegQueryValueExA' in imps_list:
	print('[+] RegQueryValueExA found. This is used to check against popular sandboxing tools\' product keys, such as 76487-640-1457236-23837 for Anubis')	
else:
	print('[-] RegQueryValueExA not found')



# Look for functions that call ExitProcess


functions_that_exit = fte.function_xrefs('ExitProcess')
print('[+] The following functions have ExitProcess: ')
for i in functions_that_exit:
	print('\t[ ] ' + i)


# Other anti-analysis detection methods


for funcEA in Functions(start,end):
	name = get_func_name(funcEA)
	for (start_func,end_func) in Chunks(funcEA):
		for head in Heads(start_func, end_func):
			disasm = GetDisasm(head)
			comments = get_cmt(head, 0)
		
			# The in instruction

			if 'in' == print_insn_mnem(head):
				print('[+] IN in ' + "0x%08x"%(head))
			
			# Timing checks 

			if 'rdtsc' in disasm:
				print '[ ] Timing check (rdtsc) detected, could be anti-debugging.'
			
			if 'GetTickCount' in disasm:
				
				# If GetTickCount referenced twice in the same function

				print '[ ] Timing check (GetTickCount) detected in ' + name + ' at ' + "0x%08x"%(head) + ' , could be anti-debugging.'
				if 'jmp     ds:' not in disasm:
					temp = head + 6 # size of GetTickCount call
					disasm_temp = GetDisasm(temp)
					for i in range(1000):
						if 'call    ds:GetTickCount' in disasm_temp:
							print '\t[ ] Another GetTickCount found at ', "0x%08x"%(temp), ": could be used to measure time difference between these two calls."
							new_temp = temp + 6
							new_disasm_temp = GetDisasm(new_temp)
							for i in range(1000):
								if 'ExitProcess' in new_disasm_temp:
									print '\t\t[+] ExitProcess found at ', "0x%08x"%(new_temp), ', could be anti-debugging technique'
									break
								elif 'call' in new_disasm_temp:
									called_function = print_operand(new_temp, 0)
									if called_function in functions_that_exit:
										print '\t\t[+] ExitProcess found within ', name, ', could be anti-debugging technique'
								
								new_temp = next_head(new_temp)
								new_disasm_temp = GetDisasm(new_temp)
							break
						else:
							temp = next_head(temp)
							disasm_temp = GetDisasm(temp)
				else:
					# For when GetTickCount is called in orphaned code

					xref_addresses = CodeRefsTo(head, 0)
					xref_addresses_better = []
					for i in xref_addresses:
						new_addr = hex(i)
						new_addr = new_addr[:-1]
						new_addr = new_addr[:2] + '00' + new_addr[2:]
						xref_addresses_better.append(new_addr)
					print('\t[ ] Addresses which call GetTickCount: ')
					for i in xref_addresses_better:
						print('\t\t[ ] '+ i)
					
					for i in xref_addresses_better:
						for j in xref_addresses_better:
							a = int(i, 16)
							b = int(j, 16)
							if a > b:
								temp = b
								temp = next_head(temp)
								counter = 0
								for k in range(12):
									if a == temp:
										print('\t\t[ ] Number of instructions between ' + hex(a) + ' and ' + hex(b) + ' is ' + str(counter))
										break
									else:
										temp = next_head(temp)
										counter += 1	

			# IsDebuggerPresent

			if 'IsDebuggerPresent' in disasm:
				print '[ ] IsDebuggerPresent in ' + name + ' at ' + "0x%08x"%(head)
				temp = next_head(temp)
				for i in range(1000):
					if 'ExitProcess' in GetDisasm(temp):
						print '\t\t[+] ExitProcess found at ', "0x%08x"%(temp), ', could be anti-debugging technique'
						break
					elif 'call' in GetDisasm(temp):
						called_function = print_operand(temp, 0)
						if called_function in functions_that_exit:
							print '\t\t[+] ExitProcess found within ', name, ', could be anti-debugging technique'

			# CheckRemoteDebuggerPresent

			if 'CheckRemoteDebuggerPresent' in disasm:
				print '[ ] CheckRemoteDebuggerPresent in ' + name + ' at ' + "0x%08x"%(head)
				temp = next_head(temp)
				for i in range(1000):
					if 'ExitProcess' in GetDisasm(temp):
						print '\t\t[+] ExitProcess found at ', "0x%08x"%(temp), ', could be anti-debugging technique'
						break
					elif 'call' in GetDisasm(temp):
						called_function = print_operand(temp, 0)
						if called_function in functions_that_exit:
							print '\t\t[+] ExitProcess found within ', name, ', could be anti-debugging technique'


			# Software breakpoints

			if 'int     3' in disasm:
				temp = head
				print '[ ] INT Scanned refrenced in ', name, ":", "0x%08x"%(head), ":", GetDisasm(head)
				for i in range(1000):
					temp = next_head(temp)
					if 'ExitProcess' in GetDisasm(temp):
						print '[+] INT Scanned at ', "0x%08x"%(temp), ' leads to termination in ', name, ":", "0x%08x"%(temp), ":", GetDisasm(head)
						break
					elif 'call' in GetDisasm(temp):
						called_function = print_operand(temp, 0)
						if called_function in functions_that_exit:
							print '\t\t[+] ExitProcess found within ', name, ', could be anti-debugging technique'

			# PEB Access

			if 'fs:' in disasm:
				if '30h' in disasm:
					print '[+] PEB (From TEB at 30h) referenced in ', name, ":", "0x%08x"%(head), ":", GetDisasm(head)	
					next_address = next_head(head)
					next_disasm = GetDisasm(next_address)

					# NTGlobalFlag accessed

					if '68h' in next_disasm:
						print '\t[ ] NTGlobalFlag accessed in ', name, ':', "0x%08x"%(next_address), ":", next_disasm, ', could be anti-debugging'
						for i in range(1000):
							if 'ExitProcess' in GetDisasm(next_address):
								print '\t\t[+] ExitProcess found at ', "0x%08x"%(next_address), ":", GetDisasm(next_address)
								break
							elif 'call' in next_disasm:
								called_function = print_operand(next_address, 0)
								if called_function in functions_that_exit:
									print '\t\t[+] ExitProcess found within ', name, ', could be anti-debugging technique'
								break
							else:
								next_address = next_head(next_address)
					
					elif '2' in next_disasm:
						print '\t[ ] BeingDebugged accessed in ', name, ':', "0x%08x"%(next_address), ":", next_disasm, ', could be anti-debugging'
						for i in range(1000):
							if 'ExitProcess' in GetDisasm(next_address):
								print '\t\t[+] ExitProcess found at ', "0x%08x"%(next_address), ":", GetDisasm(next_address)
								break
							elif 'call' in next_disasm:
								called_function = print_operand(next_address, 0)
								if called_function in functions_that_exit:
									print '\t\t[+] ExitProcess found within ', name, ', could be anti-debugging technique'
								break
							else:
								next_address = next_head(next_address)
					
					elif '18h' in disasm:
						print '[+] PEB itself referenced in ', name, ":", "0x%08x"%(head), ":", GetDisasm(head)
						prev_address = prev_head(head)
						prev_disasm = GetDisasm(prev_address)
						print('\tPrev instruction: ' + prev_disasm)
						next_address = next_head(head)
						next_disasm = GetDisasm(next_address)
						print('\tNext instruction: ' + next_disasm)
			
			# The cpuid instruction for anti-am

			if 'cpuid' in disasm:
				print '[+] CPUID instruction referenced in ', name, ":", "0x%08x"%(head), ":", GetDisasm(head), ', could be anti-VM technique.'
				prev_address = prev_head(head)
				prev_disasm = GetDisasm(prev_address)
				print('\t[+] Previous instruction: ' + prev_disasm)
				
			# Detecting VMXh

			if '564D5868' in disasm:
				print '[ ] 0x564D5868 referenced in ', name, ":", "0x%08x"%(head), ":", GetDisasm(head)
			if comments != None:
				if '76487-640-1457236-23837' in comments:
					print('[+] Code checks for an Anubis sandbox. ')
				
				if '76487-644-3177037-23510' in comments: 
					print('[+] Code checks for a CWSandbox (old version) sandbox. ')

				if '55274-640-2673064-23950' in comments: 
					print('[+] Code checks for a JoeBox sandbox. ')

				if '76497-640-6308873-23835' in comments: 
					print('[+] Code checks for a CWSandbox (2.1.22) sandbox. ')
