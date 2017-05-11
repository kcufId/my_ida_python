#!/usr/bin/env python2.7
# md5: 68CF2070D8FB4963211CFA4F2DAA72E5
# filename: 68CF2070D8FB4963211CFA4F2DAA72E5
# version: 2

## full-automatic

import idc
import idautils
import idaapi
from decode_string import done

ea = 0x004018E0         ## decrypt_string()

# call GetProcAddress to ea distance is: 0x29
# call GetProcAddress opcode: FF 15 74 00 42 00
delta = 0x29

proc_name = ''
for addr in idautils.CodeRefsTo(ea, 0):
    #print('[+] xrefs address: %#x ' % addr)
    temp = addr + delta
    if Dword(temp) == 0x7415ff and Byte(temp+6) == 0xA3:
        decode_data = Dword(addr-4)
        proc_name = done(decode_data)
        if not proc_name:
            print('[+] get proc name error')
            continue
        proc_name = 'g_%s' % proc_name
        proc_address = Dword(temp+7)
        rename = MakeName(proc_address, proc_name)
        if not rename:
            #print('[-]  proc name is already used')
            print('[-] proc_address, proc_name: %#x, %s' % (proc_address, proc_name))
    else:
        print('[-] no myGetProcAddress')





