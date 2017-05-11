#!/usr/bin/python 
# md5: 9f022df0bcfded9377baf4da1fbe7b8c
# filename: 9f022df0bcfded9377baf4da1fbe7b8c_Windows-KB271784-x86.exe
import idc
import idautils
import idaapi

def get_data(curr):
    data = []
    index = 0
    while True:
        var = Word(curr+index)
        if not var:
            break
        #print('[d] var2: %#x ' % Byte(curr+index))
        data.append(Byte(curr+index))
        index += 2
    #print(data)
    return (data, len(data))

def decode(data, size):
    for i in xrange(size):
        temp = (data[i] ^ 0x15)
        data[i] = chr(temp)
    print('[+] decode string: %s' % ''.join(data))
    return ''.join(data)
def main():
    print('[+] start')
    currer = idc.ScreenEA()
    print('[+] address: %#x' % currer)
    crypted_data, crypted_size = get_data(currer)
    if crypted_size > 0:
        decode_data = decode(crypted_data, crypted_size)
        idc.MakeRptCmt(currer, str(decode_data))
    else:
        print('[-] failed')
#main()
hotkey_ctx = idaapi.add_hotkey('z', main)
if hotkey_ctx is None:
    print('[-] Failed to register hotkey!')
    del hotkey_ctx
else:
    print('[+] Hotkey registered!')

