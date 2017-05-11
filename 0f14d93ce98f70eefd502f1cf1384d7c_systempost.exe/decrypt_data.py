#!/usr/bin/python 
# md5: 0F14D93CE98F70EEFD502F1CF1384D7C
# filename: 0f14d93ce98f70eefd502f1cf1384d7c_systempost.exe!!
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
        temp = ((data[i] - 0xF) & 0xFF) ^ 0xC8
        data[i] = chr(temp)
        # temp =  temp & 0xFF
        # data[i] = temp ^ 0xC8
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

