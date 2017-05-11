#!/usr/bin/python 2.7
# md5: 978888892A1ED13E94D2FCB832A2A6B5
# filename: wtime32.dll
import idc
import idautils
import idaapi

def list_hex(int_list):
    hex_list = []
    for x in xrange(len(int_list)):
        hex_str = hex(int_list[x])
        hex_list.append(hex_str)
    return '[%s]' % ', '.join(hex_list)

def get_data(curr):
    data = []
    index = 0
    while True:
        var = Byte(curr+index)
        if not var:
            break
        data.append(Byte(curr+index))
        index += 1
    print(list_hex(data))
    return (data, len(data))

def decode(data, size):
    for i in xrange(size):
        temp = data[i] ^ 0x12
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
