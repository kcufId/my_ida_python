#!/usr/bin/env python2.7
# md5: 68CF2070D8FB4963211CFA4F2DAA72E5
# filename: 68CF2070D8FB4963211CFA4F2DAA72E5
# version: 1.0

import idc
import idautils
import idaapi
#from print_hex import list_hex

def list_hex(int_list):
    """print to hex form list, 
    eg: [11, 23, 33] to [0xB, 0x17, 0x21]"""
    hex_list = []
    for x in xrange(len(int_list)):
        hex_str = hex(int_list[x])
        hex_list.append(hex_str)
    return '[%s]' % ', '.join(hex_list)

def get_data(curr):
    '''get crypted string'''
    data = []
    index = 0
    while True:
        var = idc.Byte(curr+index)
        if not var:
            break
        data.append(var)
        index += 1
    return (data, len(data))

def old_decode(data, size):
    '''decode data like base64'''
    sub_data = []
    for x in xrange(0, size, 4):
        for i in range(4):
            tmep = data[x+i]
            if temp == 0x3D:        ## '='
                break
            sub_data[i] = data[x]
## chr list  ;0123456789abcdefghijklmnopqrstuvwxyzABCDEF(&#^*$!@%)[]{}<>?`:,.
chr_list = [0x3B, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 
            0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B,
            0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
            0x77, 0x78, 0x79, 0x7A, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x28, 
            0x26, 0x23, 0x5E, 0x2A, 0x24, 0x21, 0x40, 0x25, 0x29, 0x5B, 0x5D, 
            0x7B, 0x7D, 0x3C, 0x3E, 0x3F, 0x60, 0x3A, 0x2C, 0x2E]

def search_chr(charr):
    """" return arg offset in list."""
    try:
        offset = chr_list.index(charr)
    except ValueError:
        print('[-] search_chr() error')
        offset = 0xFF
    return offset

def decode_four(byte_list, index=0):

    """decode list four bytes"""
    '''
    .text:004016D7                 mov     ecx, [esp+70h+offset_four]
    .text:004016DB                 mov     al, cl
    .text:004016DD                 add     al, al
    .text:004016DF                 mov     dl, ch
    .text:004016E1                 shr     dl, 4
    .text:004016E4                 and     dl, 3
    .text:004016E7                 add     al, al
    .text:004016E9                 add     dl, al
    .text:004016EB                 mov     al, byte ptr [esp+70h+offset_four+2]
    .text:004016EF                 mov     byte ptr [esp+70h+var_54], dl
    .text:004016F3                 mov     dl, al
    .text:004016F5                 shr     dl, 2
    .text:004016F8                 mov     cl, ch
    .text:004016FA                 shl     al, 6
    .text:004016FD                 add     al, byte ptr [esp+70h+offset_four+3]
    .text:00401701                 and     dl, 0Fh
    .text:00401704                 shl     cl, 4
    .text:00401707                 xor     dl, cl
    .text:00401709                 mov     byte ptr [esp+70h+var_54+1], dl
    .text:0040170D                 mov     byte ptr [esp+70h+var_54+2], al
    '''
    al = byte_list[0]
    al = (al + al) & 0xFF
    dl = byte_list[1]
    dl = dl >> 4
    dl = dl & 3
    al = (al + al) & 0xFF
    dl = (al + dl) & 0xFF
    first_chr = chr(dl)
    dl = byte_list[2]
    dl = dl >> 2
    dl = dl & 0x0F
    cl = byte_list[1]
    cl = (cl << 4) & 0xFF
    dl = dl ^ cl
    second_chr = chr(dl)
    al = byte_list[2]
    al = (al << 6) & 0xFF
    al = (al + byte_list[3]) & 0xFF
    three_chr = chr(al)
    print('[+] encode chr: %c, %c, %c' % (first_chr, second_chr, three_chr))
    if index:
        return (first_chr, second_chr, three_chr)
    return ''.join([first_chr, second_chr, three_chr])


def decode(data, size):
    """decode data like base64"""
    sub_data = [0, 0, 0, 0]
    offset = [0, 0, 0, 0]
    index = 0
    decode_str = ''
    for x in xrange(size):
        if data[x] == 0x3D:         ## '='
            break
        index += 1
        sub_index = x % 4
        sub_data[sub_index] = data[x]
        if index == 4:
            print('[+] sub_data %s' % list_hex(sub_data))
            for i in range(4):
                offset[i] = search_chr(sub_data[i])
            ## call decode this four byte
            print('[+] offset_list %s' % list_hex(offset))
            decode_str += decode_four(offset)

            index = 0
    if index:
        # surplus = 4 - index
        print("[+] exist '='  %s" % list_hex(data[-4:]))
        for i in range(4):
            offset[i] = search_chr(data[i-4])
        print('[+] end four chr offset %s' % list_hex(offset))
        end_four = decode_four(offset, index)
        for x in range(index-1):
            decode_str += end_four[x]

    return decode_str

# """
# Segmented from the main,other modules can be used.
def done(addr):
    print('[+] address: %#x' % addr)
    crypted_data, crypted_size = get_data(addr)
    if crypted_size > 0:
        decode_data = decode(crypted_data, crypted_size)
        idc.MakeRptCmt(addr, str(decode_data))
        return decode_data
        #print('[+] size: %#x' % crypted_size)
    else:
        print('[-] failed')
        return None

def main():
    print('[+] start')
    currer = idc.ScreenEA()
    done(currer)

#######################################################################
## hotkey
hotkey_ctx = idaapi.add_hotkey('z', main)
if hotkey_ctx is None:
    print('[-] Failed to register hotkey!')
    del hotkey_ctx
else:
    print('[+] Hotkey registered!')
## """

"""
## test unit
if __name__ == '__main__':
    test = [0x66, 0x7B, 0x38, 0x41, 0x6E, 0x6D, 0x67, 0x41, 0x66, 0x5D, 
            0x3A, 0x23, 0x72, 0x35, 0x34, 0x29, 0x70, 0x6C, 0x38, 0x26, 
            0x6F, 0x6A, 0x38, 0x45, 0x73, 0x35, 0x5B, 0x77, 0x72, 0x3B,
            0x3D, 0x3D]
    test2 = [0x69, 0x35, 0x3A, 0x77, 0x6F, 0x33, 0x63, 0x5B, 0x72, 0x43, 
             0x63, 0x2A, 0x72, 0x41, 0x72, 0x3D]
    decode_data = decode(test2, len(test2))
    print('[+] test unit decode_data: %s' % decode_data)
"""