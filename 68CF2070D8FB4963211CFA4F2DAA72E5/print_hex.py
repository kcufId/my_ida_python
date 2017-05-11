#!/usr/bin/env python2.7
"""print to hex form list, eg: [11, 23, 33] to [0xB, 0x17, 0x21]"""
def list_hex(int_list):
    hex_list = []
    for x in xrange(len(int_list)):
        hex_str = hex(int_list[x])
        hex_list.append(hex_str)
    return '[%s]' % ', '.join(hex_list)

"""
## test unit
if __name__ == '__main__':
    test = [11, 23, 33]
    print(list_hex(test))
"""
    