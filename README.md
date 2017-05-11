# my_ida_python
My idapython  

driectory format: md5_[filename]

0f14d93ce98f70eefd502f1cf1384d7c_systempost.exe
    crypted data format: b4 d7 b8 d7 b0 d7 b3 d7 ca d7 cb d7 cb d7 b6 d7 c9 d7 bc d7
    Decryption every byte, will receive unicode string. I ignore 0xd7(even position),receive ascii string.
    The main algorithm:
    for i in xrange(size):
        temp = ((data[i] - 0xF) & 0xFF) ^ 0xC8
        data[i] = chr(temp)

9f022df0bcfded9377baf4da1fbe7b8c_Windows-KB271784-x86
    encryption algo: xor 0x15
    for i in xrange(size):
        temp = (data[i] ^ 0x15)
        data[i] = chr(temp)

68CF2070D8FB4963211CFA4F2DAA72E5
    encryption algo: similar base64. 
    when analyzing,coding a fucntion list_hex() to print the numer in the list:
    """print to hex form list, 
    eg: [11, 23, 33] to [0xB, 0x17, 0x21]"""
    hex_list = []
    for x in xrange(len(int_list)):
        hex_str = hex(int_list[x])
        hex_list.append(hex_str)
    return '[%s]' % ', '.join(hex_list)
 
978888892A1ED13E94D2FCB832A2A6B5_wtime32.dll
    encryption algo: xor 0x12
    for i in xrange(size):
        temp = data[i] ^ 0x12
        data[i] = chr(temp)
        
 
