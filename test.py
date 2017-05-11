import idc
import idautils
import idaapi

def test():
    print('test')

#idc.AddHotkey('z', 'test')

hotkey_ctx = idaapi.add_hotkey('z', test)
if hotkey_ctx is None:
    print('Failed to register hotkey!')
    del hotkey_ctx
else:
    print('Hotkey registered!')