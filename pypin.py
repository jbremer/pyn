from ctypes import CFUNCTYPE
from ctypes import c_int, c_char_p, c_void_p


IMAGECALLBACK = CFUNCTYPE(None, c_int, c_void_p)
RTN_INSTRUMENT_CALLBACK = CFUNCTYPE(None, c_int, c_void_p)
INS_INSTRUMENT_CALLBACK = CFUNCTYPE(None, c_int, c_void_p)
AFUNPTR = CFUNCTYPE(None)


# function with void return value
def _v(*args):
    return CFUNCTYPE(None, *args)


# function with integer (or address, for that matter) return value
def _i(*args):
    return CFUNCTYPE(c_int, *args)


# function with string return value
def _s(*args):
    return CFUNCTYPE(c_char_p, *args)


# we have to make sure callback functions are not garbage collected
_gc = []

# pin function declarations - functions which start with an underscore
# get special treatment, e.g., they take a callback function
_pin_function_decl = {
    # IMG
    'IMG_Next': _i(c_int),
    'IMG_Prev': _i(c_int),
    'IMG_Invalid': _i(),
    'IMG_Valid': _i(c_int),
    'IMG_SecHead': _i(c_int),
    'IMG_SecTail': _i(c_int),
    'IMG_RegsymHead': _i(c_int),
    'IMG_Entry': _i(c_int),
    'IMG_Name': _s(c_int),
    'IMG_Gp': _i(c_int),
    'IMG_LoadOffset': _i(c_int),
    'IMG_LowAddress': _i(c_int),
    'IMG_HighAddress': _i(c_int),
    'IMG_StartAddress': _i(c_int),
    'IMG_SizeMapped': _i(c_int),
    'IMG_Type': _i(c_int),
    'IMG_IsMainExecutable': _i(c_int),
    'IMG_IsStaticExecutable': _i(c_int),
    'IMG_Id': _i(c_int),
    'IMG_FindImgById': _i(c_int),
    'IMG_FindByAddress': _i(c_int),
    '_IMG_AddInstrumentFunction': _v(IMAGECALLBACK, c_void_p),
    '_IMG_AddUnloadFunction': _v(IMAGECALLBACK, c_void_p),
    'IMG_Open': _i(c_char_p),
    'IMG_Close': _v(c_int),

    # APP
    'APP_ImgHead': _i(),
    'APP_ImgTail': _i(),

    # RTN
    'RTN_Sec': _i(c_int),
    'RTN_Next': _i(c_int),
    'RTN_Prev': _i(c_int),
    'RTN_Invalid': _i(),
    'RTN_Valid': _i(c_int),
    'RTN_Name': _s(c_int),
    'RTN_Sym': _i(c_int),
    'RTN_Funptr': _i(c_int),
    'RTN_Id': _i(c_int),
    '_RTN_AddInstrumentFunction': _v(RTN_INSTRUMENT_CALLBACK, c_void_p),
    'RTN_Range': _i(c_int),
    'RTN_Size': _i(c_int),
    'RTN_FindNameByAddress': _s(c_int),
    'RTN_FindByAddress': _i(c_int),
    'RTN_FindByName': _i(c_int, c_char_p),
    'RTN_Open': _v(c_int),
    'RTN_Close': _v(c_int),
    'RTN_InsHead': _i(c_int),
    'RTN_InsHeadOnly': _i(c_int),
    'RTN_InsTail': _i(c_int),
    'RTN_NumIns': _i(c_int),
    '_RTN_InsertCall': _v(c_int, c_int, AFUNPTR),
    'RTN_Address': _i(c_int),
    'RTN_CreateAt': _i(c_int, c_char_p),
    '_RTN_Replace': CFUNCTYPE(AFUNPTR, c_int, AFUNPTR),

    # INS Instrumentation
    '_INS_AddInstrumentFunction': _v(INS_INSTRUMENT_CALLBACK, c_void_p),
    'INS_InsertCall': _v(c_int, c_int, AFUNPTR),

    # INS Generic Inspection
    'INS_Mnemonic': _s(c_int),
    'INS_IsOriginal': _i(c_int),
    'INS_Disassemble': _s(c_int),
    'INS_Next': _i(c_int),
    'INS_Prev': _i(c_int),
    'INS_Invalid': _i(),
    'INS_Valid': _i(c_int),
    'INS_Address': _i(c_int),
    'INS_Size': _i(c_int),

    # INS Modification
    'INS_InsertIndirectJump': _v(c_int, c_int, c_int),
    'INS_InsertDirectJump': _v(c_int, c_int, c_int),
    'INS_Delete': _v(c_int),
}

# the following line(s) are actually not required,
# but these are for the strict syntax checker(s)
_pin_function_addr = globals()['_pin_function_addr']

# not hacky at all!
for name, decl in _pin_function_decl.items():
    if name.startswith('_'):
        globals()[name] = decl(_pin_function_addr[name[1:]])
    else:
        globals()[name] = decl(_pin_function_addr[name])

# the following line(s) are actually not required,
# but these are for the strict syntax checker(s) - part #2
_IMG_AddInstrumentFunction = globals()['_IMG_AddInstrumentFunction']
_IMG_AddUnloadFunction = globals()['_IMG_AddUnloadFunction']
_RTN_AddInstrumentFunction = globals()['_RTN_AddInstrumentFunction']
_RTN_InsertCall = globals()['_RTN_InsertCall']
_RTN_Replace = globals()['_RTN_Replace']
_INS_AddInstrumentFunction = globals()['_INS_AddInstrumentFunction']


# override functions which accept callback functions, because
# they need some extra care
def IMG_AddInstrumentFunction(cb, arg):
    cb = IMAGECALLBACK(cb)
    _gc.extend((cb, arg))
    _IMG_AddInstrumentFunction(cb, arg)


def IMG_AddUnloadFunction(cb, arg):
    cb = IMAGECALLBACK(cb)
    _gc.extend((cb, arg))
    _IMG_AddUnloadFunction(cb, arg)


def RTN_AddInstrumentFunction(cb, arg):
    cb = RTN_INSTRUMENT_CALLBACK(cb)
    _gc.extend((cb, arg))
    _RTN_AddInstrumentFunction(cb, arg)


def RTN_InsertCall(rtn, action, cb, *args):
    cb = AFUNPTR(cb)
    _gc.append(cb)
    _RTN_InsertCall(rtn, action, cb, *args)


def RTN_Replace(rtn, func):
    func = AFUNPTR(func)
    _gc.append(func)
    _RTN_Replace(rtn, func)


def INS_AddInstrumentFunction(cb, arg):
    cb = INS_INSTRUMENT_CALLBACK(cb)
    _gc.extend((cb, arg))
    _INS_AddInstrumentFunction(cb, arg)
