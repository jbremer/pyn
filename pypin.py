from ctypes import CFUNCTYPE
from ctypes import c_int, c_char_p, c_void_p


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
_INS_AddInstrumentFunction = globals()['_INS_AddInstrumentFunction']


# override functions which accept callback functions, because
# they need some extra care
def INS_AddInstrumentFunction(cb, arg):
    cb = INS_INSTRUMENT_CALLBACK(cb)
    _gc.extend((cb, arg))
    _INS_AddInstrumentFunction(cb, arg)
