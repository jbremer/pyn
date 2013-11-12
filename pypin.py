from ctypes import CFUNCTYPE, POINTER
from ctypes import c_int, c_char_p, c_void_p, c_longlong


IMAGECALLBACK = CFUNCTYPE(None, c_int, c_void_p)
RTN_INSTRUMENT_CALLBACK = CFUNCTYPE(None, c_int, c_void_p)
TRACE_INSTRUMENT_CALLBACK = CFUNCTYPE(None, c_int, c_void_p)
INS_INSTRUMENT_CALLBACK = CFUNCTYPE(None, c_int, c_void_p)
AFUNPTR = CFUNCTYPE(None)
TRACE_BUFFER_CALLBACK = CFUNCTYPE(c_void_p, c_int, c_int, c_void_p,
                                  c_void_p, c_longlong, c_void_p)
ROOT_THREAD_FUNC = CFUNCTYPE(None, c_void_p)
SYSCALL_ENTRY_CALLBACK = CFUNCTYPE(None, c_int, c_void_p, c_int, c_void_p)
SYSCALL_EXIT_CALLBACK = CFUNCTYPE(None, c_int, c_void_p, c_int, c_void_p)


# function with void return value
def _v(*args):
    return CFUNCTYPE(None, *args)


# function with void pointer as return value
def _vp(*args):
    return CFUNCTYPE(c_void_p, *args)


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

    # TRACE
    '_TRACE_AddInstrumentFunction': _v(TRACE_INSTRUMENT_CALLBACK, c_void_p),
    '_TRACE_InsertCall': _v(c_int, c_int, AFUNPTR),
    'TRACE_BblHead': _i(c_int),
    'TRACE_BblTail': _i(c_int),
    'TRACE_Original': _i(c_int),
    'TRACE_Address': _i(c_int),
    'TRACE_Size': _i(c_int),
    'TRACE_Rtn': _i(c_int),
    'TRACE_HasFallThrough': _i(c_int),
    'TRACE_NumBbl': _i(c_int),
    'TRACE_NumIns': _i(c_int),
    'TRACE_StubSize': _i(c_int),

    # BBL
    'BBL_MoveAllAttributes': _v(c_int, c_int),
    'BBL_NumIns': _i(c_int),
    'BBL_InsHead': _i(c_int),
    'BBL_InsTail': _i(c_int),
    'BBL_Next': _i(c_int),
    'BBL_Prev': _i(c_int),
    'BBL_Valid': _i(c_int),
    'BBL_Original': _i(c_int),
    'BBL_Address': _i(c_int),
    'BBL_Size': _i(c_int),
    '_BBL_InsertCall': _v(c_int, c_int, AFUNPTR),
    'BBL_HasFallThrough': _i(c_int),

    # INS Instrumentation
    '_INS_AddInstrumentFunction': _v(INS_INSTRUMENT_CALLBACK, c_void_p),
    'INS_InsertCall': _v(c_int, c_int, AFUNPTR),

    # INS Generic Inspection
    'INS_Category': _i(c_int),
    'INS_Extension': _i(c_int),
    'INS_MemoryOperandSize': _i(c_int, c_int),
    'INS_MemoryWriteSize': _i(c_int),
    'INS_GetPredicate': _i(c_int),
    'INS_MemoryReadSize': _i(c_int),
    'INS_IsMemoryRead': _i(c_int),
    'INS_IsMemoryWrite': _i(c_int),
    'INS_HasMemoryRead2': _i(c_int),
    'INS_HasFallThrough': _i(c_int),
    'INS_IsLea': _i(c_int),
    'INS_IsNop': _i(c_int),
    'OPCODE_StringShort': _s(c_int),
    'INS_Mnemonic': _s(c_int),
    'INS_IsBranch': _i(c_int),
    'INS_IsDirectBranch': _i(c_int),
    'INS_IsDirectCall': _i(c_int),
    'INS_IsDirectBranchOrCall': _i(c_int),
    'INS_IsBranchOrCall': _i(c_int),
    'INS_Stutters': _i(c_int),
    'INS_IsCall': _i(c_int),
    'INS_IsProcedureCall': _i(c_int),
    'INS_IsRet': _i(c_int),
    'INS_IsSysret': _i(c_int),
    'INS_IsPrefetch': _i(c_int),
    'INS_IsAtomicUpdate': _i(c_int),
    'INS_IsIndirectBranchOrCall': _i(c_int),
    'INS_RegR': _i(c_int),
    'INS_RegW': _i(c_int),
    'INS_Opcode': _i(c_int),
    'CATEGORY_StringShort': _s(c_int),
    'EXTENSION_StringShort': _s(c_int),
    'INS_MaxNumRRegs': _i(c_int),
    'INS_MaxNumWRegs': _i(c_int),
    'INS_RegRContain': _i(c_int, c_int),
    'INS_RegWContain': _i(c_int, c_int),
    'INS_IsStackRead': _i(c_int),
    'INS_IsStackWrite': _i(c_int),
    'INS_IsIpRelRead': _i(c_int),
    'INS_IsIpRelWrite': _i(c_int),
    # 'INS_IsPredicated': _i(c_int),
    'INS_IsOriginal': _i(c_int),
    'INS_Disassemble': _s(c_int),
    'INS_MemoryOperandCount': _i(c_int),
    'INS_OperandIsAddressGenerator': _i(c_int, c_int),
    'INS_MemoryOperandIsRead': _i(c_int, c_int),
    'INS_MemoryOperandIsWritten': _i(c_int, c_int),
    'INS_IsSyscall': _i(c_int),
    'INS_SyscallStd': _i(c_int),
    'INS_Rtn': _i(c_int),
    'INS_Next': _i(c_int),
    'INS_Prev': _i(c_int),
    'INS_Invalid': _i(),
    'INS_Valid': _i(c_int),
    'INS_Address': _i(c_int),
    'INS_Size': _i(c_int),
    'INS_DirectBranchOrCallTargetAddress': _i(c_int),
    'INS_NextAddress': _i(c_int),

    # INS ia32/intel64 Inspection TODO

    # INS Modification
    'INS_InsertIndirectJump': _v(c_int, c_int, c_int),
    'INS_InsertDirectJump': _v(c_int, c_int, c_int),
    'INS_Delete': _v(c_int),

    # SYM
    'SYM_Next': _i(c_int),
    'SYM_Prev': _i(c_int),
    'SYM_Name': _s(c_int),
    'SYM_Invalid': _i(),
    'SYM_Valid': _i(c_int),
    'SYM_Dynamic': _i(c_int),
    'SYM_IFunc': _i(c_int),
    'SYM_Value': _i(c_int),
    'SYM_Index': _i(c_int),
    'SYM_Address': _i(c_int),
    'PIN_UndecorateSymbolName': _s(c_char_p, c_int),

    # Controlling and Initializing
    'PIN_VmFullPath': _s(),
    'PIN_SafeCopy': _i(c_void_p, c_void_p, c_int),

    # Fast Buffering
    '_PIN_DefineTraceBuffer': _i(c_int, c_int,
                                 TRACE_BUFFER_CALLBACK, c_void_p),
    'PIN_AllocateBuffer': _vp(c_int),
    'PIN_DeallocateBuffer': _v(c_int, c_void_p),
    'PIN_GetBufferPointer': _vp(c_void_p, c_int),

    # Pin Process
    'PIN_IsProcessExiting': _i(),
    'PIN_ExitProcess': _v(c_int),
    'PIN_GetPid': _i(),
    'PIN_ExitApplication': _v(c_int),

    # Pin Thread
    'PIN_GetTid': _i(),
    'PIN_ThreadId': _i(),
    'PIN_ThreadUid': _i(),
    'PIN_GetParentTid': _i(),
    'PIN_Sleep': _v(c_int),
    'PIN_Yield': _v(),
    '_PIN_SpawnInternalThread': _i(ROOT_THREAD_FUNC, c_void_p,
                                   c_int, POINTER(c_int)),
    'PIN_ExitThread': _v(c_int),
    'PIN_IsApplicationThread': _i(),
    'PIN_WaitForThreadTermination': _i(c_void_p, c_int, POINTER(c_int)),
    'PIN_CreateThreadDataKey': _i(c_void_p),
    'PIN_DeleteThreadDataKey': _i(c_int),
    'PIN_SetThreadData': _i(c_int, c_void_p, c_int),
    'PIN_GetThreadData': _vp(c_int, c_int),

    # Pin System Call
    '_PIN_AddSyscallEntryFunction': _v(SYSCALL_ENTRY_CALLBACK, c_void_p),
    '_PIN_AddSyscallExitFunction': _v(SYSCALL_EXIT_CALLBACK, c_void_p),
    'PIN_SetSyscallArgument': _v(c_void_p, c_int, c_int, c_int),
    'PIN_GetSyscallArgument': _i(c_void_p, c_int, c_int),
    'PIN_SetSyscallNumber': _v(c_void_p, c_int, c_int),
    'PIN_GetSyscallNumber': _i(c_void_p, c_int),
    'PIN_GetSyscallReturn': _i(c_void_p, c_int),
    'PIN_GetSyscallErrno': _i(c_void_p, c_int),

    # Context Manipulation
    'PIN_SetContextReg': _v(c_void_p, c_int, c_int),
    'PIN_GetContextReg': _i(c_void_p, c_int),
    'PIN_SaveContext': _v(c_void_p, c_void_p),
    'PIN_ExecuteAt': _v(c_void_p),
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
_TRACE_AddInstrumentFunction = globals()['_TRACE_AddInstrumentFunction']
_TRACE_InsertCall = globals()['_TRACE_InsertCall']
_BBL_InsertCall = globals()['_BBL_InsertCall']
_INS_AddInstrumentFunction = globals()['_INS_AddInstrumentFunction']
_PIN_DefineTraceBuffer = globals()['_PIN_DefineTraceBuffer']
_PIN_SpawnInternalThread = globals()['_PIN_SpawnInternalThread']
_PIN_AddSyscallEntryFunction = globals()['_PIN_AddSyscallEntryFunction']
_PIN_AddSyscallExitFunction = globals()['_PIN_AddSyscallExitFunction']


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


def TRACE_AddInstrumentFunction(cb, arg):
    cb = TRACE_INSTRUMENT_CALLBACK(cb)
    _gc.extend((cb, arg))
    _TRACE_AddInstrumentFunction(cb, arg)


def TRACE_InsertCall(trace, action, cb, *args):
    cb = AFUNPTR(cb)
    _gc.append(cb)
    _TRACE_InsertCall(trace, action, cb, *args)


def BBL_InsertCall(bbl, action, cb, *args):
    cb = AFUNPTR(cb)
    _gc.append(cb)
    _BBL_InsertCall(bbl, action, cb, *args)


def INS_AddInstrumentFunction(cb, arg):
    cb = INS_INSTRUMENT_CALLBACK(cb)
    _gc.extend((cb, arg))
    _INS_AddInstrumentFunction(cb, arg)


def PIN_DefineTraceBuffer(record_size, num_pages, cb, arg):
    cb = TRACE_BUFFER_CALLBACK(cb)
    _gc.extend((cb, arg))
    _PIN_DefineTraceBuffer(record_size, num_pages, cb, arg)


def PIN_SpawnInternalThread(cb, arg, stack_size, thread_uid):
    cb = ROOT_THREAD_FUNC(cb)
    _gc.extend((cb, arg, thread_uid))
    _PIN_SpawnInternalThread(cb, arg, stack_size, thread_uid)


def PIN_AddSyscallEntryFunction(cb, arg):
    cb = SYSCALL_ENTRY_CALLBACK(cb)
    _gc.extend((cb, arg))
    _PIN_AddSyscallEntryFunction(cb, arg)


def PIN_AddSyscallExitFunction(cb, arg):
    cb = SYSCALL_EXIT_CALLBACK(cb)
    _gc.extend((cb, arg))
    _PIN_AddSyscallExitFunction(cb, arg)
