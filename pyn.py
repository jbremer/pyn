from ctypes import CFUNCTYPE, POINTER, cast, memmove, create_string_buffer
from ctypes import c_int, c_long, c_char_p, c_void_p, c_longlong


AFUNPTR = CFUNCTYPE(None)
TRACE_BUFFER_CALLBACK = CFUNCTYPE(c_void_p, c_int, c_int, c_void_p,
                                  c_void_p, c_longlong, c_void_p)
ROOT_THREAD_FUNC = CFUNCTYPE(None, c_void_p)


def read_ptr(addr):
    """Read a pointer at a given address."""
    return cast(addr, POINTER(c_long)).contents.value


def read_str(addr):
    """Read a zero-terminated string from memory."""
    return cast(addr, c_char_p).value


def read_mem(addr, size):
    """Read a chunk of memory."""
    buf = create_string_buffer(size)
    memmove(buf, addr, size)
    return buf.raw


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

# IMG
IMG_Next = _i(c_int)
IMG_Prev = _i(c_int)
IMG_Invalid = _i()
IMG_Valid = _i(c_int)
IMG_SecHead = _i(c_int)
IMG_SecTail = _i(c_int)
IMG_RegsymHead = _i(c_int)
IMG_Entry = _i(c_int)
IMG_Name = _s(c_int)
IMG_Gp = _i(c_int)
IMG_LoadOffset = _i(c_int)
IMG_LowAddress = _i(c_int)
IMG_HighAddress = _i(c_int)
IMG_StartAddress = _i(c_int)
IMG_SizeMapped = _i(c_int)
IMG_Type = _i(c_int)
IMG_IsMainExecutable = _i(c_int)
IMG_IsStaticExecutable = _i(c_int)
IMG_Id = _i(c_int)
IMG_FindImgById = _i(c_int)
IMG_FindByAddress = _i(c_int)
IMG_Open = _i(c_char_p)
IMG_Close = _v(c_int)

# APP
APP_ImgHead = _i()
APP_ImgTail = _i()

# RTN
RTN_Sec = _i(c_int)
RTN_Next = _i(c_int)
RTN_Prev = _i(c_int)
RTN_Invalid = _i()
RTN_Valid = _i(c_int)
RTN_Name = _s(c_int)
RTN_Sym = _i(c_int)
RTN_Funptr = _i(c_int)
RTN_Id = _i(c_int)
RTN_Range = _i(c_int)
RTN_Size = _i(c_int)
RTN_FindNameByAddress = _s(c_int)
RTN_FindByAddress = _i(c_int)
RTN_FindByName = _i(c_int, c_char_p)
RTN_Open = _v(c_int)
RTN_Close = _v(c_int)
RTN_InsHead = _i(c_int)
RTN_InsHeadOnly = _i(c_int)
RTN_InsTail = _i(c_int)
RTN_NumIns = _i(c_int)
_RTN_InsertCall = _v(c_int, c_int, AFUNPTR)
RTN_Address = _i(c_int)
RTN_CreateAt = _i(c_int, c_char_p)
_RTN_Replace = CFUNCTYPE(AFUNPTR, c_int, AFUNPTR)

# SEC
SEC_Img = _i(c_int)
SEC_Next = _i(c_int)
SEC_Prev = _i(c_int)
SEC_Invalid = _i()
SEC_Valid = _i(c_int)
SEC_RtnHead = _i(c_int)
SEC_RtnTail = _i(c_int)
SEC_Name = _s(c_int)
SEC_Type = _i(c_int)
SEC_Mapped = _i(c_int)
SEC_Data = _vp(c_int)
SEC_Address = _i(c_int)
SEC_IsReadable = _i(c_int)
SEC_IsWriteable = _i(c_int)
SEC_IsExecutable = _i(c_int)
SEC_Size = _i(c_int)

# TRACE
_TRACE_InsertCall = _v(c_int, c_int, AFUNPTR)
TRACE_BblHead = _i(c_int)
TRACE_BblTail = _i(c_int)
TRACE_Original = _i(c_int)
TRACE_Address = _i(c_int)
TRACE_Size = _i(c_int)
TRACE_Rtn = _i(c_int)
TRACE_HasFallThrough = _i(c_int)
TRACE_NumBbl = _i(c_int)
TRACE_NumIns = _i(c_int)
TRACE_StubSize = _i(c_int)

# BBL
BBL_MoveAllAttributes = _v(c_int, c_int)
BBL_NumIns = _i(c_int)
BBL_InsHead = _i(c_int)
BBL_InsTail = _i(c_int)
BBL_Next = _i(c_int)
BBL_Prev = _i(c_int)
BBL_Valid = _i(c_int)
BBL_Original = _i(c_int)
BBL_Address = _i(c_int)
BBL_Size = _i(c_int)
_BBL_InsertCall = _v(c_int, c_int, AFUNPTR)
BBL_HasFallThrough = _i(c_int)

# INS Instrumentation
_INS_InsertCall = _v(c_int, c_int)

# INS Generic Inspection
INS_Category = _i(c_int)
INS_Extension = _i(c_int)
INS_MemoryOperandSize = _i(c_int, c_int)
INS_MemoryWriteSize = _i(c_int)
INS_GetPredicate = _i(c_int)
INS_MemoryReadSize = _i(c_int)
INS_IsMemoryRead = _i(c_int)
INS_IsMemoryWrite = _i(c_int)
INS_HasMemoryRead2 = _i(c_int)
INS_HasFallThrough = _i(c_int)
INS_IsLea = _i(c_int)
INS_IsNop = _i(c_int)
OPCODE_StringShort = _s(c_int)
INS_Mnemonic = _s(c_int)
INS_IsBranch = _i(c_int)
INS_IsDirectBranch = _i(c_int)
INS_IsDirectCall = _i(c_int)
INS_IsDirectBranchOrCall = _i(c_int)
INS_IsBranchOrCall = _i(c_int)
INS_Stutters = _i(c_int)
INS_IsCall = _i(c_int)
INS_IsProcedureCall = _i(c_int)
INS_IsRet = _i(c_int)
INS_IsSysret = _i(c_int)
INS_IsPrefetch = _i(c_int)
INS_IsAtomicUpdate = _i(c_int)
INS_IsIndirectBranchOrCall = _i(c_int)
INS_RegR = _i(c_int)
INS_RegW = _i(c_int)
INS_Opcode = _i(c_int)
CATEGORY_StringShort = _s(c_int)
EXTENSION_StringShort = _s(c_int)
INS_MaxNumRRegs = _i(c_int)
INS_MaxNumWRegs = _i(c_int)
INS_RegRContain = _i(c_int, c_int)
INS_RegWContain = _i(c_int, c_int)
INS_IsStackRead = _i(c_int)
INS_IsStackWrite = _i(c_int)
INS_IsIpRelRead = _i(c_int)
INS_IsIpRelWrite = _i(c_int)
# INS_IsPredicated = _i(c_int)
INS_IsOriginal = _i(c_int)
INS_Disassemble = _s(c_int)
INS_MemoryOperandCount = _i(c_int)
INS_OperandIsAddressGenerator = _i(c_int, c_int)
INS_MemoryOperandIsRead = _i(c_int, c_int)
INS_MemoryOperandIsWritten = _i(c_int, c_int)
INS_IsSyscall = _i(c_int)
INS_SyscallStd = _i(c_int)
INS_Rtn = _i(c_int)
INS_Next = _i(c_int)
INS_Prev = _i(c_int)
INS_Invalid = _i()
INS_Valid = _i(c_int)
INS_Address = _i(c_int)
INS_Size = _i(c_int)
INS_DirectBranchOrCallTargetAddress = _i(c_int)
INS_NextAddress = _i(c_int)

# INS ia32/intel64 Inspection TODO

# INS Modification
INS_InsertIndirectJump = _v(c_int, c_int, c_int)
INS_InsertDirectJump = _v(c_int, c_int, c_int)
INS_Delete = _v(c_int)

# SYM
SYM_Next = _i(c_int)
SYM_Prev = _i(c_int)
SYM_Name = _s(c_int)
SYM_Invalid = _i()
SYM_Valid = _i(c_int)
SYM_Dynamic = _i(c_int)
SYM_IFunc = _i(c_int)
SYM_Value = _i(c_int)
SYM_Index = _i(c_int)
SYM_Address = _i(c_int)
PIN_UndecorateSymbolName = _s(c_char_p, c_int)

# Controlling and Initializing
PIN_VmFullPath = _s()
PIN_SafeCopy = _i(c_void_p, c_void_p, c_int)

# Fast Buffering
_PIN_DefineTraceBuffer = _i(c_int, c_int, TRACE_BUFFER_CALLBACK, c_void_p)
PIN_AllocateBuffer = _vp(c_int)
PIN_DeallocateBuffer = _v(c_int, c_void_p)
PIN_GetBufferPointer = _vp(c_void_p, c_int)

# Pin Process
PIN_IsProcessExiting = _i()
PIN_ExitProcess = _v(c_int)
PIN_GetPid = _i()
PIN_ExitApplication = _v(c_int)

# Pin Thread
PIN_GetTid = _i()
PIN_ThreadId = _i()
PIN_ThreadUid = _i()
PIN_GetParentTid = _i()
PIN_Sleep = _v(c_int)
PIN_Yield = _v()
_PIN_SpawnInternalThread = _i(ROOT_THREAD_FUNC, c_void_p,
                              c_int, POINTER(c_int))
PIN_ExitThread = _v(c_int)
PIN_IsApplicationThread = _i()
PIN_WaitForThreadTermination = _i(c_void_p, c_int, POINTER(c_int))
PIN_CreateThreadDataKey = _i(c_void_p)
PIN_DeleteThreadDataKey = _i(c_int)
PIN_SetThreadData = _i(c_int, c_void_p, c_int)
PIN_GetThreadData = _vp(c_int, c_int)

# Pin System Call
PIN_SetSyscallArgument = _v(c_void_p, c_int, c_int, c_int)
PIN_GetSyscallArgument = _i(c_void_p, c_int, c_int)
PIN_SetSyscallNumber = _v(c_void_p, c_int, c_int)
PIN_GetSyscallNumber = _i(c_void_p, c_int)
PIN_GetSyscallReturn = _i(c_void_p, c_int)
PIN_GetSyscallErrno = _i(c_void_p, c_int)

# Context Manipulation
PIN_SetContextReg = _v(c_void_p, c_int, c_int)
PIN_GetContextReg = _i(c_void_p, c_int)
PIN_SaveContext = _v(c_void_p, c_void_p)
PIN_ExecuteAt = _v(c_void_p)

# the following line(s) are actually not required,
# but these are for the strict syntax checker(s)
_pin_function_addr = globals()['_pin_function_addr']
x86 = globals()['x86']
x64 = globals()['x64']

# not hacky at all!
for _name, _decl in globals().items():
    if not _name.lstrip('_') in _pin_function_addr:
        continue

    if _name.startswith('_'):
        globals()[_name] = _decl(_pin_function_addr[_name[1:]])
    else:
        globals()[_name] = _decl(_pin_function_addr[_name])

for _name in ('RTN', 'TRACE', 'BBL', 'INS'):
    _helper = globals()['_' + _name + '_InsertCall']

    def _insert_call(obj, action, cb, *args):
        _insert_call_helper(_helper, obj, action, cb, args)

    globals()[_name + '_InsertCall'] = _insert_call


def _insert_call_helper(fn, obj, action, cb, args):
    # first extract the amount of parameters that will be required
    # by the callback function and make an according declaration for it
    ret, off = 0, 0
    while off < len(args):
        ret += 1
        off += 1 + _iarg_table.get(args[off], 0)

    decl = CFUNCTYPE(None, *[c_long for _ in xrange(ret)])

    cb = decl(cb)
    args = args + (IARG_LAST,)
    _gc.extend((cb, args))
    fn(obj, action, cb, *args)


# override functions which accept callback functions, because
# they need some extra care
def RTN_Replace(rtn, func):
    func = AFUNPTR(func)
    _gc.append(func)
    _RTN_Replace(rtn, func)


def PIN_DefineTraceBuffer(record_size, num_pages, cb, arg):
    cb = TRACE_BUFFER_CALLBACK(cb)
    _gc.extend((cb, arg))
    _PIN_DefineTraceBuffer(record_size, num_pages, cb, arg)


def PIN_SpawnInternalThread(cb, arg, stack_size, thread_uid):
    cb = ROOT_THREAD_FUNC(cb)
    _gc.extend((cb, arg, thread_uid))
    _PIN_SpawnInternalThread(cb, arg, stack_size, thread_uid)

_iota_index, _iota_value, _iota_iter = 0, 0, lambda idx, val: idx + 1


def iota(num=None, it=None):
    """Returns an incremental number every iteration.

    This is a trimmed down version of Go's iota keyword.
    """
    global _iota_index, _iota_value, _iota_iter

    if not it is None:
        _iota_iter = it

    if not num is None:
        _iota_value = num
        _iota_index = 0
    else:
        _iota_value = _iota_iter(_iota_index, _iota_value)
        _iota_index += 1

    return _iota_value


_iarg_table = {
    IARG_ADDRINT: 1, IARG_PTR: 1, IARG_BOOL: 1, IARG_UINT32: 1,
    IARG_REG_VALUE: 1, IARG_RETURN_REGS: 1,
}


class Instruction(object):
    def __init__(self, ins):
        self.ins = ins

    @property
    def valid(self):
        return INS_Valid(self.ins)

    @property
    def addr(self):
        return INS_Address(self.ins)

    @property
    def size(self):
        return INS_Size(self.ins)

    @property
    def next_addr(self):
        return INS_NextAddress(self.ins)

    @property
    def routine(self):
        return Routine(INS_Rtn(self.ins))

    @property
    def disasm(self):
        return INS_Disassemble(self.ins)

    @property
    def target(self):
        return INS_DirectBranchOrCallTargetAddress(self.ins)


class BasicBlock(object):
    def __init__(self, bbl):
        self.bbl = bbl

    @property
    def valid(self):
        return BBL_Valid(self.bbl)

    @property
    def original(self):
        return BBL_Original(self.bbl)

    @property
    def addr(self):
        return BBL_Address(self.bbl)

    @property
    def size(self):
        return BBL_Size(self.bbl)

    @property
    def fall_through(self):
        return BBL_HasFallThrough(self.bbl)

    @property
    def num_ins(self):
        return BBL_NumIns(self.bbl)

    @property
    def insns(self):
        return _Iter(typ=Instruction, start=lambda: BBL_InsHead(self.bbl),
                     end=lambda: BBL_InsTail(self.bbl), it=INS_Next)


class Trace(object):
    def __init__(self, trc):
        self.trc = trc

    @property
    def original(self):
        return TRACE_Original(self.trc)

    @property
    def addr(self):
        return TRACE_Address(self.trc)

    @property
    def size(self):
        return TRACE_Size(self.trc)

    @property
    def routine(self):
        return Routine(TRACE_Rtn(self.trc))

    @property
    def fall_through(self):
        return TRACE_HasFallThrough(self.trc)

    @property
    def bbls(self):
        return _Iter(typ=BasicBlock, start=lambda: TRACE_BblHead(self.trc),
                     end=lambda: TRACE_BblTail(self.trc), it=BBL_Next)

    @property
    def num_bbl(self):
        return TRACE_NumBbl(self.trc)

    @property
    def num_ins(self):
        return TRACE_NumIns(self.trc)

    @property
    def stub_size(self):
        return TRACE_StubSize(self.trc)


class Symbol(object):
    def __init__(self, sym):
        self.sym = sym

    @property
    def name(self):
        return SYM_Name(self.sym)

    @property
    def valid(self):
        return SYM_Valid(self.sym)

    @property
    def dynamic(self):
        return SYM_Dynamic(self.sym)

    @property
    def ifunc(self):
        return SYM_IFunc(self.sym)

    @property
    def value(self):
        return SYM_Value(self.sym)

    @property
    def index(self):
        return SYM_Index(self.sym)

    @property
    def addr(self):
        return SYM_Address(self.sym)


class Routine(object):
    def __init__(self, rtn=None, addr=None):
        if not addr is None:
            self.rtn = RTN_FindByAddress(addr)
        else:
            self.rtn = rtn

    @property
    def name(self):
        return RTN_Name(self.rtn)

    @property
    def valid(self):
        return RTN_Valid(self.rtn)

    @property
    def symbol(self):
        return RTN_Sym(self.rtn)

    @property
    def range(self):
        return RTN_Range(self.rtn)

    @property
    def size(self):
        return RTN_Size(self.rtn)

    # TODO many more functions


class Section(object):
    def __init__(self, sec):
        self.sec = sec

    @property
    def image(self):
        return Image(SEC_Img(self.sec))

    @property
    def valid(self):
        return SEC_Valid(self.sec)

    @property
    def routines(self):
        return _Iter(typ=Routine, start=lambda: SEC_RtnHead(self.sec),
                     end=lambda: SEC_RtnTail(self.sec), it=RTN_Next)

    @property
    def name(self):
        return SEC_Name(self.sec)

    @property
    def mapped(self):
        return SEC_Mapped(self.sec)

    @property
    def data(self):
        return SEC_Data(self.sec)

    @property
    def addr(self):
        return SEC_Address(self.sec)

    @property
    def readable(self):
        return SEC_IsReadable(self.sec)

    @property
    def writeable(self):
        return SEC_IsWriteable(self.sec)

    @property
    def executable(self):
        return SEC_IsExecutable(self.sec)

    @property
    def size(self):
        return SEC_Size(self.sec)


class Context(object):
    _regs = dict((k[4:].lower(), v)
                 for k, v in globals().items()
                 if k.startswith('REG_'))

    def __init__(self, ctx):
        self.ctx = ctx

    def __getitem__(self, key):
        return PIN_GetContextReg(self.ctx, self._regs[key])

    def __setitem__(self, key, value):
        PIN_SetContextReg(self.ctx, self._regs[key], value)

    def __getattr__(self, name):
        return PIN_GetContextReg(self.ctx, self._regs[name])

    def __setattr__(self, name, value):
        if not name in self._regs:
            object.__setattr__(self, name, value)
        else:
            PIN_SetContextReg(self.ctx, self._regs[name], value)


class Image(object):
    def __init__(self, img=None, addr=None):
        if not addr is None:
            self.img = IMG_FindByAddress(addr)
        else:
            self.img = img

    @staticmethod
    def open(fname):
        img = IMG_Open(fname)
        return Image(img) if IMG_Valid(img) else None

    def close(self):
        IMG_Close(self.img)

    @property
    def name(self):
        return IMG_Name(self.img)

    @property
    def valid(self):
        return IMG_Valid(self.img)

    @property
    def low_addr(self):
        return IMG_LowAddress(self.img)

    @property
    def high_addr(self):
        return IMG_HighAddress(self.img)

    @property
    def addr(self):
        return self.low_addr, self.high_addr

    @property
    def main(self):
        return IMG_IsMainExecutable(self.img)

    @property
    def static(self):
        return IMG_IsStaticExecutable(self.img)

    @property
    def entry(self):
        return IMG_Entry(self.img)

    @property
    def sections(self):
        return _Iter(typ=Section, start=lambda: IMG_SecHead(self.img),
                     end=lambda: IMG_SecTail(self.img), it=SEC_Next)

    @property
    def symbols(self):
        return _Iter(typ=Symbol, start=lambda: IMG_RegsymHead(self.img),
                     valid=SYM_Valid, it=SYM_Next)

    def routine(self, name):
        rtn = RTN_FindByName(self.img, name)
        return Routine(rtn) if RTN_Valid(rtn) else None


class _Iter(object):
    def __init__(self, typ=None, start=None, end=None, valid=None, it=None):
        self.typ = typ
        self.start = start
        self.end = end
        self.valid = valid
        self.it = it
        self.obj = None

    def next(self):
        if self.end and self.obj == self.end():
            raise StopIteration

        if self.obj is None:
            self.obj = self.start()
        else:
            self.obj = self.it(self.obj)

        if self.valid and not self.valid(self.obj):
            raise StopIteration

        return self.typ(self.obj)

    def __iter__(self):
        # provide a new object for multi-threaded support
        return _Iter(typ=self.typ, start=self.start, end=self.end,
                     valid=self.valid, it=self.it)

    def __getitem__(self, key):
        # this is very expensive for larger sets.. but pretty flexible
        return [obj for obj in self][key]


Images = _Iter(typ=Image, start=APP_ImgHead, end=APP_ImgTail, it=IMG_Next)


# some helper functions which do all the hard work of casting the parameters
# appropriately, until I find the correct way to do it directly natively
def _callback_helper(cb, typ, obj):
    return cb(typ(obj))
