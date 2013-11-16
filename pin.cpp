#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "pin.H"
#include "py.h"

// TODO fix memory leaks introduced by strdup

#ifdef _MSC_VER
# define strdup _strdup
# define snprintf _snprintf
#endif

#define ARRAYSIZE(arr) (sizeof(arr)/sizeof((arr)[0]))
#define CYCLIC(arr, idx) (&arr[idx++ % ARRAYSIZE(arr)])

#if ULONG_MAX == UINT_MAX
# define FMTPTR "0x%08x"
#else
# define FMTPTR "0x%016lx"
#endif

#define F(name) {#name, (const void *) &name}
#define F2(name) {#name, (const void *) &name##_detour}

static const char *IMG_Name_detour(IMG img);
static IMG IMG_Open_detour(const char *fname);
static const char *RTN_Name_detour(RTN rtn);
static const char *RTN_FindNameByAddress_detour(ADDRINT addr);
static RTN RTN_CreateAt_detour(ADDRINT addr, const char *name);
static const char *OPCODE_StringShort_detour(uint32_t opcode);
static const char *INS_Mnemonic_detour(INS ins);
static const char *CATEGORY_StringShort_detour(uint32_t num);
static const char *EXTENSION_StringShort_detour(uint32_t num);
static const char *INS_Disassemble_detour(INS ins);
static const char *SYM_Name_detour(SYM sym);
static const char *PIN_UndecorateSymbolName_detour(
    const char *symbol_name, UNDECORATION style);
static BOOL PIN_SetThreadData_detour(
    TLS_KEY key, const void *data, THREADID thread_id);
static void *PIN_GetThreadData_detour(TLS_KEY key, THREADID thread_id);

static const void *g_functions[][2] = {
    // IMG - Image Object
    F(IMG_Next),
    F(IMG_Prev),
    F(IMG_Invalid),
    F(IMG_Valid),
    F(IMG_SecHead),
    F(IMG_SecTail),
    F(IMG_RegsymHead),
    F(IMG_Entry),
    F2(IMG_Name),
    F(IMG_Gp),
    F(IMG_LoadOffset),
    F(IMG_LowAddress),
    F(IMG_HighAddress),
    F(IMG_StartAddress),
    F(IMG_SizeMapped),
    F(IMG_Type),
    F(IMG_IsMainExecutable),
    F(IMG_IsStaticExecutable),
    F(IMG_Id),
    F(IMG_FindImgById),
    F(IMG_FindByAddress),
    F(IMG_AddInstrumentFunction),
    F(IMG_AddUnloadFunction),
    F2(IMG_Open),
    F(IMG_Close),

    // APP
    F(APP_ImgHead),
    F(APP_ImgTail),

    // RTN - Routine Object
    F(RTN_Sec),
    F(RTN_Next),
    F(RTN_Prev),
    F(RTN_Invalid),
    F(RTN_Valid),
    F2(RTN_Name),
    F(RTN_Sym),
    F(RTN_Funptr),
    F(RTN_Id),
    F(RTN_AddInstrumentFunction),
    F(RTN_Range),
    F(RTN_Size),
    F2(RTN_FindNameByAddress),
    F(RTN_FindByAddress),
    F(RTN_FindByName),
    F(RTN_Open),
    F(RTN_Close),
    F(RTN_InsHead),
    F(RTN_InsHeadOnly),
    F(RTN_InsTail),
    F(RTN_NumIns),
    F(RTN_InsertCall),
    F(RTN_Address),
    F2(RTN_CreateAt),
    F(RTN_Replace),

    // TRACE - Single entrance, multiple exit
    F(TRACE_AddInstrumentFunction),
    F(TRACE_InsertCall),
    F(TRACE_BblHead),
    F(TRACE_BblTail),
    F(TRACE_Original),
    F(TRACE_Address),
    F(TRACE_Size),
    F(TRACE_Rtn),
    F(TRACE_HasFallThrough),
    F(TRACE_NumBbl),
    F(TRACE_NumIns),
    F(TRACE_StubSize),

    // BBL - Single entrance, single exit
    F(BBL_MoveAllAttributes),
    F(BBL_NumIns),
    F(BBL_InsHead),
    F(BBL_InsTail),
    F(BBL_Next),
    F(BBL_Prev),
    F(BBL_Valid),
    F(BBL_Original),
    F(BBL_Address),
    F(BBL_Size),
    F(BBL_InsertCall),
    F(BBL_HasFallThrough),

    // INS Instrumentation
    F(INS_AddInstrumentFunction),
    F(INS_InsertCall),

    // INS Generic Inspection
    F(INS_Category),
    F(INS_Extension),
    F(INS_MemoryOperandSize),
    F(INS_MemoryWriteSize),
    F(INS_GetPredicate),
    F(INS_MemoryReadSize),
    F(INS_IsMemoryRead),
    F(INS_IsMemoryWrite),
    F(INS_HasMemoryRead2),
    F(INS_HasFallThrough),
    F(INS_IsLea),
    F(INS_IsNop),
    F2(OPCODE_StringShort),
    F2(INS_Mnemonic),
    F(INS_IsBranch),
    F(INS_IsDirectBranch),
    F(INS_IsDirectCall),
    F(INS_IsDirectBranchOrCall),
    F(INS_IsBranchOrCall),
    F(INS_Stutters),
    F(INS_IsCall),
    F(INS_IsProcedureCall),
    F(INS_IsRet),
    F(INS_IsSysret),
    F(INS_IsPrefetch),
    F(INS_IsAtomicUpdate),
    F(INS_IsIndirectBranchOrCall),
    F(INS_RegR),
    F(INS_RegW),
    F(INS_Opcode),
    F2(CATEGORY_StringShort),
    F2(EXTENSION_StringShort),
    F(INS_MaxNumRRegs),
    F(INS_MaxNumWRegs),
    F(INS_RegRContain),
    F(INS_RegWContain),
    F(INS_IsStackRead),
    F(INS_IsStackWrite),
    F(INS_IsIpRelRead),
    F(INS_IsIpRelWrite),
    // F(INS_IsPredicated),                                (
    F(INS_IsOriginal),
    F2(INS_Disassemble),
    F(INS_MemoryOperandCount),
    F(INS_OperandIsAddressGenerator),
    F(INS_MemoryOperandIsRead),
    F(INS_MemoryOperandIsWritten),
    F(INS_IsSyscall),
    F(INS_SyscallStd),
    F(INS_Rtn),
    F(INS_Next),
    F(INS_Prev),
    F(INS_Invalid),
    F(INS_Valid),
    F(INS_Address),
    F(INS_Size),
    F(INS_DirectBranchOrCallTargetAddress),
    F(INS_NextAddress),

    // INS Modification
    F(INS_InsertIndirectJump),
    F(INS_InsertDirectJump),
    F(INS_Delete),

    // SYM - Symbol Object
    F(SYM_Next),
    F(SYM_Prev),
    F2(SYM_Name),
    F(SYM_Invalid),
    F(SYM_Valid),
    F(SYM_Dynamic),
    F(SYM_IFunc),
    F(SYM_Value),
    F(SYM_Index),
    F(SYM_Address),
    F2(PIN_UndecorateSymbolName),

    // Controlling and Initializing
    F(PIN_VmFullPath),
    F(PIN_SafeCopy),

    // Fast Buffering
    F(PIN_DefineTraceBuffer),
    F(PIN_AllocateBuffer),
    F(PIN_DeallocateBuffer),
    F(PIN_GetBufferPointer),

    // Pin Process
    F(PIN_IsProcessExiting),
    F(PIN_ExitProcess),
    F(PIN_GetPid),
    F(PIN_ExitApplication),

    // Pin Thread
    F(PIN_GetTid),
    F(PIN_ThreadId),
    F(PIN_ThreadUid),
    F(PIN_GetParentTid),
    F(PIN_Sleep),
    F(PIN_Yield),
    F(PIN_SpawnInternalThread),
    F(PIN_ExitThread),
    F(PIN_IsApplicationThread),
    F(PIN_WaitForThreadTermination),
    F(PIN_CreateThreadDataKey),
    F(PIN_DeleteThreadDataKey),
    F2(PIN_SetThreadData),
    F2(PIN_GetThreadData),

    // Pin System Call
    F(PIN_AddSyscallEntryFunction),
    F(PIN_AddSyscallExitFunction),
    F(PIN_SetSyscallArgument),
    F(PIN_GetSyscallArgument),
    F(PIN_SetSyscallNumber),
    F(PIN_GetSyscallNumber),
    F(PIN_GetSyscallReturn),
    F(PIN_GetSyscallErrno),

    // Context Manipulation
    F(PIN_SetContextReg),
    F(PIN_GetContextReg),
    F(PIN_SaveContext),
    F(PIN_ExecuteAt),
};

static const char *IMG_Name_detour(IMG img)
{
    return strdup(IMG_Name(img).c_str());
}

static IMG IMG_Open_detour(const char *fname)
{
    // IMG_Open takes a std::string as parameter,
    // hence the detour function
    return IMG_Open(fname);
}

static const char *RTN_Name_detour(RTN rtn)
{
    return strdup(RTN_Name(rtn).c_str());
}

static const char *RTN_FindNameByAddress_detour(ADDRINT addr)
{
    return strdup(RTN_FindNameByAddress(addr).c_str());
}

static RTN RTN_CreateAt_detour(ADDRINT addr, const char *name)
{
    // RTN_CreateAt takes a std::string as parameter,
    // hence the detour function
    return RTN_CreateAt(addr, name);
}

static const char *OPCODE_StringShort_detour(uint32_t opcode)
{
    return strdup(OPCODE_StringShort(opcode).c_str());
}

static const char *INS_Mnemonic_detour(INS ins)
{
    static char cyclic_strings[32][32]; static uint32_t cyclic_index;

    string s = INS_Mnemonic(ins);
    if(s.c_str() == NULL) return NULL;

    return strcpy(*CYCLIC(cyclic_strings, cyclic_index), s.c_str());
}

static const char *CATEGORY_StringShort_detour(uint32_t num)
{
    return strdup(CATEGORY_StringShort(num).c_str());
}

static const char *EXTENSION_StringShort_detour(uint32_t num)
{
    return strdup(EXTENSION_StringShort(num).c_str());
}

static const char *INS_Disassemble_detour(INS ins)
{
    static char cyclic_strings[32][64]; static uint32_t cyclic_index;

    string s = INS_Disassemble(ins);
    if(s.c_str() == NULL) return NULL;

    return strcpy(*CYCLIC(cyclic_strings, cyclic_index), s.c_str());
}

static const char *SYM_Name_detour(SYM sym)
{
    return strdup(SYM_Name(sym).c_str());
}

static const char *PIN_UndecorateSymbolName_detour(
    const char *symbol_name, UNDECORATION style)
{
    return strdup(PIN_UndecorateSymbolName(symbol_name, style).c_str());
}

// PIN_SetThreadData and PIN_GetThreadData are overloaded,
// hence we use a detour to get a single function pointer
static BOOL PIN_SetThreadData_detour(
    TLS_KEY key, const void *data, THREADID thread_id)
{
    return PIN_SetThreadData(key, data, thread_id);
}

static void *PIN_GetThreadData_detour(TLS_KEY key, THREADID thread_id)
{
    return PIN_GetThreadData(key, thread_id);
}

static void single_int_callback(uintptr_t value, void *arg)
{
    py_single_int_callback(arg, value);
}

static void *g_child_callback;

static BOOL child_callback(CHILD_PROCESS child_process, void *v)
{
    return py_single_int_bool_callback(
        g_child_callback, (uintptr_t) child_process);
}

static void *g_syscall_entry_callback;

static void syscall_entry_callback(
    THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v)
{
    py_three_int_callback(
        g_syscall_entry_callback, thread_id, (uintptr_t) ctx, std);
}

static void *g_syscall_exit_callback;

static void syscall_exit_callback(
    THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v)
{
    py_three_int_callback(
        g_syscall_exit_callback, thread_id, (uintptr_t) ctx, std);
}

int main(int argc, char *argv[])
{
    PIN_Init(argc, argv);
    PIN_InitSymbols();

    py_init();

    pyrun_simple_string("_pin_function_addr = {}");

    char buf[256];
    for (uint32_t idx = 0; idx < ARRAYSIZE(g_functions); idx++) {
        sprintf(buf, "_pin_function_addr['%s'] = "FMTPTR,
            (const char *) g_functions[idx][0],
            (uintptr_t) g_functions[idx][1]);
        pyrun_simple_string(buf);
    }

#if ULONG_MAX == UINT_MAX
    pyrun_simple_string("x86, x64 = True, False");
#else
    pyrun_simple_string("x86, x64 = False, True");
#endif

    // we want to execute pyn.py in the current namespace
    pyrun_simple_string("exec open('pyn.py', 'rb').read()");

    // turns out that IARG_END is a macro which puts IARG_FILE_NAME and
    // IARG_LINE_NO, with their values accordingly, in the argument list as
    // well.. as we take care of this inside our *_InsertCall statements, we
    // can ignore the "real" meaning of IARG_END, and just assign it IARG_LAST
    // TODO actually add some special handling for IARG_END / whatever
    pyrun_simple_string("IARG_END = IARG_LAST");

    // manually parse argv, because KNOB - do you even parse?!
    for (int i = 0, tool_arg_start = -1; i < argc; i++) {
        // end of parameters to our pintool
        if(!strcmp(argv[i], "--")) break;

        // -t specifies our pintool, after that come args to our tool
        if(!strcmp(argv[i], "-t")) {
            tool_arg_start = i + 2;
            continue;
        }

        // check if we're already in the arguments to our tool
        if(tool_arg_start < 0 || i < tool_arg_start) continue;

        // python code injection!!1
        snprintf(buf, sizeof(buf), "exec open('%s', 'rb').read()", argv[i]);
        pyrun_simple_string(buf);
    }

    void *py_globals = NULL, *py_value;
    sprintf(buf, "import ctypes; ctypes.memmove("FMTPTR", "
            "ctypes.byref(ctypes.c_int(id(globals()))), 4)",
            (uintptr_t) &py_globals);
    pyrun_simple_string(buf);

    // generic callback registration function
#define CALLBACK_REG(name, api) \
    py_value = pystring_from_string(#name); \
    g_##name##_callback = pydict_get_item(py_globals, py_value); \
    if(g_##name##_callback != NULL) { \
        api(&name##_callback, NULL); \
    }

    // callback registration function for callbacks
    // with only one integer as parameter, and which return void
#define CALLBACK_REG1(name, api, cast) \
    py_value = pystring_from_string(#name); \
    py_value = pydict_get_item(py_globals, py_value); \
    if(py_value != NULL) { \
        api((cast##CALLBACK) &single_int_callback, py_value); \
    }

    if(py_globals != NULL) {
        CALLBACK_REG1(fini, PIN_AddFiniFunction, FINI_);
        CALLBACK_REG(child, PIN_AddFollowChildProcessFunction);
        CALLBACK_REG1(img_load, IMG_AddInstrumentFunction, IMAGE);
        CALLBACK_REG1(img_unload, IMG_AddUnloadFunction, IMAGE);
        CALLBACK_REG1(routine, RTN_AddInstrumentFunction, RTN_INSTRUMENT_);
        CALLBACK_REG1(trace, TRACE_AddInstrumentFunction, TRACE_INSTRUMENT_);
        CALLBACK_REG1(instr, INS_AddInstrumentFunction, INS_INSTRUMENT_);
        CALLBACK_REG(syscall_entry, PIN_AddSyscallEntryFunction);
        CALLBACK_REG(syscall_exit, PIN_AddSyscallExitFunction);
    }

    PIN_StartProgram();
    py_fini();
    return 0;
}
