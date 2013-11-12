#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "pin.H"

#define ARRAYSIZE(arr) (sizeof(arr)/sizeof((arr)[0]))
#define CYCLIC(arr, idx) (&arr[idx++ % ARRAYSIZE(arr)])

namespace Py {
    #include "Python.h"
}

#define F(name) {#name, &name}
#define F2(name) {#name, &name##_detour}

static const char *INS_Mnemonic_detour(INS ins);
static const char *INS_Disassemble_detour(INS ins);

static void *g_functions[][2] = {
    // INS Instrumentation
    F(INS_AddInstrumentFunction),
    F(INS_InsertCall),

    // INS Generic Inspection
    F2(INS_Mnemonic),
    F(INS_IsOriginal),
    F2(INS_Disassemble),
    F(INS_Next),
    F(INS_Prev),
    F(INS_Invalid),
    F(INS_Valid),
    F(INS_Address),
    F(INS_Size),

    // INS Modification
    F(INS_InsertIndirectJump),
    F(INS_InsertDirectJump),
    F(INS_Delete),
};

static const char *INS_Mnemonic_detour(INS ins)
{
    static char cyclic_strings[32][64]; static uint32_t cyclic_index;

    string s = INS_Mnemonic(ins);
    if(s.c_str() == NULL) return NULL;

    return strcpy(*CYCLIC(cyclic_strings, cyclic_index), s.c_str());
}

static const char *INS_Disassemble_detour(INS ins)
{
    static char cyclic_strings[32][64]; static uint32_t cyclic_index;

    string s = INS_Disassemble(ins);
    if(s.c_str() == NULL) return NULL;

    return strcpy(*CYCLIC(cyclic_strings, cyclic_index), s.c_str());
}

int main(int argc, char *argv[])
{
    PIN_Init(argc, argv);
    PIN_InitSymbols();

    Py::Py_Initialize();

    Py::PyRun_SimpleString("_pin_function_addr = {}");

    char buf[256];
    for (uint32_t idx = 0; idx < ARRAYSIZE(g_functions); idx++) {
        sprintf(buf, "_pin_function_addr['%s'] = 0x%08lx",
            g_functions[idx][0], g_functions[idx][1]);
        Py::PyRun_SimpleString(buf);
    }

    // we want to execute pypin in the current namespace
    Py::PyRun_SimpleString("exec open('pypin.py', 'rb').read()");

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
        Py::PyRun_SimpleString(buf);
    }

    PIN_StartProgram();
    Py::Py_Finalize();
    return 0;
}
