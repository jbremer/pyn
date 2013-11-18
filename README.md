# pyn

Awesome Python bindings for Pintool. **Pyn** aims to offer an extremely easy
API for quickly writing Pintools.

Pyn features a *raw* API close to the original Pintool API as well as a more
Pythonic API. It's important to understand that Pyn hides various aspects of
regular Pintools, allowing one to make full-featured Pintools in just a
handful lines of code.

Pintool has several callback functions, e.g., the one registered by calling
INS_AddInstrumentFunction. As an example for a normal Pintool, take the
following piece of C code.

```C++
#include <stdio.h>
#include "pin.H"

void instructions(INS ins, void *v)
{
    printf("-> %s\n", INS_Disassemble(ins).c_str());
}

int main(int argc, char *argv[])
{
    PIN_Init(argc, argv);

    INS_AddInstrumentFunction(&instructions, NULL);

    PIN_StartProgram();
    return 0;
}
```

This is already a complete Pintool. However, when writing Pintools time after
time, each for its own specific purpose, this boilerplate code becomes
repetitive. Hence the Pintool from above can be rewritten using Pyn to just
the following few lines of code.

```Python
def instr(ins):
    print INS_Disassemble(ins)
```

Or, when using the extended Pythonic API, we do the following. (More on that
later.)

```Python
def instr2(ins):
    print ins.disasm
```

# Documentation

Currently there is no documentation for Pyn yet, as it's still under heavy
development. However, more examples and documentation are planned as
development continues and a more well-tested version of Pyn is being released.

# Binaries

Given Pintools are fairly annoying to compile by themselves, not even starting
about compiling Python with them, I plan on releasing binaries later on.
Currently I only have 32-bit Windows binaries as I'm still struggling with
linux builds and 64-bit Windows builds, but let's wait and see.
