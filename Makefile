CL = cl
CXX = g++

PINTOOL = ../pintool
LINK = C:/ProgFiles86/Microsoft\ Visual\ Studio\ 10.0/VC/Bin/link.exe

ifeq ($(OS),Windows_NT)
	PYTHON = C:/Python27
	OBJECTS86 = pin-x86.obj py-x86.obj
	PINTOOLS = pyn-x86.dll
else
	PYTHON = /usr/include/python2.7
	LIBS86 = $(PINTOOL)/ia32/runtime/cpplibs
	LIBS64 = $(PINTOOL)/intel64/runtime/cpplibs
	OBJECTS86 = pin-x86.o py-x86.o
	OBJECTS64 = pin-x64.o py-x64.o
	PINTOOLS = pyn-x86.so pyn-x64.so
endif

STUFF = $(OBJECTS86) $(OBJECTS64) $(PINTOOLS)

default: $(STUFF)

py-x86.obj: py.cpp
	$(CL) /c /MT /EHs- /EHa- /wd4530 /Gy /O2 /I$(PYTHON)/include $^ /Fo$@

pin-x86.obj: pin.cpp
	$(CL) /c /MT /EHs- /EHa- /wd4530 /DTARGET_WINDOWS \
		/DBIGARRAY_MULTIPLIER=1 /DUSING_XED /D_CRT_SECURE_NO_DEPRECATE  \
		/D_SECURE_SCL=0 /nologo /Gy /O2 /DTARGET_IA32 /DHOST_IA32 \
		/I$(PINTOOL)\source\include /I$(PINTOOL)\source\include\gen \
		/I$(PINTOOL)\source\tools\InstLib \
		/I$(PINTOOL)\extras\xed2-ia32\include \
		/I$(PINTOOL)\extras\components\include $^ /Fo$@

pyn-x86.dll: $(OBJECTS86)
	$(LINK) /DLL /EXPORT:main /NODEFAULTLIB /NOLOGO /INCREMENTAL:NO /OPT:REF \
		/MACHINE:x86 /ENTRY:Ptrace_DllMainCRTStartup@12 /BASE:0x55000000 \
		/LIBPATH:$(PINTOOL)\ia32\lib /LIBPATH:$(PINTOOL)\ia32\lib-ext \
		/LIBPATH:$(PINTOOL)\extras\xed2-ia32\lib /OUT:$@ $^ pin.lib \
		/LIBPATH:$(PYTHON)\Libs python27.lib \
		libxed.lib libcpmt.lib libcmt.lib pinvm.lib kernel32.lib ntdll-32.lib

py-x86.o: py.cpp
	$(CXX) -c -o $@ $^ -I$(PYTHON) -m32

pin-x86.o: pin.cpp
	$(CXX) -DBIGARRAY_MULTIPLIER=1 -DUSING_XED -Wall -Werror -m32 \
		-Wno-unknown-pragmas -fno-stack-protector -DTARGET_IA32 \
		-DHOST_IA32E -fPIC -DTARGET_LINUX \
		-I$(PINTOOL)/source/include/pin \
		-I$(PINTOOL)/source/include/pin/gen \
		-I$(PINTOOL)/extras/components/include \
		-I$(PINTOOL)/extras/xed2-ia32/include \
		-I$(PINTOOL)/source/tools/InstLib \
		-O3 -fomit-frame-pointer -fno-strict-aliasing -c -o $@ $^

pyn-x86.so: $(OBJECTS86)
	$(CXX) -shared -Wl,--hash-style=sysv -Wl,-Bsymbolic -m32 \
		-Wl,--version-script=$(PINTOOL)/source/include/pin/pintool.ver \
		-o $@ $^ -L$(PINTOOL)/ia32/lib -L$(PINTOOL)/ia32/lib-ext \
		-L$(PINTOOL)/ia32/runtime/glibc \
		-L$(PINTOOL)/extras/xed2-ia32/lib \
		-lpin -lxed -ldwarf -lelf -ldl -lpython2.7 -L$(LIBS86)

py-x64.o: py.cpp
	$(CXX) -c -o $@ $^ -I$(PYTHON) -fPIC

pin-x64.o: pin.cpp
	$(CXX) -DBIGARRAY_MULTIPLIER=1 -DUSING_XED -Wall -Werror \
		-Wno-unknown-pragmas -fno-stack-protector -DTARGET_IA32E \
		-DHOST_IA32E -fPIC -DTARGET_LINUX \
		-I$(PINTOOL)/source/include/pin \
		-I$(PINTOOL)/source/include/pin/gen \
		-I$(PINTOOL)/extras/components/include \
		-I$(PINTOOL)/extras/xed2-intel64/include \
		-I$(PINTOOL)/source/tools/InstLib \
		-O3 -fomit-frame-pointer -fno-strict-aliasing -c -o $@ $^ -fPIC

pyn-x64.so: $(OBJECTS64)
	$(CXX) -shared -Wl,--hash-style=sysv -Wl,-Bsymbolic \
		-Wl,--version-script=$(PINTOOL)/source/include/pin/pintool.ver \
		-o $@ $^ -L$(PINTOOL)/intel64/lib -L$(PINTOOL)/intel64/lib-ext \
		-L$(PINTOOL)/intel64/runtime/glibc \
		-L$(PINTOOL)/extras/xed2-intel64/lib \
		-lpin -lxed -ldwarf -lelf -ldl -lpython2.7 -L$(LIBS64)

test:
	make -C tests test

clean:
	rm -f $(STUFF)
