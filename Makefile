CL = cl

PYTHON = C:/Python27/
PINTOOL = ../pintool
DLLS = pypin-x86.dll
LINK = C:/ProgFiles86/Microsoft\ Visual\ Studio\ 10.0/VC/Bin/link.exe

SOURCES = $(wildcard *.cpp)
OBJECTS86 = $(patsubst %.cpp, %-x86.obj, $(SOURCES))

default: $(OBJECTS86) $(DLLS)

%-x86.obj: %.cpp
	$(CL) /c /MT /EHs- /EHa- /wd4530 /DTARGET_WINDOWS \
		/DBIGARRAY_MULTIPLIER=1 /DUSING_XED /D_CRT_SECURE_NO_DEPRECATE  \
		/D_SECURE_SCL=0 /nologo /Gy /O2 /DTARGET_IA32 /DHOST_IA32 \
		/I$(PINTOOL)\source\include /I$(PINTOOL)\source\include\gen \
		/I$(PINTOOL)\source\tools\InstLib \
		/I$(PINTOOL)\extras\xed2-ia32\include \
		/I$(PINTOOL)\extras\components\include \
		/I$(PYTHON)\include $^ /Fo$@

%-x86.dll: %-x86.obj $(OBJECTS86)
	$(LINK) /DLL /EXPORT:main /NODEFAULTLIB /NOLOGO /INCREMENTAL:NO /OPT:REF \
		/MACHINE:x86 /ENTRY:Ptrace_DllMainCRTStartup@12 /BASE:0x55000000 \
		/LIBPATH:$(PINTOOL)\ia32\lib /LIBPATH:$(PINTOOL)\ia32\lib-ext \
		/LIBPATH:$(PINTOOL)\extras\xed2-ia32\lib /OUT:$@ $^ pin.lib \
		/LIBPATH:$(PYTHON)\Libs python27.lib \
		libxed.lib libcpmt.lib libcmt.lib pinvm.lib kernel32.lib ntdll-32.lib

test:
	make -C tests test

clean:
	rm '*.dll' '*.exp' '*.lib' '*.obj'
