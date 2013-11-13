

def instr(ins):
    img, addr = APP_ImgHead(), INS_Address(ins)
    if addr >= IMG_LowAddress(img) and addr < IMG_HighAddress(img):
        print '0x%x' % addr, INS_Size(ins), INS_Disassemble(ins)


def syscall_entry(tid, ctx, std):
    print 'syscall', PIN_GetSyscallNumber(ctx, std)
