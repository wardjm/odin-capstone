package capstone

foreign import lib {
    "system:capstone"
}

CS_MNEMONIC_SIZE :: 32

csh :: u32

cs_detail :: struct {}

cs_insn :: struct {
    
    /// Instruction ID (basically a numeric ID for the instruction mnemonic)
    /// Find the instruction id in the '[ARCH]_insn' enum in the header file
    /// of corresponding architecture, such as 'arm_insn' in arm.h for ARM,
    /// 'x86_insn' in x86.h for X86, etc...
    /// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
    /// NOTE: in Skipdata mode, "data" instruction has 0 for this id field.
    id : u32,

    /// Address (EIP) of this instruction
    /// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
    address : u64,
    
    /// Size of this instruction
    /// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
    size : u16,
    
    /// Machine bytes of this instruction, with number of bytes indicated by @size above
    /// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
    bytes : [16]u8,
    
    /// Ascii text of instruction mnemonic
    /// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
    mnemonic : [CS_MNEMONIC_SIZE]u8,
    
    /// Ascii text of instruction operands
    /// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
    op_str : [160]u8,
    
    /// Pointer to cs_detail.
    /// NOTE: detail pointer is only valid when both requirements below are met:
    /// (1) CS_OP_DETAIL = CS_OPT_ON
    /// (2) Engine is not in Skipdata mode (CS_OP_SKIPDATA option set to CS_OPT_ON)
    ///
    /// NOTE 2: when in Skipdata mode, or when detail mode is OFF, even if this pointer
    ///     is not NULL, its content is still irrelevant.
    detail : ^cs_detail

}

cs_arch :: enum {
	CS_ARCH_ARM = 0,	///< ARM architecture (including Thumb, Thumb-2)
	CS_ARCH_ARM64,		///< ARM-64, also called AArch64
	CS_ARCH_MIPS,		///< Mips architecture
	CS_ARCH_X86,		///< X86 architecture (including x86 & x86-64)
	CS_ARCH_PPC,		///< PowerPC architecture
	CS_ARCH_SPARC,		///< Sparc architecture
	CS_ARCH_SYSZ,		///< SystemZ architecture
	CS_ARCH_XCORE,		///< XCore architecture
	CS_ARCH_M68K,		///< 68K architecture
	CS_ARCH_TMS320C64X,	///< TMS320C64x architecture
	CS_ARCH_M680X,		///< 680X architecture
	CS_ARCH_EVM,		///< Ethereum architecture
	CS_ARCH_MAX,
	CS_ARCH_ALL = 0xFFFF, // All architectures - for cs_support()
}

cs_err :: enum {
	CS_ERR_OK = 0,   ///< No error: everything was fine
	CS_ERR_MEM,      ///< Out-Of-Memory error: cs_open(), cs_disasm(), cs_disasm_iter()
	CS_ERR_ARCH,     ///< Unsupported architecture: cs_open()
	CS_ERR_HANDLE,   ///< Invalid handle: cs_op_count(), cs_op_index()
	CS_ERR_CSH,      ///< Invalid csh argument: cs_close(), cs_errno(), cs_option()
	CS_ERR_MODE,     ///< Invalid/unsupported mode: cs_open()
	CS_ERR_OPTION,   ///< Invalid/unsupported option: cs_option()
	CS_ERR_DETAIL,   ///< Information is unavailable because detail option is OFF
	CS_ERR_MEMSETUP, ///< Dynamic memory management uninitialized (see CS_OPT_MEM)
	CS_ERR_VERSION,  ///< Unsupported version (bindings)
	CS_ERR_DIET,     ///< Access irrelevant data in "diet" engine
	CS_ERR_SKIPDATA, ///< Access irrelevant data for "data" instruction in SKIPDATA mode
	CS_ERR_X86_ATT,  ///< X86 AT&T syntax is unsupported (opt-out at compile time)
	CS_ERR_X86_INTEL, ///< X86 Intel syntax is unsupported (opt-out at compile time)
	CS_ERR_X86_MASM, ///< X86 Masm syntax is unsupported (opt-out at compile time)
}

cs_mode :: enum {
	CS_MODE_LITTLE_ENDIAN = 0,	///< little-endian mode (default mode)
	CS_MODE_ARM = 0,	///< 32-bit ARM
	CS_MODE_16 = 1 << 1,	///< 16-bit mode (X86)
	CS_MODE_32 = 1 << 2,	///< 32-bit mode (X86)
	CS_MODE_64 = 1 << 3,	///< 64-bit mode (X86, PPC)
	CS_MODE_THUMB = 1 << 4,	///< ARM's Thumb mode, including Thumb-2
	CS_MODE_MCLASS = 1 << 5,	///< ARM's Cortex-M series
	CS_MODE_V8 = 1 << 6,	///< ARMv8 A32 encodings for ARM
	CS_MODE_MICRO = 1 << 4, ///< MicroMips mode (MIPS)
	CS_MODE_MIPS3 = 1 << 5, ///< Mips III ISA
	CS_MODE_MIPS32R6 = 1 << 6, ///< Mips32r6 ISA
	CS_MODE_MIPS2 = 1 << 7, ///< Mips II ISA
	CS_MODE_V9 = 1 << 4, ///< SparcV9 mode (Sparc)
	CS_MODE_QPX = 1 << 4, ///< Quad Processing eXtensions mode (PPC)
	CS_MODE_M68K_000 = 1 << 1, ///< M68K 68000 mode
	CS_MODE_M68K_010 = 1 << 2, ///< M68K 68010 mode
	CS_MODE_M68K_020 = 1 << 3, ///< M68K 68020 mode
	CS_MODE_M68K_030 = 1 << 4, ///< M68K 68030 mode
	CS_MODE_M68K_040 = 1 << 5, ///< M68K 68040 mode
	CS_MODE_M68K_060 = 1 << 6, ///< M68K 68060 mode
	CS_MODE_BIG_ENDIAN = 1 << 31,	///< big-endian mode
	CS_MODE_MIPS32 = CS_MODE_32,	///< Mips32 ISA (Mips)
	CS_MODE_MIPS64 = CS_MODE_64,	///< Mips64 ISA (Mips)
	CS_MODE_M680X_6301 = 1 << 1, ///< M680X Hitachi 6301,6303 mode
	CS_MODE_M680X_6309 = 1 << 2, ///< M680X Hitachi 6309 mode
	CS_MODE_M680X_6800 = 1 << 3, ///< M680X Motorola 6800,6802 mode
	CS_MODE_M680X_6801 = 1 << 4, ///< M680X Motorola 6801,6803 mode
	CS_MODE_M680X_6805 = 1 << 5, ///< M680X Motorola/Freescale 6805 mode
	CS_MODE_M680X_6808 = 1 << 6, ///< M680X Motorola/Freescale/NXP 68HC08 mode
	CS_MODE_M680X_6809 = 1 << 7, ///< M680X Motorola 6809 mode
	CS_MODE_M680X_6811 = 1 << 8, ///< M680X Motorola/Freescale/NXP 68HC11 mode
	CS_MODE_M680X_CPU12 = 1 << 9, ///< M680X Motorola/Freescale/NXP CPU12
					///< used on M68HC12/HCS12
	CS_MODE_M680X_HCS08 = 1 << 10, ///< M680X Freescale/NXP HCS08 mode
}

foreign lib {
    cs_open :: proc(arch : cs_arch, mode : cs_mode, handle : ^csh) -> cs_err ---
    cs_disasm :: proc(handle : csh, code : ^u8, code_size : u32, address : u64, count : u32, insn : ^^cs_insn) -> u32 ---
}
