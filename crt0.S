/* crt0.S - RAD750 Production Startup */
.section .boot, "ax"
.global _start

_start:
    /* 1. Clear MSR (Machine State Register) to disable interrupts */
    li      r0, 0
    mtmsr   r0
    isync

    /* 2. Initialize Primary Stack Pointer (r1) */
    lis     r1, __stack_end@ha      /* __stack_end defined in Linker Script */
    addi    r1, r1, __stack_end@l
    
    /* 3. Initialize Stack Limit (r2) - Critical for GNAT -fstack-check */
    /* This prevents r1 from ever colliding with our IO space at 0xA000_1000 */
    lis     r2, __stack_limit@ha
    addi    r2, r2, __stack_limit@l

    /* 4. Clear the BSS section (Zero-initialize uninitialized data) */
    /* Required by Ada/SPARK semantics before jumping to 'main' */
    lis     r3, __bss_start@ha
    addi    r3, r3, __bss_start@l
    lis     r4, __bss_end@ha
    addi    r4, r4, __bss_end@l
    bl      mem_zero

    /* 5. Jump to the GNAT Ada Entry Point */
    bl      _ada_main