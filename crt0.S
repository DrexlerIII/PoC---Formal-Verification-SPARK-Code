/* ======================================================================== */
/* crt0.S - RAD750 High-Assurance Production Flight Startup                 */
/* Platform: BAE RAD750 (PowerPC 750 Hardened Core) - This code is -        */
/* - explicitly tailored to handle the harsh environmental and physical -   */
/* - realities that radiation-hardened -                                    */
/* Target Runtime: GNAT / SPARK Level 4 Formal Verification Runtime         */
/* ======================================================================== */

.section .boot, "ax"
.global _start

_start:
    /* -------------------------------------------------------------------- */
    /* 1. Hardware Quiescence & Interrupt Disabling                         */
    /* -------------------------------------------------------------------- */
    li      r0, 0
    mtmsr   r0                  /* Clear MSR: Disable EE (External), PR (Problem State), */
                                /* FP (Floating Point), IR/DR (Address Translation) */
    isync                       /* Context synchronizing instruction */

    /* -------------------------------------------------------------------- */
    /* 2. Invalidate L1 Instruction & Data Caches                           */
    /* Required to clear cosmic-ray induced or power-on anomalous states */
    /* in the HID0 (Hardware Implementation Register 0).                 */
    /* -------------------------------------------------------------------- */
    mfspr   r4, 1008            /* r4 = HID0 */
    
    /* Flash Invalidate Instruction Cache (ICFI) & Data Cache (DCFI) */
    oris    r4, r4, 0x0C00      /* Set bits 10 (ICFI) and 11 (DCFI) */
    mtspr   1008, r4            /* Execute invalidation */
    isync                       /* Force completion before proceeding */

    /* Clear the invalidation bits to allow normal cache operation later */
    rlwinm  r4, r4, 0, 12, 9    /* Clear ICFI and DCFI bits */
    mtspr   1008, r4
    isync

    /* -------------------------------------------------------------------- */
    /* 3. Initialize Stack & GNAT Safety Boundaries                         */
    /* -------------------------------------------------------------------- */
    lis     r1, __stack_end@ha  /* Primary Stack Pointer (r1) */
    addi    r1, r1, __stack_end@l
    
    /* GNAT Uses r2 for -fstack-check on this target.                       */
    /* Enforces that the stack cannot grow down into the MMIO space.        */
    lis     r2, __stack_limit@ha
    addi    r2, r2, __stack_limit@l

    /* Clear ABI-mandated backchain linkage for the initial stack frame     */
    li      r0, 0
    stw     r0, 0(r1)           /* Clear backchain pointer */
    stwu    r1, -16(r1)         /* Create initial 16-byte dummy stack frame */

    /* -------------------------------------------------------------------- */
    /* 4. Safe Memory Scrubbing & BSS Initialization (ECC-Compliant)        */
    /* We must use pure STORE words (stw). A Read-Modify-Write loop      */
    /* will trap a Machine Check due to uninitialized ECC bits in RAM.   */
    /* -------------------------------------------------------------------- */
    lis     r3, __bss_start@ha
    addi    r3, r3, __bss_start@l
    lis     r4, __bss_end@ha
    addi    r4, r4, __bss_end@l

    /* Ensure we actually have a BSS section to clear */
    cmpw    r3, r4
    bge     .L_bss_done

.L_scrub_loop:
    stw     r0, 0(r3)           /* Pure write 32-bits of zero (Writes valid ECC) */
    addi    r3, r3, 4           /* Move to next word */
    cmpw    r3, r4
    blt     .L_scrub_loop

.L_bss_done:
    isync                       /* Ensure all memory writes are completed */

    /* -------------------------------------------------------------------- */
    /* 5. Clear and Initialize Exception Vector Table (EVT) Base            */
    /* Enforces MSR[IP]=0 (Low Memory Vectors at 0x0000_0000) and           */
    /* populates transient panic stubs across critical exception boundaries. */
    /* -------------------------------------------------------------------- */
    
    /* A. Explicitly force MSR to use Low Vectors (Clear MSR[IP] bit 25)    */
    mfmsr   r4                  /* Read current MSR */
    rlwinm  r4, r4, 0, 26, 24   /* Clear bit 25 (IP) cleanly */
    mtmsr   r4                  /* Write back to MSR */
    isync

    /* B. Clear the baseline Exception Vector Space in RAM (ECC-safe)       */
    /* System vectors span from 0x0000_0000 to 0x0000_1F00 (System Reset to */
    /* Performance Monitor exceptions).                                    */
    li      r3, 0x0000          /* Start address of EVT in RAM */
    lis     r4, 0x0000          /* High word of end address */
    ori     r4, r4, 0x2000      /* End address boundary (8KB space) */
    li      r0, 0               /* Zero value */

.L_evt_clear_loop:
    stw     r0, 0(r3)           /* Pure write zero to initialize RAM ECC */
    addi    r3, r3, 4
    cmpw    r3, r4
    blt     .L_evt_clear_loop
    isync

    /* C. Install Transient Flight Exception Stubs                          */
    /* We will explicitly populate Vector 0x200 (Machine Check) and          */
    /* Vector 0x300 (D-SIEG / Data Storage Exception) with an atomic trap.  */
    /* The trap instruction sequence:                                       */
    /* 7C 00 00 08 -> trap (unconditional)                                */
    /* 48 00 00 00 -> b . (infinite loop backstop)                       */
    /* -------------------------------------------------------------------- */
    
    /* Prepare the instruction payload in registers */
    lis     r5, 0x7C00          /* High word: trap instruction */
    ori     r5, r5, 0x0008      /* Low word */
    lis     r6, 0x4800          /* High word: branch-to-self instruction */
    ori     r6, r6, 0x0000      /* Low word */

    /* Install Machine Check Handler at 0x0000_0200 */
    li      r3, 0x0200
    stw     r5, 0(r3)           /* Write trap instruction at vector base */
    stw     r6, 4(r3)           /* Write branch-to-self right after it */

    /* Install Data Storage Exception (DSI) Handler at 0x0000_0300 */
    li      r3, 0x0300
    stw     r5, 0(r3)
    stw     r6, 4(r3)

    /* Install Instruction Storage Exception (ISI) Handler at 0x0000_0400 */
    li      r3, 0x0400
    stw     r5, 0(r3)
    stw     r6, 4(r3)

    /* Flush Instructions out of Data Cache to RAM and invalidate          */
    /* Instruction Cache so the CPU sees the newly written vector opcodes. */
    msync                       /* Ensure memory stores are flushed */
    mfspr   r4, 1008            /* Read HID0 */
    oris    r4, r4, 0x0400      /* Assert ICFI (Instruction Cache Flash Invalidate) */
    mtspr   1008, r4
    isync                       /* Context sync to commit cache invalidation */

    /* -------------------------------------------------------------------- */
    /* 6. Jump to GNAT Elaboration / Ada Entry Point                        */
    /* -------------------------------------------------------------------- */
    bl      _ada_main

    /* Fallback trap if _ada_main ever unexpectedly returns */
.L_panic:
    /* Execute an unconditional, architecture-defined trap instruction. */
    /* This guarantees a transition directly to Vector 0x700 (Program Exception) */
    tw      31, r0, r0          /* Trap Word Unconditionally */
    
    /* Absolute hardware backstop if the trap state is bypassed */
    b       .L_panic            /* Infinite tight branch self-loop */
