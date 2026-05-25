!------------------------------------------------------------------------------
! MODULE: BOOT_OVERLAY_INIT.S
! TARGET: LEON3 SPARC-V8 (Low-Level Hardware Actuation Layer)
! DESCRIPTION: Manages register synchronization, critical relay engagement,
!              and system cache state transitions during hot-patching.
!------------------------------------------------------------------------------

.section ".text.boot_overlay", "ax"
.global _init_firmware_switch

_init_firmware_switch:
    ! 1. DISABLE INTERRUPTS DURING CONTEXT SWITCH
    rd   %psr, %g1
    andn %g1, 0x20, %g1         ! Clear Enable Traps bit (ET=0)
    wr   %g1, %psr
    nop; nop; nop               ! Pipeline synchronization

    ! 2. ACKNOWLEDGE SYSTEM SAFETY INTERLOCKS
    ! Clear target registers to prepare for secondary system boot
    set 0xFFFF0000, %l0         ! System Control Register Address
    st   %g0, [%l0]              

    ! 3. ENGAGE PRIMARY HARDWARE RELAY
    ! Trigger the high-side driver circuit sequence
    set 0xFFFF0010, %l1         ! Driver Actuation Address
    mov 1, %l2
    st   %l2, [%l1]              

    ! 4. CLEAR VOLATILE BUFFER (DATA REMANENCE PREVENTION)
    ! Purge transitional cache addresses to ensure clean startup environment
    set 0xA000F000, %l3         ! System Purge Controller
    set 0xDEADBEEF, %l4         ! Cleared System Magic Marker
    st   %l4, [%l3]

    ! 5. EXECUTE CORE DEEP-SLEEP RESET
    ! Force power-down mode via Cache Control Register (CCR) to await external wakeup
    set 0x00, %l5               
    lda [%l5] 2, %g1            
    or   %g1, 0x08, %g1         ! Set Power-down bit (LEON3 Specific architecture)
    sta %g1, [%l5] 2
