-------------------------------------------------------------------------------
-- PACKAGE: Software_Diversification_Manager.ads
-- SPECIFICATION: Fault-Tolerant Memory Rotation & Runtime Dynamic Loading
-- TARGET: LEON3 SPARC V8 (High-Assurance Reference Core)
-------------------------------------------------------------------------------
with System;
with Interfaces; use Interfaces;

package Software_Diversification_Manager with SPARK_Mode is
   
   -- Redundant memory banks mapped directly to hardware layout links
   type Memory_Bank is (Primary_Bank, Secondary_Bank, Auxiliary_Bank);
   
   -- Aligned to standard memory.ld linker origins
   Map : constant array (Memory_Bank) of System.Address := 
     (Primary_Bank   => System'To_Address(16#A000_1000#), -- Isolated Secure RAM
      Secondary_Bank => System'To_Address(16#2000_0000#), -- System Work RAM
      Auxiliary_Bank => System'To_Address(16#7000_0000#));-- Redundant Storage Bank

   Current_Bank : Memory_Bank := Primary_Bank;

   -- Rotates the active execution bank to maintain system resilience
   procedure Rotate_Execution_Bank with
     Global  => (In_Out => Current_Bank),
     Depends => (Current_Bank => Current_Bank),
     Post    => Current_Bank /= Current_Bank'Old;

   -- Verification checks for target bank access readiness
   function Check_Memory_Writeable (Addr : System.Address) return Boolean;

end Software_Diversification_Manager;
