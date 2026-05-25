-------------------------------------------------------------------------------
-- PROCEDURE: Dynamic_Overlay_Manager
-- DESCRIPTION: Core Runtime Control Loop for High-Assurance Firmware Loading
-- TARGET: LEON3 SPARC V8 (Aerospace Reference Core)
-------------------------------------------------------------------------------
with Hardware_Interface;      use Hardware_Interface;
with Memory_Bank_Interface;   use Memory_Bank_Interface;
with Patch_Crypto;            -- AES-256 Verification Engine
with Telemetry_Network;        -- RecordFlux Verified Parser
with Fault_Isolation;         use Fault_Isolation;
with System.Machine_Code;
with System.Storage_Elements; use System.Storage_Elements;
with Hardware_IO;
with Interfaces;              use Interfaces;
 
procedure Dynamic_Overlay_Manager with 
  SPARK_Mode => On,
  Global => (In_Out => (Network_State, 
                        Current_Region, 
                        Update_Segment, 
                        Hardware_IO.Red_Hardware_State, 
                        Tamper_Detected))
is
   Incoming_Stream : Patch_Packet;
   Success         : Boolean;
   Health_Check    : Heartbeat_Status := 50; -- Subsystem Sanity Tripwire

   -------------------------------------------------------------------------
   -- HARDWARE SYNCHRONIZATION: SYNCHRONIZE_INSTRUCTION_CACHE
   -- SPARC V8: Uses 'sta' to modify the Cache Control Register (CCR) 
   -- in Address Space Identifier (ASI) 2 to guarantee instruction consistency.
   -------------------------------------------------------------------------
   procedure Synchronize_Instruction_Cache (Addr : System.Address) with
     SPARK_Mode => Off, 
     Global     => (In_Out => Hardware_IO.Red_Hardware_State)
   is
   begin
      -- 1. FLUSH: Invalidate the local Instruction Cache at the patch address.
      -- Critical for Harvard-architecture CPUs after dynamic data writes.
      System.Machine_Code.Asm (
          Template => "flush %0",
          Inputs   => (System.Address'Asm_Input ("r", Addr)),
          Volatile => True
      );
      
      -- 2. CACHE ALLOCATION: Store Alternate (sta) to ASI 2
      -- ASI 2 is the LEON3 architectural standard for Control Registers.
      System.Machine_Code.Asm (
          Template => "lda [%1] 2, %%g1; " &  -- Read current CCR
                      "or %%g1, 3, %%g1; " &  -- Ensure Instruction/Data Caches are active
                      "sta %%g1, [%1] 2",     -- Write back to CCR
          Inputs   => (System.Address'Asm_Input ("r", Addr),
                       Interfaces.Unsigned_32'Asm_Input ("r", 16#00#)), -- CCR offset
          Clobber  => "g1",
          Volatile => True
      );

      -- 3. PIPELINE BARRIER: Ensure cache stability before execution branch
      System.Machine_Code.Asm (Template => "nop; nop; nop; nop; nop", Volatile => True);
   end Synchronize_Instruction_Cache;

begin
   loop
      -- 1. FAULT ISOLATION: Instantly fail-safe if heartbeat status is nominal
      if not Verify_System_Health (Health_Check) then
          Purge_Transitional_RAM (Target_Addr => Map(Current_Region), 
                                  Size        => Storage_Offset(Patch_Buffer'Size / 8));
          return; 
      end if;

      -- 2. INGESTION: Read authenticated packets via the RecordFlux layer
      Receive_Secure_Patch (Incoming_Stream, Success);

      if Success then
          declare
              -- 3. DECRYPTION: Stream data is processed into a secure stack segment
              Decrypted_Image : constant Patch_Buffer := 
                  Patch_Crypto.Decrypt (Incoming_Stream.Payload, Runtime_Authentication_Key);
          begin
              -- 4. FAULT TOLERANCE: If target bank is unwriteable, rotate storage banks
              if not Check_Storage_Writable(Map(Current_Region)) then
                  Rotate_Memory_Bank;
              end if;

              -- 5. MEMORY LAYOUT CONFIGURATION
              declare
                 Target_Segment : Patch_Buffer with Address => Map(Current_Region);
              begin
                 Target_Segment := Decrypted_Image;
                 
                 -- 6. INTERLOCK SYNCHRONIZATION: Flush pipelines for the new instructions
                 Synchronize_Instruction_Cache(Target_Segment'Address);

                 -- 7. RE-VERIFY: Final state safety check before context switch
                 if not Verify_System_Health (Health_Check) then
                    Purge_Transitional_RAM(Target_Segment'Address, Storage_Offset(Target_Segment'Size / 8));
                    return;
                 end if;

                 -- 8. THE BOOT SWITCH: Transfer hardware control to the new routine
                 -- Utilizes 'restore' in the branch delay slot to safely reset register windows.
                 System.Machine_Code.Asm (
                    Template => "jmp %0; restore", 
                    Inputs   => (System.Address'Asm_Input ("r", Target_Segment'Address)),
                    Volatile => True
                 );
              end; 
          end; 
      end if;

      -- Fault Isolation: Brief telemetry delay interval to balance processor load
      delay until Next_Scheduling_Interval;
   end loop;
end Dynamic_Overlay_Manager;
