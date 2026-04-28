package Anti_Forensics 
  with SPARK_Mode => On,
       Abstract_State => (Security_State with External_Property => Async_Writers)
is
   -- The "Hole": 0 and 101+ are now 'Illegal' bit patterns.
   -- If a debugger forces a 0 into this memory, 'Valid fails instantly.
   type Sanity_Check is range 1 .. 100 with Default_Value => 50;
   
   -- Volatile ensures the compiler always reads the RAM, never a register.
   Tamper_Detected : Boolean := False with 
     Volatile,
     Part_Of => Security_State;

   -- We use 'Ghost' code here to prove that if Integrity fails, 
   -- the system state MUST transition to 'Tamper_Detected'.
   procedure Verify_Integrity (Value : Sanity_Check)
     with 
       Global => (In_Out => Security_State),
       Post   => (if not Value'Valid then Tamper_Detected);

   -- Mandatory zeroization of sensitive memory.
   procedure Secure_Wipe (Target_Addr : System.Address; 
                          Size        : System.Storage_Elements.Storage_Offset)
     with 
       Pre    => Tamper_Detected,
       Global => (In_Out => Security_State);

end Anti_Forensics;