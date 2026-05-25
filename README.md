High-Assurance Systems Architecture & Exploitation Sandboxes in Ada/SPARK. 

A personal weekend project exploring the boundaries of the SPARK formal verification toolchain, contrasting hardware-hardened cryptographic implementations against dynamic, polymorphic execution engines. The polymorphic code is left out of the final repo upload.  


- Anti-debugging code 
- AES S-Box Implementation
- crt0.s (Power-PC assembly)
- Silo code, defensive side.

      Secure_Boot_Enclave.adb layout
      [ REPRECENTATIVE ENCLAVE PIPELINE ]

      +--------------------------------------------------------+
      |               Inbound Network Buffer                   |
      +--------------------------------------------------------+
                                  |
                                  v
                /-----------------------------------\
               < Is the Emergency Diagnostic Token?  >
                \-----------------------------------/
                     /                         \
            YES     /                           \   NO
                   v                             v
      +-------------------------+   +-------------------------+
      |  Diagnostic Fallback    |   | Primary Crypto Pipeline |
      |  Authentication Path    |   |    (Montgomery Ladder)  |
      +-------------------------+   +-------------------------+
                   \                             /
                    \                           /
                     v                         v
      +--------------------------------------------------------+
      |              Verified Hardware Actuation               |
      +--------------------------------------------------------+

                  dynamic_overlay_manager.adb layout
                  [ PRODUCTION HOT-PATCH TIMELINE ]

                   1. INGESTION       2. VERIFICATION       3. CACHE SYNC         4. BRANCH
                  +-------------+    +---------------+    +----------------+    +------------+
                  | RecordFlux  | -> | AES-256 Stack | -> |  SPARC V8 Asm  | -> | Jump to    |
                  | Buffer Read |    | Block Decrypt |    | I-Cache Flush  |    | New Memory |
                  +-------------+    +---------------+    +----------------+    +------------+
  
        software_diversification_manager.adb & software_diversification_manager.ads layout 
        [ THE DIVERSIFICATION PROCESS ]

      +-------------------------------------------------------+
      |               Static Base Firmware Image              |
      +-------------------------------------------------------+
                                  |
                                  v
              +---------------------------------------+
              |      Software Diversification Module  |
              |       (Dynamic Memory Bank Rotation)  |
              +---------------------------------------+
                /                 |                 \
               /                  |                  \
              v                   v                   v
      +---------------+   +---------------+   +---------------+
      |   Variant A   |   |   Variant B   |   |   Variant C   |
      | Memory Layout |   | Memory Layout |   | Memory Layout |
      +---------------+   +---------------+   +---------------+
