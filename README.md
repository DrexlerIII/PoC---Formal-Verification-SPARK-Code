High-Assurance Systems Architecture & Exploitation Sandboxes in Ada/SPARK. 

A personal weekend project exploring the boundaries of the SPARK formal verification toolchain, contrasting hardware-hardened cryptographic implementations against dynamic, polymorphic execution engines. The polymorphic code is left out of the final repo upload.  


- Anti-debugging code 
- AES S-Box Implementation
- crt0.s (Power-PC assembly)
- Silo code, defensive side.


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
