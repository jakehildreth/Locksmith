``` mermaid
---
title: Availability
---
flowchart LR
    CA[CA found in AD] --> Stages[Run DNS, ICMP, transport and certutil ping together]
    Stages --> Ping{certutil -pingadmin passed?}
    Ping -- No --> NotReachable[Not Reachable: one AVAILABILITY row with the reason]
    Ping -- Yes --> Reads[Read CA settings with certutil -getreg]
    Reads --> Read{Every read passed?}
    Read -- Yes --> Checks[Run DETECT, ESC6, ESC7, ESC11, and ESC16]
    Read -- No --> Partial[One AVAILABILITY row for the failed reads. The other checks still run]
```
