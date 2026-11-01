
 ```
 _       _____  _______ _     _ _______ _______ _____ _______ _     _
 |      |     | |       |____/  |______ |  |  |   |      |    |_____|
 |_____ |_____| |_____  |    \_ ______| |  |  | __|__    |    |     |
     .--.                  .--.                  .--.
    /.-. '----------.     /.-. '----------.     /.-. '----------.
    \'-' .---'-''-'-'     \'-' .--'--''-'-'     \'-' .--'--'-''-'
     '--'                  '--'                  '--'


########## Auditing Issues ##########

Technique         : DETECT
Name              : horse-DC1-CA
DistinguishedName : CN=horse-DC1-CA,CN=Enrollment Services,CN=Public Key
                    Services,CN=Services,CN=Configuration,DC=horse,DC=local
Issue             : Auditing is not fully enabled. Current value is 0
Fix               : certutil -config 'DC1.horse.local\horse-DC1-CA' -setreg 'CA\AuditFilter' 127; Invoke-Command
                    -ComputerName 'DC1.horse.local' -ScriptBlock { Get-Service -Name 'certsvc' | Restart-Service
                    -Force }


########## Certification Authority Not Fully Evaluated ##########

Technique         : AVAILABILITY
Name              : horse-DC2-CA
DistinguishedName : CN=horse-DC2-CA,CN=Enrollment Services,CN=Public Key
                    Services,CN=Services,CN=Configuration,DC=horse,DC=local
Issue             : The host responds, but the CA service did not answer (0x800706ba). Not evaluated: DETECT, ESC6,
                    ESC7, ESC11, ESC16. Stages: DNS ok, ICMP failed, TCP 135 ok, certutil 0x800706ba.
Fix               : Check that the 'certsvc' service is running on DC2.horse.local.


########## ESC1 - Misconfigured Certificate Template ##########

Technique         : ESC1
Name              : ESC1-Vulnerable
DistinguishedName : CN=ESC1-Vulnerable,CN=Certificate Templates,CN=Public Key
                    Services,CN=Services,CN=Configuration,DC=horse,DC=local
Issue             : HORSE\kari can enroll in this Client Authentication template using a SAN without Manager
                    Approval
Fix               : Get-ADObject 'CN=ESC1-Vulnerable,CN=Certificate Templates,CN=Public Key
                    Services,CN=Services,CN=Configuration,DC=horse,DC=local' | Set-ADObject -Replace
                    @{'msPKI-Certificate-Name-Flag' = 0}


########## ESC2 - Misconfigured Certificate Template ##########

Technique         : ESC2
Name              : ESC2-Vulnerable
DistinguishedName : CN=ESC2-Vulnerable,CN=Certificate Templates,CN=Public Key
                    Services,CN=Services,CN=Configuration,DC=horse,DC=local
Issue             : NT AUTHORITY\Authenticated Users can request a SubCA certificate without Manager Approval
Fix               : Get-ADObject 'CN=ESC2-Vulnerable,CN=Certificate Templates,CN=Public Key
                    Services,CN=Services,CN=Configuration,DC=horse,DC=local' | Set-ADObject -Replace
                    @{'msPKI-Certificate-Name-Flag' = 0}


########## ESC4 - Vulnerable Certificate Template Access Control ##########

Technique         : ESC4
Name              : User
DistinguishedName : CN=User,CN=Certificate Templates,CN=Public Key
                    Services,CN=Services,CN=Configuration,DC=horse,DC=local
Issue             : NT AUTHORITY\Authenticated Users has GenericAll rights on this template
Fix               : [Available in experimental branch]

Technique         : ESC4
Name              : User
DistinguishedName : CN=User,CN=Certificate Templates,CN=Public Key
                    Services,CN=Services,CN=Configuration,DC=horse,DC=local
Issue             : HORSE\Domain Users has GenericAll rights on this template
Fix               : [Available in experimental branch]


########## ESC5 - Vulnerable PKI Object Access Control ##########

Technique         : ESC5
Name              : horse-DC1-CA
DistinguishedName : CN=horse-DC1-CA,CN=Enrollment Services,CN=Public Key
                    Services,CN=Services,CN=Configuration,DC=horse,DC=local
Issue             : HORSE\kari has CreateChild, DeleteChild, Self, WriteProperty, DeleteTree, Delete, GenericRead,
                    WriteDacl, WriteOwner rights on this object
Fix               : [Available in experimental branch]

Technique         : ESC5
Name              : DC1
DistinguishedName : CN=DC1,CN=AIA,CN=Public Key Services,CN=Services,CN=Configuration,DC=horse,DC=local
Issue             : HORSE\kari has GenericAll rights on this object
Fix               : [Available in experimental branch]


########## ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2 ##########

Technique         : ESC6
Name              : horse-DC1-CA
DistinguishedName : CN=horse-DC1-CA,CN=Enrollment Services,CN=Public Key
                    Services,CN=Services,CN=Configuration,DC=horse,DC=local
Issue             : EDITF_ATTRIBUTESUBJECTALTNAME2 is enabled.
Fix               : certutil -config DC1.horse.local\horse-DC1-CA -setreg policy\EditFlags
                    -EDITF_ATTRIBUTESUBJECTALTNAME2; Invoke-Command -ComputerName "DC1.horse.local" -ScriptBlock {
                    Get-Service -Name 'certsvc' | Restart-Service -Force }


########## ESC8 - HTTP Enrollment Enabled ##########

Technique           : ESC8
Name                : horse-DC1-CA
DistinguishedName   : CN=horse-DC1-CA,CN=Enrollment Services,CN=Public Key
                      Services,CN=Services,CN=Configuration,DC=horse,DC=local
EnrollmentEndpoints : {http://DC1.horse.local/certsrv/}
Issue               : HTTP enrollment is enabled.
Fix                 : 