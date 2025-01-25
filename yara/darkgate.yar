import "pe"

rule WIN_MAL_TROJAN_DARKGATE_JAN25
{
meta:
    description="Detects Darkgate trojan"
    author="lazarg"
    date="2025-01-25"
    reference="https://www.virustotal.com/gui/file/0efb25b41efef47892a1ed5dfbea4a8374189593217929ef6c46724d0580db23/community"
    hash="0efb25b41efef47892a1ed5dfbea4a8374189593217929ef6c46724d0580db23" //SHA256  
strings:
    $l1 = "fopen" fullword wide // Low confidence strings
    $l2 = "WinHTTP Example/1.0" wide
    $l3 = "Washington1"
    $l4 = "Redmond1"   
    $l5 = "Virtual Machine Detected" 
    $l6 = "cleanhelper.pdf"
    $l7 = "cleanmgr"
    $l8 = "GetTempPath2W"
    $l9 = "WinHttpOpenRequest"
    $l10 = "GetUserDefaultLocaleName"
    $l11 = "ShellExecuteW"
    $h1 = "Not compatable!" // High confidence strings
    $h2 = "SilentCleanup.xml.txt" wide
    $h3 = "\\Dropper\\wldp\\x64\\Release\\wldp.pdb"
    $h4 = "funtic321b"
    $h5 = "Meow-meow!"
    $h6 = "cryptbase.SystemFunction"
    $h7 = "MAGA\\cryptbase_meow"
    $h8 = "abdwufkw" wide

condition:
    pe.is_pe and not
    pe.is_signed and // The executable is unsigned
    filesize < 1500KB and
    all of ($l*) or 5 of ($h*)
} 

