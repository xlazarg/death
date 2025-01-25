import "pe"

rule WIN_MAL_AsyncRAT_JAN25
{
meta:
    description="Detects AsyncRAT samples"
    author="lazarg"
    date="2025-01-25"
    reference="https://www.virustotal.com/gui/file/8579bd550e62d5c01e34f4fefc627374d7598d62aed57dda018ae2804b1219fb/community"
    hash="8579bd550e62d5c01e34f4fefc627374d7598d62aed57dda018ae2804b1219fb" //SHA256  
strings:
    $l1 = "Select * from AntivirusProduct" wide // Low confidence suspicious strings
    $l2 = "/c taskkill.exe /im chrome.exe /f" wide
    $l3 = "cmd.exe" wide
    $l4 = "127.0.0.1" wide
    $l5 = "wallets" wide 
    $h1="\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" // High confidence suspicious strings    
    $h2=/\\User Data\\Default\\Local Extension Settings\\[a-z]{32}/ wide
condition:
    pe.is_pe and not
    pe.is_signed and // The executable is unsigned
    filesize < 100KB and
    (   (pe.version_info["OriginalFilename"] contains "Stub.exe" and all of ($l*))
        or 1 of ($h*)
    )
} 

