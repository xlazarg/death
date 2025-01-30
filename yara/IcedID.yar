import "pe"

rule WIN_MAL_TROJAN_ICEDID_JAN27
{
meta:
    description="Detects IcedID trojan."
    author="lazarg"
    date="2025-01-27"
    reference="https://www.virustotal.com/gui/file/cdf05d78f3a588cfb721a36c6ae43365c45858a26a9145b719d8e98eee69e3fc/community"
    hash="cdf05d78f3a588cfb721a36c6ae43365c45858a26a9145b719d8e98eee69e3fc" //SHA256  
strings:
    $h1 = "jrsoftware.org" wide
    $h2 = "Software\\CodeGear\\" wide
    $h3 = "SOFTWARE\\Borland\\" wide
    $h4 = "Freemake Video Converter" wide
    $h5 = "avast.com"
    $h6 = "FastMM Borland Edition"
    $h7 = "Inno Setup"
    $h8 = "GetKeyboardType"
    $h9="Sleep"
    $h10="GetCurrentProcess"
    $h11="GetCommandLineW"
    $h12="RegOpenKeyExW"
    $h13="RegQueryValueExW"
    $h14="CreateDirectoryW"
    $h15="GetDiskFreeSpaceExW" wide
    $h16="Stack overflow" wide
condition:
    pe.is_pe and
    8 of ($h*) and
    filesize < 4000KB
} 