import "pe"

rule WIN_MAL_TROJAN_LATRODECTUS_JAN27
{
meta:
    description="Detects Latrodectus trojan based on either anomalous PE properties or unique malware strings."
    author="lazarg"
    date="2025-01-27"
    reference="https://www.virustotal.com/gui/file/aee22a35cbdac3f16c3ed742c0b1bfe9739a13469cf43b36fb2c63565111028c/community"
    hash="aee22a35cbdac3f16c3ed742c0b1bfe9739a13469cf43b36fb2c63565111028c" //SHA256  
strings:
    $h1 = "\\bin_win7\\x64\\Release\\trufos.pdb" // pdb path
    $h2 = "\\builds\\ARK23181_2\\trufos_dll\\" 
    $h3 = "\\Build\\PETRU-DEFAULT-SOURCES\\"
condition:
    pe.is_pe and not
    pe.is_signed and // The DLL is unsigned
    ( pe.version_info["OriginalFilename"] contains "TRUFOS.DLL" or // The DLL has an OriginalFileName attribute of TRUFOS.DLL
    all of ($h*)
    ) and 
    filesize < 1000KB
} 