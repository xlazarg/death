import "pe"

rule WIN_MAL_TROJAN_PIKABOT_JAN27
{
meta:
    description="Detects pikabot trojan based on either PE attributes or Strings."
    author="lazarg"
    date="2025-01-27"
    reference="https://www.virustotal.com/gui/file/7d18e238febf88bc7c868e3ee4189fd12a2aa4db21f66151bb4c15c0600eca6e/community"
    hash="7d18e238febf88bc7c868e3ee4189fd12a2aa4db21f66151bb4c15c0600eca6e" //SHA256  
strings:
    $h1 = "\\vmagent_new\\bin\\joblist\\498883\\out\\Release\\QHFileSmasher.pdb" // pdb path
    $h2 = "vctools\\vc7libs\\ship\\atlmfc\\include\\afxwin" wide
    $h3 = "FullMatch|CSIDL_WINDOWS|system32\\drivers\\" wide
    $l1 = "360TotalSecurity" wide
    $l2 = ".\\common\\image\\Window_pop" wide
    $l3 = "360safe.exe" wide
    $l4 = "Please reinstall 360 Total Security and scan for viruses." wide
condition:
    pe.is_pe and not
    pe.is_signed and // The EXE is unsigned
    ( (pe.version_info["OriginalFilename"] contains "QHFileSmasher.exe" and 1 of ($l*) ) or // The EXE has an OriginalFileName attribute of QHFileSmasher.exe
    all of ($h*)
    ) and 
    filesize < 1500KB
} 