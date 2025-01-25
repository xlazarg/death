import "pe"

rule MAL_CRIME_LOADER_WIN_JAN25
{
meta:
    description="Detects matanbuchus loaders disgused as CPL files."
    author="lazarg"
    date="2025-01-25"
    reference="https://bazaar.abuse.ch/browse/yara/crime_win32_matanbuchus_loader/"
    hash="1ca1315f03f4d1bca5867ad1c7a661033c49bbb16c4b84bea72caa9bc36bd98b" //SHA256  
strings:
    $l1 = "CHOSEN_DATA_PUM"
    $l2 = "DllRegisterServer"
    $l3 = "DllUnregisterServer"
    $l4 = "GetEnvironmentStringsW"
    $l5 = "StartIdle"
    $l6 = "Start Monitoring A" wide
    $l7 = "GET_MSG_BODY" wide
    $l8 = "CHOSEN_DATA_PUM" wide
condition:
    pe.is_pe and
    pe.imports("KERNEL32.DLL","IsDebuggerPresent") and
    pe.exports("DllRegisterServer") and
    all of ($l*)
} 