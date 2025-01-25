import "pe"

rule WIN_MAL_TROJAN_QBOT_CRIME_JAN25
{
meta:
    description="Detects qbot DLL downloaded and executed via powershell in the final stages of the infection chain."
    author="lazarg"
    date="2025-01-25"
    reference="https://www.filescan.io/reports/6a8557a2f8e1338e6edb2a07c345882389230ea24ffeb741a59621b7e8b56c59/662371d6-8c68-4ac8-990c-750a55fcd4fe"
    hash="6a8557a2f8e1338e6edb2a07c345882389230ea24ffeb741a59621b7e8b56c59" //SHA256  
strings:
    $l1 = "GDK_IS_SCREEN" // Strings related to Gimp Drawing Kit
    $l2 = "gdk_display_list_devices"
    $l3 = "gdk_device_get_source"
    $l4 = "GIMP Drawing Kit" wide
    $l5 = "bugzilla.gnome.org"
    $l6 = "Tdk_keymap_get_type"  // Strings related to GTK
    $l7 = "Tdk_gc_values_mask_get_type" 
    $l8 = "Tdk_get_default_root_window" 
    $l9 = "LoadLibraryA" // Other uncommon imported functions.
    $l10 = "SetClipboardData"
    $l11 = "TrackMouseEvent"
condition:
    pe.is_pe and not
    pe.is_signed and // The DLL is unsigned
    filesize < 1000KB and
    pe.imports("USER32.DLL","GetForegroundWindow") and // winapi functions related to keylogging
    pe.imports("USER32.DLL","MapVirtualKeyA") and
    5 of ($l*)
} 

