/*
   YARA — cross-sample pivot: non-standard ".mackt" section.
   Observed in BOTH client.exe (Blackshades RAT) and vcscore.exe (a "crack"),
   indicating a shared protector/cracking tool. Use as a hunting pivot, not a
   standalone conviction (a benign file could in theory use the name).
*/
import "pe"

rule Shared_mackt_section_pivot
{
    meta:
        description = "PE with non-standard .mackt section (shared protector pivot)"
        reference   = "EXECUTABLES_ANALYSIS.md"
        confidence  = "hunting-pivot"
    condition:
        uint16(0) == 0x5A4D and
        for any s in pe.sections : (s.name == ".mackt")
}

rule Crack_with_injection_imports
{
    meta:
        description = "A 'crack'/utility importing a process-injection toolkit"
        reference   = "EXECUTABLES_ANALYSIS.md (vcscore.exe)"
        confidence  = "suspected-malware"
    condition:
        uint16(0) == 0x5A4D and
        pe.imports("kernel32.dll", "CreateRemoteThread") and
        pe.imports("kernel32.dll", "WriteProcessMemory") and
        pe.imports("kernel32.dll", "VirtualAllocEx") and
        pe.imports("user32.dll", "SetWindowsHookExA")
}
