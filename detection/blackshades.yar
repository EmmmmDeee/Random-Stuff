/*
   YARA rules — Blackshades NET (Windows RAT, VB6 controller/builder)
   Defensive detection. Tested against:
     client.exe sha256 5b239d680aac3e49d722a6859e397d327cd6b9dcbfd8eb09c3ccfaa007bbb95e
                md5    6eff4657d417c4a1393cb8f63849b4e5
                imphash e22efc208b0220bae4bf4bd600a00c70
*/

import "pe"

rule Blackshades_NET_client
{
    meta:
        description = "Blackshades NET RAT controller/builder (VB6)"
        author      = "defensive analysis"
        reference   = "MALWARE_ANALYSIS.md"
        malware     = "Blackshades"
        platform    = "windows"
    strings:
        $vbp   = "Blackshades Project\\bs_net\\client\\client.vbp" ascii
        $b1    = "Blackshades NET" ascii wide
        $b2    = "bss_client" ascii
        $b3    = "DownloadExecute.bss" ascii
        $crack = "Blackshades cracked by MaxXor" ascii
        $f1    = "frmKeylogLive" ascii
        $f2    = "frmFormGrabber" ascii
        $f3    = "frmInfector" ascii
        $f4    = "frmBotkiller" ascii
    condition:
        uint16(0) == 0x5A4D and
        (
            $vbp or $crack or
            (2 of ($b1, $b2, $b3)) or
            (3 of ($f1, $f2, $f3, $f4))
        )
}

rule Blackshades_NET_imphash
{
    meta:
        description = "Blackshades NET by import hash (VB6 build)"
        malware     = "Blackshades"
    condition:
        pe.imphash() == "e22efc208b0220bae4bf4bd600a00c70"
}
