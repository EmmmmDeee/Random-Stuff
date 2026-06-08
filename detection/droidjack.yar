/*
   YARA rules — DroidJack / SandroRat (Android RAT)
   Defensive detection. Tested against:
     APK  sha256 30aa2eeeb8401e4a312a7e99462432769a7c569114180aaedbfcbef18b6db268
     dex  sha256 fcac2275c833038982ed5bf3f27715bb1991f679d398a125661df15821737a1e
*/

rule DroidJack_SandroRat_dex
{
    meta:
        description = "DroidJack/SandroRat Android RAT (dex/apk)"
        author      = "defensive analysis"
        reference   = "MALWARE_ANALYSIS.md, SOURCE_LEVEL_ANALYSIS.md"
        malware     = "DroidJack"
        platform    = "android"
    strings:
        $dex   = { 64 65 78 0A 30 33 35 00 }   // "dex\n035\0" DEX file magic
        $pkg   = "net/droidjack/server" ascii   // slash form present in dex, not prose
        $c2a   = "droidjack.net/Access/DJ" ascii
        $c2b   = "droidjack.net/storeReport.php" ascii
        $cmd   = "DJ_GooDbYe:(" ascii
        $tbl1  = "SandroRat_Contacts_Database" ascii
        $tbl2  = "RecordedCallLogsTable" ascii
        $wa    = "com.whatsapp/databases/msgstore.db" ascii
        $cls1  = "CamSnapDJ" ascii
        $cls2  = "VideoCapDJ" ascii
    condition:
        // Must be a real DEX (anchored), then strong indicator(s).
        // Avoids matching documentation that merely quotes the IOC strings.
        $dex at 0 and
        (
            any of ($c2a, $c2b, $cmd) or
            ($pkg and 2 of ($tbl1, $tbl2, $wa, $cls1, $cls2))
        )
}

rule DroidJack_APK_container
{
    meta:
        description = "ZIP/APK container holding a DroidJack server payload"
        malware     = "DroidJack"
    strings:
        $z   = { 50 4B 03 04 }            // ZIP local file header
        $a   = "SandroRat.apk" ascii
        $b   = "net.droidjack.server" ascii
    condition:
        $z at 0 and any of ($a, $b)
}
