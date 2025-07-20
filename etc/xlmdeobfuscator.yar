private rule CompoundFile
{
meta:
author = "Malware Utkonos"
date = "2020-07-04"
description = "Magic number for Microsoft compound files: 'D0CF11E0A1B11AE1'."
condition:
uint32(0) == 0xE011CFD0 and uint32(4) == 0xE11AB1A1
}

rule Excel5_RootCLSID
{
meta:
author = "Malware Utkonos"
date = "2020-07-15"
description = "Excel BIFF5 root entry record class ID."
strings:
$clsid = { 10 08 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 }
condition:
CompoundFile and
$clsid at ((uint32(48) + 1) * (1 << uint16(30)) + 80)
}

rule Excel8_RootCLSID
{
meta:
author = "Malware Utkonos"
date = "2020-08-08"
description = "Excel BIFF8 root entry record class ID."
strings:
$clsid = { 20 08 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 }
condition:
CompoundFile and
$clsid at ((uint32(48) + 1) * (1 << uint16(30)) + 80)
}

rule Excel_DirEntryName_BIFF5
{
meta:
author = "Malware Utkonos"
date = "2020-08-09"
description = "Directory entry for a stream named 'Book' in a compound file."
strings:
$dirname = { 42 00 6F 00 6F 00 6B 00 [57] 00 02 0? } // Book
condition:
CompoundFile and
for any i in (1..#dirname) : (
for any j in (1..31) : ( @dirname[i] == (uint32(48) + 1) * (1 << uint16(30)) + j * 128 )
)
}

rule Excel_DirEntryName_BIFF8
{
meta:
author = "Malware Utkonos"
date = "2020-08-09"
description = "Directory entry for a stream named 'Workbook' in a compound file."
strings:
$dirname = { 57 00 6F 00 72 00 6B 00 62 00 6F 00 6F 00 6B 00 [49] 00 02 0? } // Workbook
condition:
CompoundFile and
for any i in (1..#dirname) : (
for any j in (1..31) : ( @dirname[i] == (uint32(48) + 1) * (1 << uint16(30)) + j * 128 )
)
}

rule Excel_CompoundFile
{
condition:
Excel5_RootCLSID or Excel8_RootCLSID or Excel_DirEntryName_BIFF5 or Excel_DirEntryName_BIFF8
}

rule Excel_Macros40_String : xlm4
{
meta:
author = "Malware Utkonos"
date = "2020-07-23"
description = "Variations of the Excel 4.0 Macros string found in the Document Summary Info property."
strings:
$a = { 20 45 78 63 65 6C 20 34 2E 30 00 }
$b = { 00 45 78 63 65 6C 20 34 2E 30 20 }
$c = { 00 45 78 63 65 6C 20 34 2E 30 2D }
$fp = { 31 39 39 32 20 45 78 63 65 6C 20 34 2E 30 00 }
condition:
Excel_CompoundFile and any of ($a,$b,$c) and
not $fp
}

rule Excel_DocSumInfo_Macros40_Prop : xlm4
{
meta:
author = "Malware Utkonos"
date = "2020-07-23"
description = "Document Summary Information containing a property value for Excel 4.0 macros."
strings:
$ = { 1E 00 00 00 ?? 00 00 00 [0-20] 20 45 78 63 65 6C 20 34 2E 30 00 }
$ = { 1E 00 00 00 ?? 00 00 00 [0-20] 45 78 63 65 6C 20 34 2E 30 20 }
$ = { 1E 00 00 00 ?? 00 00 00 [0-20] 45 78 63 65 6C 20 34 2E 30 2D }
condition:
Excel_CompoundFile and any of them
}

rule Excel_BOF_BIFF57_Macros40 : xlm4
{
meta:
author = "Malware Utkonos"
date = "2020-07-23"
description = "Beginning of File (BOF) record in BIFF5 or BIFF7 format with Excel 4.0 macros."
strings:
$bof = { 09 08 08 00 00 05 40 00 }
condition:
Excel_CompoundFile and $bof
}

rule Excel_BOF_BIFF8_Macros40_8 : xlm4
{
meta:
author = "Malware Utkonos"
date = "2020-07-23"
description = "Beginning of File (BOF) record in BIFF8 format with Excel 4.0 macros of length 8."
strings:
$bof = { 09 08 08 00 00 06 40 00 }
condition:
Excel_CompoundFile and $bof
}

rule Excel_BOF_BIFF8_Macros40_16 : xlm4
{
meta:
author = "Malware Utkonos"
date = "2020-07-23"
description = "Beginning of File (BOF) record in BIFF8 format with Excel 4.0 macros of length 16."
strings:
$bof = { 09 08 10 00 00 06 40 00 [10] 00 00 }
condition:
Excel_CompoundFile and $bof
}

rule Excel_Boundsheet_Macros40 : xlm4
{
meta:
author = "Malware Utkonos"
date = "2020-07-23"
description = "Boundsheet record with sheet type: Excel 4.0 macro at any visibility setting."
strings:
$bs = { 85 00 ?? 00 [5] 01 }
condition:
Excel_CompoundFile and $bs and
for any i in (1..#bs) : (
for any j in (0..2) : ( uint8(@bs[i] + 8) & 0x3 == j and uint8(@bs[i] + 2) >= 0x8 and uint8(@bs[i] + 2) <= 0x88 )
)
}

rule Excel_Boundsheet_Macros40_ResSet : xlm4
{
meta:
author = "Malware Utkonos"
date = "2020-07-23"
description = "Boundsheet record with sheet type: Excel 4.0 macro at any visibility setting and data in the reserved bits."
strings:
$bs = { 85 00 ?? 00 [5] 01 }
condition:
Excel_CompoundFile and $bs and
for any i in (1..#bs) : (
for any j in (0..2) : ( uint8(@bs[i] + 8) & 0x3 == j and uint8(@bs[i] + 8) > 0x2 and uint8(@bs[i] + 2) >= 0x8 and uint8(@bs[i] + 2) <= 0x88 )
)
}
rule XLSM_with_xlm_macro: xlm4 {
        meta:
                tlp = "green"
                author = "DissectMalware"
                date = "2020-04-14"
                malware_family = "misc"
                description = "Detects xlm macros in xlsm excel docs"
                hashes = "['01558388b33abe05f25afb6e96b0c899221fe75b037c088fa60fe8bbf668f606']"
                scope = "['collection', 'detection']"
                platform = "['VirusTotal', 'ICET', 'EX']"
                intel = "['']"
        strings:
                $zip_marker = "PK"
                $xlsx_marker = {5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C}
                $macrosheet_marker = {6D 61 63 72 6F 73 68 65 65 74 73}
        condition:
                $zip_marker at 0 and $xlsx_marker and $macrosheet_marker
}
rule GEN_ModernExcel4MacroZIP: xlm4
{
    meta:
        tlp = "green"
        author = "John Lambert @JohnLaTwC"
        date = "2020-04-15"
        malware_family = "misc"
        description = "Detects Modern Excel4 macro use"
        hashes = "['01558388b33abe05f25afb6e96b0c899221fe75b037c088fa60fe8bbf668f606']"
        scope = "['collection', 'detection']"
        platform = "['VirusTotal', 'ICET', 'EX']"
        intel = "https://twitter.com/DissectMalware/status/1250411834953420808"
    strings:
        $header_zip = { 50 4b 03 04 }

        $header_content_xml="[Content_Types].xml" nocase

        //00000e30: cc 02 00 00 19 00 00 00 78 6c 2f 6d 61 63 72 6f  ........xl/macro
        //00000e40: 73 68 65 65 74 73 2f 73 68 65 65 74 34 2e 78 6d  sheets/sheet1.xm
        $sheets = { 78 6c 2f 6d 61 63 72 6f 73 68 65 65 74 73 2f 73 68 65 65 74 3? [0-1] 2e 78 6d 6c}
    condition:
        filesize < 2400KB
        and $header_zip at 0
        and $header_content_xml in (0 .. 0x200)
        and #sheets > 0
}
rule GEN_ModernExcel4MacroZIPManySheets: xlm4
{
    meta:
        tlp = "green"
        author = "John Lambert @JohnLaTwC"
        date = "2020-04-15"
        malware_family = "misc"
        description = "Detects Modern Excel4 macro use"
        hashes = "['dfe1f9afcb096c83169a0708ffdc5ed4efbf51dea909c3e3334aa3d1a2ffec6b', '831cdf20a1a9b8ecd332e330922bd011fd0d32e2f27dbbf6d1f3985b9e640581']"
        scope = "['collection', 'detection']"
        platform = "['VirusTotal', 'ICET', 'EX']"
        intel = "https://twitter.com/DissectMalware/status/1250411834953420808"
    strings:
        $sheets = { 78 6c 2f 6d 61 63 72 6f 73 68 65 65 74 73 2f 73 68 65 65 74 3? [0-1] 2e 78 6d 6c}
    condition:
        GEN_ModernExcel4MacroZIP
        and #sheets > 5
}
