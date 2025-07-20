import "pe"

rule PE_File_pyinstaller: pyinstaller3
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
        description = "Detect PE file produced by pyinstaller"
    strings:
        $a = "pyi-windows-manifest-filename"
    condition:
        pe.number_of_resources > 0 and $a
}

rule PE_File_pyinstaller2: pyinstaller2
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
        description = "Detect PE file produced by pyinstaller"
    strings:
        $a = "pyi-windows-manifest-filename"
        $b = /python2\d\.dll/ ascii wide nocase
    condition:
        pe.number_of_resources > 0 and all of them
}

rule PE_File_pyinstaller3: pyinstaller3
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
        description = "Detect PE file produced by pyinstaller"
    strings:
        $a = "pyi-windows-manifest-filename"
        $b = /python3\d\.dll/ ascii wide nocase
    condition:
        pe.number_of_resources > 0 and all of them
}

