rule vbs: vbs{
        
    strings:
        $kw1 = /\n\s*Function\s+[_a-z]+/ nocase
        $kw2 = "Exit Function" nocase
        $kw3 = "End If" nocase
        $kw4 = "End With" nocase
        $kw5 = "on error resume next" nocase
        $kw6 = "GetObject" nocase
        $kw7 = "CreateObject" nocase
        $kw8 = /\n\s*dim\s+[_a-z]+/ nocase
        $kw9 = "wscript" nocase
        $kw10 = /\n\s*Sub\s+[_a-z]+/
        $kw11 = "End Sub" nocase
        $kw12 = "Array(" nocase
        $kw13 = /\n\s*const\s+[_a-z]+/ nocase
        $kw14 = /\n\s*REM\s+/ nocase
                                                                                                                                                                                                                                                                                                                                                                      
    condition:
        4 of them
}
