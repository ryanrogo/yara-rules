rule detect_EML
{
    meta:
        author = "Ryan Rogowski"
        description = "Detects EML files by defining strings"
        date = "11/01/2025"
        version = "1.0"
    strings:
        $a1 = /^From:\s+/ nocase
        $a2 = /^Subject:\s+/ nocase
        
    condition:
        any of ($a1, $a2)
}
