rule detect_32bit_exe
{
	meta:
		author = "Ryan Rogowski"
		description = "Detects 32bit EXE files by looking at the header"
		date = "11/01/2025"
		version = "1.0"
    strings:
        $header = {4D 5A}
        $pe32 = {50 45 00 00 4C 01}
    condition:
        $header at 0 and $pe32 in (0..1024)
}
