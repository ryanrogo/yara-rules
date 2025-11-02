rule detect_64bit_exe
{
	meta:
		author = "Ryan Rogowski"
		description = "Detects 64bit EXE files by looking at the header"
		date = "11/01/2025"
		version = "1.0"
    strings:
        $header = {4D 5A}
        $pe64 = {50 45 00 00 64 86}
    condition:
        $header at 0 and $pe64 in (0..1024)
}
