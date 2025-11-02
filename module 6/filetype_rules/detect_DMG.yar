rule detect_DMG
{
	meta:
		author = "Ryan Rogowski"
		description = "Detects DMG files by checking the magic number."
		date = "10/31/2025"
		version = "1.0"
	strings:
		$header = {65 6E 63 72 63 64 73 61}
		$header2 = {63 64 73 61 65 6E 63 72}
		
	condition:
		$header at 0 or $header2 at 4
}
