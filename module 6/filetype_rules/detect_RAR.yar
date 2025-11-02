rule detect_RAR
{
	meta:
		author = "Ryan Rogowski"
		description = "Detects RAR files by checking the magic number."
		date = "10/31/2025"
		version = "1.0"
	strings:
		$header = {52 61 72 21 1A 07 00}
		$header2 = {52 61 72 21 1A 07 01 00}
		
	condition:
		$header at 0 or $header2 at 0
}
