rule detect_ISO
{
	meta:
		author = "Ryan Rogowski"
		description = "Detects ISO files by checking the magic number."
		date = "10/31/2025"
		version = "1.0"
	strings:
		$header = {45 52 02 00 00}
		$header2 = {43 44 30 30 31}
		
	condition:
		$header at 0 or $header2 at 0 or $header2 at 32769 or $header2 at 34817 or $header2 at 36865
}
