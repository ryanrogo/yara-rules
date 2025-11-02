rule detect_LNK
{
	meta:
		author = "Ryan Rogowski"
		description = "Detects LNK files by checking the magic number."
		date = "10/31/2025"
		version = "1.0"
	strings:
		$header = {4C 00 00 00 01 14 02 00}
		
	condition:
		$header at 0
}
