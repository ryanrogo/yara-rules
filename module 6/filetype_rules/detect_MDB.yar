rule detect_MDB
{
	meta:
		author = "Ryan Rogowski"
		description = "Detects MDB files by checking the magic number."
		date = "10/31/2025"
		version = "1.0"
	strings:
		$header = {00 01 00 00 53 74 61 6E 64 61 72 64 20 4A 65 74 20 44 42}
		
	condition:
		$header at 0
}
