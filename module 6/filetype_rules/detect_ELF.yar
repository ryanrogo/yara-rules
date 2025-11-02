rule detect_ELF
{
	meta:
		author = "Ryan Rogowski"
		description = "Detects ELF files by checking the magic number."
		date = "11/01/2025"
		version = "1.0"
	strings:
		$header = {7F 45 4C 46}
		
	condition:
		$header at 0
}
