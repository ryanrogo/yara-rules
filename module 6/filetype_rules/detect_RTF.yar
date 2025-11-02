rule detect_RTF
{
	meta:
		author = "Ryan Rogowski"
		description = "Detects RTF files by checking the magic number."
		date = "11/01/2025"
		version = "1.0"
	strings:
		$header = {7B 5C 72 74 66}
		
	condition:
		$header at 0
}
