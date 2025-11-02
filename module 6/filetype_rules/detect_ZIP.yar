rule detect_ZIP
{
	meta:
		author = "Ryan Rogowski"
		description = "Detects ZIP files by checking the magic number."
		date = "10/31/2025"
		version = "1.0"
	strings:
		$header = {50 4B 03 04}
		
	condition:
		$header at 0
}
