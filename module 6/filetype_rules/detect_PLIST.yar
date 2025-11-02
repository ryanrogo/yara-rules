rule detect_PLIST
{
	meta:
		author = "Ryan Rogowski"
		description = "Detects PLIST files by checking the magic number."
		date = "10/31/2025"
		version = "1.0"
	strings:
		$header = {62 70 6C 69 73 74}
		
	condition:
		$header at 0
}
