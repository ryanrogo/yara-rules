rule detect_7Z
{
	meta:
		author = "Ryan Rogowski"
		description = "Detects 7Z files by checking the magic number."
		date = "10/31/2025"
		version = "1.0"
	strings:
		$header = {37 7A BC AF 27 1C}
		
	condition:
		$header at 0
}
