rule detect_EPUB
{
	meta:
		author = "Ryan Rogowski"
		description = "Detects EPUB files by checking the magic number."
		date = "10/31/2025"
		version = "1.0"
	strings:
		$header = {50 4B 03 04 0A 00 02 00}
		
	condition:
		$header at 0
}
