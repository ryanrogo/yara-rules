rule detect_CUR
{
	meta:
		author = "Ryan Rogowski"
		description = "Detects CUR files by checking the magic number."
		date = "10/31/2025"
		version = "1.0"
	strings:
		$header = {00 00 02 00}
		
	condition:
		$header at 0
}
