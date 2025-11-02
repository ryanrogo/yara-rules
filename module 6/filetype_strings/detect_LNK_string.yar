rule detect_LNK_string
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for .lnk string existing"
		date = "10/31/2025"
		version = "1.0"
	strings:
		$string = ".lnk"
		
	condition:
		$string
}
