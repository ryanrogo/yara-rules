rule detect_RTF_string
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for .rtf string existing"
		date = "10/31/2025"
		version = "1.0"
	strings:
		$string = ".rtf"
		
	condition:
		$string
}
