rule detect_PIF_string
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for .pif string existing"
		date = "10/31/2025"
		version = "1.0"
	strings:
		$string = ".pif"
		
	condition:
		$string
}
