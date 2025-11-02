rule detect_HTM_string
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for .htm string existing"
		date = "10/31/2025"
		version = "1.0"
	strings:
		$string = ".htm"
		
	condition:
		$string
}
