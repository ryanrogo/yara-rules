rule detect_7Z_string
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for .7z string existing"
		date = "10/31/2025"
		version = "1.0"
	strings:
		$string = ".7z"
		
	condition:
		$string
}
