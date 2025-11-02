rule detect_DLL_string
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for .dll string existing"
		date = "10/31/2025"
		version = "1.0"
	strings:
		$string = ".dll"
		
	condition:
		$string
}
