rule detect_EXE_string
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for .exe string existing"
		date = "10/31/2025"
		version = "1.0"
	strings:
		$string = ".exe"
		
	condition:
		$string
}
