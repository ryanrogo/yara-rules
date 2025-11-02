rule detect_RAR_string
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for .rar string existing"
		date = "10/31/2025"
		version = "1.0"
	strings:
		$string = ".rar"
		
	condition:
		$string
}
