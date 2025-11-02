rule detect_ZIP_string
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for .zip string existing"
		date = "10/31/2025"
		version = "1.0"
	strings:
		$string = ".zip"
		
	condition:
		$string
}
