rule detect_DOCX_string
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for .docx string existing"
		date = "10/31/2025"
		version = "1.0"
	strings:
		$string = ".docx"
		
	condition:
		$string
}
