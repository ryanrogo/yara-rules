rule detect_PDF_string
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for .pdf string existing"
		date = "10/31/2025"
		version = "1.0"
	strings:
		$string = ".pdf"
		
	condition:
		$string
}
