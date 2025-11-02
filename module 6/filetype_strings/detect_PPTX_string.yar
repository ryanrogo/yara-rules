rule detect_PPTX_string
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for .pptx string existing"
		date = "10/31/2025"
		version = "1.0"
	strings:
		$string = ".pptx"
		
	condition:
		$string
}
