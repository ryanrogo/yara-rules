rule detect_HTML_string
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for .html string existing"
		date = "10/31/2025"
		version = "1.0"
	strings:
		$string = ".html"
		
	condition:
		$string
}
