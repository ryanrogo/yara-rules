rule detect_HTML
{
	meta:
		author = "Ryan Rogowski"
		description = "Detects HMTL files by defining strings"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$a1 = "<!DOCTYPE html"
		$a2 = "<html"
		
	condition:
		any of ($a1, $a2)
}
