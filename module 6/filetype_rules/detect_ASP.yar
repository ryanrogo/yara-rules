rule detect_ASP
{
	meta:
		author = "Ryan Rogowski"
		description = "Detects ASP files by defining strings"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$a1 = "<%@"
		$a2 = "<%"
		
	condition:
		any of ($a1, $a2)
}
