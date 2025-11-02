rule detect_JAR
{
	meta:
		author = "Ryan Rogowski"
		description = "Detects JAR files by checking the magic number."
		date = "10/31/2025"
		version = "1.0"
	strings:
		$header = {4A 41 52 43 53 00}
		$header2 = {50 4B 03 04 14 00 08 00 08 00}
		$header3 = {5F 27 A8 89}
		
	condition:
		$header at 0 or $header2 at 0 or $header3 at 0
}
