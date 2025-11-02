rule detect_SCR
{
	meta:
		author = "Ryan Rogowski"
		description = "Detects SCR files through the file header even though its the same as a PE"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$header = {4D 5A}
		
	condition:
		$header
}
