rule detect_PIF
{
	meta:
		author = "Ryan Rogowski"
		description = "Detects PIF files by checking the magic number."
		date = "10/31/2025"
		version = "1.0"
	strings:
		$header = {4D 5A}
		
	condition:
		$header at 0
}
