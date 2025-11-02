rule detect_EVTX
{
	meta:
		author = "Ryan Rogowski"
		description = "Detects EVTX files by checking the magic number."
		date = "10/31/2025"
		version = "1.0"
	strings:
		$header = {45 6C 66 46 69 6C 65 00}
		
	condition:
		$header at 0
}
