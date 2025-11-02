rule detect_EPS
{
	meta:
		author = "Ryan Rogowski"
		description = "Detects EPS files by checking the magic number."
		date = "10/31/2025"
		version = "1.0"
	strings:
		$header = {C5 D0 D3 C6}
		
	condition:
		$header at 0
}
