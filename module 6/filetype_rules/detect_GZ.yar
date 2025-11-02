rule detect_GZ
{
	meta:
		author = "Ryan Rogowski"
		description = "Detects GZ files by checking the magic number."
		date = "10/31/2025"
		version = "1.0"
	strings:
		$header = {1F 8B 08}
		
	condition:
		$header at 0
}
