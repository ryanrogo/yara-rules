rule detect_SWF
{
	meta:
		author = "Ryan Rogowski"
		description = "Detects SWF files by checking the magic number."
		date = "10/31/2025"
		version = "1.0"
	strings:
		$header = {43 57 53}
		$header2 = {46 57 53}
		$header3 = {5A 57 53}
		
	condition:
		$header at 0 or $header2 at 0 or $header3 at 0
}
