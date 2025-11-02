rule detect_VDMK
{
	meta:
		author = "Ryan Rogowski"
		description = "Detects VDMK files by checking the magic number."
		date = "10/31/2025"
		version = "1.0"
	strings:
		$header = {4B 44 4D}
		$header2 = {4B 44 4D 56}
		$header3 = {43 4F 57 44}
		$header4 = {23 20 44 69 73 6B 20 44 65 73 63 72 69 70 74 6F}
		
	condition:
		$header at 0 or $header2 at 0 or $header3 at 0 or $header4 at 0
}
