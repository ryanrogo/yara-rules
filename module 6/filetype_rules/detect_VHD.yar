rule detect_VHD
{
	meta:
		author = "Ryan Rogowski"
		description = "Detects VHD files by checking the magic number."
		date = "10/31/2025"
		version = "1.0"
	strings:
		$header = {63 78 73 70 61 72 73 65}
		
	condition:
		$header at 0
}
