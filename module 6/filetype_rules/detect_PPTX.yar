rule detect_PPTX
{
	meta:
		author = "Ryan Rogowski"
		description = "Detects PPTX files by their magic number."
		date = "11/01/2025"
		version = "1.0"
	strings:
		$header = {50 4B 03 04 14 00 06 00}
		$dir = "ppt/"
		
	condition:
		$header at 0 and $dir
}
