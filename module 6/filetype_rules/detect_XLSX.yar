rule detect_XLSX
{
	meta:
		author = "Ryan Rogowski"
		description = "Detects XLSX files by their magic number."
		date = "11/01/2025"
		version = "1.0"
	strings:
		$header = {50 4B 03 04 14 00 06 00}
		$dir = "xl/"
		
	condition:
		$header at 0 and $dir
}
