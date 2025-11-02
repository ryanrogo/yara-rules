rule detect_XLS
{
	meta:
		author = "Ryan Rogowski"
		description = "Detects XLS files by their magic number."
		date = "11/01/2025"
		version = "1.0"
	strings:
		$header = {D0 CF 11 E0 A1 B1 1A E1}
		$a = "Workbook"
		
	condition:
		$header at 0 and $a
}
