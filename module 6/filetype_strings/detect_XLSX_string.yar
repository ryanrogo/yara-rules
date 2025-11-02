rule detect_XLSX_string
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for .xlsx string existing"
		date = "10/31/2025"
		version = "1.0"
	strings:
		$string = ".xlsx"
		
	condition:
		$string
}
