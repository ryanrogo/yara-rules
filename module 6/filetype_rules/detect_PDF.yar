rule detect_PDF
{
	meta:
		author = "Ryan Rogowski"
		description = "Detects PDF files by checking the magic number."
		date = "10/31/2025"
		version = "1.0"
	strings:
		$header = {25 50 44 46}
		$trailer1 = {0A 25 25 45 4F 46}
		$trailer2 = {0A 25 25 45 4F 46 0A}
		$trailer3 = {0D 0A 25 25 45 4F 46 0D 0A}
		$trailer4 = {0D 25 25 45 4F 46 0D}
		
	condition:
		$header at 0 and ($trailer1 or $trailer2 or $trailer3 or $trailer4)
}
