rule detect_PECompact
{
	meta:
		author = "Ryan Rogowski"
		description = "Detects PECompact packed files"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$a1 = "PEC2"
		$a2 = "PECompact"
		
	condition:
		$a1 or $a2
}
