rule detect_Themida
{
	meta:
		author = "Ryan Rogowski"
		description = "Detects Themida packed files"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$a1 = "Themida"
		$a2 = ".themida"
		
	condition:
		$a1 or $a2
}
