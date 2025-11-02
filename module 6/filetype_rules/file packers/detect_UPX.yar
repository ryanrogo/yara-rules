rule detect_UPX
{
	meta:
		author = "Ryan Rogowski"
		description = "Detects UPX packed files"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$a1 = "UPX0"
		$a2 = "UPX1"
		
	condition:
		$a1 or $a2
}
