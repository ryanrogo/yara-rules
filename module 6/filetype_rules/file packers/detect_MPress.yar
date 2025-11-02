rule detect_MPress
{
	meta:
		author = "Ryan Rogowski"
		description = "Detects MPress packed files"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$a1 = "MPRESS"
		
	condition:
		$a1
}
