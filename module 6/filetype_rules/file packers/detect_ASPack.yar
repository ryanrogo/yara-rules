rule detect_ASPack
{
	meta:
		author = "Ryan Rogowski"
		description = "Detects ASPack packed files"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$a1 = "ASPack"
		
	condition:
		$a1
}
