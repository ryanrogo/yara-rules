rule detect_ASP_execute
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the Execute function being called (ASP)"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$func = "Execute("
		
	condition:
		$func
}
