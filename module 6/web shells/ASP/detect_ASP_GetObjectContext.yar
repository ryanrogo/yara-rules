rule detect_ASP_GetObjectContext
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the GetObjectContext function being called (ASP)"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$func = "GetObjectContext("
		
	condition:
		$func
}
