rule detect_ASP_ResponseWrite
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the Response.Write function being called (ASP)"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$func = "Response.Write("
		
	condition:
		$func
}
