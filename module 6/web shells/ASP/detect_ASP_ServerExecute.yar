rule detect_ASP_ServerExecute
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the Server.Execute function being called (ASP)"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$func = "Server.Execute("
		
	condition:
		$func
}
