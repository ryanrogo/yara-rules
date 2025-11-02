rule detect_ASP_ServerMapPath
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the Server.MapPath function being called (ASP)"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$func = "Server.MapPath("
		
	condition:
		$func
}
