rule detect_ASP_CreateObjectShellApplication
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the Server.CreateObject(\"Shell.Application\") function being called (ASP)"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$func = "Server.CreateObject(\"Shell.Application\")"
		
	condition:
		$func
}
