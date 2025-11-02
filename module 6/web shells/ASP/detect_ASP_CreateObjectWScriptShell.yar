rule detect_ASP_CreateObjectWScriptShell
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the Server.CreateObject(\"WScript.Shell\") function being called (ASP)"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$func = "Server.CreateObject(\"WScript.Shell\")"
		
	condition:
		$func
}
