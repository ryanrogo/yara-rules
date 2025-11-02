rule detect_ASP_ScriptControlExecuteStatement
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the ScriptControl.ExecuteStatement function being called (ASP)"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$func = "ScriptControl.ExecuteStatement"
		
	condition:
		$func
}
