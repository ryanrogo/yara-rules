rule detect_ASP_ScriptControlEval
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the ScriptControl.Eval function being called (ASP)"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$func = "ScriptControl.Eval"
		
	condition:
		$func
}
