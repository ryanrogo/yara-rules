rule detect_JSP_ScriptEngine_eval
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for javax.script.ScriptEngine.eval being called (JSP)"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$func = "javax.script.ScriptEngine.eval("
		
	condition:
		$func
}
