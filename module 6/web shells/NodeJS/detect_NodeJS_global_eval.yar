rule detect_NodeJS_global_eval
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the global.eval function being called (NodeJS)"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$func = "global.eval("
		
	condition:
		$func
}
