rule detect_NodeJS_eval
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the eval function being called (NodeJS)"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$func = "eval("
		
	condition:
		$func
}
