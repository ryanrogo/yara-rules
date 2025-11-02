rule detect_ASP_eval
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the Eval function being called (ASP)"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$func = "Eval("
		
	condition:
		$func
}
