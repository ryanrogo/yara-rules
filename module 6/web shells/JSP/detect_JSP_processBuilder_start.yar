rule detect_JSP_processBuilder_start
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the ProcessBuilder.start being called (JSP)"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$func = "ProcessBuilder.start("
		
	condition:
		$func
}
