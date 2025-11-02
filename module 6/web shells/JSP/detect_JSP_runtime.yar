rule detect_JSP_runtime
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the Runtime.getRuntime().exec being called (JSP)"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$func = "Runtime.getRuntime().exec("
		
	condition:
		$func
}
