rule detect_JSP_getMethod_invoke
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for getMethod and invoke being called (JSP)"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$func = /Class.forName\(.*\).getMethod\(.*\).invoke\(/
		
	condition:
		$func
}
