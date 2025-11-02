rule detect_JSP_jspinclude
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for jsp:include being called (JSP)"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$func = "jsp:include"
		
	condition:
		$func
}
