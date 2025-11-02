rule detect_JSP_pageContext_include
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for pageContext.include being called (JSP)"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$func = "pageContext.include("
		
	condition:
		$func
}
