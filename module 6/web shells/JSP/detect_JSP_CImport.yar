rule detect_JSP_CImport
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for c:import - JSTL (JSP)"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$func = "c:import"
		
	condition:
		$func
}
