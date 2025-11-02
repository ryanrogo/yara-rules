rule detect_JSP_JspWriter_print
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for javax.servlet.jsp.JspWriter.print being called (JSP)"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$func = "javax.servlet.jsp.JspWriter.print("
		
	condition:
		$func
}
