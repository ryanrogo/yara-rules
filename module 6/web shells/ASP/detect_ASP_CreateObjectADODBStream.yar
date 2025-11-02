rule detect_ASP_CreateObjectADODBStream
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for the Server.CreateObject(\"ADODB.Stream\") function being called (ASP)"
		date = "11/01/2025"
		version = "1.0"
	strings:
		$func = "Server.CreateObject(\"ADODB.Stream\")"
		
	condition:
		$func
}
