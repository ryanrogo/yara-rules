rule passwordFileRead
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for calls that read /etc/passwd"
		date = "11/07/2025"
		version = "1.0"
	strings:
		$call = "fopen(\"/etc/passwd\", \"r\")"
		
	condition:
		$call
}