rule shadowFileAccess
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for calls that access /etc/shadow - root read only, contains password hashes"
		date = "11/07/2025"
		version = "1.0"
	strings:
		$call = /fopen\(\"\/etc\/shadow\", \"r\"\)/
		
	condition:
		$call
}