rule executablePermissions
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for calls that read /etc/passwd"
		date = "11/07/2025"
		version = "1.0"
	strings:
		$call = /chmod\(".*", [0-9]*\)/
		
	condition:
		$call
}