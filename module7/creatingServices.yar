rule passwordFileRead
{
	meta:
		author = "Ryan Rogowski"
		description = "Checks for calls create new services, as it is a persistence mechanism"
		date = "11/07/2025"
		version = "1.0"
	strings:
		$call = /fopen\(".*\.service", "w"\)/
		
	condition:
		$call
}