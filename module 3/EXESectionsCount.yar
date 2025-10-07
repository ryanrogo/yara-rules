import "pe"

rule EXESectionsCount
{
meta:
		author = "Ryan Rogowski"
	description = "check to see if abnormal amount of sections in EXE"
	date = "2025-09-17"

condition:
		pe.number_of_sections > 7 or pe.number_of_sections < 6

}