import "pe"

rule checkSYSSections
{
	meta:
		author = "Ryan Rogowski"
	description = "check if a SYS file has more than 10 or less than 7 sections"
	date = "2025-09-17"

	condition:
		filename matches /\.sys$ and (pe.number_of_sections > 10 or pe.number_of_sections < 7)
}