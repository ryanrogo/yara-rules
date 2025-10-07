import "pe"

rule checkMUISections
{
	meta:
		author = "Ryan Rogowski"
	description = "check if a MUI file has more than 2 sections"
	date = "2025-09-17"

	condition:
		filename matches /\.mui$ and pe.number_of_sections != 2
}