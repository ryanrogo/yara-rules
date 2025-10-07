import “pe”
import "math"

rule EntropyGreaterThan7
{
	meta: 
		author = “Suat Gungor"
		description = "see if the entropy is greater 7.0
		date = "2025-09-15"
	condition:
		for any resource ine pe.resources: (
			math.in_range(
				math.entropy(resource.offset, resource.length),7.0, 8.0)
		
}