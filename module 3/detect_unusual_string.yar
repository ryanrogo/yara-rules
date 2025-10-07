import "pe"
rule detect_unusual_string
{
meta:
   author = "Kenneth Moran"
   description = "Alert if strings found in sections with no strings usually"
   date = "9/17/2025"

strings:
   $expectedException1 = ".?AVbad_alloc@std@@"
   $expectedException2 = ".?AVlength_error@std@@"
   $expectedException3 = ".?AVlogic_error@std@@"
   $expectedException4 = ".?AVout_of_range@std@@"

condition:
pe.is_pe and
for any section in pe.sections : (
   section.name == ".data" and
   not $expectedException1 in (section.raw_data_offset..section.raw_data_offset + section.raw_data_size) and
   not $expectedException2 in (section.raw_data_offset..section.raw_data_offset + section.raw_data_size) and
   not $expectedException3 in (section.raw_data_offset..section.raw_data_offset + section.raw_data_size) and
   not $expectedException4 in (section.raw_data_offset..section.raw_data_offset + section.raw_data_size)
)
}