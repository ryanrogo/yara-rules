rule detect_TIFF {
  meta:
    description = "Detects TIFF files by checking the magic number and trailer."
  strings:
    $header1 = { 49 20 49 }
	$header2 = { 49 49 2A 00 }
	$header3 = { 4D 4D 00 2A }
  condition:
    $header1 at 0 or $header2 at 0 or $header3 at 0
}