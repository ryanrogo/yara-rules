rule detect_AIFF {
  meta:
    description = "Detects AIFF files by checking the magic number and trailer."
  strings:
    $header = { 46 4F 52 4D 00 }
  condition:
    $header at 0
}