rule detect_FLAC {
  meta:
    description = "Detects FLAC files by checking the magic number and trailer."
  strings:
    $header = { 66 4C 61 43 00 00 00 22 }
  condition:
    $header at 0
}