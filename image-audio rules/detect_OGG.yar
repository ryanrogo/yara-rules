rule detect_OGG {
  meta:
    description = "Detects OGG files by checking the magic number and trailer."
  strings:
    $header = { 4F 67 67 53 00 02 00 00 00 00 00 00 00 00 }
  condition:
    $header at 0
}