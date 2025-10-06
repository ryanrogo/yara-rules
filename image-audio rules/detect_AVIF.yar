rule detect_AVIF {
  meta:
    description = "Detects AVIF files by checking the magic number and trailer."
  strings:
    $header = { 66 74 79 70 61 76 69 66 }
  condition:
    $header at 4
}