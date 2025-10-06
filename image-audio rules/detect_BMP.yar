rule detect_BMP {
  meta:
    description = "Detects BMP files by checking the magic number and trailer."
  strings:
    $header = { 42 4D }
  condition:
    $header at 0
}