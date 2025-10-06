rule detect_PSD {
  meta:
    description = "Detects PSD files by checking the magic number and trailer."
  strings:
    $header = { 38 42 50 53 }
  condition:
    $header at 0
}