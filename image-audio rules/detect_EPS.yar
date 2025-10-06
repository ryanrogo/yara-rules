rule detect_EPS {
  meta:
    description = "Detects EPS files by checking the magic number and trailer."
  strings:
    $header = { C5 D0 D3 C6 }
  condition:
    $header at 0
}