rule detect_MSV {
  meta:
    description = "Detects MSV files by checking the magic number and trailer."
  strings:
    $header = { 4D 53 5F 56 4F 49 43 45 }
  condition:
    $header at 0
}