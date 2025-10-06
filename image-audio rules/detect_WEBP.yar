rule detect_WEBP {
  meta:
    description = "Detects WEBP files by checking the magic number and trailer."
  strings:
    $header = { 52 49 46 46 ?? ?? ?? ?? 57 45 42 50 }
  condition:
    $header at 0
}