rule detect_RF64 {
  meta:
    description = "Detects RF64 files by checking the magic number and trailer."
  strings:
    $header = { 52 49 46 46 ?? ?? ?? ?? 43 44 44 41 66 6D 74 20 }
  condition:
    $header at 0
}