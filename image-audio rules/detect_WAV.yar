rule detect_WAV {
  meta:
    description = "Detects WAV files by checking the magic number and trailer."
  strings:
    $header = { 52 49 46 46 ?? ?? ?? ?? 57 41 56 45 66 6D 74 20 }
  condition:
    $header at 0
}