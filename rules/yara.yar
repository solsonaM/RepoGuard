rule RepoGuard_Suspicious_Exec {
  meta:
    description = "Common suspicious shell execution strings"
  strings:
    $a = "/dev/tcp/" ascii nocase
    $b = "bash -i" ascii nocase
    $c = "nc -e" ascii nocase
    $d = "powershell -enc" ascii nocase
  condition:
    1 of them
}

rule RepoGuard_Destructive {
  meta:
    description = "Destructive disk or deletion command strings"
  strings:
    $a = "rm -rf /" ascii nocase
    $b = "mkfs." ascii nocase
    $c = "diskpart" ascii nocase
  condition:
    1 of them
}
