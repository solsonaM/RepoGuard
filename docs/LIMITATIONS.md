# Limitations

RepoGuard is defense in depth, not a proof of safety.

No static scanner can prove that arbitrary software is non-malicious in every possible environment.

Rice's theorem applies: there is no analyzer that can perfectly decide the behavior of all programs.

Other limitations:
- Novel malware, logic bombs, dependency compromise, and environment-specific abuse can evade pattern-based detection.
- Repository reputation signals are observational and incomplete. A single API snapshot cannot directly prove star-growth anomalies or historical force-push behavior.
- OSV results depend on the vulnerability data available in the offline database.
- Gitleaks detects secrets according to its rules; it cannot prove that no credential exists.
- YARA only detects what its configured rules describe.
- Minified and encoded files are normalized for several common layers, but deeply custom transformations can remain unanalyzable and are rejected.
- Opaque binaries without an acceptable analysis path are rejected.
- Hosted scanning does not execute target setup/install behavior.
- The optional behavior test is local-only and cannot reproduce every possible host environment.

APPROVED does not mean safe. It means every file was analyzed and no threats were found by the listed checks.

No scanner can guarantee the absence of all threats.
