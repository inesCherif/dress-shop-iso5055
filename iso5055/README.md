# ISO/IEC 5055 view of a SonarQube project

SonarQube has no ISO/IEC 5055 report. This small tool builds one from SonarQube's Web API:

1. `iso5055-cwes.json` lists the 137 CWEs of ISO/IEC 5055:2021 clause 7, each with its characteristic
   (Security, Reliability, Performance Efficiency, Maintainability).
2. `iso5055_report.py` reads the CWE of every SonarQube rule (the cwe.mitre.org links in the rule description, and
   its security standards), keeps the ones in the ISO list, and counts your open issues per characteristic, the way
   clause 9 counts occurrences. It also shows how many ISO CWEs SonarQube has a rule for, for your languages.

Only the Python standard library is used: nothing to install.

## Use it on your project
1. Download both files and keep them **in the same folder**, for example:
   ```
   projects/
     my-project/      <- your code, already analysed by SonarQube
     tools/
       iso5055_report.py
       iso5055-cwes.json
   ```
2. Analyse your project with the **Sonar way comprehensive** quality profile (the default "Sonar way core" profile
   hides most reliability and maintainability rules), with your dependencies installed.
3. Create a user token in SonarQube: **My Account → Security → Generate token** (type: User token).
4. From inside your project folder:
   ```powershell
   $env:SONAR_TOKEN = "<your user token>"      # Git Bash / macOS / Linux: export SONAR_TOKEN=<your user token>
   python ..\tools\iso5055_report.py --project <your-project-key>
   ```
   Options: `--url` (default `http://localhost:9000`), `--details` (every issue with file:line), `--json out.json`.

Never commit your token.

## Read the result carefully
- SonarQube is not an ISO/IEC 5055 measurement tool. A **0** can mean "SonarQube has no rule for it", not "clean":
  check the coverage columns (for TypeScript: 15 of the 137 ISO CWEs, 0 of 18 for Performance).
- A SonarQube rule and an ISO detection pattern can share a CWE number without detecting exactly the same thing
  (example: CWE-390, ISO pattern "Ban Empty Exception Block" vs SonarQube rule S2486).
