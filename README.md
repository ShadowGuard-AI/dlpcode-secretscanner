![Banner](banner.png)

# dlpcode-SecretScanner
Scans code for accidentally committed secrets (API keys, passwords, etc.) using regular expressions, prints each finding with its surrounding code highlighted in the terminal, and redacts the matched secret itself in that output. - Focused on This category centers on scanning code repositories or individual code files for sensitive information such as API keys, passwords, credentials, personally identifiable information (PII), and other confidential data that should not be exposed. The tools use regular expressions and code syntax analysis to identify potentially leaked secrets within source code. Code highlighting and context are essential for accurate analysis.

Matched secrets are masked in every part of the output, including the code snippet around a finding. A run that cannot read a file it was asked to scan exits 1 and names the unreadable file, instead of reporting that no secrets were found.

## Install
`git clone https://github.com/ShadowStrikeHQ/dlpcode-secretscanner`

## Usage
`./dlpcode-secretscanner [params]`

## Parameters
- `-h`: Show help message and exit
- `-v`: Enable verbose logging.
- `-e`: No description provided

## License
Copyright (c) ShadowStrikeHQ
