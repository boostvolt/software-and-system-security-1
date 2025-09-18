# Lab 03

## Web Attack 3: Command Injection

### Vulnerabilities

1. **Command Injection:** Pinger functionality executes system commands without input sanitization
2. **Information Disclosure:** Application files and environment variables accessible through command injection

### Attack Steps

1. **Vulnerability Discovery:** Input `127.0.0.1; ls` confirmed command injection by executing both ping and ls commands
2. **Reconnaissance:** Used `127.0.0.1 && cat Readme.md` to analyze application documentation
3. **Intelligence Gathering:** Readme.md revealed key hint about "environment based dynamic ctf flag handling in `/etc/cont-init-d/99-add-flag.sh`"
4. **Flag Extraction:** `127.0.0.1 && env | grep -i flag` searched environment variables and extracted the flag

### Flag

**Flag:** FLAG{ThePwr0fTheS3m1}

## Web Security: Username Enumeration

