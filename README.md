# Cybersecurity Portfolio

## passwordtest.py
The Python file will check the strength of the given password that we use in our daily lives and it suggests what needs to be added to make our passwords more secured.

To run it:
python3 passwordtest.py

Then it will ask to enter the password: ....

Then it will give the feedbacks of what needs to be added in the password to make it strong. 

-----------------------------------------------------------------------

## zerotrust.py

The python file will ask for a password to setup for the file called myvault.txt. Run the following in the terminal:
1. python3 zerotrust.py setup (this will create a field asking for your password and then it will send a QR code in which after scanning it, you will receive a TOTP code which will be needed for later
2. echo "Dont forget to do Portfolio" >> ~/.myvault.txt
3. python3 zerotrust.py access (Will ask for the password to access the file and the TOTP code that is in obtained after scanning the QR code. After a successful verification, it will then display the contents of myvault.txt. This implementation is only acting as gateways, however it doesnt mean that it encrypts the content of the file.

## ThreatIntelligence.py

The Enhanced Indicator Checker works by accepting either a single indicator or a file of indicators via command-line options, automatically determining whether each entry is an IP address, a CVE identifier, or something else, and then checking it against preset lists of known malicious IPs and CVEs. When you run the script with the -i flag, it processes that one value; with -f, it reads each line of the given file. For each indicator, it uses regular expressions to classify its type, tests membership in the malicious lists, and then logs a timestamped message to the console (and, if requested, to an output file) stating whether that indicator is “MALICIOUS” or “Clean.” This approach gives you immediate, human-readable feedback and, through the optional output file, a persistent record of the scan results.

Under the hood, the script is a Python program organized around three core functions—detect_type, which applies compiled regex patterns to spot IP versus CVE formats; is_malicious, which performs simple list membership checks based on that type; and process_indicator, which ties detection and blacklist lookup together and handles both console logging (via the standard logging module) and optional file writing. It uses argparse to parse four command-line flags (-i, -f, -l, and -o), cleanly separating responsibilities: listing the current blacklists, processing one or many indicators, and directing output. The modular design means you can extend or replace the blacklist arrays, hook in an external feed, or swap in a database or API lookup for more dynamic threat intelligence without touching the CLI interface.
