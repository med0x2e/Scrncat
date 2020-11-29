## Scrncat
A script i created to help with RT/PT reporting by grouping, organizing and redacting passwords/hashes in screenshots taken during long-term PT/RT engagements (> 1 month), it mainly uses OCR (pytesseract) and PIL to process screenshots and redact passwords based on common password patterns (Regex) or a password list of choice and/or rename/group Screenshots based on which RT/PT stage executed commands correspond to.

## Features
* Redact passwords/hashes (--redact switch) based on commond password patterns (regex) or a password list.
* Rename screenshots to <DATE_SCREENSHOT_WAS_TAKEN_COMMAND_EXECUTE.png> (based on command extracted when using --group switch)
* Group screenshots into PT/RT stages directory structure (Persistence, Recon, Lateral Movement, PrivEsc ..etc) based on c2.yaml config file structure/commands
* Command extraction based on a prefix of choice (--prefix)
* Multi-threaded
* c2.yaml was created/tested for cobaltstrike commands only.

## Usage
  `-p , --path           Screenshots folder path`
  `-h, --help            show this help message and exit`<br><br>
  `-o , --output         Output directory name`<br><br>
  `-gr, --group          Group screenshots into multiple folders based on phases listed in cobaltstrike.yaml`<br><br>
  `-r, --redact          Redact passwords, check _COMMON_PASSWORDS_REGEX for default password regex patterns used to match against
                        screenshots containing passwords`<br><br>
  `-pr , --prefix        C2 command shell/prompt prefix, example; the default cobaltstrike prefix is "beacon>" and "meterpreter >" for
                        MSF, by specifying a prefix you'll get better results and accuracy, default prefix is set to match against "{}\w*.*>" regex`<br><br>
  `-pw , --passwords-dict
                        ' ' separated Passwords list to redact, optional in case you want to get better results than the default regex
                        based masking`<br><br>
  `-t , --threads        Number of worker threads`<br><br>
  `-v, --verbose         verbose messages`<br><br>

----------------------------

## Examples:
 `python scrncat.py -p <screenshots_folder_path> -o <output_dir> --group --redact (to redact passwords)`<br>

 * Rename Screenshots (<REDACTED-SCREENSHOT-DATETIME.png>) and Redact passwords (default regex "_COMMON_PASSWORDS_REGEX"):<br>
		`>python3 scrncat.py -p /home/user/Screenshots/ -o generated-screenshots --redact`

 * Rename Screenshots (<REDACTED-SCREENSHOT-DATETIME.png>) Redact passwords based on a dictionary of known passwords:<br>
		`>python3 scrncat.py -p /home/user/Screenshots/ -o generated-screenshots --redact -pw cracked-passwords.txt`

 * Group Screenshots into phases listed in "c2.yaml", this will also rename screenshots to <SCREENSHOT-DATETIME-EXECUTED-COMMAND.png> and place it in the  appropriate sub-folder (Persistence, LT ..etc): <br>
		`>python3 scrncat.py -p /home/user/Screenshots/ -o generated-screenshots --group`

 * Group Screenshots into phases listed in "c2.yaml" & rename to <SCREENSHOT-DATETIME-EXECUTED-COMMAND.png> & move to the appropriate sub-folder (Persistence, LT ..etc) & uses "beacon>" as a prefix for accurate command extraction:<br>
		`>python3 scrncat.py -p /home/user/Screenshots/ -o generated-screenshots --group --prefix "beacon>"`

 * Group and Redact .... all the above:<br>
		`>python3 scrncat.py -p /home/user/Screenshots/ -o generated-screenshots --group --redact --prefix "beacon>"`
		
## TODO:
This was an experimental attempt to automate few boring tasks when doing reporting, feel free to contribute/improve
* Support for other other C2 frameworks (yaml files for other c2 frameworks commands)
* Adding PDF/Word support (reports)
* Tweaking pytesseract arguments and PIL image resize to improve accuracy (dynamic resizing based on image width/height ..etc.)

## Current Known Issues
* So far tested only for screenshots taken for the "cobaltstrike" CLI with almost 80% success rate, Pytesseract text recongnition is not always 100% accurate for screenshots with higher dimensions (ex: 'l' recognized as '1' and vice-versa), may be cv2 'threshold' would help (need some tweaking and testing).
* Sequence of commands; for example Lateral Movement "make_token" and "ls" commands sequence are considered as local system recon, should be LT instead.
* Few persistence and local system recon commands are grouped as Misc.

