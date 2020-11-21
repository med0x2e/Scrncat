# Author @med0x2e

import argparse
import logging
from PIL import Image as PILImage
import pytesseract
import sys
import os
from wand.image import Image
import zipfile
from datetime import datetime
import calendar
import time
import yaml
import shutil
import concurrent.futures
import re
import json
import operator
import cv2
from pytesseract import Output
import re

_STAGES_CMDS = {}
_STAGES = {}
_YAML = "./c2.yaml"

_COMMON_PASSWORDS_REGEX = ["^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$", 
		"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$",
		"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$",
		"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$",
		"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,10}$"]

def mask(_img, results, text, conf, index):

	x = results["left"][index]
	y = results["top"][index]
	w = results["width"][index]
	h = results["height"][index]

	# checking confidence
	if conf >= 30:
		text = "".join([c if ord(c) < 128 else "" for c in text]).strip()
		cv2.rectangle(_img, (x, y), (x + w, y + h), (96, 96, 96), 3)
		_img[y:y+h, x:x+w] = [102,255,255]
		cv2.putText(_img, "Redacted", (x+int(w/4), y+int(h/2)+15), cv2.FONT_HERSHEY_DUPLEX,1.5, (96, 96, 96), 4)


def redactAndSave(results, _img, _sPath, _sFName, _passwords, _outputDir):

	_isPasswordFound = False
	
	for i in range(0, len(results["text"])):

		text = results["text"][i]
		conf = int(results["conf"][i])

		if (text.startswith('"') or text.startswith("'") or text.startswith("‘")) and (text.endswith('"') or text.endswith("'") or text.endswith("‘")):
			text = text[1:-1]

		if _passwords:
			for _password in _passwords:
				if _password in text:
					_isPasswordFound = True
					mask(_img, results, text, conf, i)

		else:
			if any(re.match(regex, text) for regex in _COMMON_PASSWORDS_REGEX):
				_isPasswordFound = True
				mask(_img, results, text, conf, i)

	if _isPasswordFound:
		_resizedImg = cv2.resize(_img,None,fx=0.25,fy=0.25)
		_redactedScreenshotPath = ""

		if _outputDir:
			_redactedScreenshotPath = os.path.join(_outputDir, _sFName)
		else:
			_redactedScreenshotPath = os.path.join(_sPath, _sFName)

		cv2.imwrite(_redactedScreenshotPath, _resizedImg)

	else:
		logging.debug("\t[debug]: Not password match found in screenshot %s" % _sFName)


def redactScreenshot(_screenshotPath, _screenshotTFPath, _sPath, sFName, _passwords, _outputDir):

	print(" [.]: Redacting Screenshot %s ..." %(_screenshotPath))

	try:
		with Image(filename=_screenshotPath) as screenshot:
		    screenshot.transform(resize='400%')
		    screenshot.type = 'grayscale';
		    screenshot.save(filename=_screenshotTFPath);

		_pim = PILImage.open(_screenshotTFPath)

		_imgText = pytesseract.image_to_data(_pim, lang='eng', output_type=Output.DICT)

		_img = cv2.imread(_screenshotTFPath)

		redactAndSave(_imgText, _img, _sPath, sFName, _passwords, _outputDir)

		os.remove(_screenshotTFPath)

	except:
		print("[!]: Error processing screenshot '%s'" %(_screenshotPath))
		exit(0)


def init(_screenshotsPath, _outputDir, _grouped):
	
	print("[+]: Initializing ...")
	archive(_screenshotsPath)

	with open('./cobaltstrike.yaml') as _configFile:
		_config = yaml.full_load(_configFile)

	if not os.path.exists(_outputDir):
		os.mkdir(_outputDir)

	if _grouped:
		print("[+]: Creating folders structure.")
		for stage, cmd in _config.items():

			_STAGES_CMDS[stage] = cmd
			_STAGES[stage] = 0

			if not os.path.exists(_outputDir+"/"+stage):
				try:
					os.mkdir(_outputDir+"/"+stage)
				except OSError:
				    print("[!]: Error creating folder '%s'" % (_outputDir+"/"+stage))
				    exit(0)
				else:
				    logging.debug("\t[debug]: Successfully created the directory '%s'" % (_outputDir+"/"+stage))
			else:
				logging.debug("\t[debug]: Folder '%s' already created." % (_outputDir+"/"+stage))

	print("[+]: Initialization done.")


def _maxScoreStages(scores):
	for key, value in scores.items():
		if key != "Local System Reconnaissance":
			scores[key] += 1

	_max_score_stages = []
	for key, value in scores.items():
		if value == max(scores.values()):
			_max_score_stages.append(key)

	return _max_score_stages


def groupStuff(_screenshotPath, _imgText, _outputDir, _ctTime, _stages, _stages_cmds, _prefix):
    
    try:
	    _screenshotStrings = _imgText.lower().split("\n")

	    _csCmd = ""
	    _csCmds = []
	    _processed = ""

	    for _cmdStr in _screenshotStrings:
	        if re.search(r"{}\w*.*>".format(_prefix), _cmdStr, re.IGNORECASE) and (_cmdStr.split(">")[1].replace(" ", "")) != "":
	            _csCmd = _cmdStr.split(">")[1]
	            _csCmds.append(_csCmd)
	            logging.debug("\t[debug]: Extracted command '%s'" % _csCmd)
	    
	    _TempStages = {}

	    for stage in _stages_cmds:
	    	for cmd in _stages_cmds[stage]:
	    		for _csCmdItem in _csCmds:
		    		if cmd.lower() in _csCmdItem:
		    			
		    			_isHostname = False
		    			
		    			if re.search(r"[A-Za-z0-9]+\.+[A-Za-z0-9][A-Za-z0-9-]{0,61}[A-Za-z0-9]\.+[A-Za-z]+", _csCmdItem, re.IGNORECASE):
		    				_hostnames = re.findall(r"[A-Za-z0-9]+\.+[A-Za-z0-9][A-Za-z0-9-]{0,61}[A-Za-z0-9]\.+[A-Za-z]+", _csCmdItem)
			    			if(cmd.lower() in _hostnames[0]):
			    				_isHostname = True

			    		if _isHostname == False:
			    			_stages[stage] += 1
			    			if stage not in _TempStages:
			    				_TempStages[stage] = cmd
			    			else:
			    				_TempStages[stage] = _TempStages[stage] + "_" + cmd

	    # couldn't confirm which stage/phase is it, rename then move to the Miscellaneous folder.
	    if(len(_maxScoreStages(_stages)) > 2):
	    	_phase = _maxScoreStages(_stages)[0]
	    	_dstScreenshotName = _outputDir + "/Miscellaneous/" + str(_ctTime) + "_"
	    	if _phase in _TempStages:
	    		_dstScreenshotName = _dstScreenshotName + _TempStages[_phase] + ".png"
	    	else:
	    		_dstScreenshotName = _dstScreenshotName + "misc" + ".png"

	    	logging.debug("\t[debug]: Renaming and copying screenshot '%s' to 'Miscellaneous/%s' " %(_screenshotPath, _dstScreenshotName))
	    	shutil.copy(_screenshotPath, _dstScreenshotName)
	    	_processed = os.path.abspath(_dstScreenshotName)

	    # otherwise select the first stage/phase with maximum score
	    else:
	    	_phase = _maxScoreStages(_stages)[0]
	    	_dstScreenshotName = _outputDir + "/" + _phase + "/" + str(_ctTime) + "_" + _TempStages[_phase] + ".png"
	    	logging.debug("\t[debug]: Renaming and copying screenshot '%s' to '%s'" %( _screenshotPath, _dstScreenshotName))
	    	shutil.copy(_screenshotPath, _dstScreenshotName)
	    	_processed = os.path.abspath(_dstScreenshotName)
		#print("[+]: Grouping screenshots done.")
	    for stage in _stages_cmds:
	    	_stages[stage] = 0

	    return _processed
    except:
        print ("[!]: Error grouping & renaming screenshot '%s'" %(_screenshotPath))
        return ""


def processScreenshot(_screenshotPath, _screenshotTFPath, _ctTime, _outputDir, _stages, _stages_cmds, _prefix):

	print(" [.]: Processing Screenshot %s ..." %(_screenshotPath))

	try:
		#transform the screenshot for better text extraction accuracy
		with Image(filename=_screenshotPath) as screenshot:
			screenshot.transform(resize='400%')
			screenshot.type = 'grayscale'
			screenshot.save(filename=_screenshotTFPath)

		_pim = PILImage.open(_screenshotTFPath)

		_imgText = pytesseract.image_to_string(_pim, lang = 'eng')

		os.remove(_screenshotTFPath)

		_processed = groupStuff(_screenshotPath, _imgText, _outputDir, _ctTime, _stages, _stages_cmds, _prefix)

		return _processed
	except:
		print("[!]: Error processing screenshot '%s'" %(_screenshotPath))
		exit(0)


def archive(_screenshotsPath):

	print("[+]: Archiving folder %s ..." %(_screenshotsPath))

	try:
		if os.path.exists(_screenshotsPath):
			_ts = calendar.timegm(time.gmtime())
			outZipFile = zipfile.ZipFile("archive-"+str(_ts)+".zip", 'w', zipfile.ZIP_DEFLATED)

			rootdir = os.path.basename(_screenshotsPath)

			for dirpath, dirnames, filenames in os.walk(_screenshotsPath):
				for filename in filenames:
					filepath   = os.path.join(dirpath, filename)
					parentpath = os.path.relpath(filepath, _screenshotsPath)
					arcname    = os.path.join(rootdir, parentpath)

					outZipFile.write(filepath, arcname)

			outZipFile.close()
			print("[+]: Archiving done.")

	except:
		print("[!]: Error compressing folder %s ..." %(_screenshotsPath))
		exit(0)


def PSWorker(_args):
	return processScreenshot(_args[0],_args[1],_args[2],_args[3],_args[4], _args[5], _args[6])


def RDWorker(_args):
	return redactScreenshot(_args[0],_args[1],_args[2], _args[3], _args[4], _args[5])


def main(args):

	if args.verbose:
		logging.basicConfig(level=logging.DEBUG, format='%(message)s')

	_imgsPath = args.path
	_outputDir = args.output

	if not (os.path.exists(_imgsPath)):
		print("[!]: Error Screenshots folder '%s' doesn\'t exist" % (_imgsPath))
		exit(0)

	init(_imgsPath, _outputDir, args.group)

	_poolArgs = []
	_processed = []

	if args.group:
		for _screenshot in os.listdir(_imgsPath):
			if _screenshot.endswith(".png") or _screenshot.endswith(".jpg") or _screenshot.endswith(".jpeg"): 
				_screenshotFPath = os.path.join(_imgsPath, _screenshot)
				_ctTime = datetime.fromtimestamp(os.path.getmtime(_screenshotFPath)).strftime('%Y-%m-%d_%H-%M-%S')
				sPath,sFname = os.path.split(_screenshotFPath)
				_screenshotTFPath = os.path.join(sPath, os.path.splitext(sFname)[0]+'.tif')
				_poolArgs.append([_screenshotFPath, _screenshotTFPath, _ctTime, _outputDir, _STAGES, _STAGES_CMDS, args.prefix])


		with concurrent.futures.ProcessPoolExecutor(max_workers=args.threads) as executor:
			for processedScreenshot in executor.map(PSWorker, _poolArgs):
				_processed.append(processedScreenshot)


	if args.redact:

		_passwords = []
		_poolArgs = []

		if args.passwordsDict:

			if not (os.path.exists(args.passwordsDict)):
				print("[!]: Error Passwords file '%s' not found " % (passwordsDict))
				exit(0)

			with open(args.passwordsDict) as pwdFile:
				_passwords = pwdFile.readlines()

			_passwords = [pwd.strip() for pwd in _passwords]

		if not (os.path.exists(_outputDir)):
			print("[!]: Error Output folder '%s' not found" % (_outputDir))
			exit(0)

		if len(_processed) > 0 :
			for _screenshot in _processed:
				sPath,sFname = os.path.split(_screenshot)
				_screenshotTFPath = os.path.join(sPath, os.path.splitext(sFname)[0]+'.tif')
				_poolArgs.append([_screenshot, _screenshotTFPath, sPath, 'REDACTED-'+os.path.splitext(sFname)[0]+'.png',  _passwords, ""])
		else:
			for _screenshot in os.listdir(_imgsPath):
				if _screenshot.endswith(".png") or _screenshot.endswith(".jpg") or _screenshot.endswith(".jpeg"): 
					_screenshotFPath = os.path.join(_imgsPath, _screenshot)
					_ctTime = datetime.fromtimestamp(os.path.getmtime(_screenshotFPath)).strftime('%Y-%m-%d_%H-%M-%S')
					sPath,sFname = os.path.split(_screenshotFPath)
					_screenshotTFPath = os.path.join(sPath, os.path.splitext(sFname)[0]+'.tif')
					_poolArgs.append([_screenshotFPath, _screenshotTFPath, sPath, 'REDACTED-'+os.path.splitext(sFname)[0]+'.png', _passwords, _outputDir])


		with concurrent.futures.ProcessPoolExecutor(max_workers=args.threads) as executor:
			for _ in executor.map(RDWorker, _poolArgs):
				pass

	print("[+]: Finished")


if __name__ == "__main__":


	_argParser = argparse.ArgumentParser(
	formatter_class=argparse.RawDescriptionHelpFormatter,
	prog='scrncat.py',
	description='Description: Using OCR (pytesseract) and PIL to order/group Screenshots into folders based on which RT/PT stage executed commands corresopnd to & Redact passwords based on common password patterns (Regex)',
	usage='-h for Examples'
	,epilog='----------------------------\n' +
	'\n Examples: python %(prog)s -p <screenshots_folder_path> -o <output_dir> --group --redact (to redact passwords)\n\n\t- Rename Screenshots (<REDACTED-SCREENSHOT-DATETIME.png>) and Redact passwords (default regex "_COMMON_PASSWORDS_REGEX"): \n\t\t>python3 scrncat.py -p /home/user/Screenshots/ -o generated-screenshots --redact' +
	'\n\n\t- Rename Screenshots (<REDACTED-SCREENSHOT-DATETIME.png>) Redact passwords based on a dictionary of known passwords: \n\t\t>python3 scrncat.py -p /home/user/Screenshots/ -o generated-screenshots --redact -pw cracked-passwords.txt' +
	'\n\n\t- Group Screenshots into phases listed in "c2.yaml", this will also rename screenshots to <SCREENSHOT-DATETIME-EXECUTED-COMMAND.png> and place it in the appropriate sub-folder (Persistence, LT ..etc): \n\t\t>python3 scrncat.py -p /home/user/Screenshots/ -o generated-screenshots --group' +
	'\n\n\t- Group Screenshots into phases listed in "c2.yaml" & rename to <SCREENSHOT-DATETIME-EXECUTED-COMMAND.png> & move to appropriate sub-folder (Persistence, LT ..etc) & Depends on "beacon>" prefix for accurate command extraction: \n\t\t>python3 scrncat.py -p /home/user/Screenshots/ -o generated-screenshots --group --prefix "beacon>" ' +
	'\n\n\t- Group and Redact .... all the above: \n\t\t>python3 scrncat.py -p /home/user/Screenshots/ -o generated-screenshots --group --redact --prefix "beacon>" \n\n')

	_requiredArgs = _argParser.add_argument_group('Required Arguments')
	
	_requiredArgs.add_argument('-p', '--path', metavar='', dest='path', type=str, help='Screenshots folder path', required=True)
	_argParser.add_argument('-o', '--output', metavar='', dest='output', type=str, help='Output directory name', default="output")
	_argParser.add_argument("-gr", "--group", dest='group', help="Group screenshots into multiple folders based on phases listed in cobaltstrike.yaml", action="store_true", default=0)
	_argParser.add_argument("-r", "--redact", dest='redact', help="Redact passwords, check _COMMON_PASSWORDS_REGEX for default password regex patterns used to match against screenshots containing passwords", action="store_true", default=0)
	_argParser.add_argument('-pr', '--prefix', metavar='', dest='prefix', type=str, help='C2 command shell/prompt prefix, example; the default cobaltstrike prefix is "beacon>" and "meterpreter >" for MSF, by specifying a prefix you\'ll get better results and accuracy, default prefix is set to "{}\w*.*>" regex', default="")
	_argParser.add_argument("-pw", "--passwords-dict", metavar='', dest='passwordsDict', help="'\n' separated Passwords list to redact, optional in case you want to get better results than the default regex based masking", type=str, default="")
	_argParser.add_argument('-t', '--threads', metavar='', dest='threads', type=int, help='Number of worker threads', default=4)
	_argParser.add_argument("-v", "--verbose", help="verbose messages", action="store_true", default=0)

	_args = _argParser.parse_args()

	if not (_args.redact or _args.group):
		_argParser.error('No action requested, add --group or --redact')

	main(_args)
