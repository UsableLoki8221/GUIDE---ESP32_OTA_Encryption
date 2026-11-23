'''
Code and guide posted at:
https://github.com/UsableLoki8221/GUIDE---ESP32_OTA_Encryption
'''


import sys
import serial
import subprocess
import re
import time
import os
import csv
from pathlib import Path
from datetime import datetime
from serial.tools import list_ports

# efuse summary command example
#    python -m platformio pkg exec -p tool-esptoolpy -- espefuse.py --chip esp32c3 --port COM22 summary
# json form:
#   python -m platformio pkg exec -p tool-esptoolpy -- espefuse.py --chip esp32c3 --port COM22 summary --format json

ESP_CHIP = "esp32s3"            # state the ESP you are burning to, no hyphen

COM_PORT = ""                   # leave as "" to auto-detect esp COM port, otherwise manually enter with COMxx format

LOG_MAC_ID_TO_CSV = True        # if you want to record provisioned devices

BURN_FLASH_ENCRYPTION = True
BURN_OTA_ENCRYPTION = True


#choose your mode: (choose one, comment the rest)
#FLASH_BIT_TO_BURN = "0b001"    #<--recommended imo
                                    # "Dev" mode- this mode allows you to come back from 
                                    # flash encryption one more time when you transition to 0b011.  
                                    # Nice for letting makers mod your board if you want to give 
                                    # them that freedom (do it ;) )

FLASH_BIT_TO_BURN = "0b011"        # undo flash encryption: this is a one-time fallback to allow 
                                    # a device to be flashed with plain text code once again

#FLASH_BIT_TO_BURN = "0b111"         # "Release" mode- PERMANENT; CANNOT BE UNDONE.  Permantly set to flash encryption.
SET_TO_TRUE_RELEASE_MODE = True    # Setting the bit to 0b111 isn't true release, to be truly release additional fuses, look at code to see
                                    # True release mode may disable serial monitor communication, again this is permanent
                                    #
''' # you can also put this in your firmware and let the ESP self-burn its own fuses to finalize the mode, its good to do your research on this topic
#include "esp_flash_encrypt.h"

if (!esp_flash_encryption_cfg_verify_release_mode()) {
    esp_flash_encryption_set_release_mode();
}
'''

ENABLE_INFO = True

###
### you shouldn't need to change anything below here
###

PROJECT_DIR = Path(__file__).resolve().parent

########################
FLASH_ENCRYPTION_KEY_FILE = PROJECT_DIR / "flash_encryption_key.bin" 
FLASH_ENCRYPTION_KEY_SLOT = 0 # BLOCK_KEY0 (BLOCK4) ASSIGNED FOR FLASH ENCRYPTION KEY
########################

########################
OTA_ENCRYPTION_KEY_FILE = PROJECT_DIR / "ota_encryption_key.bin" 
OTA_ENCRYPTION_KEY_SLOT = 1 # BLOCK_KEY1 (BLOCK5) ASSIGNED FOR OTA ENCRYPTION KEY
########################

CSV_FILE = PROJECT_DIR / "flash_encrypted_devices.csv" 

def info(message):
    if ENABLE_INFO:
        print(f"[INFO] {message}")

RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
PURPLE = "\033[35m"
ORANGE = "\033[38;5;208m"
INDIGO = "\033[38;5;54m"
VIOLET = "\033[35m"

BOLD = "\033[1m"
RESET = "\033[0m"

colors = [RED, ORANGE, YELLOW, GREEN, BLUE, INDIGO, VIOLET]
def print_rainbow(text, index=-1, end='\n'):
    output = BOLD
    color_index = 0
    fixed_color = None
    if index != -1:
        fixed_color = colors[index % len(colors)]
    for char in text:
        if fixed_color is not None:
            color = fixed_color
        elif char not in [' ', '\n']:
            color = colors[color_index % len(colors)]
            color_index += 1
        output += f"{color}{char}"
    output += RESET
    print(output, end=end)


def find_esp32_com_port():
    known_usb_ids = {
        (0x303A, 0x1001),  # Espressif USB Serial/JTAG
        (0x10C4, 0xEA60),  # Silicon Labs CP210x
        (0x1A86, 0x7523),  # WCH CH340
        (0x1A86, 0x55D4),  # WCH CH9102
        (0x0403, 0x6001),  # FTDI FT232
    }

    candidates = []
    for port in list_ports.comports():
        description = (port.description or "").lower()
        if (
            (port.vid, port.pid) in known_usb_ids
            or "usb serial/jtag" in description
            or "esp32" in description
            or "cp210" in description
            or "ch340" in description
            or "ch910" in description
        ):
            candidates.append(port.device)

    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) > 1:
        raise RuntimeError(
            "Multiple likely ESP32 serial ports found: "
            + ", ".join(candidates)
            + ". Set COM_PORT explicitly."
        )
    return None


def resolve_com_port():
    global COM_PORT

    if COM_PORT == "":
        detected = find_esp32_com_port()
        if detected is None:
            raise RuntimeError(
                "No likely ESP32 serial port detected. Set COM_PORT manually."
            )
        COM_PORT = detected
        info(f"Automatically detected serial port: {COM_PORT}")
    else:
        if not isinstance(COM_PORT, str) or not re.fullmatch(
            r"COM[1-9]\d*", COM_PORT, flags=re.IGNORECASE
        ):
            raise ValueError(
                f"Invalid COM_PORT {COM_PORT!r}. Use '' for auto-detection "
                'or a value such as "COM21".'
            )
        COM_PORT = COM_PORT.upper()

    available_ports = {port.device.upper() for port in list_ports.comports()}
    if COM_PORT.upper() not in available_ports:
        raise RuntimeError(
            f"{COM_PORT} is not currently listed by Windows. "
            "Check the cable, driver, and selected port."
        )

    return COM_PORT


def load_key(filepath):

    if not os.path.exists(filepath):
        print(f"{RED}ERROR: Key file not found:{RESET} {YELLOW}{filepath}{RESET}")
        return None

    extension = os.path.splitext(filepath)[1].lower()

    try:

        if extension == ".txt":

            with open(filepath, "r") as f:
                key_hex = f.read().strip()

            if len(key_hex) != 64:
                print(f"{RED}ERROR: TXT key must be 64 hex characters{RESET}")
                return None

            try:
                key_bytes = bytes.fromhex(key_hex)
            except ValueError:
                print(f"{RED}ERROR: Invalid hex in TXT key{RESET}")
                return None

            return key_bytes

        elif extension == ".bin":

            with open(filepath, "rb") as f:
                key_bytes = f.read()

            if len(key_bytes) != 32:
                print(f"{RED}ERROR: BIN key must be exactly 32 bytes{RESET}")
                return None

            return key_bytes

        else:
            print(f"{RED}ERROR: Unsupported key file type:{RESET} {extension}")
            return None

    except Exception as e:
        print(f"{RED}ERROR loading key:{RESET} {e}")
        return None


def esp_retrieve_fuse_summary(COM_PORT):

    result = subprocess.run(
        [sys.executable, "-m", "espefuse", "--port", COM_PORT, "summary"],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print(f"{RED}Failed to read eFuse summary{RESET}")
        return False  # fail safe
    
    """ FOR PRINTING WHOLE LINE OUT STATEMENT
    lines = result.stdout.splitlines()
    for i, line in enumerate(lines):
        l = lines[i].strip()
        print(f"{BLUE}Line {i}:{RESET} {l}")
    """

    return result


def confirm_burn(mac):
    print(f"\n{YELLOW}About to burn eFuse for device:{RESET} {BLUE}{mac}{RESET}")
    print(f"{RED}THIS IS PERMANENT AND CANNOT BE UNDONE{RESET}")

    try:
        confirm1 = input("Type 'YES' or 'y' to continue: ")
    except KeyboardInterrupt:
        print(f"\n{RED}User interrupted input. Aborting.{RESET}")
        return False

    if confirm1.lower() == "yes" or confirm1.lower() == "y":
        return True

    return False


def get_esp32_mac(COM_PORT):
    try:
        result = subprocess.run(
            [sys.executable, "-m", "esptool", "--port", COM_PORT, "read-mac"],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            print(f"{RED}No ESP32 found on {COM_PORT}, aborting all operations.{RESET}")
            print(result.stderr.strip())
            sys.exit(1)
            return None

        output = result.stdout
        # print(output)

        mac_match = re.search(r"MAC:\s*([0-9A-Fa-f:]+)", output)
        if mac_match:
            mac = mac_match.group(1)
            mac_bytes = bytes(int(b, 16) for b in mac.split(":"))
            print(f"Device MAC: {BLUE}{mac}{RESET}")
            return mac, mac_bytes

        print(f"{RED}Failed to parse MAC{RESET}")
        return None

    except Exception as e:
        print(f"{RED}Error: {e}{RESET}")
        return None


def enter_bootloader(COM_PORT):
    # This only works if the board exposes RTS/DTR for reset/boot
    with serial.Serial(COM_PORT, 115200) as ser:
        ser.setDTR(False)   # DTR low → RESET low
        ser.setRTS(True)    # RTS high → BOOT/IO0 low
        time.sleep(0.1)
        ser.setDTR(True)    # Release RESET
        time.sleep(0.05)
        ser.setRTS(False)   # Release BOOT
        time.sleep(0.1)



######################## UPDATE STATEMENT IF ADDING MORE KEYS
def burn_efuse(
    COM_PORT,
    FLASH_ENCRYPTION_KEY_flag=False,
    OTA_ENCRYPTION_KEY_flag=False,
    SPI_BOOT_CRYPT_CNT_flag=False
):

    try:
        def run_stream(command, description, timeout=60):
            print(f"\n=== {description} ===")
            print(" ".join(map(str, command)))
            print()

            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )

            try:
                if ENABLE_INFO:
                    print("[[[[[[[[[[[[[[[[[[[[[[[FUSE COMMAND MESSAGES]]]]]]]]]]]]]]]]]]]]]]]")
                    for line in process.stdout:
                        print(line, end="")
                    #print("[[[[[[[[[[[[[[[[[[[[[[[END MESSAGES]]]]]]]]]]]]]]]]]]]]]]]")
                process.wait(timeout=timeout)

            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                print(f"{RED}{description} TIMED OUT{RESET}")
                return False

            if process.returncode != 0:
                print(f"{RED}{description} FAILED{RESET}")
                return False

            print(f"{GREEN}{description} OPERATION COMPLETED{RESET}")
            print(f"{ORANGE}\nCONTINUING...\n{RESET}")

            return True

        # Burn the encryption keys
        key_command = [
            sys.executable,
            "-m", "espefuse",
            "--chip", ESP_CHIP,
            "--port", COM_PORT,
            "--do-not-confirm",
            "burn-key"]

        
        ########################
        if FLASH_ENCRYPTION_KEY_flag:
            key_command.extend([
                f"BLOCK_KEY{FLASH_ENCRYPTION_KEY_SLOT}",
                str(FLASH_ENCRYPTION_KEY_FILE),
                "XTS_AES_128_KEY", # THIS DESIGNATES THE KEY TYPE IN THE DESIGNATED SLOT
            ])
        ########################
        
        ########################
        if OTA_ENCRYPTION_KEY_flag:
            key_command.extend([
                f"BLOCK_KEY{OTA_ENCRYPTION_KEY_SLOT}",
                str(OTA_ENCRYPTION_KEY_FILE),
                "HMAC_UP",
            ])
        ########################


        ######################## UPDATE STATEMENT IF ADDING MORE KEYS
        if FLASH_ENCRYPTION_KEY_flag or OTA_ENCRYPTION_KEY_flag:
            if not run_stream(key_command, "Burn encryption keys"): #ensure pass before burning flash enable fuse
                return False

        # Burn the selected SPI_BOOT_CRYPT_CNT bits.
        if SPI_BOOT_CRYPT_CNT_flag:
            counter_command = [
                sys.executable,
                "-m", "espefuse",
                "--chip", ESP_CHIP,
                "--port", COM_PORT,
                "--do-not-confirm",
                "burn-efuse", 
            ]

            counter_command.extend(["SPI_BOOT_CRYPT_CNT",str(int(FLASH_BIT_TO_BURN, 2)),])

            if ESP_CHIP == "esp32":
                counter_command.extend(["FLASH_CRYPT_CONFIG","0xF",])
                if SET_TO_TRUE_RELEASE_MODE and FLASH_BIT_TO_BURN == '0b111':
                    counter_command.extend([
                        "DISABLE_DL_ENCRYPT", "1",
                        "DISABLE_DL_DECRYPT", "1",
                        "DISABLE_DL_CACHE", "1",
                        "JTAG_DISABLE", "1",
                    ])
            else:
                if SET_TO_TRUE_RELEASE_MODE and FLASH_BIT_TO_BURN == '0b111':
                    counter_command.extend([
                        "DIS_DOWNLOAD_ICACHE", "1",
                        "DIS_DOWNLOAD_MANUAL_ENCRYPT", "1",
                    ])

            '''
            #burn additional fuses in pair as fuse name + value like so: (espressif recommends a bunch of these for commercial releases, do them at your own call)
            counter_command.extend(["
                "DIS_LEGACY_SPI_BOOT", "1",
                "DIS_USB_JTAG", "1",
                "DIS_PAD_JTAG", "1",
            ])
            '''

            if not run_stream(
                counter_command,
                f"Burn fuse settings",
            ):
                return False

        return True

    except Exception as e:
        print(f"{RED}eFuse provisioning exception: {e}{RESET}")
        return False



def verify_key_purpose(efuse_summary, slot, purpose_name):
    print(f"{BLUE}Verifying key purpose for slot {slot}...{RESET}")

    lines = efuse_summary.stdout.splitlines()

    target = f"KEY_PURPOSE_{slot}"

    for i, line in enumerate(lines):
        l = line.strip()

        if l.startswith(target):
            print(f"{GREEN}Found {target} at line {i}:{RESET}")
            print(f"{PURPLE}{l}{RESET}")

            if "=" in l:
                value = l.split("=")[1].strip()

                print(f"{YELLOW}Parsed purpose: {value}{RESET}")

                if purpose_name in value:
                    print(f"{GREEN}Slot {slot} correctly set for {purpose_name}{RESET}")
                    return True
                else:
                    print(f"{RED}Slot {slot} NOT set for HMAC (found: {value}).  Value should be: {purpose_name}{RESET}")
                    return False

    print(f"{RED}Could not find KEY_PURPOSE_{slot}{RESET}")
    return False


def is_efuse_already_burned(efuse_summary, block_num):

    lines = efuse_summary.stdout.splitlines()
    if block_num == "BLOCK_USR_DATA (BLOCK3)":
        print(f"{RESET}Checking BLOCK_USR_DATA (BLOCK3)...{RESET}")
        block_name = f"BLOCK_USR_DATA (BLOCK3)"
    else:
        print(f"{RESET}Checking eFuse block {block_num}...{RESET}")
        block_name = f"BLOCK_KEY{block_num}"

    for i, line in enumerate(lines):
        if line.strip().startswith(block_name):

            print(f"{GREEN}Found {block_name} at line {i}:{RESET}")
            #print(f"{PURPLE}{line.strip()}{RESET}")

            # Look ahead for the data line
            for j in range(i + 1, min(i + 10, len(lines))):
                l = lines[j].strip()

                # print(f"{BLUE}Scanning line {j}:{RESET} {l}")

                if l.startswith("="):
                    print(f"{GREEN}Found key data line at {j}: {YELLOW}{l}{RESET}")

                    # Extract only hex bytes (ignore R/W)
                    parts = l.split("=")[1].strip().split()
                    hex_bytes = [p for p in parts if len(p) == 2]

                    #print(f"{PURPLE}Parsed hex bytes ({len(hex_bytes)}):{RESET}")
                    #print(f"{YELLOW}{' '.join(hex_bytes)}{RESET}")

                    if len(hex_bytes) != 32:
                        print(f"{RED}Unexpected key length in {block_name}{RESET}")
                        return True  # fail safe

                    if any(b != "00" for b in hex_bytes):
                        print(f"{YELLOW}Notice: {block_name} already programmed!{RESET}")
                        return True
                    else:
                        print(f"{GREEN}{block_name} is EMPTY (all zeros){RESET}")
                        return False

            print(f"{RED}Did not find '=' line for {block_name}{RESET}")
            return True  # fail safe

    print(f"{RED}Could not find {block_name} in eFuse summary{RESET}")
    return True  # fail safe

FOUND_BIT = None

def is_efuse_flag_burned(efuse_summary, efuse_name):
    global FOUND_BIT

    print(f"{RESET}Checking eFuse flag {efuse_name}...{RESET}")

    lines = efuse_summary.stdout.splitlines()

    for line in lines:

        stripped = line.strip()

        if not stripped.startswith(efuse_name):
            continue

        print(f"{GREEN}Found {efuse_name}:{RESET}")
        print(f"{YELLOW}{stripped}{RESET}")

        # =====================================================
        # SPECIAL CASE: SPI_BOOT_CRYPT_CNT (bit-parity fuse)
        # =====================================================
        if efuse_name == "SPI_BOOT_CRYPT_CNT":

            match = re.search(r"\b0b[01]+\b", stripped)

            if match:
                FOUND_BIT = match.group(0)
                print(f"{GREEN}FOUND_BIT = {FOUND_BIT}{RESET}")
            else:
                FOUND_BIT = None
                print(f"{RED}Could not extract binary fuse value{RESET}")
                return False
            
            lowered = stripped.lower()

            if "disable" in lowered:
                print(f"{GREEN}{efuse_name} is currently DISABLED{RESET}")
                if FLASH_BIT_TO_BURN in ("0b001", "0b111"): return False
                else: return True

            if "enable" in lowered:
                print(f"{YELLOW}{efuse_name} is ENABLED{RESET}")
                if FLASH_BIT_TO_BURN in ("0b001", "0b111"): return True
                else: return False

            # fallback: treat unknown as NOT safe to assume burned
            print(f"{RED}Could not reliably parse SPI_BOOT_CRYPT_CNT state{RESET}")
            return False

        # =====================================================
        # BOOLEAN FUSES
        # =====================================================
        if "= True" in stripped:
            print(f"{YELLOW}{efuse_name} is already burned/enabled{RESET}")
            return True

        if "= False" in stripped:
            print(f"{GREEN}{efuse_name} is not burned{RESET}")
            return False

        # =====================================================
        # NUMERIC FUSES
        # =====================================================
        if "=" in stripped:

            value = stripped.split("=")[1].strip().split()[0]

            try:
                parsed = int(value, 16) if value.startswith("0x") else int(value)

                if parsed != 0:
                    print(f"{YELLOW}{efuse_name} already programmed: {parsed}{RESET}")
                    return True
                else:
                    print(f"{GREEN}{efuse_name} is zero/unset{RESET}")
                    return False

            except:
                pass

        print(f"{RED}Could not parse {efuse_name}{RESET}")
        return True

    print(f"{RED}Could not find {efuse_name} in summary output{RESET}")
    return True


def setFuseFlag(fuse_summary, name, confirmation_message=False):
    if confirmation_message: # reverses statement because it was sloppy quick, don't judge
        if is_efuse_flag_burned(fuse_summary, name):
            print(f"{GREEN}FUSE '{name}' successfully burned!{RESET}")
            return True
        print(f"{RED}ERROR: FUSE '{name}' not burned{RESET}")
        return False
    else:
        if is_efuse_flag_burned(fuse_summary, name):
            print(f"{YELLOW}FUSE '{name}' already burned: Setting flag to prevent overwriting eFuse{RESET}")
            return False
        print(f"{GREEN}FUSE '{name}' not burned: Setting flag for burning{RESET}")
        return True


def log_to_csv(mac, bit_burned): #, master_key_hex, ota_key_hex):
    file_exists = os.path.exists(CSV_FILE)
    ts = datetime.now().isoformat()

    with open(CSV_FILE, "a", newline="") as f:
        writer = csv.writer(f)

        if not file_exists:
            writer.writerow(["timestamp", "mac", "SPI_BOOT_CRYPT_CNT"])

        writer.writerow([
            ts,
            mac,
            bit_burned
        ])

    print(f"{GREEN}Logged to CSV: {CSV_FILE}{RESET}")



def main():
    resolve_com_port() # sets global COM port value

    mac_result = get_esp32_mac(COM_PORT)
    if mac_result is None:
        print(f"mac_result is None{RESET}")
        return False

    mac, mac_bytes = mac_result

    ######################## Key block
    if BURN_FLASH_ENCRYPTION:
        FLASH_ENCRYPTION_KEY = load_key(FLASH_ENCRYPTION_KEY_FILE)
        if FLASH_ENCRYPTION_KEY is not None: print(f"{PURPLE}FLASH_ENCRYPTION key loaded{RESET}")
        else: 
            print(f"ERROR: FLASH_ENCRYPTION_KEY is None{RESET}")
            return False
        if len(FLASH_ENCRYPTION_KEY) != 32:
            raise ValueError("FLASH_ENCRYPTION_KEY must be 32 bytes")
    ######################## Key block

    ######################## Key block
    if BURN_OTA_ENCRYPTION:
        OTA_ENCRYPTION_KEY = load_key(OTA_ENCRYPTION_KEY_FILE)
        if OTA_ENCRYPTION_KEY is not None: print(f"{PURPLE}OTA_ENCRYPTION key loaded{RESET}")
        else: 
            print(f"ERROR: OTA_ENCRYPTION_KEY is None{RESET}")
            return False
        if len(OTA_ENCRYPTION_KEY) != 32:
            raise ValueError("OTA_ENCRYPTION_KEY must be 32 bytes")
    ######################## Key block
    


    fuse_summary = esp_retrieve_fuse_summary(COM_PORT)
    if not fuse_summary:
        print(f"{RED}Failed to retrieve eFuse summary, aborting.{RESET}")
        return False

    ##################
    #FLAGS SECTION
    ##################

    ######################## Key block
    FLASH_ENCRYPTION_KEY_flag = BURN_FLASH_ENCRYPTION
    if BURN_FLASH_ENCRYPTION:
        flash_encryption_slot_burned = is_efuse_already_burned(fuse_summary, FLASH_ENCRYPTION_KEY_SLOT)
        if flash_encryption_slot_burned:
            print(f"{YELLOW}slot{FLASH_ENCRYPTION_KEY_SLOT} (flash_encryption) already burned: Setting flag to prevent overwriting eFuse{RESET}")
            FLASH_ENCRYPTION_KEY_flag = False
            if not verify_key_purpose(fuse_summary, FLASH_ENCRYPTION_KEY_SLOT, "XTS_AES_128_KEY"):
                print(f"{RED}DESIGNATED SLOT FOR ENCRYPTION ALREADY HAS A DIFFERENT TYPE OF KEY PLACED IN SLOT: {FLASH_ENCRYPTION_KEY_SLOT}{RESET}") 
            else: 
                print(f"{GREEN}XTS_AES_128_KEY has already been assigned in slot: {FLASH_ENCRYPTION_KEY_SLOT}{RESET}") 
    ######################## Key block
    
    ######################## Key block
    OTA_ENCRYPTION_KEY_flag = BURN_OTA_ENCRYPTION
    if BURN_OTA_ENCRYPTION:
        ota_encryption_slot_burned = is_efuse_already_burned(fuse_summary, OTA_ENCRYPTION_KEY_SLOT)
        if ota_encryption_slot_burned:
            print(f"{YELLOW}slot{OTA_ENCRYPTION_KEY_SLOT} (ota_encryption) already burned: Setting flag to prevent overwriting eFuse{RESET}")
            OTA_ENCRYPTION_KEY_flag = False
            if not verify_key_purpose(fuse_summary, OTA_ENCRYPTION_KEY_SLOT, "HMAC_UP"):
                print(f"{RED}DESIGNATED SLOT FOR OTA ENCRYPTION ALREADY HAS A DIFFERENT TYPE OF KEY PLACED IN SLOT: {OTA_ENCRYPTION_KEY_SLOT}{RESET}") 
            else: 
                print(f"{GREEN}HMAC_UP has already been assigned in slot: {OTA_ENCRYPTION_KEY_SLOT}{RESET}") 
    ######################## Key block

    ######################## eFuse setting
    SPI_BOOT_CRYPT_CNT_flag = BURN_FLASH_ENCRYPTION
    if BURN_FLASH_ENCRYPTION:
        SPI_BOOT_CRYPT_CNT_flag = setFuseFlag(fuse_summary, "SPI_BOOT_CRYPT_CNT") # this used to set the bool but realized it was unncessary with the logic below
                                                                                # leaving it in because it updates a global variable (FOUND_BIT)
        SPI_BOOT_CRYPT_CNT_flag = True
        if int(FLASH_BIT_TO_BURN, 2) < int(FOUND_BIT, 2):
            print(
                f"{RED}The SPI_BOOT_CRYPT_CNT bit cannot be less than {BOLD}{BLUE}{FOUND_BIT}{RESET}{RED} "
                f"as that is what was found within the ESP\n"
                f"You currently have FLASH_BIT_TO_BURN set to: {ORANGE}{FLASH_BIT_TO_BURN}{RESET}"
            )
            return False
    ######################## eFuse setting

       
    ###############
    # MESSAGES TO USER SECTION BEFORE CONFIRM OPERATION
    ###############

    print(f"{ORANGE}Settings-{RESET}")    
    ######################## Key block
    if BURN_FLASH_ENCRYPTION:
        if FLASH_ENCRYPTION_KEY_flag: print(f"{ORANGE}Preparing to burn key into device: {PURPLE}FLASH_ENCRYPTION_KEY_flag, Slot: {FLASH_ENCRYPTION_KEY_SLOT}{RESET}")
        else : print(f"{ORANGE}Flash encryption key is flagged to {BOLD}NOT{RESET}{ORANGE} burn since there is already a key in slot {FLASH_ENCRYPTION_KEY_SLOT}{RESET}")
    ######################## Key block

    ######################## Key block
    if BURN_OTA_ENCRYPTION:
        if OTA_ENCRYPTION_KEY_flag: print(f"{ORANGE}Preparing to burn key into device: {PURPLE}OTA_ENCRYPTION_KEY_flag, Slot: {OTA_ENCRYPTION_KEY_SLOT}{RESET}")
        else : print(f"{ORANGE}OTA encryption key is flagged to {BOLD}NOT{RESET}{ORANGE} burn since there is already a key in slot {OTA_ENCRYPTION_KEY_SLOT}{RESET}")
    ######################## Key block

    ######################## eFuse setting
    if BURN_FLASH_ENCRYPTION:
        if int(FLASH_BIT_TO_BURN, 2) == int(FOUND_BIT, 2):
            SPI_BOOT_CRYPT_CNT_flag = False
            print(f"{ORANGE}SPI_BOOT_CRYPT_CNT already set to {FLASH_BIT_TO_BURN}{RESET}")
        else:
            print(
                f"{BLUE}Found bit in device: {FOUND_BIT}{ORANGE} -> Flash bit to burn: {VIOLET}{FLASH_BIT_TO_BURN} - "
                f"({ 'Dev mode' if FLASH_BIT_TO_BURN == '0b001' else 'Release mode' if FLASH_BIT_TO_BURN == '0b111' else 'Flash encryption disabled' if FLASH_BIT_TO_BURN in ('0b011', '0b000') else 'Unknown mode' }){RESET}"
            )

        print(f"{ORANGE}\nONCE A KEY OR A SETTING HAS BEEN BURNED INTO THE DEVICE IT CANNOT BE UNDONE- Example: 0b111 -> 0b011 is not possible\n")
    ######################## eFuse setting


    ######################## update here if adding more efuse keys and settings
    if not SPI_BOOT_CRYPT_CNT_flag and not FLASH_ENCRYPTION_KEY_flag and not OTA_ENCRYPTION_KEY_flag:
        print(f"{ORANGE}{BOLD}ALL FUSES TO THIS DEVICES HAVE BEEN DETECT AS ALREADY SET{RED} - ABORTING{RESET}")
        return False
    ######################## update here if adding more keys keys and settings


    # Confirm---------------------------------------------- 
    # I preferred this because espressif's burn command has you manually type BURN before actually executing the command (and its invisible so you don't know if you typo'd)
    # You can comment/remove this if you're confident in this process for faster burning
    if not confirm_burn(mac):
        print(f"{RED}User aborted{RESET}")
        return False

    print(f"{ORANGE}\nTHE FOLLOWING OPERATIONS TAKE A WHILE TO EXECUTE, ITS RECOMMENDED TO NOT INTERRUPT THE SCRIPT AT THIS POINT\n{RESET}")

    enter_bootloader(COM_PORT)

    #BURN BABY BURN ######################## update all flags
    burn_efuse(COM_PORT, FLASH_ENCRYPTION_KEY_flag, OTA_ENCRYPTION_KEY_flag, SPI_BOOT_CRYPT_CNT_flag)
    #BURN BABY BURN ######################## update all flags

    time.sleep(0.5)
    fuse_summary = esp_retrieve_fuse_summary(COM_PORT)
    if not fuse_summary:
        print(f"{RED}Failed to retrieve eFuse summary after burning, aborting.{RESET}")
        return False

    failFlag = False

    ################
    #CONFIRM ALL EFUSE ACTIONS
    ################

    ######################## Key block
    if BURN_FLASH_ENCRYPTION:
        flash_encryption_slot_burned = is_efuse_already_burned(fuse_summary, FLASH_ENCRYPTION_KEY_SLOT)
        if not flash_encryption_slot_burned:
            print(f"{RED}eFuse slot did not have key burned: slot {FLASH_ENCRYPTION_KEY_SLOT}{RESET}") 
            failFlag = True
        if not verify_key_purpose(fuse_summary, FLASH_ENCRYPTION_KEY_SLOT, "XTS_AES_128_KEY"):
            print(f"{RED}eFuse purpose incorrect- slot {FLASH_ENCRYPTION_KEY_SLOT}{RESET}") 
            failFlag = True 
    ######################## Key block

    ######################## Key block
    if BURN_OTA_ENCRYPTION:
        ota_encryption_slot_burned = is_efuse_already_burned(fuse_summary, OTA_ENCRYPTION_KEY_SLOT)
        if not ota_encryption_slot_burned:
            print(f"{RED}eFuse slot did not have key burned: slot {OTA_ENCRYPTION_KEY_SLOT}{RESET}") 
            failFlag = True
        if not verify_key_purpose(fuse_summary, OTA_ENCRYPTION_KEY_SLOT, "HMAC"):
            print(f"{RED}eFuse purpose incorrect- slot {OTA_ENCRYPTION_KEY_SLOT}{RESET}") 
            failFlag = True 
    ######################## Key block
    
    ######################## eFuse setting
    if BURN_FLASH_ENCRYPTION:
        SPI_BOOT_CRYPT_CNT_flag = setFuseFlag(fuse_summary, "SPI_BOOT_CRYPT_CNT", True)
        if SPI_BOOT_CRYPT_CNT_flag:
            print(f"{GREEN}eFuse flags successfully programmed!{RESET}")
        else: 
            print(f"{RED}eFuse PROGRAMMING DID NOT WORK!{RESET}")
            print(f"SPI_BOOT_CRYPT_CNT_flag: {SPI_BOOT_CRYPT_CNT_flag}")
            failFlag = True
    ######################## eFuse setting

    if failFlag:
        print(f"ERROR WITH {mac}")
        mac = mac + "_ERROR"
        if LOG_MAC_ID_TO_CSV:log_to_csv(mac, FLASH_BIT_TO_BURN)
        return False
    
    # Log
    if LOG_MAC_ID_TO_CSV:log_to_csv(mac, FLASH_BIT_TO_BURN)

    print(f"{GREEN}Provisioning complete{RESET}")
    return True


if __name__ == "__main__":
    try:
        if main():
            print_rainbow("SUCCESS")
            print_rainbow("ALL DONE")
            sys.exit(0)
        else:
            print(f"{RED}ERROR ERROR ERROR{RESET}")
            sys.exit(1)
    except Exception as error:
        print(f"{RED}ERROR: {error}{RESET}", file=sys.stderr)
        sys.exit(1)
