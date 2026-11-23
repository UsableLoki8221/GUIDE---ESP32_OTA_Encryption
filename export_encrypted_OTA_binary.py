'''
Code and guide posted at:
https://github.com/UsableLoki8221/GUIDE---ESP32_OTA_Encryption
'''

import re
import requests
import sys
import requests
import subprocess
import os
import hmac
import hashlib
from Crypto.Cipher import AES
from Crypto.Util import Counter
import time
from pathlib import Path
import configparser

# INFO: OTA updates do NOT use pre-encrypted binaries- if flash encryption is enabled then the ESP32 will encrypt it during download/update.
# OTA uses plaintext binary whether or not flash encryption is enabled
# This script is a manual encryption of the binary using OTA_KEY with HMAC capabilities to ENCRYPT the file

ENV_NAME = "esp32-s3"                               # match this to the env name you're using in your platformio.ini

version_info_URL = "https://raw.githubusercontent.com/UsableLoki8221/GUIDE---ESP32_OTA_Encryption/refs/heads/main/version.txt" # YOUR URL WHERE YOU PLACE JSON INFORMATION- FOLLOW THE FORMAT OF:
'''
{
"fw_url":"https://raw.githubusercontent.com/.../encrypted_firmware.bin",
"fw_version":"0.1.7",
"fw_size":"1340656",
"fw_hash":"31e43e9b5a2eb13e04122f4cb72220d370a73adb332a7a7e9e59b7d9e87699b8"
,
"fs_url":"https://raw.githubusercontent.com/.../encrypted_filesystem.bin",
"fs_version":"0.0.5",
"fs_size":"1572896",
"fs_hash":"33013485de2c92a492e27500574b2c9b0f73d438dde03e49af5163db87df8971"
}
'''

FILESYSTEM = True # if you use a filesystem in your project this script can also encrypt it for security

DEBUGGING_CONFIGURATION = True # allows for non-version-controlled export of serial log messages for testing, set to [False] when ready for release state
# the script does checks for release status since this is aimed at commercial releases (if you don't want to accidentally upload a debug firmware)
''' release flags checked in .ini file
    pattern1 = "build_type = release"
    pattern2 = "-DPRODUCTION=1"
    pattern3 = "-DCORE_DEBUG_LEVEL=0"
'''


SCRIPT_DIR = Path(__file__).resolve().parent

FIRMWARE_PATH = SCRIPT_DIR / "src/main.cpp"                         # your main file needs the line:        const String FIRMWARE_VERSION = "X.X.X";
FILESYSTEM_VERSION_TXT_PATH = SCRIPT_DIR / "data/fs_version.txt"    # your file system needs a file on root called fs_version.txt with one-line plain information:      X.X.X
#   THESE COMPARISONS ARE MADE AGAINST THE LISTED VERSIONS AT version_info_URL - https://raw.githubusercontent.com/.../version.txt

KEY_BASE_NAME = SCRIPT_DIR / "OTA_encryption_key"
PLATFORMIO_INI = SCRIPT_DIR / "platformio.ini"      # ini location

# this is where the encrypted binaries will be outputted for upload to your web server
OTA_FS_BINARY_PATH = SCRIPT_DIR / "OTA_Versions/encrypted_filesystem.bin"
OTA_FW_BINARY_PATH = SCRIPT_DIR / "OTA_Versions/encrypted_firmware.bin" 

# these are the new json texts that should be copy/pasted into your version URL (see example below), but you can just copy/paste from the terminal window when this script runs
OTA_FS_VERSION = SCRIPT_DIR / "OTA_Versions/OTA_FS_Version.txt"
OTA_FW_VERSION = SCRIPT_DIR / "OTA_Versions/OTA_FW_Version.txt"


ENABLE_INFO = False                         # display logging events for troubleshooting if needed

###
### you shouldn't need to change anything below here
###

OTA_KEY_PATH = r"OTA_encryption_key.bin"

RED = "\033[31m"
ORANGE = "\033[38;5;208m"
YELLOW = "\033[33m"
GREEN = "\033[32m"
BLUE = "\033[34m"
PURPLE = "\033[35m"
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


def printInfo(msg):
    if ENABLE_INFO:
        print(f"[INFO] {msg}")



def check_pio_ini_release_flags(path):
    config = configparser.ConfigParser(interpolation=None)

    if not config.read(path):
        raise FileNotFoundError(f"Could not read {path}")

    def clean_value(value):
        return value.split(";", 1)[0].strip().strip('"').strip("'")

    def get_setting(key, fallback=""):
        section = f"env:{ENV_NAME}"
        visited = set()

        while section and section not in visited:
            visited.add(section)

            if section not in config:
                break

            if config.has_option(section, key):
                return clean_value(config.get(section, key))

            section = config.get(section, "extends", fallback="").strip()

        if config.has_section("env") and config.has_option("env", key):
            return clean_value(config.get("env", key))

        return fallback

    build_type = get_setting("build_type")
    build_flags = get_setting("build_flags")

    pattern1_found = build_type.lower() == "release"
    pattern2_found = "-DPRODUCTION=1" in build_flags
    pattern3_found = "-DCORE_DEBUG_LEVEL=0" in build_flags

    if pattern1_found and pattern2_found and pattern3_found:
        print(f"{GREEN}PlatformIO environment '{ENV_NAME}' is correctly configured for Release{RESET}")
        return True


    print(
        f"{GREEN if pattern1_found else YELLOW}'build_type = release':{pattern1_found}{RESET}      "
        f"{GREEN if pattern2_found else YELLOW}'-DPRODUCTION=1':{pattern2_found}{RESET}      "
        f"{GREEN if pattern3_found else YELLOW}'-DCORE_DEBUG_LEVEL=0':{pattern3_found}{RESET}"
    )

    if DEBUGGING_CONFIGURATION:
        print(f"{ORANGE}DEBUGGING CONFIGURATION IS ACTIVE, SET TO FALSE TO CHECK FOR RELEASE STATE{RESET}")
        return True

    sys.exit(
        f"{RED}PlatformIO environment '{ENV_NAME}' is still set to a debug configuration, go change it right meow{RESET}"
    )



def extract_local_version(path):
    pattern = re.compile(r'FIRMWARE_VERSION\s*=\s*"([\d.]+)"')

    with open(path, "r", encoding="utf-8") as f:
        contents = f.read()

    match = pattern.search(contents)
    if match:
        return match.group(1)

    sys.exit(f"{RED}FIRMWARE_VERSION not found in .ino{RESET}")


def fetch_remote_version(fs_version_or_fw_version):
    r = requests.get(version_info_URL, timeout=10)
    r.raise_for_status()
    data = r.json()
    return data[fs_version_or_fw_version]

def parse_version(v):
    return tuple(int(x) for x in v.split("."))

def compare_firmware_versions(path):
    local_version = extract_local_version(path)
    
    remote_version = fetch_remote_version("fw_version")

    local_parsed = parse_version(local_version)
    remote_parsed = parse_version(remote_version)

    if local_parsed > remote_parsed:
        print(f"{GREEN}Local firmware ({local_version}) is newer than remote ({remote_version}){RESET}")
        return local_version
    elif local_parsed == remote_parsed:
        print(f"{YELLOW}Local firmware ({local_version}) is the same as remote ({remote_version}){RESET}")
        return local_version if DEBUGGING_CONFIGURATION else None
        #sys.exit(f"{YELLOW}Firmware version has not been updated to be above github webpage's firmware")
    else:
        print(f"{RED}Local firmware ({local_version}) is older than remote ({remote_version}){RESET}")
        return local_version if DEBUGGING_CONFIGURATION else None
        #sys.exit(f"{RED}Firmware version has not been updated to be above github webpage's firmware")

def check_internet_connection():
    try:
        response = requests.get(version_info_URL, timeout=5)
        response.raise_for_status()
    except requests.RequestException:
        sys.exit(f"{RED}ERROR: No access to the webpage or no internet connection.{RESET}")







def compare_filesystem_versions(path):
    if not os.path.exists(path):
        sys.exit(f"{RED}ERROR: Filesystem not found at: {path}{RESET}")
    with open(path, "r", encoding="utf-8") as f:
        local_fs_version = f.read()

    remote_fs_version = fetch_remote_version("fs_version")
    #remote_fs_version = "0.0.3"

    local_parsed = parse_version(local_fs_version)
    remote_parsed = parse_version(remote_fs_version)

    if local_parsed > remote_parsed:
        print(f"{GREEN}Local filesystem ({local_fs_version}) is newer than remote ({remote_fs_version}){RESET}")
        return local_fs_version
    elif local_parsed == remote_parsed:
        print(f"{YELLOW}Local filesystem ({local_fs_version}) is the same as remote ({remote_fs_version}){RESET}")
        return local_fs_version if DEBUGGING_CONFIGURATION else None
        #sys.exit(f"{YELLOW}filesystem version has not been updated to be above github webpage's filesystem")
    else:
        print(f"{RED}Local filesystem ({local_fs_version}) is older than remote ({remote_fs_version}){RESET}")
        return local_fs_version if DEBUGGING_CONFIGURATION else None
        #sys.exit(f"{RED}filesystem version has not been updated to be above github webpage's filesystem")


def build_firmware_image(firmware_version: str, project_dir="."):
    import os, subprocess, hashlib, time, configparser
    from pathlib import Path

    project_path = Path(project_dir).resolve()
    ini_path = project_path / "platformio.ini"

    if not ini_path.exists():
        raise FileNotFoundError("platformio.ini not found")

    config = configparser.ConfigParser()
    config.read(ini_path)

    env_sections = [s for s in config.sections() if s.startswith("env:")]

    if len(env_sections) == 0:
        raise RuntimeError("No [env:...] section found in platformio.ini")

    if len(env_sections) > 1:
        raise RuntimeError("Multiple environments found; expected only one")
    
    env_name = env_sections[0].split("env:")[1]

    build_dir = project_path / ".pio" / "build" / env_name
    bin_path = build_dir / "firmware.bin"

    if bin_path.exists():
        age = time.time() - os.path.getmtime(bin_path)
        if age > 10:
            print(f"[INFO] Firmware image too old ({age:.1f}s), deleting and rebuilding...")
            try:
                os.remove(bin_path)
            except FileNotFoundError:
                pass


    result = subprocess.run(
        ["python", "-m", "platformio", "run", "-e", env_name],
        cwd=project_path,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        raise RuntimeError(f"Firmware build failed:\n{result.stderr}")

    if not bin_path.exists():
        raise FileNotFoundError("firmware.bin not found in build directory")

    age = time.time() - os.path.getmtime(bin_path)
    if age > 10:
        raise RuntimeError(f"Firmware image too old ({age:.1f}s)")


    sha256 = hashlib.sha256()
    with open(bin_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)

    hash_bytes = sha256.digest()
    hash_hex = sha256.hexdigest()

    with open(bin_path, "ab") as f:
        f.write(hash_bytes)

    binary_size = os.path.getsize(bin_path)

    metadata_path = Path(OTA_FW_VERSION)
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    metadata_path.write_text(
        f'"fw_version":"{firmware_version}",\n'
        f'"fw_size":"{binary_size}",\n'
        f'"fw_hash":"{hash_hex}"\n'
    )

    print(f"{BLUE}Created {ORANGE}FIRMWARE{BLUE} image at {bin_path}{RESET}")
    print(f"{BLUE}Updated OTA_FW_VERSION with:{RESET}")
    print(f'{BLUE}"fw_version":"{firmware_version}",{RESET}')
    print(f'{BLUE}"fw_size":"{binary_size}",{RESET}')
    print(f'{BLUE}"fw_hash":"{hash_hex}"{RESET}')

    return str(bin_path.relative_to(project_path)), hash_hex


def build_filesystem_image(filesystem_version: str, project_dir="."):
    project_path = Path(project_dir).resolve()
    ini_path = project_path / "platformio.ini"

    if not ini_path.exists():
        raise FileNotFoundError("platformio.ini not found")

    config = configparser.ConfigParser()
    config.read(ini_path)

    env_sections = [s for s in config.sections() if s.startswith("env:")]

    if len(env_sections) == 0:
        raise RuntimeError("No [env:...] section found in platformio.ini")

    if len(env_sections) > 1:
        raise RuntimeError("Multiple environments found; expected only one")

    env_name = env_sections[0].split("env:")[1]
    filesystem = config[env_sections[0]].get("board_build.filesystem", "spiffs").lower()

    result = subprocess.run(
        ["python", "-m", "platformio", "run", "-e", env_name, "-t", "buildfs"],
        cwd=project_path,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        raise RuntimeError(f"buildfs failed:\n{result.stderr}")

    build_dir = project_path / ".pio" / "build" / env_name

    fs_map = {
        "spiffs": "spiffs.bin",
        "littlefs": "littlefs.bin",
        "fatfs": "fatfs.bin"
    }

    expected_bin = fs_map.get(filesystem, "spiffs.bin")
    bin_path = build_dir / expected_bin

    if not bin_path.exists():
        raise FileNotFoundError(f"{expected_bin} not found in build directory")

    age = time.time() - os.path.getmtime(bin_path)
    if age > 10:
        raise RuntimeError(f"Filesystem image too old ({age:.1f}s)")

    sha256 = hashlib.sha256()
    with open(bin_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)

    hash_bytes = sha256.digest()
    hash_hex = sha256.hexdigest()

    with open(bin_path, "ab") as f:
        f.write(hash_bytes)

    binary_size = os.path.getsize(bin_path)

    metadata_path = Path(OTA_FS_VERSION)
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    metadata_path.write_text(
        f'"fs_version":"{filesystem_version}",\n'
        f'"fs_size":"{binary_size}",\n'
        f'"fs_hash":"{hash_hex}"\n'
    )

    print(f"{BLUE}Created {ORANGE}FILESYSTEM{BLUE} image at {bin_path}{RESET}")
    print(f"{BLUE}Updated OTA_FS_Version.txt with:{RESET}")
    print(f'{BLUE}"fs_version":"{filesystem_version}",{RESET}')
    print(f'{BLUE}"fs_size":"{binary_size}",{RESET}')
    print(f'{BLUE}"fs_hash":"{hash_hex}"{RESET}')

    return str(bin_path.relative_to(project_path)), hash_hex



def encrypt_binary_with_hmac(input_bin_path, key_path, output_binary_path):
    import os
    import hmac
    import hashlib
    import time
    from Crypto.Cipher import AES
    from Crypto.Util import Counter

    printInfo(" Starting firmware encryption process...")

    if not os.path.exists(input_bin_path):
        print(f"[ERROR] Firmware file not found: {input_bin_path}")
        return None

    if not input_bin_path.lower().endswith(".bin"):
        print("[WARNING] Input file does not have .bin extension")

    if not os.path.exists(key_path):
        print(f"[ERROR] OTA key file not found: {key_path}")
        return None

    if not key_path.lower().endswith(".bin"):
        print("[ERROR] OTA key file must have a .bin extension")
        return None

    try:
        with open(key_path, "rb") as f:
            ota_key = f.read()

        if len(ota_key) != 32:
            print(f"[ERROR] OTA key must be exactly 32 bytes (received {len(ota_key)} bytes)")
            return None

    except Exception as e:
        print(f"[ERROR] Failed to read OTA key file: {e}")
        return None

    printInfo(" OTA key loaded successfully")

    try:
        enc_key = hmac.new(ota_key, b"OTA_AES_KEY_V1", hashlib.sha256).digest()[:16]
        mac_key = hmac.new(ota_key, b"OTA_HMAC_KEY_V1", hashlib.sha256).digest()
    except Exception as e:
        print(f"[ERROR] Key derivation failed: {e}")
        return None

    printInfo(" AES key derived")

    if os.path.exists(output_binary_path):
        age = time.time() - os.path.getmtime(output_binary_path)
        if age > 10:
            print(f"[INFO] {output_binary_path} too old ({age:.1f}s), deleting and rebuilding...")
            try:
                os.remove(output_binary_path)
            except FileNotFoundError:
                pass

    try:
        nonce = os.urandom(8)
        ctr = Counter.new(64, prefix=nonce, initial_value=0)
        cipher = AES.new(enc_key, AES.MODE_CTR, counter=ctr)

        hmac_ctx = hmac.new(mac_key, nonce, hashlib.sha256)

        with open(input_bin_path, "rb") as f_in, open(output_binary_path, "wb") as f_out:
            printInfo("Writing nonce...")
            f_out.write(nonce)

            total_bytes = 0

            while True:
                chunk = f_in.read(1024)
                if not chunk:
                    break

                encrypted = cipher.encrypt(chunk)

                hmac_ctx.update(encrypted)
                f_out.write(encrypted)

                total_bytes += len(chunk)

            printInfo(f"Processed {total_bytes} bytes")

            tag = hmac_ctx.digest()
            f_out.write(tag)

        printInfo(" Encryption + HMAC complete")

    except Exception as e:
        print(f"[ERROR] Encryption failed: {e}")
        return None

    if not os.path.exists(output_binary_path):
        print("[ERROR] Output file was not created")
        return None

    with open(input_bin_path, "rb") as f:
        original = f.read()

    with open(output_binary_path, "rb") as f:
        encrypted = f.read()

    if encrypted != original:
        print(f"{GREEN}[SUCCESS] Encrypted file written to: {output_binary_path}{RESET}")
        return output_binary_path
    else:
        print("[ERROR] File was not encrypted.")
        return None


def verify_encrypted_binary(encrypted_file_location, original_file_location, key_path, hash_hex):
    import os
    import hmac
    import hashlib
    from Crypto.Cipher import AES
    from Crypto.Util import Counter

    printInfo(" Starting firmware verification...")

    if not os.path.exists(encrypted_file_location):
        print(f"[ERROR] Encrypted file not found: {encrypted_file_location}")
        return False

    if not os.path.exists(original_file_location):
        print(f"[ERROR] Original file not found: {original_file_location}")
        return False

    if not os.path.exists(key_path):
        print(f"[ERROR] Key file not found: {key_path}")
        return False

    if not key_path.lower().endswith(".bin"):
        print("[ERROR] OTA key file must have a .bin extension")
        return False

    if not isinstance(hash_hex, str) or len(hash_hex) != 64:
        print("[ERROR] Expected SHA-256 hash must be 64 hex characters")
        return False

    try:
        bytes.fromhex(hash_hex)
    except ValueError:
        print("[ERROR] Expected SHA-256 hash contains invalid hexadecimal characters")
        return False

    try:
        with open(key_path, "rb") as f:
            ota_key = f.read()

        if len(ota_key) != 32:
            print(f"[ERROR] OTA key must be exactly 32 bytes (received {len(ota_key)} bytes)")
            return False

    except Exception as e:
        print(f"[ERROR] Failed to load OTA key: {e}")
        return False

    try:
        enc_key = hmac.new(ota_key, b"OTA_AES_KEY_V1", hashlib.sha256).digest()[:16]
        mac_key = hmac.new(ota_key, b"OTA_HMAC_KEY_V1", hashlib.sha256).digest()
    except Exception as e:
        print(f"[ERROR] Key derivation failed: {e}")
        return False

    try:
        with open(encrypted_file_location, "rb") as f:
            data = f.read()

        if len(data) < 40:
            print("[ERROR] File too small to be valid (missing nonce or HMAC)")
            return False

    except Exception as e:
        print(f"[ERROR] Failed to read encrypted file: {e}")
        return False

    nonce = data[:8]
    tag = data[-32:]
    ciphertext = data[8:-32]

    printInfo(f"[INFO] Nonce: {nonce.hex()}")
    printInfo(f"[INFO] Ciphertext size: {len(ciphertext)} bytes")

    try:
        h = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()

        if not hmac.compare_digest(h, tag):
            print("[ERROR] HMAC verification failed (file corrupted or modified)")
            return False

        printInfo(" HMAC verification passed")

    except Exception as e:
        print(f"[ERROR] HMAC computation failed: {e}")
        return False

    try:
        ctr = Counter.new(64, prefix=nonce, initial_value=0)
        cipher = AES.new(enc_key, AES.MODE_CTR, counter=ctr)
        decrypted = cipher.decrypt(ciphertext)

    except Exception as e:
        print(f"[ERROR] Decryption failed: {e}")
        return False

    if len(decrypted) < 32:
        print("[ERROR] Decrypted payload too small for embedded SHA-256")
        return False

    firmware_data = decrypted[:-32]
    embedded_hash = decrypted[-32:]

    calculated_hash = hashlib.sha256(firmware_data).hexdigest()

    if not hmac.compare_digest(calculated_hash.lower(), hash_hex.lower()):
        print("[ERROR] SHA-256 does not match expected hash")
        print(f"[ERROR] Expected:   {hash_hex}")
        print(f"[ERROR] Calculated: {calculated_hash}")
        return False

    printInfo(" Expected SHA-256 verification passed")

    if not hmac.compare_digest(embedded_hash.hex(), hash_hex.lower()):
        print("[ERROR] Embedded SHA-256 does not match expected hash")
        return False

    printInfo(" Embedded SHA-256 verification passed")

    try:
        with open(original_file_location, "rb") as f:
            original = f.read()

        if decrypted != original:
            print("[ERROR] Decrypted file does NOT match original")
            return False

    except Exception as e:
        print(f"[ERROR] Failed to read original file: {e}")
        return False

    print(f"{GREEN}[SUCCESS] File integrity verified successfully{RESET}")
    return True



def verify_encrypted_binary_chunked(encrypted_file_location, original_file_location, key_path, hash_hex):
    import os
    import hmac
    import hashlib
    from Crypto.Cipher import AES
    from Crypto.Util import Counter

    printInfo(" Starting chunked firmware verification...")

    if not os.path.exists(encrypted_file_location):
        print(f"[FAIL] Encrypted file not found: {encrypted_file_location}")
        return False

    if not os.path.exists(original_file_location):
        print(f"[FAIL] Original file not found: {original_file_location}")
        return False

    if not os.path.exists(key_path):
        print(f"[FAIL] Key file not found: {key_path}")
        return False

    if not key_path.lower().endswith(".bin"):
        print("[ERROR] OTA key file must have a .bin extension")
        return False

    if not isinstance(hash_hex, str) or len(hash_hex) != 64:
        print("[ERROR] Expected SHA-256 hash must be 64 hex characters")
        return False

    try:
        bytes.fromhex(hash_hex)
    except ValueError:
        print("[ERROR] Expected SHA-256 hash contains invalid hexadecimal characters")
        return False

    try:
        with open(key_path, "rb") as f:
            ota_key = f.read()

        if len(ota_key) != 32:
            print(f"[ERROR] OTA key must be exactly 32 bytes (received {len(ota_key)} bytes)")
            return False

    except Exception as e:
        print(f"[ERROR] Failed to load OTA key: {e}")
        return False

    enc_key = hmac.new(ota_key, b"OTA_AES_KEY_V1", hashlib.sha256).digest()[:16]
    mac_key = hmac.new(ota_key, b"OTA_HMAC_KEY_V1", hashlib.sha256).digest()

    file_size = os.path.getsize(encrypted_file_location)

    if file_size < 40:
        print("[ERROR] File too small to be valid (missing nonce or HMAC)")
        return False

    try:
        with open(encrypted_file_location, "rb") as f_enc, open(original_file_location, "rb") as f_orig:

            nonce = f_enc.read(8)

            if len(nonce) != 8:
                print("[FAIL] Invalid nonce length")
                return False

            ciphertext_len = file_size - 8 - 32

            ctr = Counter.new(64, prefix=nonce, initial_value=0)
            cipher = AES.new(enc_key, AES.MODE_CTR, counter=ctr)

            hmac_ctx = hmac.new(mac_key, nonce, hashlib.sha256)
            sha256_ctx = hashlib.sha256()
            hash_tail = b""

            remaining = ciphertext_len

            while remaining > 0:
                chunk_size = min(1024, remaining)
                enc_chunk = f_enc.read(chunk_size)

                if len(enc_chunk) != chunk_size:
                    print("[FAIL] Error with chunk sizing")
                    return False

                hmac_ctx.update(enc_chunk)

                dec_chunk = cipher.decrypt(enc_chunk)
                orig_chunk = f_orig.read(chunk_size)

                if dec_chunk != orig_chunk:
                    print(f"[FAIL] Decrypted data mismatch at chunk {remaining}")
                    return False

                combined = hash_tail + dec_chunk

                if len(combined) > 32:
                    sha256_ctx.update(combined[:-32])
                    hash_tail = combined[-32:]
                else:
                    hash_tail = combined

                remaining -= chunk_size

            expected_tag = f_enc.read(32)
            computed_tag = hmac_ctx.digest()

            if len(expected_tag) != 32 or not hmac.compare_digest(computed_tag, expected_tag):
                print("[FAIL] HMAC verification failed")
                return False

            if f_orig.read(1):
                print("[FAIL] Original file contains additional data")
                return False

            if len(hash_tail) != 32:
                print("[FAIL] Invalid embedded SHA-256 length")
                return False

            calculated_hash = sha256_ctx.hexdigest()

            if not hmac.compare_digest(calculated_hash.lower(), hash_hex.lower()):
                print("[FAIL] SHA-256 does not match expected hash")
                print(f"[FAIL] Expected:   {hash_hex}")
                print(f"[FAIL] Calculated: {calculated_hash}")
                return False

            printInfo(" Expected SHA-256 verification passed")

            if not hmac.compare_digest(hash_tail.hex(), hash_hex.lower()):
                print("[FAIL] Embedded SHA-256 does not match expected hash")
                return False

            printInfo(" Embedded SHA-256 verification passed")

    except Exception as e:
        print(f"[FAIL] Verification failed: {e}")
        return False

    print(f"{GREEN}[SUCCESS] Chunked file integrity verified successfully{RESET}")
    return True



def main():
    check_internet_connection()
    
    check_pio_ini_release_flags(PLATFORMIO_INI)

    update_firmware_version_number = compare_firmware_versions(FIRMWARE_PATH)

    if update_firmware_version_number is not None:
        firmware_path, hash_hex = build_firmware_image(update_firmware_version_number)
        encrypted_firmware_path = encrypt_binary_with_hmac(firmware_path, OTA_KEY_PATH, OTA_FW_BINARY_PATH)
        verify_encrypted_binary(encrypted_firmware_path, firmware_path, OTA_KEY_PATH, hash_hex)
        verify_encrypted_binary_chunked(encrypted_firmware_path, firmware_path, OTA_KEY_PATH, hash_hex)

    if FILESYSTEM:
        update_filesystem_version_number = compare_filesystem_versions(FILESYSTEM_VERSION_TXT_PATH)
        if update_filesystem_version_number is not None:
            filesystem_path, hash_hex = build_filesystem_image(update_filesystem_version_number)
            encrypted_filesystem_path = encrypt_binary_with_hmac(filesystem_path, OTA_KEY_PATH, OTA_FS_BINARY_PATH)
            verify_encrypted_binary(encrypted_filesystem_path, filesystem_path, OTA_KEY_PATH, hash_hex)
            verify_encrypted_binary_chunked(encrypted_filesystem_path, filesystem_path, OTA_KEY_PATH, hash_hex)


if __name__ == "__main__":
    main()
    print_rainbow("ALL DONE")



