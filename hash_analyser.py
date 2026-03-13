import subprocess
import os
import re
import sys

class HashAnalyser():
    def __init__(self):
        pass

    def check_hashid_installed(self) -> bool:
        """
        Checks if hashid is installed and installs it if not.

        Returns:
            bool: True if hashid is available, False if installation failed.
        """
        try:
            subprocess.run(
                ["hashid", "--version"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True
            )
            print("[+] hashid is already installed.")
            return True

        except FileNotFoundError:
            print("[-] hashid not found. Installing...")
            try:
                subprocess.run(
                    [sys.executable, "-m", "pip", "install", "hashid"],
                    check=True
                )
                print("[+] hashid installed successfully.")
                return True

            except subprocess.CalledProcessError as e:
                print(f"[-] Failed to install hashid: {e}")
                return False

    def get_list_hashcat_type_with_hashid(self, hash:str) -> list:
        '''
        get_list_hash_type_with_hashid(hash) -> renvoit le résultat de la commande "hashid -m"
        utilise "hashid -m" -> reperer les types de hash possibles
        '''
        assert type(hash) == str, "hash must be string"

        if not self.check_hashid_installed():
            return None
        
        command = ["hashid", "-m", hash]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True
            )
            
            # Extrait toutes les valeurs numériques après [Hashcat Mode: ...]
            modes = re.findall(r'\[Hashcat Mode: (\d+)\]', result.stdout)

            # Convertit en entiers et déduplique en préservant l'ordre
            seen = set()
            unique_modes = []
            for m in modes:
                val = int(m)
                if val not in seen:
                    seen.add(val)
                    unique_modes.append(val)

            return unique_modes 

        except subprocess.CalledProcessError as e:
            print("Error during hashid execution :")
            print(e.stdout)
            print(e.stderr)
            return None

    def detect_hash_type(self, hash_value: str) -> list[str]:

        """
        Detects the most likely hash type(s) based on the hash format and length.

        Args:
            hash_value (str): The hash string to analyze.

        Returns:
            list[str]: A list containing the hash name and hashcat mode ID.
                    Returns ["Unknown"] if no match is found.
        """
        assert isinstance(hash_value, str) and hash_value.strip(), \
            "hash_value must be a non-empty string."

        hash_value = hash_value.strip()

        # ── Hex-only hashes ───────────────────────────────────────────────────────
        if re.fullmatch(r"[a-fA-F0-9]{8}", hash_value):
            return ["CRC32", "11500"]

        if re.fullmatch(r"[a-fA-F0-9]{16}", hash_value):
            return ["MySQL323", "200"]

        if re.fullmatch(r"[a-fA-F0-9]{32}", hash_value):
            return ["MD5 / NTLM / MD4", "0"]        # 0=MD5 | 1000=NTLM | 900=MD4

        if re.fullmatch(r"[a-fA-F0-9]{40}", hash_value):
            return ["SHA1 / MySQL4.1", "100"]        # 100=SHA1 | 300=MySQL4.1

        if re.fullmatch(r"[a-fA-F0-9]{48}", hash_value):
            return ["SHA2-224 / Keccak-224", "1300"] # 1300=SHA224

        if re.fullmatch(r"[a-fA-F0-9]{56}", hash_value):
            return ["SHA2-256 (Half) / Keccak-224", "1300"]

        if re.fullmatch(r"[a-fA-F0-9]{64}", hash_value):
            return ["SHA2-256 / SHA3-256 / Keccak-256 / BLAKE2s-256", "1400"]

        if re.fullmatch(r"[a-fA-F0-9]{80}", hash_value):
            return ["RIPEMD-320", "28900"]

        if re.fullmatch(r"[a-fA-F0-9]{96}", hash_value):
            return ["SHA2-384 / SHA3-384 / Keccak-384", "10800"]

        if re.fullmatch(r"[a-fA-F0-9]{128}", hash_value):
            return ["SHA2-512 / SHA3-512 / Keccak-512 / Whirlpool / BLAKE2b-512", "1700"]

        # ── BCrypt ────────────────────────────────────────────────────────────────
        if re.fullmatch(r"\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}", hash_value):
            return ["bcrypt", "3200"]

        # ── Unix crypt ────────────────────────────────────────────────────────────
        if re.fullmatch(r"\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}", hash_value):
            return ["md5crypt (Unix / Cisco $1$)", "500"]

        if re.fullmatch(r"\$5\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}", hash_value):
            return ["sha256crypt $5$ (Unix)", "7400"]

        if re.fullmatch(r"\$6\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}", hash_value):
            return ["sha512crypt $6$ (Unix)", "1800"]

        if re.fullmatch(r"\$y\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{,86}\$[./A-Za-z0-9]{43}", hash_value):
            return ["yescrypt", "15700"]

        # ── Windows ───────────────────────────────────────────────────────────────
        if re.fullmatch(r"[a-fA-F0-9]{32}:[a-fA-F0-9]{32}", hash_value):
            return ["NetNTLMv1", "5500"]

        if re.fullmatch(r".+::.+:[a-fA-F0-9]{16}:[a-fA-F0-9]{32}:[a-fA-F0-9]+", hash_value):
            return ["NetNTLMv2", "5600"]

        if re.fullmatch(r"\$DCC2\$\d+#.+#[a-fA-F0-9]{32}", hash_value):
            return ["Domain Cached Credentials 2 (MS Cache 2)", "2100"]

        # ── LDAP / Base64 ─────────────────────────────────────────────────────────
        if re.fullmatch(r"\{SHA\}[A-Za-z0-9+/=]{28}", hash_value):
            return ["nsldap SHA-1 (Base64)", "101"]

        if re.fullmatch(r"\{SSHA\}[A-Za-z0-9+/=]{40}", hash_value):
            return ["nsldaps SSHA-1 (Base64)", "111"]

        if re.fullmatch(r"\{SSHA256\}[A-Za-z0-9+/=]{60}", hash_value):
            return ["SSHA-256 (Base64)", "1411"]

        if re.fullmatch(r"\{SSHA512\}[A-Za-z0-9+/=]{96}", hash_value):
            return ["SSHA-512 (Base64)", "1711"]

        # ── Cisco ─────────────────────────────────────────────────────────────────
        if re.fullmatch(r"\$8\$[./A-Za-z0-9]{14}\$[./A-Za-z0-9]{43}", hash_value):
            return ["Cisco-IOS $8$ (PBKDF2-SHA256)", "9200"]

        if re.fullmatch(r"\$9\$[./A-Za-z0-9]{14}\$[./A-Za-z0-9]{43}", hash_value):
            return ["Cisco-IOS $9$ (scrypt)", "9300"]

        # ── Databases ─────────────────────────────────────────────────────────────
        if re.fullmatch(r"0x0100[a-fA-F0-9]{88}", hash_value):
            return ["MSSQL (2000)", "131"]

        if re.fullmatch(r"0x0100[a-fA-F0-9]{40}", hash_value):
            return ["MSSQL (2005)", "132"]

        if re.fullmatch(r"0x0200[a-fA-F0-9]{136}", hash_value):
            return ["MSSQL (2012/2014)", "1731"]

        if re.fullmatch(r"\*[a-fA-F0-9]{40}", hash_value):
            return ["MySQL4.1 / MySQL5", "300"]

        # ── CMS / Web ─────────────────────────────────────────────────────────────
        if re.fullmatch(r"\$P\$[./A-Za-z0-9]{31}", hash_value):
            return ["phpass (WordPress / phpBB)", "400"]

        if re.fullmatch(r"\$H\$[./A-Za-z0-9]{31}", hash_value):
            return ["phpass (phpBB)", "400"]

        if re.fullmatch(r"[a-fA-F0-9]{32}:[a-zA-Z0-9]{2}", hash_value):
            return ["osCommerce / xt:Commerce", "21000"]

        # ── WPA ───────────────────────────────────────────────────────────────────
        if re.fullmatch(r"[a-fA-F0-9]{64}\*[^\*]+\*[^\*]+", hash_value):
            return ["WPA-PMKID-PBKDF2", "22000"]

        # ── Archives ─────────────────────────────────────────────────────────────
        if re.fullmatch(r"\$zip2\$\*.+", hash_value):
            return ["WinZip", "13600"]

        if re.fullmatch(r"\$RAR3\$\*.+", hash_value):
            return ["RAR3", "12500"]

        if re.fullmatch(r"\$rar5\$.+", hash_value):
            return ["RAR5", "13000"]

        # ── JWT ───────────────────────────────────────────────────────────────────
        if re.fullmatch(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", hash_value):
            return ["JWT (JSON Web Token)", "16500"]

        # ── Kerberos ──────────────────────────────────────────────────────────────
        if re.fullmatch(r"\$krb5asrep\$23\$.+", hash_value):
            return ["Kerberos 5 AS-REP etype 23", "18200"]

        if re.fullmatch(r"\$krb5tgs\$23\$.+", hash_value):
            return ["Kerberos 5 TGS-REP etype 23", "13100"]

        return ["Unknown"]
    
    def get_hashcat_type(self, hash:str):

        hash_type = self.detect_hash_type(hash)
        if len(hash_type) >= 2:
            print(f"[HashAnalyser][INFO] Hashtype : {hash_type[0]} -> Hashcat mode : {hash_type[1]}\n")
            return hash_type[1]

        hashcat_type_with_hashid = self.get_list_hashcat_type_with_hashid(hash=hash)
        if len(hashcat_type_with_hashid) >= 1:
            return hash_type[0]
        
        return ""