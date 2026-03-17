import os
import subprocess
import sys
import importlib
import time
from config import Config
from tools.hash_analyser import HashAnalyser
from pathlib import Path

class HashDecode():
    def __init__(self):
        self.config = Config()
        self.hash_analyser = HashAnalyser()

        # ===== Hashcat =====
        self.folder_path = Path(os.getcwd())
        self.hashcat_path = self.config.FOLDER_HASHCAT_PATH
        self.hashcat_exe_path = Path(os.path.join(self.hashcat_path, "hashcat.exe"))

        # ===== Rules =====
        self.rule_path = self.config.FOLDER_RULES_PATH
        self.default_rule_path = Path(os.path.join(self.config.FOLDER_RULES_PATH, self.config.LIST_RULES[0]))

        # ===== Wordlist =====
        self.wordlist_path = Path(os.path.join(self.config.WORDLIST_PATH, self.config.LIST_WORDLIST[0]))
        
        # ===== Other parameter =====
        self.default_runtime = 60

        # === Check and install modules ===
        self.check_and_install_modules()
        self.check_required_files()

    def check_and_install_modules(self):
        """
        Vérifie si les modules sont installés.
        Les installe ou les met à jour si nécessaire.
        """

        required_modules = [
            "requests",
            "tqdm",
        ]

        for module in required_modules:
            try:
                importlib.import_module(module)
                print(f"[OK] Module '{module}' déjà installé.")
            except ImportError:
                print(f"[INSTALL] Installation du module '{module}'...")
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install", "--upgrade", module]
                )
                print(f"[DONE] Module '{module}' installé/mis à jour.")

    def check_required_files(self):
        """
        Vérifie que hashcat, rule et wordlist existent.
        """

        print(f"[INFO] Hashcat PATH : {self.hashcat_path}")
        if not os.path.isdir(self.hashcat_path):
            print(f"[ERREUR] Dossier hashcat introuvable : {self.hashcat_path}")
        else:
            print("[OK] Hashcat détecté.")

        if not os.path.isdir(self.rule_path):
            print(f"[ERREUR] Dossier rule introuvable : {self.rule_path}")
        else:
            print("[OK] Rule détectée.")

        if not os.path.isfile(self.wordlist_path):
            print(f"[ERREUR] Wordlist introuvable : {self.wordlist_path}")
        else:
            print("[OK] Wordlist détectée.")

    ###############################################
    #__________________TOOLS______________________#
    ###############################################

    def give_time(self):
        return time.time()
    
    def print_result(self, result:str) -> None:
        if result is None:
            return
        
        l = len(result)
        char = '='
        n = int(l/2)
        print(f"\n{char*n} Result {char*n}")
        print(f"==> {result}")
        print(f"{char*n}========{char*n}")

    ###############################################
    #_______________HASH_DECODE___________________#
    ###############################################

    def clean_result(self, result_of_command:str, hash:str) -> str:
        len_hash= int(len(hash))+1
        return result_of_command[len_hash:][:-1]

    def execute_command(self, command: list, hash: str) -> str:
        try:
            command_str = [str(c) for c in command]
            print(f"[COMMAND EXECUTES] {' '.join(command_str)}")
            subprocess.run(command_str, cwd=self.hashcat_path, check=True)
            
            command_show = command_str + ["--show"]
            print(f"[COMMAND EXECUTES] {' '.join(command_show)}")
            result = subprocess.run(
                command_show,
                cwd=self.hashcat_path,
                capture_output=True,
                text=True,
                check=True
            )
            
            if result.returncode != 0:
                raise HashDecodeError(result.stderr)
            
            return self.clean_result(result.stdout, hash)
        
        except subprocess.CalledProcessError as e:
            if e.returncode == 1:
                print(f"[-] Uncracked hash : {hash}")
            else:
                print(f"[-] hashcat errror (code {e.returncode}) : {e}")
            return None

        except FileNotFoundError:
            print(f"[-] hashcat.exe not found : {self.hashcat_exe_path}")
            return None

        except Exception as e:
            print(f"[-] Error : {e}")
            return None

    def get_command(self,
                      hash:str,
                      hash_type:str,
                      attack_mode:str,
                      rules: str | None = None,
                      runtime:int | None = None,
                      other_argument:list | None = None,
                      other_file:list | None = None
                      ) -> list:
        
        command = [
            self.hashcat_exe_path,
            "-m", hash_type,
            "-a", attack_mode,
            "-O"]

        if rules is not None:
            command.extend(["-r", rules, "--loopback"])

        if runtime is not None:
            command.append(f"--runtime={runtime}")

        if other_argument is not None:
            command.extend(other_argument)

        command.extend([hash])
    
        if other_file is not None:
            command.extend(other_file)
        else:
            command.extend([self.wordlist_path])

        return command

    def brute_force_attack(self, hash_type:str, hash:str) -> str:
        """
        Performs a brute-force attack on a given hash using a mask attack (attack mode 3).
        Tries all possible character combinations up to 11 characters using full charset (?a).

        Args:
            hash_type (str | int): The hashcat hash type identifier (e.g., '0' for MD5, '1000' for NTLM).
            hash (str): The target hash string to crack.

        Returns:
            str | None: The cracked plaintext password if successful, None otherwise.

        Raises:
            subprocess.CalledProcessError: If hashcat exits with an unexpected error code.
            FileNotFoundError: If the hashcat executable cannot be found.
        """
        assert isinstance(hash, str) and hash.strip(), \
            "hash must be a non-empty string."
        assert isinstance(hash_type, (str, int)), \
            "hash_type must be a string or integer."
    
        assert type(hash)==str, ("Le hash doit etre en string")
        assert type(hash_type)==str or type(hash_type)==int, ("Le hash doit etre en string")

        command = self.get_command(hash=hash,
                         hash_type=hash_type,
                         attack_mode="3",
                         )

        command.extend(["--loopback", "?a?a?a?a?a?a?a?a?a?a?a", "--increment"])
        return self.execute_command(command=command, hash=hash)

    def rules_attack(self, hash_type: str, hash: str, rules: str | None = None) -> str:
        """
        Performs a dictionary attack on a given hash using a wordlist and optional rules.

        Args:
            hash_type (str): The hashcat hash type identifier (e.g., '0' for MD5, '1000' for NTLM).
            hash (str): The target hash string to crack.
            rules (str | None): Path to a hashcat rule file. If None, no rules are applied.

        Returns:
            str | None: The cracked plaintext password if successful, None otherwise.
        """

        assert isinstance(hash, str) and hash.strip(), \
            "hash must be a non-empty string."
        assert isinstance(hash_type, (str, int)), \
            "hash_type must be a string or integer."
    
        command = self.get_command(hash=hash,
                        hash_type=hash_type,
                        attack_mode="0",
                        rules=rules)

        return self.execute_command(command=command, hash=hash)

    def rules_and_file_attack(self, hash_type:str, hash:str, file_path:Path, rules: str | None = None) -> str:
        assert isinstance(hash, str) and hash.strip(), \
            "hash must be a non-empty string."
        assert isinstance(hash_type, (str, int)), \
            "hash_type must be a string or integer."
        assert isinstance(file_path, Path), \
            "file_path must be a path <class Path>"

        command = self.get_command(hash=hash,
                        hash_type=hash_type,
                        attack_mode="9",
                        rules=rules,
                        other_file=[file_path])

        return self.execute_command(command=command, hash=hash)


class HashDecodeError(Exception):
    pass

class HashDecodeOtherError(HashDecodeError):
    pass