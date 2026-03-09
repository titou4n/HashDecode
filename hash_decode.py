import os
import subprocess
import sys
import importlib
from config import Config
from hash_analyser import HashAnalyser
from choice_of_rules import choice_of_rules
import time
from pathlib import Path

class HashDecode():
    def __init__(self):
        self.config = Config()
        self.hash_analyser = HashAnalyser()
        self.folder_path = os.getcwd()
        self.hashcat_path = self.config.FOLDER_HASHCAT_PATH
        self.hashcat_exe_path = os.path.join(self.hashcat_path, "hashcat.exe")
        self.rule_path = self.config.RULES_PATH
        self.default_rule_path = f"{self.folder_path}\\rules_hash\\pantagrule-master\\rules\\hashesorg.v6\\pantagrule.hashorg.v6.raw1m.rule"
        self.wordlist_path = f"{self.config.WORDLIST_PATH}\\rockyou.txt"

        self.default_runtime = 60

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
    
    def print_result(self, result:str):
        l = len(result)
        char = '='
        n = int(l/2)
        print(f"\n{char*n} Result {char*n}")
        print(f"==> {result}")
        print(f"{char*n}========{char*n}")

    ###############################################
    #_______________HASH_DECODE___________________#
    ###############################################

    def clean_result(self, result_of_command, hash) -> str:
        len_hash= int(len(hash))+1
        return result_of_command[len_hash:][:-1]

    def execute_command(self, command: list, hash: str) -> str:
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

        print(result.stdout)
        print(result.stderr)

        if result.returncode != 0:
            raise HashDecodeError(result.stderr)
        
        return self.clean_result(result.stdout, hash)

    def get_command(self,
                      hash:str,
                      hash_type:str,
                      attack_mode:str,
                      rules: str | None = None,
                      runtime:int | None = None
                      ) -> list:
        
        command = [
            self.hashcat_exe_path,
            hash,
            self.wordlist_path,
            "-O",
            "-m", hash_type,
            "-a", attack_mode
        ]

        #if rules is None:
        #    rules = self.default_rule_path

        if rules is not None:
            command.extend(["-r", rules, "--loopback"])

        if runtime is not None:
            command.append(f"--runtime={runtime}")
        
        return command

    def hash_brute_force_wordlist_rules(self, hash_type: str, hash: str, rules: str | None = None) -> str:
        """
        hash_brute_force_wordlist_rules(hash_type: str or int, hash: str)
        return result: str
        """
        assert type(hash)==str, ("Le hash doit etre en string")
        assert type(hash_type)==str or type(hash_type)==int , ("Le hash doit etre en string")

        command = self.get_command(hash=hash,
                         hash_type=hash_type,
                         attack_mode=0,
                         rules=rules)

        return self.execute_command(command=command, hash=hash)
    
    def hash_brute_force(self, hash_type:str, hash:str) -> str:
        assert type(hash)==str, ("Le hash doit etre en string")
        assert type(hash_type)==str or type(hash_type)==int , ("Le hash doit etre en string")

        command = [
            self.hashcat_exe_path,
            "--loopback",
            "-m", str(hash_type),
            "-a", "3",
            hash,
            "?a?a?a?a?a?a?a?a?a?a?a",
            "--increment"
        ]
        return self.execute_command(command=command, hash=hash)

    def hash_brute_force_list_with_name_rules(self, hash_type:str, hash:str, name:str, rules: str | None = None) -> str:
        assert type(hash)==str, ("Le hash doit etre en string")
        assert type(hash_type)==str or type(hash_type)==int , ("Le hash doit etre en string")
        assert type(name)==str, ("Le name doit etre en string")

        command = [
            self.hashcat_exe_path,
            "--loopback",
            "-O",
            "-m", hash_type,
            "-a", "0",
            "-r", rules,
            f"C:\hash_decode\personalized_attack\\{str(name)}.txt",
            hash,
            self.wordlist_path,
        ]

        return self.execute_command(command=command, hash=hash)
    
    ###############################################
    #______________CRACK_PASSWORD_________________#
    ###############################################

    def personalized_attack(self, type_hash, hash, name):
        os.makedirs("personalized_attack", exist_ok=True)
        fichier_name = open("personalized_attack\\"+name+".txt", "a")
        fichier_name.write(str(name))
        fichier_name.close()
        print("Please enter information of the victim in the document 'personalized_attack\\"+name+".txt' : ")
        validation = str(input("Avez-vous fini de remplir les information (Y/N) : "))
        if validation == "Y" or validation == "y":
            #result = self.hash_decode.hash_brute_force_list_with_name_rules(str(type_hash),hash, name)
            result = self.hash_decode.hash_brute_force_wordlist_rules(str(type_hash),hash)
            return result

    def crak_password(self, hash:str, mode, select_rules=False) -> str:

        result=""
        type_hash = self.hash_analyser.detect_hash_type(hash)[1]

        start = self.give_time()

        match mode:
            case 0:
                if select_rules:
                    rules = choice_of_rules()
                    print(f"[RULES SELECTED] {rules}")
                    path_rules = self.config.RULES_PATH / rules
                    result = self.hash_brute_force_wordlist_rules(str(type_hash),hash, path_rules)
                else:
                    result = self.hash_brute_force_wordlist_rules(str(type_hash),hash)
            case 3:
                result = self.hash_brute_force_wordlist_rules(str(type_hash),hash)
            case 9:
                name = str(input("Input the name of the victim : "))
                result = self.personalized_attack(type_hash, hash, name)
            case _:
                raise HashDecodeModeError(f"Mode {mode} not implemented")

        end = self.give_time()
        elapsed = end - start
        print(f"\nExecution time : {elapsed:.2f}ms")

        self.print_result(result=result)

class HashDecodeError(Exception):
    pass

class HashDecodeModeError(HashDecodeError):
    pass