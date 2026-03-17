from tools.hash_decode import HashDecode
from tools.crack_file_of_password import CrackFileOfPassword
from tools.setup_hashcat import SetupHashcat
from tools.choice_of_rules import choice_of_rules
from config import Config

from pathlib import Path
import os

config = Config()
setup_hashcat = SetupHashcat()
hash_decode = HashDecode()
crack_file_of_password = CrackFileOfPassword()

###############################################
#______________CRACK_PASSWORD_________________#
###############################################

def personalized_attack(type_hash, hash, name):

    file_path = Path(os.path.join(config.FOLDER_PERSONALIZED_ATTACK, f"{name}.txt"))
    if not os.path.exists(file_path):
        try:
            fichier_name = open(file_path, "a")
            fichier_name.write(str(name))
            fichier_name.close()
        except FileNotFoundError:
            print(f"This file doesn't exist.")
            raise FileNotFoundError
    
    print(f"Please enter information of the victim in the document 'personalized_attack\\{name}.txt' : ")
    validation = str(input("Avez-vous fini de remplir les information (Y/N) : "))
    if validation == "Y" or validation == "y":
        result = hash_decode.rules_and_file_attack(str(type_hash),hash, file_path=file_path)
        return result
    

def crak_password(hash:str, mode, select_rules=False) -> str:

    result=""
    type_hash = hash_decode.hash_analyser.get_hashcat_type(hash=hash)

    start = hash_decode.give_time()

    match mode:
        case 0:
            if select_rules:
                rules = choice_of_rules()
                print(f"[RULES SELECTED] {rules}")
                path_rules = hash_decode.config.FOLDER_RULES_PATH / rules
                result = hash_decode.rules_attack(str(type_hash),hash, path_rules)
            else:
                result = hash_decode.rules_attack(str(type_hash),hash)
        case 3:
            result = hash_decode.brute_force_attack(str(type_hash),hash)
        case 9:
            name = str(input("Input the name of the victim : "))
            result = personalized_attack(type_hash, hash, name)
        case _:
            return

    end = hash_decode.give_time()
    elapsed = end - start
    print(f"\nExecution time : {elapsed:.2f}ms")

    hash_decode.print_result(result=result)

if __name__ == "__main__":
    while True:
        print(config.WARNING)
        avertissement = str(input("En répondant 'Y', J'ai lu et accepté l'avertissement ci-dessus (Y/N) :"))
        if not(avertissement == "Y" or avertissement == "y"):
            print("Vous ne pouvez utiliser ce programe")
            break

        setup_hashcat.setup_hashcat()

        #-------HASH-------------------------------------------------------------------------------#
        #hash=str(input("\nVeuillez-entrez le hash à cracker : "))
        hash = "3481f408ebcb62fe455fa5ed10a0b448"
        #------------------------------------------------------------------------------------------#
        attack_mode = '''
        [ Attack Modes ] -

        # | Mode
        ===+======
        0 | Straight
        1 | Combination             -> NOT IMPLEMENTED
        3 | Brute-force
        6 | Hybrid Wordlist + Mask  -> NOT IMPLEMENTED
        7 | Hybrid Mask + Wordlist  -> NOT IMPLEMENTED
        9 | Association
        '''
        print(attack_mode)

        mode = int(input("Please enter the desired attack type : "))
        crak_password(hash=hash, mode=mode, select_rules=True)

        #chemin = str(input("Veuillez entrez le chemin du fichier '.txt' contenant les hashs : "))
        #crack_file_of_password.crak_file_password_hash(chemin)