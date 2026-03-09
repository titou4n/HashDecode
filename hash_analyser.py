import subprocess
import os
import re

class HashAnalyser():
    def __init__(self):
        pass

    def detect_hash_type(self, hash_value):
        if re.fullmatch(r"[a-fA-F0-9]{32}", hash_value):
            return ["MD5", "0"]

        elif re.fullmatch(r"[a-fA-F0-9]{40}", hash_value):
            return ["SHA1", "100"]

        elif re.fullmatch(r"[a-fA-F0-9]{64}", hash_value):
            return ["SHA256", "1400"]

        else:
            return ["Unknown"]

    def detect_hash_type_with_hashid(self, hash:str):
        '''
        detect_hash_type_with_hashid(hash) -> renvoit le résultat de la commande "hashid -m"
        utilise "hashid -m" -> reperer les types de hash possibles
        '''
        assert type(hash) == str, "Le hash doit être un string"
        command = ["hashid", "-m", hash]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout

        except subprocess.CalledProcessError as e:
            print("Erreur lors de l'exécution de hashid :")
            print(e.stdout)
            print(e.stderr)
            return None
    
    def list_hash_possible_hashcat(self, hash:str):
        '''
        list_hash_possible_hashcat(hash:str) renvoie la liste des type de hashs posibles
        Mode de la fonction open()
        "r" - Read - Default value. Opens a file for reading, error if the file does not exist
        "a" - Append - Opens a file for appending, creates the file if it does not exist
        "w" - Write - Opens a file for writing, creates the file if it does not exist
        "x" - Create - Creates the specified file, returns an error if the file exist
        '''
        assert type(hash) == str, "Le hash doit être un string"
        os.makedirs("type_of_hash", exist_ok=True)
        fichier_name = open("type_of_hash\\type_of_hash.txt", "w")
        fichier_name.write(str(self.type_hash_analyser(hash)))
        fichier_name.close()
        list_type_of_hash = []
        with open("type_of_hash\\type_of_hash.txt",'r') as file:
            lines = file.readlines()
            for line in lines:
                if "[Hashcat Mode:" in line:
                    occurence = int(line.find(":"))+1
                    type_of_hash = line[occurence:-2]
                    list_type_of_hash.append(int(type_of_hash))
        os.remove("type_of_hash\\type_of_hash.txt")
        os.rmdir("type_of_hash")
        return list_type_of_hash