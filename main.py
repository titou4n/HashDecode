from hash_decode import HashDecode
from crack_file_of_password import CrackFileOfPassword
from config import Config

config = Config()
hash_decode = HashDecode()
crack_file_of_password = CrackFileOfPassword()

if __name__ == "__main__":
    while True:

        print(config.WARNING)
        avertissement = str(input("En répondant 'Y', J'ai lu et accepté l'avertissement ci-dessus (Y/N) :"))
        if not(avertissement == "Y" or avertissement == "y"):
            print("Vous ne pouvez utiliser ce programe")
            break

        config.setup_hashcat()

        #-------HASH-------------------------------------------------------------------------------#
        #hash=str(input("\nVeuillez-entrez le hash à cracker : "))
        hash = "adf2e981f833c1b58b947d1670878020"
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
        hash_decode.crak_password(hash=hash, mode=mode, select_rules=True)

        #chemin = str(input("Veuillez entrez le chemin du fichier '.txt' contenant les hashs : "))
        #crack_file_of_password.crak_file_password_hash(chemin)