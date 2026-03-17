import os
from pathlib import Path

class Config:
    WARNING = '''
    Avertissement : Toutes les informations fournies dans cette publication le sont à des fins éducatives uniquement.
    Nous ne sommes en aucun cas responsable de toute utilisation abusive de ces informations.
    Vous êtes seul responsable de vos actes devant la loi.
    L’article 323-1 du code pénal sanctionne le piratage frauduleux
    d’au moins deux ans d’emprisonnement et de 60 000 euros d’amende.
    '''

    FOLDER_PATH = Path(os.getcwd())

    TOOLS_DIR = FOLDER_PATH / "tools"
    TOOLS_DIR.mkdir(exist_ok=True)

    # ===== HASHCAT =====
    HASHCAT_VERSION = "hashcat-7.1.2"
    URL_DOWNLOAD = f"https://hashcat.net/files/{HASHCAT_VERSION}.7z"
    FOLDER_HASHCAT_PATH = TOOLS_DIR / HASHCAT_VERSION
    HASHCAT_EXE_PATH = FOLDER_HASHCAT_PATH / "hashcat.exe"

    # ===== RULES =====
    FOLDER_RULES_PATH = TOOLS_DIR / "rules"
    FOLDER_RULES_PATH.mkdir(exist_ok=True)
    LIST_RULES = os.listdir(FOLDER_RULES_PATH)

    # ===== WORDLISTS =====
    FOLDER_WORDLIST = TOOLS_DIR / "wordlists"
    FOLDER_WORDLIST.mkdir(exist_ok=True)
    LIST_WORDLIST = ["rockyou.txt"]
    WORDLIST_PATH = FOLDER_WORDLIST

    # ===== PERSONALIZED ATTACK =====
    FOLDER_PERSONALIZED_ATTACK = FOLDER_PATH / "personalized_attack"
    FOLDER_PERSONALIZED_ATTACK.mkdir(exist_ok=True)