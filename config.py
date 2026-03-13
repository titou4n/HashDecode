import os
from pathlib import Path
from dotenv import load_dotenv
from pathlib import Path
import subprocess
import sys
import requests

try:
    import py7zr
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "py7zr"])
    import py7zr

def extract_and_delete_7z(archive_path: str, extract_to: str = None) -> None:
    """
    Extrait un fichier .7z puis le supprime après extraction.

    :param archive_path: Chemin vers le fichier .7z
    :param extract_to: Dossier de destination (optionnel)
    """

    archive_path = Path(archive_path)

    if not archive_path.exists():
        raise FileNotFoundError(f"Archive introuvable : {archive_path}")

    if archive_path.suffix != ".7z":
        raise ValueError("Le fichier fourni n'est pas un .7z")

    # Dossier d'extraction par défaut = même dossier
    if extract_to is None:
        extract_to = archive_path.parent
    else:
        extract_to = Path(extract_to)

    extract_to.mkdir(parents=True, exist_ok=True)

    try:
        print(f"[INFO] Extraction de {archive_path}...")
        with py7zr.SevenZipFile(archive_path, mode='r') as archive:
            archive.extractall(path=extract_to)

        print("[OK] Extraction terminée.")

        # Suppression du fichier 7z
        archive_path.unlink()

        print(f"[DELETE] Archive supprimée : {archive_path}")

    except Exception as e:
        print(f"[ERREUR] Problème lors de l'extraction : {e}")

class Config:

    WARNING = '''
    Avertissement : Toutes les informations fournies dans cette publication le sont à des fins éducatives uniquement.
    Nous ne sommes en aucun cas responsable de toute utilisation abusive de ces informations.
    Vous êtes seul responsable de vos actes devant la loi.
    L’article 323-1 du code pénal sanctionne le piratage frauduleux
    d’au moins deux ans d’emprisonnement et de 60 000 euros d’amende.
    '''

    FOLDER_PATH = Path(os.getcwd())

    # ===== HASHCAT =====
    HASHCAT_VERSION = "hashcat-7.1.2"
    URL_DOWNLOAD = f"https://hashcat.net/files/{HASHCAT_VERSION}.7z"

    TOOLS_DIR = FOLDER_PATH / "tools"
    TOOLS_DIR.mkdir(exist_ok=True)

    FOLDER_HASHCAT_PATH = TOOLS_DIR / HASHCAT_VERSION
    HASHCAT_EXE_PATH = FOLDER_HASHCAT_PATH / "hashcat.exe"

    @classmethod
    def setup_hashcat(cls):
        """
        Vérifie si hashcat est installé.
        Sinon → télécharge + extrait + supprime archive.
        """

        if cls.FOLDER_HASHCAT_PATH.exists():
            print("[OK] Hashcat déjà installé.")
            return

        archive_name = f"{cls.HASHCAT_VERSION}.7z"
        archive_path = cls.FOLDER_PATH / archive_name

        print("[INFO] Hashcat non trouvé. Installation en cours...")

        # Télécharger le fichier

        response = requests.get(cls.URL_DOWNLOAD, stream=True)
        with open(archive_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        print("[OK] Téléchargement terminé.")

        # Extraction + suppression
        extract_and_delete_7z(archive_path, cls.TOOLS_DIR)
        print("[SUCCESS] Hashcat installé.")

    # ===== RULES =====
    FOLDER_RULES_PATH = FOLDER_PATH / "rules"
    FOLDER_RULES_PATH.mkdir(exist_ok=True)

    LIST_RULES = os.listdir(FOLDER_RULES_PATH)

    # ===== WORDLISTS =====
    FOLDER_WORDLIST = FOLDER_PATH / "wordlists"
    FOLDER_WORDLIST.mkdir(exist_ok=True)

    LIST_WORDLIST = ["rockyou.txt"]

    WORDLIST_PATH = FOLDER_WORDLIST