import subprocess
import sys
from pathlib import Path
from config import Config
import requests
import os

try:
    import py7zr

except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "py7zr"])
    import py7zr

class SetupHashcat():
    def __init__(self):
        self.config = Config()

    def extract_7z(self, archive_path: str, extract_to: str = None) -> None:
        """
        Extrait un fichier .7z.

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

        except Exception as e:
            print(f"[ERREUR] Problème lors de l'extraction : {e}")

    def setup_hashcat(self):
        """
        Vérifie si hashcat est installé.
        Sinon → télécharge + extrait + supprime archive.
        """

        if self.config.FOLDER_HASHCAT_PATH.exists():
            print("[OK] Hashcat déjà installé.")
            return

        archive_name = f"{self.config.HASHCAT_VERSION}.7z"
        archive_path = self.config.FOLDER_PATH / archive_name

        print("[INFO] Hashcat non trouvé. Installation en cours...")

        # Télécharger le fichier

        response = requests.get(self.config.URL_DOWNLOAD, stream=True)
        with open(archive_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        print("[OK] Téléchargement terminé.")

        # Extraction + suppression
        self.extract_7z(archive_path, self.config.TOOLS_DIR)
        print("[SUCCESS] Hashcat installé.")

        try:
            os.remove(archive_name)
            print(f"[DELETE] Archive supprimée : {archive_name}")

        except Exception as e:
            print(f"[ERREUR] Problème lors de la suppression : {e}")