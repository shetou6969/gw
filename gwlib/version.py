from pathlib import Path
API_VERSION=1

def current():
    return (Path(__file__).resolve().parents[1]/'VERSION').read_text().strip()
