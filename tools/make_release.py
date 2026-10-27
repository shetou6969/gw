#!/usr/bin/env python3
"""Build the release asset expected by bootstrap.sh and the updater."""
import hashlib
from pathlib import Path
import tarfile

root=Path(__file__).resolve().parents[1]
version=(root/'VERSION').read_text().strip()
destination=root/'dist'/('v'+version)
destination.mkdir(parents=True,exist_ok=True)
archive=destination/'gw-panel.tar.gz'
with tarfile.open(archive,'w:gz') as output:
    for path in sorted(root.rglob('*')):
        if any(part in ('.git','__pycache__','dist','.pytest_cache') for part in path.relative_to(root).parts):continue
        if not path.is_file():continue
        output.add(path,arcname=str(Path('gw-panel')/path.relative_to(root)))
digest=hashlib.sha256(archive.read_bytes()).hexdigest()
(destination/'SHA256SUMS').write_text(f'{digest}  gw-panel.tar.gz\n')
print(destination)
