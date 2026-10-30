"""Write a new diagnostic file without clobbering existing inputs or reports."""
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
def write_new(path,text,install=None):
    dest=Path(path).resolve()
    if not dest.is_relative_to((ROOT/'work').resolve()): raise ValueError('Output must be inside ignored project work/')
    if install is not None and dest.is_relative_to(Path(install).resolve()):
        raise ValueError('Output cannot be inside the original installation')
    # O_EXCL also rejects existing symlinks and hardlinks, including input aliases.
    if dest.exists():raise ValueError('Output exists; choose a new report path')
    dest.parent.mkdir(parents=True,exist_ok=True)
    with dest.open('x') as stream:stream.write(text+'\n')
