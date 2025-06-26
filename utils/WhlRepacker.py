import zipfile
import os
import shutil
from pathlib import Path

def repack_single_wheel(wheel_path: Path, output_dir: Path):
    """Repack a single wheel to use Metadata-Version: 2.3"""
    temp_dir = output_dir / (wheel_path.stem + '_unpacked')

    # Unpack the wheel
    with zipfile.ZipFile(wheel_path, 'r') as zip_ref:
        zip_ref.extractall(temp_dir)

    # Locate the METADATA file
    metadata_file = None
    for root, _, files in os.walk(temp_dir):
        for file in files:
            if file == 'METADATA':
                metadata_file = Path(root) / file
                break
        if metadata_file:
            break

    if not metadata_file or not metadata_file.exists():
        print(f"[ERROR] METADATA not found in: {wheel_path.name}")
        shutil.rmtree(temp_dir)
        return

    # Modify Metadata-Version
    with open(metadata_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    with open(metadata_file, 'w', encoding='utf-8') as f:
        for line in lines:
            if line.startswith("Metadata-Version:"):
                f.write("Metadata-Version: 2.3\n")
            else:
                f.write(line)

    # Repack the wheel
    new_wheel_name = wheel_path.stem + '.whl'
    new_wheel_path = output_dir / new_wheel_name

    with zipfile.ZipFile(new_wheel_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(temp_dir):
            for file in files:
                file_path = Path(root) / file
                arcname = file_path.relative_to(temp_dir)
                zipf.write(file_path, arcname)

    shutil.rmtree(temp_dir)
    print(f"[DONE] Repacked: {new_wheel_path.name}")

def process_all_wheels(input_dir: str, output_dir: str = None):
    """Scan folder and process all .whl files"""
    input_dir = Path(input_dir)
    output_dir = Path(output_dir) if output_dir else input_dir

    if not input_dir.is_dir():
        raise ValueError("Input path must be a directory.")

    whl_files = list(input_dir.glob("*.whl"))
    if not whl_files:
        print("No .whl files found.")
        return

    print(f"Found {len(whl_files)} .whl file(s). Starting conversion...")

    for whl_file in whl_files:
        repack_single_wheel(whl_file, output_dir)

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python repack_wheels_batch.py <input_dir> [<output_dir>]")
    else:
        input_dir = sys.argv[1]
        output_dir = sys.argv[2] if len(sys.argv) > 2 else None
        process_all_wheels(input_dir, output_dir)
