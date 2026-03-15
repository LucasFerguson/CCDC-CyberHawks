import json
import os
import tarfile

def preserve_assets(json_file):
    # 1. Load the JSON data
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Error: {json_file} not found.")
        return

    # 2. Setup the destination directory
    target_dir = ".kitten"
    if not os.path.exists(target_dir):
        os.makedirs(target_dir)
        print(f"Created directory: {target_dir}")

    preserve_list = data.get("preserve_files", [])

    # 3. Process each file/folder
    for path in preserve_list:
        if os.path.exists(path):
            # Create a safe filename (e.g., /etc -> etc.tar.gz)
            clean_name = path.strip("/").replace("/", "_") or "root_dir"
            archive_name = os.path.join(target_dir, f"{clean_name}.tar.gz")

            print(f"Archiving {path} to {archive_name}...")
            
            try:
                with tarfile.open(archive_name, "w:gz") as tar:
                    # arcname prevents the full absolute path from being 
                    # stored inside the tar, making extraction easier later.
                    tar.add(path, arcname=os.path.basename(path))
            except PermissionError:
                print(f"Permission denied: Could not read {path}. Try running with sudo.")
            except Exception as e:
                print(f"Failed to archive {path}: {e}")
        else:
            print(f"Skipping: {path} (Path does not exist)")

if __name__ == "__main__":
    preserve_assets("device.json")
