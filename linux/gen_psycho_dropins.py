import os
import subprocess
import json


def cmd(command):
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT).decode() # .split("\n")
        return output
    except subprocess.CalledProcessError as e:
        return ""

DROPINS_EXT = ".dropins"
DROPIN_SRCFILE_DELIM = " # src file: "

def generate_dropin_fromfile(filepath, dropin_dictionary=None, is_summary_file=False):
    if not dropin_dictionary:
        dropin_dict = {}
    else:
        dropin_dict = dropin_dictionary 
    
    with open(filepath, 'r') as file:
        dropin_confs = [line.strip() for line in file.read().splitlines() if line.strip() and not line.startswith("#")]

        curr_section = None
        for line in dropin_confs:
            if line.startswith("["):
                assert line.endswith("]"), "Error! Some weird configuration. this code doesn't handle yet...blame Ben :)"
                section = line[1:-1]
                if section not in dropin_dict:
                    dropin_dict[section] = []
                curr_section = section
            else:
                assert curr_section, "Error! Weird configuration, not listed under a [] section header!"
                if is_summary_file:
                    assert DROPIN_SRCFILE_DELIM in line
                    delim_idx = line.index(DROPIN_SRCFILE_DELIM)
                    dropin_dict[section].append([line[:delim_idx], line[delim_idx+len(DROPIN_SRCFILE_DELIM):]])    
                else:
                    dropin_dict[section].append([line, filepath])
    return dropin_dict

# Generates a summary configuration file of all dropin configurations
def generate_dropin_fromservice(service):
    dropin_files = cmd(f"systemctl show -P DropInPaths {service}").strip()

    if not dropin_files:
        return {}

    dropin_dict = {}
    
    # Compile dropin configurations
    for dropin_file in dropin_files.split(" "):
        dropin_dict = generate_dropin_fromfile(dropin_file, dropin_dict)
    return dropin_dict

def main():
    # Read device JSON file
    with open('device.json', 'r') as file:
        device = json.load(file)

    assert "arch" in device and (device['arch'] == "deb" or device['arch'] == 'rhel'), "device.json file doesn't have the arch attribute specified, or it has an improper value (not deb or rhel)!"

    # Get base truth service folder
    BASEFOLDER = f"psychocity-{device['arch']}"

    base_services = []
    with os.scandir(BASEFOLDER) as files:
        for file in files:
            if file.is_file() and not file.name.endswith(DROPINS_EXT):
                base_services.append(file.name)
    
    for service in base_services:
        dropin_dict = generate_dropin_fromservice(service)
        summ = []
        if dropin_dict:
            for section in dropin_dict:
                summ.append(f"[{section}]")
                conf_strs = [f"{conflst[0]}{DROPIN_SRCFILE_DELIM}{conflst[1]}" for conflst in dropin_dict[section]]
                summ.extend(conf_strs)
            with open(f'{BASEFOLDER}/{service}{DROPINS_EXT}', 'w') as file:
                file.write("\n".join(summ))
    

if __name__ == "__main__":
    main()