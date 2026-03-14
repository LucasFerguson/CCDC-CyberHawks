import os
import subprocess
from difflib import unified_diff
import json
from gen_psycho_dropins import generate_dropin_fromfile, generate_dropin_fromservice, get_file_configurations, DROPIN_SRCFILE_DELIM, DROPINS_EXT


def cmd(command):
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT).decode() # .split("\n")
        return output
    except subprocess.CalledProcessError as e:
        return ""

# Read device JSON file
with open('device.json', 'r') as file:
    device = json.load(file)

assert "arch" in device and (device['arch'] == "deb" or device['arch'] == 'rhel'), "device.json file doesn't have the arch attribute specified, or it has an improper value (not deb or rhel)!"

# Get base truth service folder
BASEFOLDER = f"psychocity-{device['arch']}"

# Check for presence of services from base folder
base_services = []
dropin_files = {}
with os.scandir(BASEFOLDER) as files:
    for file in files:
        if file.is_file():
            if file.name.endswith(DROPINS_EXT):
                dropin_files[file.name[:-1*len(DROPINS_EXT)]] = file.name
            else:
                base_services.append(file.name)


print("Diffing...")
diffs_found = False

# Get present service confs and compare
for service in base_services:
    confpath = cmd(f"systemctl show -P FragmentPath {service}").strip()
    if confpath: # service is present
        # Compare core configurations
        base_path = BASEFOLDER + "/" + service
        basecontent = get_file_configurations(base_path)
        realcontent = get_file_configurations(confpath)

        if basecontent != realcontent: # service files not the same!
            print(f"\nSystem's service {service} configuration file is different than the one stored!")
            # print("\n".join(list(unified_diff(basecontent, realcontent, fromfile=base_path, tofile=confpath))))
            print("\n".join(unified_diff(basecontent, realcontent, fromfile=base_path, tofile=confpath, n=0)))
            diffs_found = True
        
        # Compare dropins (extension configurations) if present

        
        dropin_real = generate_dropin_fromservice(service) # Get current service dropins

        if service in dropin_files: # Get stored service dropins
            dropin_summfile = dropin_files[service]
            # dropin_dict_base = generate_dropin_fromfile(f"{BASEFOLDER}/{dropin_summfile}", is_summary_file=True)
            # dropin_dict_real = generate_dropin_fromservice(service)
            dropin_base = generate_dropin_fromfile(f"{BASEFOLDER}/{dropin_summfile}", is_summary_file=True)
        else:
            dropin_base = []
        
        dropin_base_confs = [conf[0] for conf in dropin_base]
        dropin_real_confs = [conf[0] for conf in dropin_real]

        dropin_base_uniq = [f"{dropin_base[i][0]}{DROPIN_SRCFILE_DELIM}{dropin_base[i][1]}" for i in range(len(dropin_base)) if dropin_base_confs[i] not in dropin_real_confs]
        dropin_real_uniq = [f"{dropin_real[i][0]}{DROPIN_SRCFILE_DELIM}{dropin_real[i][1]}" for i in range(len(dropin_real)) if dropin_real_confs[i] not in dropin_base_confs]

        if dropin_base_uniq or dropin_real_uniq:
            diffs_found = True
            print(f"Service '{service}' extension differences:")
            print("\n".join(unified_diff(dropin_base_uniq, dropin_real_uniq, fromfile=f"Stored service {service} dropins/extensions", tofile=f"Real service {service} dropins/extensions", n=0)))

        #     base_section_uniq = [section for section in dropin_dict_base if section not in dropin_dict_real]
        #     real_section_uniq = [section for section in dropin_dict_real if section not in dropin_dict_base]
        #     shared_sections = [section for section in dropin_dict_base if section not in base_section_uniq] # get sections shared by both real and base

        #     if base_section_uniq:
        #         diffs_found = True
        #         print(f"Entire drop-in sections {base_section_uniq} in the stored {dropin_summfile} file that aren't present in service {service} running on this system!")
        #         print("Configurations:")
        #         for section in base_section_uniq:
        #             print(f"--- [{section}]")
        #             conf_strs = [f"--- {conflst[0]}{DROPIN_SRCFILE_DELIM}{conflst[1]}" for conflst in dropin_dict_base[section]]
        #             print("\n".join(conf_strs))
        #     if real_section_uniq:
        #         diffs_found = True
        #         print(f"Entire drop-in sections {real_section_uniq} in service {service} running on this system that aren't present in the stored {dropin_summfile} file!")
        #         print("Configurations:")
        #         for section in real_section_uniq:
        #             print(f"+++ [{section}]")
        #             conf_strs = [f"+++ {conflst[0]}{DROPIN_SRCFILE_DELIM}{conflst[1]}" for conflst in dropin_dict_real[section]]
        #             print("\n".join(conf_strs))
        #     if shared_sections:
        #         for section in shared_sections:
        #             base_conflst = dropin_dict_base[section]
        #             real_conflst = dropin_dict_real[section]
        #             base_confs = [lst[0] for lst in base_conflst]
        #             real_confs = [lst[0] for lst in real_conflst]

        #             base_uniq = [lst for lst in base_conflst if lst[0] not in real_confs]
        #             real_uniq = [lst for lst in real_conflst if lst[0] not in base_confs]

        #             if base_uniq or real_uniq:
        #                 diffs_found = True
        #                 print(f"Service {service} differs!! (+++ are confs present on this system, --- are confs stored in ground truth files)")
        #                 base_strs = [f"--- {conflst[0]}{DROPIN_SRCFILE_DELIM}{conflst[1]}" for conflst in base_uniq]
        #                 real_strs = [f"+++ {conflst[0]}{DROPIN_SRCFILE_DELIM}{conflst[1]}" for conflst in real_uniq]
                        
        #                 print("\n".join([f"[{section}]"] + base_strs + real_strs))
        # elif (dropin_dict:=generate_dropin_fromservice(service)): # no dropins present in basefolder but they are present on the system!
        #     diffs_found = True
        #     print(f"Service {service} dropins present on system but not present in grouth truth files!!")
        #     summ = []
        #     for section in dropin_dict:
        #         summ.append(f"+++ [{section}]")
        #         conf_strs = [f"+++ {conflst[0]}{DROPIN_SRCFILE_DELIM}{conflst[1]}" for conflst in dropin_dict[section]]
        #         summ.extend(conf_strs)
        #     print("\n".join(summ))
            

if not diffs_found:
    print("No service configuration diffs found!")

print("\nChecking for default systemd configuration settings (/etc/systemd/system.conf)...")
SYSTEMD_DEFAULT_PATH = "/etc/systemd/system.conf"
if os.path.exists(SYSTEMD_DEFAULT_PATH):
    confs = get_file_configurations(SYSTEMD_DEFAULT_PATH, keep_sections=False)
    if confs:
        print("There are default configurations set! This isn't standard, maybe check these out:")
        print("\n".join(confs))
    else:
        print("No default systemd configurations. Good!")
else:
    print("No default systemd configurations. Good!")