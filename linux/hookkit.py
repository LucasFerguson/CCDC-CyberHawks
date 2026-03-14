import subprocess

def cmd(command):
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT).decode() # .split("\n")
        return output
    except subprocess.CalledProcessError as e:
        return ""

# Brute force PIDs
print("Search for hidden pids:")
proc_files = cmd("sudo ls /proc").splitlines()
pids = []
for file in proc_files:
    try:
        pids.append(int(file))
    except:
        pass

pids.sort()

for brutepid in range(pids[0],pids[-1]):
    if brutepid not in pids:
        tryout = cmd(f"sudo file /proc/{brutepid}/stat")
        if "No such file or directory" not in tryout:
            print("FOUND HIDDEN PID:", brutepid, cmd(f"sudo ls -l /proc/{brutepid}/exe"))
            # print(cmd(f"sudo ls /proc/{brutepid}"))