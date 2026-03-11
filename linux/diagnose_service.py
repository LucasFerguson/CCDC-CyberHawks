import subprocess
import hashlib
import json

# Read device JSON file
with open('device.json', 'r') as file:
    device = json.load(file)

assert "ipv4_addresses" in device and "services" in device and "ports" in device and "hashfile" in device, "device.json doesn't have the required attributes!"

IPV4_ADDRESSES = device['ipv4_addresses']
SERVICES = device['services']
PORTS = device['ports']
HASHFILE = device['hashfile']

def cmd(command):
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT).decode() # .split("\n")
        return output
    except subprocess.CalledProcessError as e:
        if e.output:
            print(f"Shell command returned with non-zero exit code! Output:\n-------------------------------------------------\n{e.output.decode()}-------------------------------------------------")
        return e.output.decode()


fixing_commands = []

# Check if IP interfaces are up
interfaces = cmd("ip a | grep -Pe '^\\d:'").splitlines()
print("Checking network interface health...")
print("Interfaces found:", [int_str.split(" ")[1][:-1] for int_str in interfaces])
up = [int for int in interfaces if "UP" in int]
down = [int for int in interfaces if "DOWN" in int]
if not up:
    print("WARNING!! No network interfaces up!")
else:
    for int in up:
        print("Network Interface UP: ", int)
if not down:
    print("No network interfaces down!")
else:
    print("WARNING!! Some network interfaces down")
    print("To restore, try running: sudo ip link set dev <interface> up")
    for int in up:
        fixing_commands.append(f"Network Interface DOWN: {int}. Try running sudo ip link set dev {int} up")
        print("Network Interface DOWN: ", int)

# Check if correct IP addresses are set
print("\nChecking if required IPv4 addresses are present")
print("Note: if you have multiple network interfaces, this is NOT checking that each address is assigned to the CORRECT interface. This is just checking that the required IPv4 addresses are assigned to A interface")
print("Checking for:", IPV4_ADDRESSES)
for ipv4 in IPV4_ADDRESSES:
    if not (output:=cmd(f"ip a | grep 'inet {ipv4}'")):
        print("ERROR! Required IPv4 address not found in running ip a. To restore, try running: sudo ip addr add <ip addr>/<cidr> dev <interface>")
        if "/" in ipv4:
            fixing_commands.append(f"Required IPv4 address {ipv4} not found in ip a. Try running: sudo ip addr add {ipv4} dev <interface>")
        else:
            fixing_commands.append(f"Required IPv4 address {ipv4} not found in ip a. Try running: sudo ip addr add {ipv4}/<cidr> dev <interface>")
    else:
        print(f'IPv4 address {ipv4} assigned! Looks like to {output.splitlines()[0].split(" ")[-1]}')


# Check if systemctl services are running
print(f"\nChecking if neccesary services {SERVICES} are running...")
for service in SERVICES:
    output = cmd(f"systemctl status {service}")
    if len(output.splitlines()) == 1 and output.startswith(f"Unit {service}") and output.endswith("could not be found.\n"):
        print(f"ERROR! Service {service} could not be found!!")
        fixing_commands.append(f"Service {service} not present! Try installing the relevant package!")
    elif "Active: active (running) since" in output:
        print(f"Service {service} is running")
    elif "Active: inactive (dead) since" in output:
        print(f"ERROR! Service {service} is not running! To restore, try running sudo systemctl start {service}")
        fixing_commands.append(f"Service {service} is not running! To restore, try running sudo systemctl start {service}")
    else:
        print("Warning! Unable to parse systemctl status output. Output:\n", output)

# Check if ports are open and right names are attached to the port
print("Checking if neccesary ports are running...")
ss = [line.split() for line in cmd("sudo ss -plunta").splitlines()[1:]]
ss_ports = [s[4] for s in ss]
for portspec in PORTS:
    port_no = portspec['port_no']
    process_name = portspec['process_name']

    tofind = f"0.0.0.0:{port_no}"
    if tofind in ss_ports:
        conn = ss[ss_ports.index(tofind)]
        if len(conn) < 7:
            print(f"Warning! Port {port_no} is present but ss doesn't show the process associated with it...check it yourself!")
        else:
            process = "".join(conn[6:]).split("\"")
            name = process[1]
            if name == process_name:
                print(f"Port {port_no} is listening by process {process_name}")
            else:
                print(f"ERROR! Port {port_no} is listening, but by process {name} instead of {process_name}!")
                fixing_commands.append(f"ERROR! Port {port_no} is listening, but by process {name} instead of {process_name}!")
    else:
        print(f"ERROR! Port {port_no} is not being listened on!")
        fixing_commands.append(f"ERROR! Port {port_no} is not being listened on!")

# Check if the hashes have changed
print("Checking hashes...")

with open(HASHFILE, 'r') as file:
    HASHES = file.read().splitlines()

HASHES = [line.split(" ") for line in HASHES]

for hashspec in HASHES:
    filepath = hashspec[0]
    hash = hashspec[1]
    try:
        with open(filepath, 'rb') as file:
            cntnt = file.read()
        curr_hash = hashlib.sha256(cntnt).hexdigest()
        if curr_hash != hash:
            print(f"ERROR! File {filepath}'s SHA256 hash doesn't match stored hash!!")
            fixing_commands.append(f"ERROR! File {filepath}'s SHA256 hash doesn't match stored hash!")
    except FileNotFoundError:
        print(f"ERROR! File {filepath} doesn't exist!!")
        fixing_commands.append(f"ERROR! File {filepath} doesn't exist!!")

if fixing_commands:
    print("\nERROR SUMMARY:")
    print("\n".join(fixing_commands))
else:
    print("\nNO ERRORS FOUND! Services pass initial health checks")