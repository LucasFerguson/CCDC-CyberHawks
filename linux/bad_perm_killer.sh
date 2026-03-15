#!/bin/bash


function echol(){
    echo "";
    echo "$@";
}

echo "Searching for all suid binaries:"
sudo find / -user root -type f -perm /a+x -perm -4000 2>/dev/null > active_suid.tmp
cat active_suid.tmp

echol "Searching for all sgid binaries:"
sudo find / -user root -type f -perm /a+x -perm -2000 2>/dev/null > active_sgid.tmp
cat active_sgid.tmp

echol "Comparing to bad-suid.txt..."
cat active_suid.tmp | while read -r line; do echo "$(basename "$line")"; done > suid_lst.tmp
cat bad-suid.txt >> suid_lst.tmp

echo "Bad Suid:"
cat suid_lst.tmp | sort | uniq -d | while read -r line; do
    echo "Killing bad suid $line";
    sudo chmod u-s "$(grep -E "$line\$" active_suid.tmp)";
done

cat active_sgid.tmp | while read -r line; do echo "$(basename "$line")"; done > sgid_lst.tmp
cat bad-suid.txt >> sgid_lst.tmp

echo ""
echo "Bad Sgid:"
cat sgid_lst.tmp | sort | uniq -d | while read -r line; do echo "Killing bad sgid $line";
    sudo chmod u-g "$(grep -E "$line\$" active_sgid.tmp)";
done

echol "Searching for all cap binaries:"
sudo getcap -r / 2>/dev/null > active_cap.tmp
cat active_cap.tmp

echol "Comparing to bad-cap.txt..."
cat active_cap.tmp | cut -d' ' -f1 | while read -r line; do echo "$(basename "$line")"; done > cap_lst.tmp
cat bad-cap.txt >> cap_lst.tmp

echo "Potentially bad cap binaries (check whether they have the specific bad capability that makes them dangerous):"
cat suid_lst.tmp | sort | uniq -d

echo ""