latest_time() {
    local file="$1"
    local tW tY tZ label ts
    tW=$(stat -c '%W' "$file" 2>/dev/null)
    tY=$(stat -c '%Y' "$file" 2>/dev/null)
    tZ=$(stat -c '%Z' "$file" 2>/dev/null)
    ts=$tY; label="mtime"
    [ "${tZ:-0}" -gt "$ts" ] && ts=$tZ && label="ctime"
    [ "${tW:-0}" -gt "$ts" ] && ts=$tW && label="birth"
    echo "$(date -d "@$ts" '+%Y-%m-%d %H:%M:%S') [$label]"
}

fmt_delta() {
    local secs=$1
    local sign=""
    [ "$secs" -lt 0 ] && sign="-" && secs=$(( -secs ))
    if   [ "$secs" -lt 60 ];    then echo "${sign}${secs}s"
    elif [ "$secs" -lt 3600 ];  then echo "${sign}$(( secs/60 ))m $(( secs%60 ))s"
    elif [ "$secs" -lt 86400 ]; then echo "${sign}$(( secs/3600 ))h $(( (secs%3600)/60 ))m"
    else echo "${sign}$(( secs/86400 ))d $(( (secs%86400)/3600 ))h"
    fi
}

parse_rpm_flags() {
    local flags="$1"
    local file="$2"
    [ "${flags:0:1}" = "S" ] && echo "  size:     $(stat -c '%s bytes' "$file" 2>/dev/null)"
    [ "${flags:1:1}" = "M" ] && echo "  mode:     $(stat -c '%a (%A)' "$file" 2>/dev/null)"
    [ "${flags:2:1}" = "5" ] && echo "  md5:      $(md5sum "$file" 2>/dev/null | awk '{print $1}')"
    [ "${flags:4:1}" = "L" ] && echo "  symlink:  $(readlink "$file" 2>/dev/null)"
    [ "${flags:5:1}" = "U" ] && echo "  owner:    $(stat -c '%U' "$file" 2>/dev/null)"
    [ "${flags:6:1}" = "G" ] && echo "  group:    $(stat -c '%G' "$file" 2>/dev/null)"
    [ "${flags:8:1}" = "P" ] && echo "  caps:     $(getcap "$file" 2>/dev/null)"
}

# ── get dpkg install epoch for a package ─────────────────────────────────────
# uses dpkg.log if available, falls back to .list mtime
get_install_epoch() {
    local pkg="$1"
    local epoch=""
    if [ -f /var/log/dpkg.log ]; then
        epoch=$(grep -h " install \| upgrade " /var/log/dpkg.log /var/log/dpkg.log.1 2>/dev/null \
            | grep " ${pkg}[: ]" \
            | tail -1 \
            | awk '{print $1" "$2}' \
            | xargs -I{} date -d "{}" '+%s' 2>/dev/null)
    fi
    if [ -z "$epoch" ] && [ -f "/var/lib/dpkg/info/${pkg}.list" ]; then
        epoch=$(stat -c '%Y' "/var/lib/dpkg/info/${pkg}.list" 2>/dev/null)
    fi
    echo "$epoch"
}


echo "
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣷⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⢻⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⡴⠋⣨⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⠤⠖⠛⠉⠉⠀⠉⠙⠛⠉⠉⠉⠓⠦⢄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣠⠖⠉⠀⠀⢀⡄⠀⠀⠀⠀⠀⠀⠀⠀⠈⠑⠢⣄⠉⠲⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢠⠞⠁⠀⠀⠀⡴⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠑⢄⠈⢳⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣰⠃⠀⠀⠀⠀⡼⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢧⡀⢱⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢠⠃⠀⠀⠀⠀⢸⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢳⡄⢷⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣼⠀⠀⠀⠀⢀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⢰⣆⠀⠀⠀⠀⠀⢹⡌⡆⠀⠀⠀⠀⠀
⠀⠀⠀⡇⠀⠀⠀⠀⣸⠁⠀⠀⠀⡄⠀⣠⠀⢠⠀⠀⠀⠀⣇⠘⡘⣆⠀⠀⠀⠀⠀⢳⢹⠀⠀⠀⠀⠀
⠀⠀⠀⡇⠀⠀⠀⣰⡇⠀⠀⠀⢀⡇⢠⢿⠀⢸⠀⠀⠀⠀⣿⡄⢳⣸⣦⣄⣀⠀⠀⠈⢷⡄⠀⠀⠀⠀
⠀⠀⠀⡇⠀⠀⠀⡇⠃⠀⠀⠀⢸⣇⡾⠶⣟⢻⡗⠀⠀⠀⢡⠻⣍⠉⠛⠦⢷⣅⡀⠀⠀⠳⣄⠀⠀⠀
⠀⠀⠀⡇⠀⠀⠀⢁⠀⠀⠀⠀⢸⣿⠃⠀⠘⢎⡾⡄⠀⠀⢸⡄⣬⣽⣶⣶⢤⣻⣝⠒⢦⡤⠼⠗⠂⠀
⠀⠀⠀⡗⠀⠀⣸⠐⠀⠀⠀⠀⢈⣿⣤⡶⣶⣾⣟⠙⢄⡀⠀⢧⠀⠀⣿⣿⡆⣸⢉⠁⠘⡇⠀⠀⠀⠀
⠀⠀⢰⠁⠀⢸⠉⡓⡆⠀⠀⠘⡄⢃⠀⠀⢿⣿⣿⠀⠀⠙⠒⠼⠄⠀⣿⣿⠇⡿⡼⠀⠀⣧⠀⠀⠀⠀
⠀⢀⡏⣰⠇⠘⡄⣌⣧⠀⡀⠀⠱⡜⡆⠀⠘⣿⡟⠀⠀⠀⠀⠀⠀⠀⠈⢩⣤⢿⡇⠀⡀⣯⣧⠀⠀⠀    \"Next time, don't let red team in.\"
⠀⢸⠃⣿⠀⢰⡳⣘⡼⡄⣧⠀⠀⡟⢾⣤⠰⠄⠀⠀⢀⡤⠤⢄⡀⠀⠀⠀⠀⡼⠃⠀⡇⡇⢻⣇⠀⠀    hash tamp checker - cc00ffee
⠀⡜⢠⣽⠀⠀⣇⠀⠙⢣⢹⡄⠀⢳⣄⠉⠑⠀⠀⢰⠁⠀⠀⠀⡿⠀⢀⣠⠚⡇⠀⣰⣇⡇⠈⢿⣆⠀
⢠⡇⢸⢸⠀⠀⢹⡀⠀⠘⢮⣿⡀⠘⣇⠉⣲⠦⢄⣈⣁⣀⣀⣉⡤⠖⠋⠸⣦⠁⢠⠇⣿⠀⠀⠘⡼⡀
⢸⡄⠸⡸⡄⠀⠀⢳⡀⠀⢸⢿⡙⢦⡸⣶⡿⢧⣤⣀⢈⣹⢿⣿⣤⠀⠀⠀⣾⣶⣣⠎⡏⠀⠀⢀⡇⣷
⠀⠙⠦⣝⣿⣄⠀⠀⠹⣄⢨⠀⣳⣞⢙⣾⣦⣨⣿⣿⡿⡏⠀⢹⣷⡀⣠⡾⠋⡼⠃⠀⠀⠀⣴⣿⡷⠁
⠀⠀⠀⠀⠉⠛⢷⣤⡀⠴⠛⠉⠀⢸⠁⢀⡿⣿⣯⣸⣸⣽⣦⣾⠟⣿⣇⠀⡾⠁⠀⠀⣠⣾⠟⠁⠀⠀
⠀⠀⠀⠀⣠⡴⡿⠋⠀⠀⠀⠀⠀⠀⠳⣏⠀⠸⠉⠛⡟⠛⢻⠁⡴⠁⠈⢠⣧⠠⠒⠺⣿⣅⠀⠀⠀⠀
⠀⠀⠀⢰⡋⢰⡇⠀⠀⠀⠀⠀⠀⠀⠀⠈⠑⠧⠤⣀⣇⣀⠼⠶⠻⣄⠀⠀⢷⠀⠀⠀⣸⠞⡇⠀⠀⠀
⠀⠀⠀⠀⢷⣼⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣨⠧⠀⣸⠀⣀⣾⠁⢰⡇⠀⠀⠀
==========================================================

"

# CHECK 1 — Hash tamper (rpm -Va / debsums / manual md5)
check_hashes() {
    echo "=== [1] Hash tamper check ==="

    if command -v rpm &>/dev/null; then
        rpm -Va 2>/dev/null | grep '^..5' | while read -r flags type file; do
            [ "$type" != "c" ] && [ "$type" != "d" ] && [ "$type" != "g" ] \
                && file="$type" && type=""
            echo ""
            echo "$flags ${type:+$type }$file"
            echo "  changed:  $(echo "$flags" | sed \
                -e 's/S/Size /g' -e 's/M/Mode /g' -e 's/5/MD5 /g' \
                -e 's/D/Device /g' -e 's/L/Symlink /g' -e 's/U/Owner /g' \
                -e 's/G/Group /g' -e 's/T/Mtime /g' -e 's/P/Caps /g' \
                -e 's/\.//g')"
            if [ -e "$file" ]; then
                echo "  latest:   $(latest_time "$file")"
                parse_rpm_flags "$flags" "$file"
            else
                echo "  !! file missing"
            fi
        done

    elif command -v debsums &>/dev/null; then
        debsums -c 2>/dev/null | while read -r file _; do
            echo ""
            echo "FAIL $file"
            echo "  latest:   $(latest_time "$file")"
            echo "  size:     $(stat -c '%s bytes' "$file" 2>/dev/null)"
            echo "  owner:    $(stat -c '%U:%G' "$file" 2>/dev/null)"
            echo "  md5:      $(md5sum "$file" 2>/dev/null | awk '{print $1}')"
        done

    else
        find /var/lib/dpkg/info -name '*.md5sums' | while read -r f; do
            pkg=$(basename "$f" .md5sums)
            while read -r hash path; do
                actual=$(md5sum "/$path" 2>/dev/null | awk '{print $1}')
                if [ "$actual" != "$hash" ]; then
                    echo ""
                    echo "FAIL [$pkg] /$path"
                    echo "  latest:   $(latest_time "/$path")"
                    echo "  size:     $(stat -c '%s bytes' "/$path" 2>/dev/null)"
                    echo "  owner:    $(stat -c '%U:%G' "/$path" 2>/dev/null)"
                    echo "  md5 now:  $actual"
                    echo "  md5 pkg:  $hash"
                fi
            done < "$f"
        done
    fi
}

# CHECK 2 — Files in .md5sums but not in .list (or vice versa)
check_md5sums_vs_list() {
    echo ""
    echo "=== [2] .md5sums vs .list content diff ==="
    local found=0

    find /var/lib/dpkg/info -name '*.md5sums' | while read -r md5f; do
        pkg=$(basename "$md5f" .md5sums)
        listf="/var/lib/dpkg/info/${pkg}.list"
        [ -f "$listf" ] || continue

        # paths recorded in md5sums (prepend /)
        while read -r _ path; do
            fabs="/$path"
            if ! grep -qxF "$fabs" "$listf" 2>/dev/null; then
                echo "  [$pkg] in md5sums but NOT in .list: $fabs"
                found=1
            fi
        done < "$md5f"

        # paths in .list that have no md5 entry (dirs are expected, flag files)
        while read -r fabs; do
            [ -f "$fabs" ] || continue   # skip dirs/symlinks
            rel="${fabs#/}"
            if ! grep -qF "$rel" "$md5f" 2>/dev/null; then
                echo "  [$pkg] in .list but NOT in md5sums: $fabs"
                found=1
            fi
        done < "$listf"
    done

    [ "$found" -eq 0 ] && echo "  no discrepancies found"
}

# CHECK 3 — Install date vs .md5sums mtime
check_install_vs_md5sums() {
    echo ""
    echo "=== [3] Install date vs .md5sums mtime ==="
    local found=0

    find /var/lib/dpkg/info -name '*.md5sums' | while read -r md5f; do
        pkg=$(basename "$md5f" .md5sums)
        install_epoch=$(get_install_epoch "$pkg")
        [ -z "$install_epoch" ] && continue

        md5_epoch=$(stat -c '%Y' "$md5f" 2>/dev/null)
        delta=$(( md5_epoch - install_epoch ))

        # flag if md5sums is >60s different from install (either direction is suspicious)
        if [ "${delta#-}" -gt 60 ]; then
            install_str=$(date -d "@$install_epoch" '+%Y-%m-%d %H:%M:%S')
            md5_str=$(date -d "@$md5_epoch" '+%Y-%m-%d %H:%M:%S')
            human=$(fmt_delta "$delta")
            echo ""
            echo "  [$pkg]"
            echo "    install:  $install_str"
            echo "    md5sums:  $md5_str"
            echo "    delta:    $human"
            found=1
        fi
    done

    [ "$found" -eq 0 ] && echo "  no suspicious gaps found"
}

# CHECK 4 — .postinst mtime vs .md5sums mtime
check_postinst_vs_md5sums() {
    echo ""
    echo "=== [4] .postinst vs .md5sums mtime ==="
    local found=0

    find /var/lib/dpkg/info -name '*.md5sums' | while read -r md5f; do
        pkg=$(basename "$md5f" .md5sums)
        postf="/var/lib/dpkg/info/${pkg}.postinst"
        [ -f "$postf" ] || continue

        t_post=$(stat -c '%Y' "$postf" 2>/dev/null)
        t_md5=$(stat -c '%Y' "$md5f" 2>/dev/null)
        delta=$(( t_md5 - t_post ))

        if [ "${delta#-}" -gt 60 ]; then
            post_str=$(date -d "@$t_post" '+%Y-%m-%d %H:%M:%S')
            md5_str=$(date -d "@$t_md5" '+%Y-%m-%d %H:%M:%S')
            human=$(fmt_delta "$delta")
            echo ""
            echo "  [$pkg]"
            echo "    postinst: $post_str"
            echo "    md5sums:  $md5_str"
            echo "    delta:    $human  $([ "$delta" -gt 0 ] && echo '(md5sums newer — suspicious)' || echo '(postinst newer)')"
            found=1
        fi
    done

    [ "$found" -eq 0 ] && echo "  no suspicious gaps found"
}

# CHECK 5 — Install date vs actual file mtime on disk
check_install_vs_file_mtime() {
    echo ""
    echo "=== [5] Install date vs file mtime on disk ==="
    local threshold=60
    local found=0

    if command -v rpm &>/dev/null; then
        rpm -qa --qf "%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH} %{INSTALLTIME}\n" \
        | while read -r pkg install_epoch; do
            rpm -ql "$pkg" 2>/dev/null | while read -r f; do
                [ -f "$f" ] || continue
                file_epoch=$(stat -c '%Y' "$f" 2>/dev/null)
                delta=$(( file_epoch - install_epoch ))
                if [ "$delta" -gt "$threshold" ]; then
                    echo "  [$(fmt_delta "$delta") after install] $f  [$pkg]"
                    echo "    install:  $(date -d "@$install_epoch" '+%Y-%m-%d %H:%M:%S')"
                    echo "    file:     $(date -d "@$file_epoch"    '+%Y-%m-%d %H:%M:%S')"
                    found=1
                fi
            done
        done

    else
        dpkg-query -W -f='${Package}\n' 2>/dev/null | while read -r pkg; do
            listf="/var/lib/dpkg/info/${pkg}.list"
            [ -f "$listf" ] || continue

            install_epoch=$(get_install_epoch "$pkg")
            [ -z "$install_epoch" ] && continue

            while read -r fabs; do
                [ -f "$fabs" ] || continue
                file_epoch=$(stat -c '%Y' "$fabs" 2>/dev/null)
                delta=$(( file_epoch - install_epoch ))
                if [ "$delta" -gt "$threshold" ]; then
                    echo "  [$(fmt_delta "$delta") after install] $fabs  [$pkg]"
                    echo "    install:  $(date -d "@$install_epoch" '+%Y-%m-%d %H:%M:%S')"
                    echo "    file:     $(date -d "@$file_epoch"    '+%Y-%m-%d %H:%M:%S')"
                    found=1
                fi
            done < "$listf"
        done
    fi

    [ "$found" -eq 0 ] && echo "  no files modified after install"
}

check_hashes
check_md5sums_vs_list
check_install_vs_md5sums
check_postinst_vs_md5sums
check_install_vs_file_mtime
