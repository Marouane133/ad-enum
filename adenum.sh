#!/bin/bash

init() {
    # Create the enumeration directory if it doesn't exist
    mkdir -p enumeration
    # Ensure the usernames file exists
    if [ -z "$USERNAMES_FILE" ]; then
        echo "Error: USERNAMES_FILE variable is not set."
        exit 1
    fi
    touch "$USERNAMES_FILE"
}


crackmapexec_enum() {
    local USER="$1"
    local PASSWORD="$2"
    local TOOL="crackmapexec"
    local DIR="$ENUMERATION_DIRECTORY/$TOOL/$USER"
    mkdir -p "$ENUMERATION_DIRECTORY/$TOOL"
    mkdir -p "$DIR"

    echo "[+] Started $TOOL Enumeration"
    crackmapexec smb "$IP" -u "$USER" -p "$PASSWORD" --users > "$DIR"/crackmap-users.txt
    awk '{print $5}' "$DIR"/crackmap-users.txt > "$DIR"/usersDomains.txt
    echo "[+] Enumerating Domains ..."
    sed -E '/^\[\*\]/d;/^\[\+\]/d' "$DIR"/usersDomains.txt | awk -F'.' '!seen[$1]++ {print $1}' > $DIR/domains.txt
    echo "[+] Enumerating Usernames ..."
    awk -F'\\' '$2 != "" {print $2}' "$DIR"/usersDomains.txt > $DIR/usernames.txt
    grep -Fvxf $USERNAMES_FILE $DIR/usernames.txt >> $USERNAMES_FILE
    echo "[+] Enumerating Shares ..."
    crackmapexec smb "$IP" -u "$USER" -p "$PASSWORD" --shares > $DIR/shares.txt
    echo "[+] Enumerating Password Policy ..."
    crackmapexec smb "$IP" -u "$USER" -p "$PASSWORD" --pass-pol > $DIR/pass-policy.txt
    rm -f "$DIR"/crackmap-users.txt "$DIR"/usersDomains.txt
    echo -e "[+] Ended $TOOL Enumeration\n"
}

enum4linux_enum() {
    local USER="$1"
    local PASSWORD="$2"
    local TOOL="enum4linux"
    local DIR="$ENUMERATION_DIRECTORY/$TOOL/$USER"
    mkdir -p "$ENUMERATION_DIRECTORY/$TOOL"
    mkdir -p $DIR

    echo "[+] Started $TOOL Enumeration"
    echo "[+] Enumerating Usernames ..."
    enum4linux -U -u "$USER" -p "$PASSWORD" $IP | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]" > $DIR/usernames.txt
    grep -Fvxf $USERNAMES_FILE $DIR/usernames.txt >> $USERNAMES_FILE
    echo "[+] Enumerating Shares ..."
    enum4linux -S -u "$USER" -p "$PASSWORD" $IP > $DIR/shares.txt
    echo "[+] Enumerating Password Policy ..."
    enum4linux -P -u "$USER" -p "$PASSWORD" $IP > $DIR/pass-policy.txt
    echo "[+] Enumerating Machines ..."
    enum4linux -M -u "$USER" -p "$PASSWORD" $IP > $DIR/machines.txt
    echo "[+] Enumerating Groups ..."
    enum4linux -G -u "$USER" -p "$PASSWORD" $IP > $DIR/groups.txt
    echo -e "[+] Ended $TOOL Enumeration\n"
}

smbmap_enum() {
    local USER="$1"
    local PASSWORD="$2"
    local TOOL="smbmap"
    local DIR="$ENUMERATION_DIRECTORY/$TOOL/$USER"
    mkdir -p "$ENUMERATION_DIRECTORY/$TOOL"
    mkdir -p $DIR

    echo "[+] Started $TOOL Enumeration"
    echo "[+] Enumerating Shares ..."
    smbmap -u "$USER" -p "$PASSWORD" -H $IP | sed -n '/^\s*Disk/,/^\s*\[/p' > $DIR/shares.txt
    echo -e "[+] Ended $TOOL Enumeration\n"
}

login() {
    local USER="$1"
    local PASSWORD="$2"

    echo "[*] Testing login for $USER@$IP..."
    LOGIN_RESULT=$(crackmapexec smb "$IP" -u "$USER" -p "$PASSWORD" | grep '\[+\]')
    
    if [ -z "$LOGIN_RESULT" ]; then
        echo -e "[!] Login failed for $USER@$IP\n"
        return 1  # Indicate failure
    fi

    echo -e "[+] Login successful for $USER@$IP\n"
    return 0  # Indicate success
}


# Function for Kerbrute, crackmapexec RID brute force
bf_function() {
    local DOMAIN="$1"
    local IP="$2"

    echo "Running Kerbrute..."
    kerbrute userenum -d "$DOMAIN" --dc "$IP" /opt/jsmith.txt > kerb-results
    echo "Kerbrute completed."

    echo "Running RID brute force (Placeholder)..."
}

# Function to confirm overwriting existing files
confirm_overwrite() {
    local scenario="$1"
    echo "This script may overwrite existing files for the following scenario: $scenario."
    echo "Do you want to continue? [y/N]"

    read -r CONFIRMATION < /dev/tty
    if [[ "$CONFIRMATION" != "y" && "$CONFIRMATION" != "Y" ]]; then
        echo "[-] Aborting $scenario."
        exit 1
    fi
}

confirm_enum() {
    local tool="$1"
    echo "Do you want to run $tool? [y/N]"
    # Use /dev/tty to ensure clean input
    read -r CONFIRMATION < /dev/tty
    if [[ "$CONFIRMATION" != "y" && "$CONFIRMATION" != "Y" ]]; then
        echo -e "[-] Skipping $tool.\n"
        return 1  # Indicate the tool should be skipped
    fi
    return 0  # Indicate the tool should be run
}


nb_users() {
    sed -i '/^\(administrator\|krbtgt\|guest\)$/Id' $USERNAMES_FILE
    USER_COUNT=$(wc -l < "$USERNAMES_FILE")
    echo -e "[+] Enumerated $USER_COUNT users :)"
}



# Function for enumeration
enum() {
    local USER="$1"
    local PASSWORD="$2"
    if confirm_enum "Crackmapexec Enumeration"; then
        crackmapexec_enum "$USER" "$PASSWORD"
    fi
    if confirm_enum "Enum4linux Enumeration"; then
        enum4linux_enum "$USER" "$PASSWORD"
    fi
    if confirm_enum "Smbmap Enumeration"; then
        smbmap_enum "$USER" "$PASSWORD"
    fi
}


# Script logic
if [ "$#" -lt 2 ]; then
    echo "Usage:"
    echo "  $0 <Domain> <IP>"
    echo "  $0 <Domain> <IP> <Username> <Password>"
    echo "  $0 <Domain> <IP> <File>"
    exit 1
fi

DOMAIN="$1"
IP="$2"
ENUMERATION_DIRECTORY="enumeration"
USERNAMES_FILE=$ENUMERATION_DIRECTORY/"usernames.txt"

# Initiation the enumeration directory
init

if [ "$#" -eq 2 ]; then
    # If only Domain and IP are provided
    confirm_overwrite "Brute Forcing Users Without Credentials"
    bf_function "$DOMAIN" "$IP"
    confirm_overwrite "Anonymous Enumeration"
    enum "" ""
    confirm_overwrite "Guest User Enumeration"
    enum "guest" ""
elif [ "$#" -eq 3 ]; then
    # If Domain, IP, and File are provided
    FILE="$3"
    if [ ! -f "$FILE" ]; then
        echo "[!] File not found: $FILE"
        exit 1
    fi
    # Make sure it ends with \n
    sed -i -e '$a\' $FILE
    confirm_overwrite "File-Based Enumeration"
    while IFS=: read -r USER PASSWORD; do
        if ! login "$USER" "$PASSWORD"; then
            continue  # Skip to the next iteration on login failure
        fi
        # Proceed with the enumeration
        echo -e "[*] Running additional commands for $USER...\n"
        enum "$USER" "$PASSWORD"
    done < <(cat "$FILE")
else
    # If Domain, IP, Username, and Password are provided
    USER="$3"
    PASSWORD="$4"
    confirm_overwrite "Single User Enumeration"

    # Call login function
    if ! login "$USER" "$PASSWORD"; then
        echo "[!] Skipping enumeration due to login failure."
    else
        # Proceed with enumeration if login succeeds
        enum "$USER" "$PASSWORD"
    fi
fi

# Showing the number of enumerated users
nb_users