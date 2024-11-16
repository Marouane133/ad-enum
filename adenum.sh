#!/bin/bash

init() {
    # Create the enumeration directory if it doesn't exist
    mkdir -p "$ENUMERATION_DIRECTORY"
    # Ensure the usernames file exists
    if [ -z "$USERNAMES_FILE" ]; then
        echo "Error: USERNAMES_FILE variable is not set."
        exit 1
    fi
    touch "$USERNAMES_FILE"

    if [ -z "$CREDS_FILE" ]; then
        echo "Error: CREDS_FILE variable is not set."
        exit 1
    fi
    touch "$CREDS_FILE"
}

password_spray() {
    local PASSWORD="$1"
    local TOOL="passwordspraying"
    local DIR="$ENUMERATION_DIRECTORY/$TOOL/${PASSWORD:-''}"
    mkdir -p "$ENUMERATION_DIRECTORY/$TOOL"
    mkdir -p "$DIR"

    local TIMESTAMP=$(date '+%Y-%m-%d_%H-%M-%S')  # Format: YYYY-MM-DD_HH-MM-SS
    local OUTPUT_FILE="$DIR/$TIMESTAMP.txt"  # File name with timestamp

    echo "[+] Started '$PASSWORD' Spraying ..."
    # Perform password spraying and write output to timestamped file
    crackmapexec smb $IP -u $USERNAMES_FILE -p "$PASSWORD" --continue-on-success > "$OUTPUT_FILE"
    # Extract valid credentials and append to creds file
    cat "$OUTPUT_FILE" | grep + | awk -F'\\' '{print $2}' | sed 's/ $//' >> $DIR/creds.txt
    sort $DIR/creds.txt | uniq > $DIR/temp.txt && mv $DIR/temp.txt $DIR/creds.txt
    grep -Fvxf $CREDS_FILE $DIR/creds.txt >> $CREDS_FILE
    rm -f "$DIR/creds.txt"
    # Count the number of sprayed users
    USER_COUNT=$(wc -l < "$CREDS_FILE")
    echo -e "[+] Sprayed $USER_COUNT users :)"
    echo "[+] Ended '$PASSWORD' Spraying"
}



crackmapexec_enum() {
    local USER="$1"
    local PASSWORD="$2"
    local TOOL="crackmapexec"
    local DIR="$ENUMERATION_DIRECTORY/$TOOL/${USER:-''}"
    mkdir -p "$ENUMERATION_DIRECTORY/$TOOL"
    mkdir -p "$DIR"

    echo "[+] Started $TOOL Enumeration"
    if confirm_enum "Crackmapexec RID BRUTE FORCE !"; then
        echo "[+] RID Brute Forcing ..."
        crackmapexec smb "$IP" -u "$USER" -p "$PASSWORD" --rid-brute > "$DIR"/crackmap-users.txt
        cat "$DIR"/crackmap-users.txt | grep SidTypeUser | awk -F'\\' {'print $2'} | awk {'print $1'} >> $DIR/usernames.txt
    fi
    crackmapexec smb "$IP" -u "$USER" -p "$PASSWORD" --users > "$DIR"/crackmap-users.txt
    awk '{print $5}' "$DIR"/crackmap-users.txt > "$DIR"/usersDomains.txt
    echo "[+] Enumerating Domains ..."
    sed -E '/^\[\*\]/d;/^\[\+\]/d' "$DIR"/usersDomains.txt | awk -F'.' '!seen[$1]++ {print $1}' >> $DIR/domains.txt
    echo "[+] Enumerating Usernames ..."
    awk -F'\\' '$2 != "" {print $2}' "$DIR"/usersDomains.txt >> $DIR/usernames.txt
    sort $DIR/usernames.txt | uniq > $DIR/temp.txt && mv $DIR/temp.txt $DIR/usernames.txt
    grep -Fvxf $USERNAMES_FILE $DIR/usernames.txt >> $USERNAMES_FILE
    echo "[+] Enumerating Shares ..."
    crackmapexec smb "$IP" -u "$USER" -p "$PASSWORD" --shares >> $DIR/shares.txt
    echo "[+] Enumerating Password Policy ..."
    crackmapexec smb "$IP" -u "$USER" -p "$PASSWORD" --pass-pol >> $DIR/pass-policy.txt
    rm -f "$DIR"/crackmap-users.txt "$DIR"/usersDomains.txt
    echo -e "[+] Ended $TOOL Enumeration\n"
}


enum4linux_enum() {
    local USER="$1"
    local PASSWORD="$2"
    local TOOL="enum4linux"
    local DIR="$ENUMERATION_DIRECTORY/$TOOL/${USER:-''}"
    mkdir -p "$ENUMERATION_DIRECTORY/$TOOL"
    mkdir -p $DIR

    echo "[+] Started $TOOL Enumeration"
    echo "[+] Enumerating Usernames ..."
    enum4linux -U -u "$USER" -p "$PASSWORD" $IP >> $DIR/users.txt
    cat $DIR/users.txt | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]" >> $DIR/usernames.txt
    sort $DIR/usernames.txt | uniq > $DIR/temp.txt && mv $DIR/temp.txt $DIR/usernames.txt
    grep -Fvxf $USERNAMES_FILE $DIR/usernames.txt >> $USERNAMES_FILE
    echo "[+] Enumerating Shares ..."
    enum4linux -S -u "$USER" -p "$PASSWORD" $IP >> $DIR/shares.txt
    echo "[+] Enumerating Password Policy ..."
    enum4linux -P -u "$USER" -p "$PASSWORD" $IP >> $DIR/pass-policy.txt
    echo "[+] Enumerating Machines ..."
    enum4linux -M -u "$USER" -p "$PASSWORD" $IP >> $DIR/machines.txt
    echo "[+] Enumerating Groups ..."
    enum4linux -G -u "$USER" -p "$PASSWORD" $IP >> $DIR/groups.txt
    echo -e "[+] Ended $TOOL Enumeration\n"
}

smbmap_enum() {
    local USER="$1"
    local PASSWORD="$2"
    local TOOL="smbmap"
    local DIR="$ENUMERATION_DIRECTORY/$TOOL/${USER:-''}"
    mkdir -p "$ENUMERATION_DIRECTORY/$TOOL"
    mkdir -p $DIR

    echo "[+] Started $TOOL Enumeration"
    echo "[+] Enumerating Shares ..."
    smbmap -u "$USER" -p "$PASSWORD" -H $IP | sed -n '/^\s*Disk/,/^\s*\[/p' >> $DIR/shares.txt
    echo -e "[+] Ended $TOOL Enumeration\n"
}

kerbrute_enum () {
    local USER="$1"
    local PASSWORD="$2"
    local TOOL="kerbrute"
    local DIR="$ENUMERATION_DIRECTORY/$TOOL/${USER:-''}"
    mkdir -p "$ENUMERATION_DIRECTORY/$TOOL"
    mkdir -p $DIR

    echo "[+] Started $TOOL Enumeration"
    echo "[+] Enumerating Users ..."
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
    sort $USERNAMES_FILE | uniq > $ENUMERATION_DIRECTORY/temp.txt && mv $ENUMERATION_DIRECTORY/temp.txt $USERNAMES_FILE
    sed -i '/^\(administrator\|krbtgt\|guest\)$/Id' $USERNAMES_FILE
    USER_COUNT=$(wc -l < "$USERNAMES_FILE")
    echo -e "[+] Enumerated $USER_COUNT users :)"
}

# Function for Kerbrute, crackmapexec RID brute force
no_creds_enum() {
    if confirm_enum "Anonymous Enumeration"; then
        enum "" ""
    fi
    if confirm_enum "Guest Enumeration"; then
        enum "guest" ""
    fi
    if confirm_enum "Kerbrute Users Brute Force"; then
        kerbrute_enum
    fi
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

show_help() {
    echo "Usage:"
    echo "  $0 -d DOMAIN -i IP [-u USER -p PASSWORD]"
    echo "  $0 -d DOMAIN -i IP -s PASSWORD"
    echo "  $0 -d DOMAIN -i IP -f FILE"
    echo "  $0 -d DOMAIN -i IP -n"
    echo
    echo "Options:"
    echo "  -d, --domain       Specify the domain to enumerate."
    echo "  -i, --ip           Specify the target IP address."
    echo "  -u, --user         Specify the username for authentication."
    echo "  -p, --password     Specify the password for authentication."
    echo "  -f, --file         Specify a file containing username:password pairs."
    echo "  -n, --no-creds     Enumerate without credentials."
    echo "  -s, --spray        Perform a password spray with the given password."
    echo "  -h, --help         Display this help message."
    exit 0
}


# Results
ENUMERATION_DIRECTORY="enumeration"
USERNAMES_FILE=$ENUMERATION_DIRECTORY/"usernames.txt"
CREDS_FILE=$ENUMERATION_DIRECTORY/"creds.txt"
USER=""

# Parsing args
while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--domain)
            DOMAIN="$2"
            shift 2
            ;;
        -i|--ip)
            IP="$2"
            shift 2
            ;;
        -u|--user)
            USER="$2"
            shift 2
            ;;
        -p|--password)
            PASSWORD="$2"
            shift 2
            ;;
        -f|--file)
            FILE="$2"
            shift 2
            ;;
        -n|--no-creds)
            NO_CREDS=true
            shift
            ;;
        -s|--spray)
            SPRAY_PASSWORD="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            ;;
        *)
            echo "[!] Unknown option: $1"
            exit 1
            ;;
    esac
done

# Displaying Usage 
if [[ -z "$DOMAIN" || -z "$IP" ]]; then
    echo "Usage:"
    echo "  $0 -d DOMAIN -i IP [-u USER -p PASSWORD]"
    echo "  $0 -d DOMAIN -i IP -f FILE"
    echo "  $0 -d DOMAIN -i IP -n"
    exit 1
fi


# Initiation the enumeration directory
init

# Script logic
if [[ "$NO_CREDS" == true ]]; then
    confirm_overwrite "Enumerating Users Without Credentials"
    no_creds_enum
elif [[ -n "$SPRAY_PASSWORD" ]]; then
    confirm_overwrite "Password Spraying"
    password_spray "$SPRAY_PASSWORD"
elif [[ -n "$FILE" ]]; then
    if [[ ! -f "$FILE" ]]; then
        echo "[!] File not found: $FILE"
        exit 1
    fi
    sed -i -e '$a\' "$FILE"  # Ensure the file ends with a newline
    confirm_overwrite "File-Based Enumeration"
    while IFS=: read -r USER PASSWORD; do
        if ! login "$USER" "$PASSWORD"; then
            continue
        fi
        echo -e "[*] Running additional commands for $USER...\n"
        enum "$USER" "$PASSWORD"
    done < "$FILE"
elif [[ -n "$USER" && -n "$PASSWORD" ]]; then
    confirm_overwrite "Single User Enumeration"
    if ! login "$USER" "$PASSWORD"; then
        echo "[!] Skipping enumeration due to login failure."
    else
        enum "$USER" "$PASSWORD"
    fi
else
    echo "[!] Invalid arguments. Use --help for usage."
    exit 1
fi

# Showing the number of enumerated users
nb_users