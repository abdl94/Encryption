#!/bin/bash
#
# Password Generator - Bash Version
# Generates strong, random passwords using bash and standard Unix tools
#

# Default values
LENGTH=16
COUNT=1
USE_UPPERCASE=true
USE_LOWERCASE=true
USE_DIGITS=true
USE_SPECIAL=true

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Show usage
show_usage() {
    cat << EOF
Password Generator - Bash Version

Usage: $0 [OPTIONS]

Options:
    -l, --length NUM        Password length (default: 16)
    -c, --count NUM         Number of passwords to generate (default: 1)
    --no-uppercase          Exclude uppercase letters
    --no-lowercase          Exclude lowercase letters
    --no-digits             Exclude digits
    --no-special            Exclude special characters
    --digits-only           Generate digits only
    --alphanumeric          Alphanumeric only, no special characters
    -h, --help              Show this help message

Examples:
    $0                              # Default: 16 chars with all types
    $0 -l 32                        # 32 character password
    $0 -l 20 --no-special           # No special characters
    $0 -c 5 -l 16                   # Generate 5 passwords
    $0 --digits-only -l 12          # 12 digit password

EOF
    exit 0
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -l|--length)
            LENGTH="$2"
            shift 2
            ;;
        -c|--count)
            COUNT="$2"
            shift 2
            ;;
        --no-uppercase)
            USE_UPPERCASE=false
            shift
            ;;
        --no-lowercase)
            USE_LOWERCASE=false
            shift
            ;;
        --no-digits)
            USE_DIGITS=false
            shift
            ;;
        --no-special)
            USE_SPECIAL=false
            shift
            ;;
        --digits-only)
            USE_UPPERCASE=false
            USE_LOWERCASE=false
            USE_DIGITS=true
            USE_SPECIAL=false
            shift
            ;;
        --alphanumeric)
            USE_SPECIAL=false
            shift
            ;;
        -h|--help)
            show_usage
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}" >&2
            echo "Use -h or --help for usage information" >&2
            exit 1
            ;;
    esac
done

# Validate inputs
if ! [[ "$LENGTH" =~ ^[0-9]+$ ]] || [ "$LENGTH" -lt 1 ]; then
    echo -e "${RED}Error: Password length must be a positive integer${NC}" >&2
    exit 1
fi

if ! [[ "$COUNT" =~ ^[0-9]+$ ]] || [ "$COUNT" -lt 1 ]; then
    echo -e "${RED}Error: Count must be a positive integer${NC}" >&2
    exit 1
fi

# Check if at least one character type is selected
if [ "$USE_UPPERCASE" = false ] && [ "$USE_LOWERCASE" = false ] && \
   [ "$USE_DIGITS" = false ] && [ "$USE_SPECIAL" = false ]; then
    echo -e "${RED}Error: At least one character type must be selected${NC}" >&2
    exit 1
fi

# Build character set
CHARSET=""
[ "$USE_UPPERCASE" = true ] && CHARSET+="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
[ "$USE_LOWERCASE" = true ] && CHARSET+="abcdefghijklmnopqrstuvwxyz"
[ "$USE_DIGITS" = true ] && CHARSET+="0123456789"
[ "$USE_SPECIAL" = true ] && CHARSET+='!@#$%^&*()_+-=[]{}|;:,.<>?'

# Function to generate a single password
generate_password() {
    local LENGTH=$1
    local CHARSET=$2
    local password=""
    
    for ((i = 0; i < LENGTH; i++)); do
        # Get random number between 0 and length of charset - 1
        local RANDOM_INDEX=$((RANDOM % ${#CHARSET}))
        # Extract character at that index
        password+="${CHARSET:$RANDOM_INDEX:1}"
    done
    
    echo "$password"
}

# Generate passwords
for ((i = 0; i < COUNT; i++)); do
    generate_password "$LENGTH" "$CHARSET"
done

exit 0
