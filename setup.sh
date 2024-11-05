#!/bin/bash

################
# Update .env

# Path to the .env file
ENV_FILE=".env"

# Set default values if arguments are not provided
DEFAULT_SHARES=5
DEFAULT_THRESHOLD=3

# Check if SHARES and THRESHOLD arguments are provided
if [ -z "$1" ]; then
    echo "SHARES not provided, using default: $DEFAULT_SHARES"
    NEW_SHARES=$DEFAULT_SHARES
else
    NEW_SHARES=$1
fi

if [ -z "$2" ]; then
    echo "THRESHOLD not provided, using default: $DEFAULT_THRESHOLD"
    NEW_THRESHOLD=$DEFAULT_THRESHOLD
else
    NEW_THRESHOLD=$2
fi

# Validate that SHARES is at least 5
if [ "$NEW_SHARES" -lt 5 ]; then
    echo "Error: SHARES must be at least 5."
    exit 1
fi

# Validate that THRESHOLD is less than or equal to SHARES
if [ "$NEW_THRESHOLD" -gt "$NEW_SHARES" ]; then
    echo "Error: THRESHOLD must be less than or equal to SHARES."
    exit 1
fi

# Update or append SHARES and THRESHOLD in .env file
if grep -q "^SHARES=" "$ENV_FILE"; then
    sed -i '' "s/^SHARES=.*/SHARES=$NEW_SHARES/" "$ENV_FILE"  # Added '' after -i for macOS compatibility
else
    echo "SHARES=$NEW_SHARES" >> "$ENV_FILE"
fi

if grep -q "^THRESHOLD=" "$ENV_FILE"; then
    sed -i '' "s/^THRESHOLD=.*/THRESHOLD=$NEW_THRESHOLD/" "$ENV_FILE"  # Added '' after -i for macOS compatibility
else
    echo "THRESHOLD=$NEW_THRESHOLD" >> "$ENV_FILE"
fi

echo "Updated .env with SHARES=$NEW_SHARES and THRESHOLD=$NEW_THRESHOLD."

################
# Clear data folder

DIR="data"

if [ -d "$DIR" ]; then
  rm -rf "$DIR"
  echo "Directory '$DIR' and its contents have been deleted."
else
  echo "Directory '$DIR' does not exist."
fi