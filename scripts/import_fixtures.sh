#!/bin/bash
set -e

if ! [ -d "fixtures" ]; then
    echo "No fixtures folder found!"
    exit
fi

if [ "$(whoami)" != "postgres" ]; then
    echo "Not running as postgres user, switching user..."
    sudo -u postgres $0
    exit
fi

FIXTURES=$(find fixtures -type f -name "*.sql")

for x in $FIXTURES; do
    psql -U postgres ion < $x > /dev/null
    echo "Imported $x"
done