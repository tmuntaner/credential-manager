#!/bin/sh
# A fake pinentry for the tests of the pinentry adapter.
# $1: how to answer (ok, escaped, cancel, no, crash, hang, no-greeting)
# $2: file that records every command received
mode="$1"
log="$2"

[ "$mode" = "no-greeting" ] && exit 1
echo "OK Pleased to meet you"

while IFS= read -r line; do
  echo "$line" >> "$log"
  case "$line" in
    GETPIN)
      case "$mode" in
        ok) echo "S ignored status"; echo "D hunter 2"; echo "OK" ;;
        escaped) echo "D a%25b%0Ac"; echo "D  d+"; echo "OK" ;;
        cancel) echo "ERR 83886179 Operation cancelled <Pinentry>" ;;
        crash) exit 3 ;;
        hang) exec sleep 30 ;;
      esac ;;
    CONFIRM)
      case "$mode" in
        ok) echo "OK" ;;
        no) echo "ERR 83886194 Not confirmed <Pinentry>" ;;
        cancel) echo "ERR 83886179 Operation cancelled <Pinentry>" ;;
      esac ;;
    BYE) echo "OK closing connection"; exit 0 ;;
    *) echo "OK" ;;
  esac
done
