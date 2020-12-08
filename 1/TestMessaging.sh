#!/bin/bash

# Check correct number of arguments
if [[ $# -ne 1 ]]; then
  printf "USAGE: $0 [server port]\n"
  exit 1
fi

PORT=$1
M=./SecureMessaging.py 

# Function to compare messages
# $1 = file with sent message
# $2 = file with received message
function compare {
  if diff -q $1 $2 > /dev/null; then
    printf "\nSUCCESS: Message received matches message sent!\n"      
  else
    printf "\nFAILURE: Message received doesn't match message sent.\n"
    echo Differences:
    diff $1 $2
  fi
  printf "________________________________________\n"               
}

# Function to run a test with one message
# $1 = port
# $2 = message
function test {

  # start server
  python3 $M $1 > test_output.txt &
  SERVER_PID=$!
  sleep 0.2

  # start client and send message
  echo "${2}" > test_input.txt
  python3 $M 127.0.0.1 $1 < test_input.txt >/dev/null
  sleep 0.2

  # kill the server if necessary
  #kill $SERVER_PID
  wait $SERVER_PID 2> /dev/null
  sleep 0.2

  # create a file with tabbed message for comparison
  echo "  ${2}" > test_input.txt
  compare test_input.txt test_output.txt

  # remote created files
  #rm -f test_output.txt
  #rm -f test_input.txt
  sleep 0.2
}

## Tests - Feel free to add your own!
test "$PORT" "Go Raiders!" 1 1