#!/bin/bash

# Run the Service Provider (Bob)
./out/build/linux/frontend/frontend -SpHsh ./dataset/cleartext.csv -r 2 -csv -hash 0 &

# Run the Receiver (Alice)
./out/build/linux/frontend/frontend -SpHsh ./dataset/receiver.csv -r 1 -csv -hash 0 &

# Run the Sender (Alice)
./out/build/linux/frontend/frontend -SpHsh ./dataset/sender.csv -r 0 -csv -hash 0 &

# Wait for all processes to finish
wait