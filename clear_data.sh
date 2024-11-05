#!/bin/bash

DIR="data"

if [ -d "$DIR" ]; then
  rm -rf "$DIR"
  echo "Directory '$DIR' and its contents have been deleted."
else
  echo "Directory '$DIR' does not exist."
fi