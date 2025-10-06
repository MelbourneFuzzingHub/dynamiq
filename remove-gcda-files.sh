#!/bin/bash

# Script to remove all .gcda files in the specified folder

SRC_FOLDER=$1

cd $SRC_FOLDER

# Find and remove all .gcda files
find ./ -name "*.gcda" -exec rm -f {} \;
