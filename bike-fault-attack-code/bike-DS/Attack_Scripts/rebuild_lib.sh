#!/bin/bash

# Set the build directory path
BUILD_DIR=./../bike_Modified_CodeBase/build

# Check if the build directory exists
if [ ! -d "$BUILD_DIR" ]; then
    echo "Build directory does not exist. Creating it..."
    mkdir -p "$BUILD_DIR" || exit 1
    echo "Build the program"

    # Change to the build directory
    cd "$BUILD_DIR" || exit
    
    # Run cmake with the specified options
    cmake -DCMAKE_BUILD_TYPE=Release ..

    # Check if cmake was successful
    if [ $? -eq 0 ]; then
        echo "CMake configuration successful."
    else
        echo "CMake configuration failed."
        exit 1
    fi
else
    # Change to the build directory
    cd "$BUILD_DIR" || exit
fi

# Run the make command
make

# Check if make was successful
if [ $? -eq 0 ]; then
    echo "Make successful."
else
    echo "Make failed."
fi
