#!/bin/bash

# Set the default C file if not provided
c_file="test.c"

# Set the common path
common_path="./codebase/"

filename="test"

# Set the path to patterns.c
patterns_path="${common_path}"

# Add the common path to the provided C file
c_file="${common_path}${c_file}"

# Check if the -norecompile flag is provided
if [ "$3" != "-norecompile" ]; then
    # Print the rebuild command
    echo "Rebuilding lib:"
    echo "./rebuild_lib.sh"
    
    # Execute the rebuild script
    ./rebuild_lib.sh
fi

# Check if the -noparallel flag is provided
if [ "$2" == "-noparallel" ]; then
    # Compile patterns.c into patterns.o
    gcc -c -o $patterns_path/patterns.o $patterns_path/patterns.c -I./../bike_Modified_CodeBase/include/internal/ -I./../bike_Modified_CodeBase/include/ -L./../bike_Modified_CodeBase/build/ -lm -lbike

    # Link patterns.o with test.c
    gcc -o ${filename%.*}.out $c_file $patterns_path/patterns.o -I$patterns_path -I./../bike_Modified_CodeBase/include/internal/ -I./../bike_Modified_CodeBase/include/ -L./../bike_Modified_CodeBase/build/ -lbike -lm
else
    # Compile patterns.c into patterns.o with OpenMP
    gcc -c -o $patterns_path/patterns.o $patterns_path/patterns.c -I./../bike_Modified_CodeBase/include/internal/ -I./../bike_Modified_CodeBase/include/ -L./../bike_Modified_CodeBase/build/ -lm -lbike -fopenmp

    # Link patterns.o with test.c and OpenMP
    gcc -o ${filename%.*}.out $c_file $patterns_path/patterns.o -I$patterns_path -I./../bike_Modified_CodeBase/include/internal/ -I./../bike_Modified_CodeBase/include/ -L./../bike_Modified_CodeBase/build/ -lbike -fopenmp -lm
fi

# Check if compilation was successful
if [ $? -eq 0 ]; then
    echo "Compilation successful. Executable: ${filename%.*}"
else
    echo "Compilation failed."
fi
