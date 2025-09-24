# BIKE Setup
For the general attack attack pipeline the following steps can be followed. To the concrete attack from our paper please skip ahead to the example section.

Checkout the parent attack folder with "bike_Modified_CodeBase", then run 
```
sh ./build_file.sh
```

you need openmp for prallelism otherwise choose: "-noparallel"

it should produce a "test.out" which you can run with

```
./test.out <filename> [--change_e <number>]
```

for testing we changed the code in :
Attack_Scripts/codebase/test.c
bike_Modified_CodeBase/src/kem.c

[--change_e <number>]
defines the number of blocked 1s in e0


# Analysis of Distance Spectrum

You can analyse the distance spectrum as by running the code in `testing.ipynb`:

Here, set the corresponding file_path to your data.

This produces the DS images figure in the folder `/fig` and a `.csv` which can be tested using the CNN model.


# CNN Model Testing

For the ML test you can run one of the pretrained models and see if the model can classify all but 2 within the top K predictions.

```
cd ML
```

Next change this part for your folder:
```
filename = 'test_key/trace.csv'
use_old_model = 1
num_test_samples_all = 1 
num_test_samples = 1 
```

and run the script to see for which K enough distances can be recoverd. 
Here, the model searches only for the distances outside of the block (71-34 = 37) for BIKE level 1 and a block of size 34.


# Example for the Key in our Paper

Start by running:
```
./test.out test_key --change_e 4
```

and define the number of traces as: 9000000

Next, open `testing.iypnb` and execute all code cells.

Then go to `ML` and test the CNN Model:
```
cd ML
python CNN_DS_finder
```
    
Leave the structure as default:
```
filename = 'test_key/trace.csv'
use_old_model = 1
num_test_samples_all = 1 
num_test_samples = 1 
```

Finally, you can see in the output how many correct distances have been recovered.

