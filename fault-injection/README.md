# BIKE Fault Attacks

This repo was released to provide supplementary material for the paper __Efficient Weak Key Recovery for QC-MDPC Codes like BIKE__

There are several firmware versions with triggers at different positions. The jupyter notebook [Fault Pattern 2](jupyter/Fault%20Pattern%202.ipynb) is supposed to provide an easy start and holds 3 configurations to successful attacks.

The changes made are basically limited to the files `kem.c`, `sampling.c`, and `sampling_portable.c` in the folders `pqm4/[mupq/]crypto_kem/bikel1_*/[opt|m4f]`, while the interactive firmware file can be found at `pqm4/mupq/crypto_kem/fi.c`.

## Folder/Projects
Some subfolders/submodules were removed to keep anonymity for the submission. The removal may cause some minor functionality to break.

- `jupyter`: contains several jupyter notebooks. They are nice to set code in context and create reproducibility. Only [KAT.ipynb](jupyter/KAT.ipynb) and [Interactive Target.ipynb](jupyter/Interactive%20Target.ipynb) are meant to be used directly. They provide handy ways to make KATs and use the interactive firmware (from `pqm4`) for the targets `ChipWhisperer-Lite ARM` and `discovery board stm23f4`. Some notebooks come from the [`chipwhisperer` Project](https://github.com/newaetech/chipwhisperer/)
- [`pqm4`](https://github.com/mupq/pqm4): It holds several implementations of post quantum sign and kem schemes (which were under consideration from NIST). Here I had to adjust the code in many ways to build a firmware that is suitable for my work.
- `scripts`: self written scripts which are in use by the jupyter notebooks.

### pqm4
Inside the pqm4 folder one can use
```
make -j4 PLATFORM=cw308t-stm32f415 OPT_SIZE=1
```
to build the firmware for the target `cw308t-stm32f415`, other supported targets are `stm32f4discovery`, `cw308t-stm32f3`, `mps2-an386`. The `-j` flag allows to set the number of cores to use for building. Besides the `OPT_SIZE` flag there are multiple others which can be found in the pqm4 [README](pqm4/README.md).
To run the interactive firmware with the `mps2-an386` target one can call
```qemu-system-arm -M mps2-an386 -nographic -serial pty -semihosting -kernel elf/mupq_crypto_kem_bikel1_opt_fi.elf```
This prompts the pty device which can be used as serial.

### Scripts
Functionality of the scripts found in the `scripts/` folder.

#### Shell
- `preparse_sage.sh` is used to generate `.py` files from the two `.sage` files. The generated `.py` files can be imported in other python scripts. It is way more easy this way, than directly calling sage scripts from python.

#### Python
- `bike_key.py` handles BIKE cryptographic keys. Can handle both, keys from the Reference Implementation as well as keys from pqm4. Pivotal methods are `calculate_pk`, `faulty_key`, `analyze_key` and the class `BIKE_key`.
- `kat_bike.py` implements a KAT `.rsp` file parser for BIKE KATs generated with the Reference Implementation, a KAT parser for the target's output, the possibility to compare KAT entries and the class Level. The latter holds some security level specific values and by this is very helpful.
- `target_com.py` is the counter part for the interactive firmware implemented in `pqm4/mupq/crypto_kem/fi.c`. It is basically a wrapper for the serial interface to make communication less error prone.
- `BIKE_params.py` and `threshold.py` were generated from the corresponding `.sage` files.

#### Sage
- `BIKE_params.sage` has three methods, `hardcode_params`, `properties` and `print_defines`. These offer to calculate proper BIKE parameters given a `r`, additionally the row weight `D` and/or the error weight `T` can be given. The first method uses the code which can be found at `pqm4/crypto_kem/bikel*/m4f/gf2x_inv.c` or at `pqm4/mupq/crypto_kem/bikel*/opt/gf2x_inv.c` to generate hardcoded values for optimization. `properties` can check the mathematical properties `r` should hold, suggests values for `D` and `T` and calculates the threshold coefficients. The last method `print_defines` prints out all the calculated values which can be copied and pasted into the corresponding files inside the pqm4 level definition.
- `threshold.sage` was adapted from Ketelsen. For this repo the most important function is to calculate the threshold given a set of BIKE parameters and calculate an approximation (linear function) and give the coefficients for the approximation.

## Clone this Repo
Either use `git clone --recursive ...` to clone this repository and all ist submodules or if you already cloned it, you can use `git submodule update --init --recursive` to clone all the submodules.