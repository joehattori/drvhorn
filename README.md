DrvHorn is a tool to detect reference counting bugs in Linux kernel drivers, based on a CHC verification framework [SeaHorn](https://github.com/seahorn/seahorn).

# Setup
As DrvHorn is implemented as an extension of SeaHorn, the building process is the same as SeaHorn.
The easiest way would be to use docker, as explained in [SeaHorn's README](https://github.com/seahorn/seahorn/blob/main/README.md#installation).

DrvHorn targets Linux kernel v6.6, and the LLVM bitcode file of the Linux kernel is needed to run DrvHorn.
Users can either apply [this patch](https://github.com/joehattori/drvhorn/blob/main/patches/gen-llvm-bc.patch) to the Linux kernel repository and run `make LLVM=-14 BUILD_BC=1`, or download [an example LLVM bitcode file](https://drive.google.com/file/d/1UfBD8rnrLpGEOew3ZuU9CYK2_a_BR2g4/view?usp=sharing) which we prepared.

# Usage
After building DrvHorn and acquiring the LLVM bitcode file, users can run DrvHorn as follows (assuming the user is in `./build`):
- `./run/bin/sea kernel --i2c-driver=ht16k33_driver /path/to/kernel.bc` should emit `sat`, indicating that the driver `ht16k33_driver` had a refcount bug.
- `./run/bin/sea kernel --platform-driver=ged_driver /path/to/kernel.bc` should emit `unsat`, indicating that the driver `ged_driver` is free of refcount bugs.
