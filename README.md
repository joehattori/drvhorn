DrvHorn is a tool to detect reference counting bugs in Linux kernel drivers, based on a CHC verification framework [SeaHorn](https://github.com/seahorn/seahorn).

# Setup and Example Usage

Users can use DrvHorn via Docker image we provided.

```shell
docker pull joehattori/drvhorn
```

`./scripts/run-drvhorn.sh` is a handy script to run DrvHorn with Docker.
When refcount bugs are detected, `sat` is emitted at the end of the output, and `unsat` is emitted when no bugs are found.

For example,

```shell
./scripts/run-drvhorn.sh --file-operations=tpm_bios_measurements_ops
```

outputs `sat` at the last line, indicating a refcount bug is detected in `tpm_bios_measurements_ops`.
This bug was fixed in [this commit](https://github.com/torvalds/linux/commit/5d8e2971e817bb64225fc0b6327a78752f58a9aa).

On the other hand, for drivers that DrvHorn do not find any refcount bugs, such as `ged_driver`,

```shell
./scripts/run-drvhorn.sh --platform-driver=ged_driver
```

outputs `unsat` at the last line.

## Manual Setup

### Building the Docker Image

Users can also build this image from the Dockerfile we provided.
After downloading a simple LLVM bitcode of Linux kernel from [here](https://drive.google.com/file/d/1UfBD8rnrLpGEOew3ZuU9CYK2_a_BR2g4/view?usp=sharing) to `./simple_kernel.bc`.

```shell
docker build -t joehattori/drvhorn -f docker/drvhorn.Dockerfile .
```

will build the Docker image.

### Building Locally

If users want to build DrvHorn in their local environment, manually executing the commands in [docker/drvhorn.Dockerfile](docker/drvhorn.Dockerfile) should work.
Note that users need to download Z3 of a specific version.
More detailed instructions can be found in the [seahorn repository](https://github.com/seahorn/seahorn).

### Building Linux Kernel into LLVM bitcode

When users wish to analyze Linux kernel with a custom config, they need to build the Linux kernel into an LLVM bitcode file.
After configuring the kernel, users can apply [this patch](https://github.com/joehattori/drvhorn/blob/main/patches/gen-llvm-bc.patch) to the Linux kernel repository and run `make LLVM=-14 BUILD_BC=1` to obtain the LLVM file.

# Evaluation

For lightweight evaluation, we provided a simple script to run DrvHorn with a trimmed down kernel on multiple drivers in `./scripts/eval.sh`.

```shell
./scripts/eval.sh
```

As described above, `sat` indicates that refcount bugs are detected by the tool, and `unsat` indicates no bugs are found.
The result for each driver is emitted with its "expected" (correct) result -
if the tool emits `sat` and the "expected" is also `sat`, it means the target driver actually has a refcount bug and the tool detected it.
On the other hand, if the tool emits `sat` with the "expected" being `unsat`, it indicates a false positive
(`acpi_wmi_driver` in this script is an example of a false positive).
This script will take about 5 minutes.

For full evaluation on all platform drivers, download the LLVM bitcode file we provided [here](https://drive.google.com/file/d/1qIu_5Z9rING1phQ0vd7DC9VRv7B95F69/view?usp=sharing) and run:

```shell
./scripts/full-eval.sh --full-kernel-bc=path/to/full/kernel.bc
```

Users can also build the LLVM bitcode file by themselves by building the Linux kernel configured with `allyesconfig` into LLVM bitcode.
Please note that this script will take about 3-4 days without parallelisation.
We will provide an option to run the evaluation in parallel, but each thread will require about 10GB of free RAM.

# Paper-code mapping

DrvHorn is developed as a fork of SeaHorn, and most of the modifications are made in the directory[lib/Transforms/Kernel/]{https://github.com/joehattori/drvhorn/tree/main/lib/Transforms/Kernel}.

The following table gives a mapping describing in which file the contents of the paper can be found.
| Functionality/Step                                 | Appearance in the paper                       | Where it is implemented                                                                                                                                                                                                |
| -------------------------------------------------- | --------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Insertion of assertions on the refcount invariants | Section 3.1 | [SetupEntrypoint.cc](https://github.com/joehattori/drvhorn/blob/main/lib/Transforms/Kernel/SetupEntrypoint.cc), [AssertKrefs.cc](https://github.com/joehattori/drvhorn/blob/main/lib/Transforms/Kernel/AssertKrefs.cc) |
| Modelling of device tree and firmware nodes        | Section 3.2               | [Device.cc](https://github.com/joehattori/drvhorn/blob/main/lib/Transforms/Kernel/Device.cc)                                                                                                                           |
| Modeling of devices, buses, and device classes     | Section 3.2               | [Device.cc](https://github.com/joehattori/drvhorn/blob/main/lib/Transforms/Kernel/Device.cc)                                                                                                                           |
| Modeling of device resource management             | Section 3.2               | [Devm.cc](https://github.com/joehattori/drvhorn/blob/main/lib/Transforms/Kernel/Devm.cc)                                                                                                                               |
| Modeling of other APIs                             | Section 3.2               | [Device.cc](https://github.com/joehattori/drvhorn/blob/main/lib/Transforms/Kernel/Device.cc)                                                                                                                           |
| Program slicing                                    | Section 3.2                | [Slicer.cc](https://github.com/joehattori/drvhorn/blob/main/lib/Transforms/Kernel/Slicer.cc)                                                                                                                           |
| Replacement of inline assemblies                   | Section 3.1 | [HandleInlineAsm.cc](https://github.com/joehattori/drvhorn/blob/main/lib/Transforms/Kernel/HandleInlineAsm.cc)                                                                                                         |
