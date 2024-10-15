ARG BASE_IMAGE=jammy-llvm14
FROM seahorn/buildpack-deps-seahorn:$BASE_IMAGE

RUN ln -s $(which clang-14) /usr/bin/clang
RUN ln -s $(which llvm-objcopy-14) /usr/bin/llvm-objcopy
RUN ln -s $(which llvm-symbolizer-14) /usr/bin/llvm-symbolizer
RUN apt-get update && apt-get install -y file

ENV PATH "/seahorn/build/run/bin:$PATH"
WORKDIR /seahorn
