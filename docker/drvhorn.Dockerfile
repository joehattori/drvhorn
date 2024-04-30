ARG BASE_IMAGE=jammy-llvm14
FROM seahorn/buildpack-deps-seahorn:$BASE_IMAGE

RUN pip install wllvm
RUN ln -s $(which clang-14) /usr/bin/clang
RUN ln -s $(which llvm-objcopy-14) /usr/bin/llvm-objcopy
RUN ln -s $(which llvm-symbolizer-14) /usr/bin/llvm-symbolizer
RUN apt-get update && apt-get install -y file

ENV PATH "/seahorn/build/run/bin:$PATH"
ENV WLLVM_OBJCOPY "llvm-objcopy"
ENV LLVM_COMPILER "clang"
ENV LLVM_CC_NAME "clang-14"
ENV LLVM_CXX_NAME "clang-14"
ENV LLVM_LINK_NAME "llvm-link-14"
ENV LLVM_AR_NAME "llvm-ar-14"
WORKDIR /seahorn
