ARG BASE_IMAGE=jammy-llvm14
FROM seahorn/buildpack-deps-seahorn:$BASE_IMAGE

RUN pip install wllvm

ENV PATH "/seahorn/build/run/bin:$PATH"
WORKDIR /seahorn
