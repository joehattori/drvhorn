ARG BASE_IMAGE=jammy-llvm14
FROM seahorn/buildpack-deps-seahorn:${BASE_IMAGE}

COPY . /drvhorn
WORKDIR /drvhorn

RUN rm -rf /drvhorn/build /drvhorn/debug /drvhorn/release && \
  mkdir /drvhorn/build && \
  rm -rf /drvhorn/clam /drvhorn/sea-dsa /drvhorn/llvm-seahorn

WORKDIR /drvhorn/build

ARG BUILD_TYPE=RelWithDebInfo

RUN cmake .. -GNinja \
  -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
  -DZ3_ROOT=/opt/z3-4.8.9 \
  -DCMAKE_INSTALL_PREFIX=run \
  -DCMAKE_CXX_COMPILER=clang++-14 \
  -DCMAKE_C_COMPILER=clang-14 \
  -DSEA_ENABLE_LLD=ON

RUN ninja extra
RUN ninja crab
RUN cmake ..
RUN ninja
RUN ninja install

WORKDIR /drvhorn/build
