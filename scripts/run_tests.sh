#!/bin/bash

set -eu

pushd build
../scripts/build-seahorn.sh
SEAHORN=$PWD/run/bin/sea lit ../test/kernel/
popd
