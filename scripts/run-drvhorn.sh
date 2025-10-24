#!/bin/bash

docker run --rm joehattori/drvhorn /drvhorn/build/run/bin/sea kernel "${@:1}" /drvhorn/simple_kernel.bc 2>/dev/null

