#!/bin/sh

docker build -t drvhorn . -f ./docker/drvhorn.Dockerfile
docker run --rm -it -v $PWD:/seahorn drvhorn
