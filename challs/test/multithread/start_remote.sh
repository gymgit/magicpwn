#!/bin/bash

socat tcp-l:1337,fork,reuseaddr EXEC:"./app.sh"
