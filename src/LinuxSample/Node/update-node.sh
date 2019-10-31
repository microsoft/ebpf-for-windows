#!/bin/bash

echo ----------- Node -----------------------------
nodejs --version

sudo npm cache clean -f
sudo npm install -g n
sudo n stable

nodejs --version
