#!/bin/sh
if ! grep llvm /etc/apt/sources.list
then
cat >> /etc/apt/sources.list << EOF
deb http://apt.llvm.org/buster/ llvm-toolchain-buster main 
deb-src http://apt.llvm.org/buster/ llvm-toolchain-buster main 
deb http://apt.llvm.org/buster/ llvm-toolchain-buster-10 main 
deb-src http://apt.llvm.org/buster/ llvm-toolchain-buster-10 main 
deb http://apt.llvm.org/buster/ llvm-toolchain-buster-11 main 
deb-src http://apt.llvm.org/buster/ llvm-toolchain-buster-11 main
EOF
fi
wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -
dpkg --add-architecture i386
apt-get update
apt-get install -y clang-11 libelf-dev:i386
