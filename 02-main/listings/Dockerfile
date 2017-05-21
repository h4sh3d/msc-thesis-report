FROM debian:8
MAINTAINER "Joel.Gugger@master.hes-so.ch"

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get dist-upgrade -y

RUN apt-get install -y --no-install-recommends \
	dialog apt-utils software-properties-common

# Install utilities
RUN apt-get install -y vim nano wget make

# Install llvm 4.0
RUN add-apt-repository 'deb http://apt.llvm.org/jessie/ llvm-toolchain-jessie-4.0 main'
RUN wget -O - http://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - && apt-get update
RUN apt-get install -y clang-4.0 lldb-4.0 lld-4.0

# Install 32 bits dependencies and gdb
RUN dpkg --add-architecture i386 && \
	apt-get update && \
	apt-get install -y build-essential gcc-multilib rpm libstdc++6:i386 libgcc1:i386 zlib1g:i386 libncurses5:i386
RUN apt-get install -y gdb file

COPY ./.bash_profile /root/.bash_profile
RUN cat /root/.bash_profile >> /root/.bashrc

WORKDIR /shared

ENTRYPOINT echo "The container is ready!" && sleep 10000000