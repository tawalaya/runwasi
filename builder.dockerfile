FROM rust:1.86
RUN apt-get update && apt-get install -y protobuf-compiler libseccomp-dev pkg-config
