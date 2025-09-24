FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    wget build-essential libssl-dev \
    git \
    python3 \
    python3-pip \
    python3-venv \
    python3-matplotlib \
    python3-seaborn \
    python3-ipykernel \
    python3-h5py \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN pip install numpy==1.26.0 --break-system-packages
RUN pip install tensorflow --break-system-packages
RUN update-alternatives --install /usr/bin/python python /usr/bin/python3 1

WORKDIR /workspace

CMD ["python"]

RUN wget https://github.com/Kitware/CMake/releases/download/v3.22.0/cmake-3.22.0-linux-x86_64.sh \
    && chmod +x cmake-3.22.0-linux-x86_64.sh \
    && ./cmake-3.22.0-linux-x86_64.sh --skip-license --prefix=/usr/local \
    && rm cmake-3.22.0-linux-x86_64.sh
RUN cmake --version


