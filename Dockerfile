FROM python:3.8-buster
RUN pip3 install threatspec && apt-get update && apt-get install -y graphviz && rm -rf /var/lib/apt/lists/*
WORKDIR /data
ENTRYPOINT ["threatspec"]