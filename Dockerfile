FROM ubuntu:latest

MAINTAINER ymorired

RUN locale-gen en_US.UTF-8  
ENV LANG en_US.UTF-8  
ENV LANGUAGE en_US:en  
ENV LC_ALL en_US.UTF-8

RUN apt-get update && \
    apt-get install -yq python-dev wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    wget https://bootstrap.pypa.io/ez_setup.py -O - | python && \
    easy_install pip && \
    mkdir -p /var/app && \
    mkdir -p /var/data

ADD requirements.txt /var/app/
WORKDIR /var/app/
RUN pip install -r requirements.txt
ADD . /var/app/

VOLUME ["/var/data"]
WORKDIR /var/data
ENTRYPOINT [ "/var/app/s4backup.py" ]

