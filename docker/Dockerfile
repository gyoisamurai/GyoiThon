# 
# Gyoithon Dockerfile!
#
# Author: Isaac Thiessen May 2019 
# 
# How to run:
# 	0. build image ( ./build.sh )
# 	1. edit host file
#	2. run Gyoithon ( ./run.sh )
#
# Tested on Ubuntu 19.10

FROM ubuntu:latest

ENV LANG C.UTF-8
ENV LC_ALL C.UTF-8

ARG DIR=/opt/GyoiThon

WORKDIR $DIR

# preventing one of the installs from requesting user input
COPY ./timezonefix.sh /tmp/timezonefix.sh

# Procedure
#    1. updating package lists
#    2. fixing timezone issue
#    3. installing dependancies   
#    4/5. cleaning up
#    6. Downloading gyoithon
#    7. Installing python requirements
RUN apt-get update && \
	bash /tmp/timezonefix.sh && \
	apt-get install -y tmux git python3-pip python3-pandas \
		 python3-docopt python3-msgpack python3-jinja2 && \ 
	apt-get clean && \
	rm -rf /var/lib/apt/lists/* && \
	git clone https://github.com/gyoisamurai/GyoiThon.git /opt/GyoiThon && \
	pip3 install -r $DIR/requirements.txt 

# updating cve database
# this just saves time everytime you run the image
COPY ./download_cves.py $DIR/download_cves.py
RUN python3 $DIR/download_cves.py

CMD ["python3", "gyoithon.py", "-m", "-e", "-c", "-s"]

