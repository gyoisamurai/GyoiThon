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

# downloading GyoiThon files
RUN apt-get update && \
 	apt-get install git -y && \
	git clone https://github.com/gyoisamurai/GyoiThon.git /opt/GyoiThon

# Procedure
#    1. fixing timezone issue
#    2. installing dependancies   
#    3/4. cleaning up
#    5. Installing python requirements
RUN 	bash $DIR/docker/timezonefix.sh && \
	apt-get install -y dnsutils tmux python3-pip python3-pandas \
		 python3-docopt python3-msgpack python3-jinja2 && \ 
	apt-get clean && \
	rm -rf /var/lib/apt/lists/* && \
	pip3 install -r $DIR/requirements.txt


#    6. Downloading CVE database
RUN cp $DIR/docker/download_cves.py $DIR/download_cves.py && \
	python3 $DIR/download_cves.py 

CMD ["python3", "gyoithon.py", "-m", "-e"]

