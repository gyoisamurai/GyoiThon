FROM kalilinux/kali-linux-docker

RUN apt-get update && apt-get install -y metasploit-framework tmux python3-pandas python3-docopt python3-msgpack python3-jinja2 && apt-get clean && rm -rf /var/lib/apt/lists/*

##Setup MSF
RUN curl -sSL https://github.com/gyoisamurai/GyoiThon/raw/master/docker/msf_setup/db.sql --output /tmp/db.sql
RUN /etc/init.d/postgresql start && su postgres -c "psql -f /tmp/db.sql"
RUN curl -sSL https://github.com/gyoisamurai/GyoiThon/raw/master/docker/msf_setup/database.yml --output /usr/share/metasploit-framework/config/database.yml

#Setup Gyoithon
RUN git clone https://github.com/gyoisamurai/GyoiThon /opt/gyiothon
RUN curl -sSL https://github.com/gyoisamurai/GyoiThon/raw/master/docker/msf_setup/meterpreter.rc --output /tmp/meterpreter.rc
RUN curl -sSL https://github.com/gyoisamurai/GyoiThon/raw/master/docker/gyoithon_setup/config.ini --output /opt/gyiothon/classifier4gyoithon/config.ini

##Clean up a few things broken in the code due to suboptimal development
RUN find /opt/gyiothon -name "*.py" -type f | xargs sed -i -e '/OKGREEN + banner + ENDC/d'

WORKDIR "/opt/gyiothon/"

CMD /etc/init.d/postgresql start; tmux new-session -d -s cool 'msfconsole -r /tmp/meterpreter.rc'; sleep 180; curl localhost:55553; python3 /opt/gyiothon/gyoithon.py

########How to run
#Prepopulate your host file with the targets (IE testaspnet.vulnweb.com 80 / )
#docker run -v $PWD/host.txt:/opt/gyiothon/host.txt <container name>
