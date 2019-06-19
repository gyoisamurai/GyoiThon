docker rm -f gyoithon  2> /dev/null

docker run \
	--rm \
	-it \
	-v ${PWD}/host.txt:/opt/GyoiThon/host.txt \
	-v ${PWD}/report:/opt/GyoiThon/report \
	--name gyoithon_test \
	gyoithon 
