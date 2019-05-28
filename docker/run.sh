docker stop sst_api_gyoithon 2> /dev/null
docker rm sst_api_gyoithon  2> /dev/null

docker run \
	--rm \
	-it \
	-v ${PWD}/host.txt:/opt/GyoiThon/host.txt \
	-v ${PWD}/report:/opt/GyoiThon/report \
	--name gyoithon_test \
	sst_api_gyoithon 
