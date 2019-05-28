#
# Timezonefix.sh
#
# Building the dockerfile requested user input to ask for the timezone.
# We cannot provide manual user input when building containers.
# This script will prevent the installation of tzdata from requesting
# user input.
#

# set noninteractive installation
export DEBIAN_FRONTEND=noninteractive

#install tzdata package
apt-get install -y tzdata

# set your timezone
ln -fs /usr/share/zoneinfo/Americas/Vancouver /etc/localtime
dpkg-reconfigure --frontend noninteractive tzdata
