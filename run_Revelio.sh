#!/usr/bin/env sh

# call the script with sudo!!
# example:
# sudo bash ./run_Revelio.sh revelio_on_location "unique-location-name"
# the name of the location should not go over 100 characters

# get the working directory
DIR="$( cd "$( dirname $0 )" && pwd )"

# create the results file in /tmp ? 
# add curl command to download the test binary here 

# get the mac address
# ---------------------------------------------------------------------------
unamestr=`uname`
if [[ "$unamestr" == 'Linux' ]]; then
  # gnu/linux
  mac=$( ( ip link show | grep eth | awk '/ether/ {print $2}' | head -1 ) \
           2>/dev/null );
  if [ -z "$mac" ]; then
    # openwrt
    mac=$( ( ifconfig br-lan | awk '/HWaddr/ {print $5}' ) 2> /dev/null );
  fi
elif [[ "$unamestr" == 'Darwin' ]]; then
  # mac os x
  mac=$( ( ifconfig | awk '/ether/ {print $2}' ) 2> /dev/null );
fi

if [ -z "$mac" ]; then
  if [ -z "$MACADDRESS" ]; then
    echo "cannot set mac address; set MACADDRESS env" > /dev/stderr;
    exit 1
  else
    mac=$MACADDRESS;
  fi
fi

# uniform UUID representation
mac=`echo $mac | tr "[:upper:]" "[:lower:]"`
# ---------------------------------------------------------------------------

# retrieve the boxid from the server
# ---------------------------------------------------------------------------
data="{\"mac\" : \"${mac}\"}"
boxid=$( (curl -X POST -H "Content-Type: application/json" -d "$data" http://zompopo.it.uc3m.es/measurement_agent 2> /dev/null ) );

if [ -z "$boxid" ]; then
  echo "server did not send uuid" > /dev/stderr; # boxid = uuid
  exit 1
fi
# ---------------------------------------------------------------------------

# verify if miniupnp is installed
miniupnp=$(ldconfig -p | grep "miniupnpc")
#if [ -z "$miniupnp" ]; then
    


#-----------------------------------------------------------------------------

#result file
mkdir -p $DIR/results && touch $DIR/results/$boxid

hour=$( date '+%H' )
day=$( date '+%d' )

$DIR/bin/$1 -l $2 >> $DIR/results/$boxid 2> /dev/null

curl -X POST -F results=@"$DIR/results/$boxid" "http://zompopo.it.uc3m.es/Revelio/$boxid/result" > /dev/null 2>&1
rm -rf $DIR/results 

