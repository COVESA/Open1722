
# Simulate two ecus bridged


sudo ip link add dev ecu1 type acfcan
sudo ip link add dev ecu2 type acfcan

sudo ip link set ecu1 mtu 72
sudo ip link set ecu2 mtu 72

sudo echo -n "mon1"  | sudo tee /sys/class/net/ecu1/acfcan/ethif
sudo echo -n "mon2"  | sudo tee /sys/class/net/ecu2/acfcan/ethif

sudo echo -n $(cat /sys/class/net/mon2/address)  | sudo tee /sys/class/net/ecu1/acfcan/dstmac
sudo echo -n $(cat /sys/class/net/mon1/address)  | sudo tee /sys/class/net/ecu2/acfcan/dstmac


sudo echo -n "cafe11"  | sudo tee /sys/class/net/ecu1/acfcan/tx_streamid
sudo echo -n "dead22"  | sudo tee /sys/class/net/ecu2/acfcan/tx_streamid

sudo echo -n "dead22"  | sudo tee /sys/class/net/ecu1/acfcan/rx_streamid
sudo echo -n "cafe11"  | sudo tee /sys/class/net/ecu2/acfcan/rx_streamid

sudo ip link set up ecu1
sudo ip link set up ecu2



