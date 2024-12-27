sudo ip link add dev acfcan1 type acfcan
sudo ip link set acfcan1 mtu 72
sudo echo -n "lo"  | sudo tee /sys/class/net/acfcan1/acfcan/ethif
sudo ip link set up acfcan1
