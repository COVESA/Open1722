sudo ip link add dev acfcan0 type acfcan
sudo ip link set acfcan0 mtu 16
sudo echo -n "lo"  | sudo tee /sys/class/net/acfcan0/acfcan/ethif
sudo ip link set up acfcan0
