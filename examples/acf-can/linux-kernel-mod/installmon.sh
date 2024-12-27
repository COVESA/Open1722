ip link add dev mon1 type veth peer name mon2
ip link set dev mon2 up
ip link set dev mon1 up
