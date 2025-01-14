# MMA-DT2STIN
Through this repository, we provide readers with some basic frameworks, tools, and use cases about MMA

## Scenario 1: The container communicates with an external host

### Given

**Ubuntu Host A:**

- Wired network card `enx207bd2bd5ad5` with IP: `192.168.2.44/24`
- OVS virtual switch: `192.188.1.1/16`
- Container network: `192.188.0.0/16`

**Windows Host B:**

- Wired Ethernet with IP: `192.168.2.37/24`

**Direct cable connection between A and B**



### Configuration

#### Ubuntu Host A

**Configure the virtual switch and routes on Host A**

##### (1) Configure the virtual switch IP and subnet mask, and bring up the interface:

Configure the OVS virtual switch to act as a gateway, assigning an IP address within the `192.188.0.0/16` network segment. For example, set it to `192.188.1.1`:

```
sudo ifconfig myswitch 192.188.1.1 netmask 255.255.0.0 up 
# Note: This IP is within the container network segment, e.g., 192.188.0.0/16, here it's 192.188.1.1
```

##### (2) Set a static route for the `192.168.2.0/24` network through the gateway `192.168.2.44`:

```
sudo route add –net 192.168.2.0 netmask 255.255.255.0 gw 192.168.2.44
```

##### (3) Disable the firewall:

```
sudo ufw disable
```

**Check the physical interface names and status of the host** (In Linux distributions, the naming convention for network interfaces might differ, such as `enp0s3`, `enp3s0`, `wlp2s0`, etc. It may not be `eth0`, here it is `enx207bd2bd5ad5`)

```
#ip link # List all network interfaces to confirm available interface names on your Ubuntu host
# After knowing the name, you can check the port information directly:
#ip link | grep enx207bd2bd5ad5
ip addr show enx207bd2bd5ad5
# Output:
45: myswitch: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN group default qlen 1000
    link/ether 20:7b:d2:bd:5a:d5 brd ff:ff:ff:ff:ff:ff
    inet 192.188.1.1/16 brd 192.188.255.255 scope global myswitch
       valid_lft forever preferred_lft forever
    inet6 fe80::227b:d2ff:febd:5ad5/64 scope link 
       valid_lft forever preferred_lft forever
ip addr show myswitch
# Output:
4: enx207bd2bd5ad5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel master ovs-system state UP group default qlen 1000
    link/ether 20:7b:d2:bd:5a:d5 brd ff:ff:ff:ff:ff:ff
    inet 192.168.2.44/24 brd 192.168.2.255 scope global enx207bd2bd5ad5
       valid_lft forever preferred_lft forever

# The physical network interface on the Ubuntu host is `enx207bd2bd5ad5`
# If the interface is 'DOWN', you need to bring it up:
#sudo ip link set enx207bd2bd5ad5 up
```

#### Inside the Container

Add a route or default gateway (choose one of the two options):

```
ip route add default via 192.188.1.1 dev eth1 # Recommended
ip route add 192.168.2.37 via 192.188.1.1 dev eth1
```

#### Windows Host B

##### 1. Configure Host B

- The IP address of Windows Host B has been set to `192.168.1.21`, which is in the same subnet as Host A, and is directly connected to Host A via a network cable.
- Test network connectivity:
  - Use `ping 192.168.2.44 -n 100` from the Windows host to test connectivity to the Ubuntu host.
  - Use `ping 192.188.1.1` to test connectivity to the OVS virtual switch (if it doesn’t ping, check the firewall and routing settings on the Ubuntu host).

##### 2. Add a Route

```
route add 192.188.0.0 mask 255.255.0.0 192.168.1.47
# This tells the Windows host that packets destined for the 192.188.0.0/16 network should be routed through the next-hop gateway 192.168.1.47.
```

**During the troubleshooting process, you can use `tcpdump` on Host A and the container to capture packets and identify where the issue occurs:**

```
# Capture ICMP (ping) packets
sudo tcpdump -i enx207bd2bd5ad5 -nn icmp
sudo tcpdump -i myswitch -nn icmp

# Capture ARP packets
sudo tcpdump -i enx207bd2bd5ad5 -nn arp
sudo tcpdump -i myswitch -nn arp
```
