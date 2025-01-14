# MMA-DT2STIN
Through this repository, we provide readers with some basic frameworks, tools, and use cases about MMA

We will continue to update later


## Scenario 1: The container communicates with an external host

### Given

**Ubuntu Host A:**

- Wired network card `enx207bd2bd5ad5` with IP: `192.168.2.44/24`
- virtual NIC on the OVS: `192.188.1.1/16`
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





## Scenario 2: Container Network Horizontal Deployment Across Hosts

**Goal:** Achieve large-scale horizontal scaling of container clusters. Due to the limitations of single-machine hardware resources, containers can be horizontally deployed across multiple hosts. By using VXLAN to connect Open vSwitch (OVS) instances on different hosts, and launching a Ryu controller on one host, we can connect all OVS instances to this centralized Ryu controller for unified management of flow tables across multiple hosts. From the perspective of a single container, the entire container cluster appears to run in the same host environment.

### (1) **what is VXLAN**

Overlay networks are a commonly used technology for container networking. They create a virtual network layer that operates on top of the existing network infrastructure. For example, using **VXLAN** (Virtual Extensible LAN) technology, an overlay network can be established between Host A and Host B, **enabling containers on both hosts to communicate as if they were in the same network**. This means that regardless of the host or data center where a container instance is located, the containers can seamlessly communicate via the overlay network.

**Application of VXLAN Technology**

- **VXLAN** (Virtual Extensible LAN) is a popular overlay network technology that uses a Layer 3 IP network (e.g., the Internet) to support large-scale Layer 2 virtual LANs (VLANs). With VXLAN, each container is assigned a unique Virtual Network Identifier (VNI), allowing a logical Layer 2 network to be established across different hosts. The process of VXLAN packet encapsulation and decapsulation allows these packets to be securely transmitted across different network segments, enabling communication between containers.

- **Network Function Virtualization (NFV):** By using advanced virtual switches like Open vSwitch (OVS), we can implement more complex network functions and policies at the network layer, such as routing, firewalls, load balancing, etc. By configuring OVS and a Ryu controller, we can enforce these network policies on top of the overlay network, further controlling and managing cross-host container communication.

### (2) Implementation Steps

The following example will deploy 5 containers on Host A connected to an OVS named `myswitch_1` and 5 containers on Host B connected to an OVS named `myswitch_2`. The Ryu controller will be started on Host A, forming a chain topology with 5+5=10 containers.

#### **Host A Script (Deploy Ryu Controller)**

```bash
#!/bin/bash
# Host A (IP: 192.168.2.44)

# Create OVS virtual switch (if not already created)
sudo ovs-vsctl del-br myswitch_1
sudo ovs-vsctl add-br myswitch_1

# Set OVS virtual switch controller
sudo ovs-vsctl set-controller myswitch_1 tcp:127.0.0.1:6633

# Create and configure containers
for i in {1..5}
do
   # Remove any existing containers with the same name
   if [ $(sudo docker ps -a -q -f name=c_$i) ]; then
       docker rm -f c_$i
   fi

   # Create new containers
   docker run -itd --rm --privileged --name=c_$i --network=none -e DISPLAY=$DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix -v /home/Desktop/crossHostContainers/volume_file:/volume_file ubuntu_htop:18.04 /bin/bash

   # Add OVS ports
   sudo ovs-docker add-port myswitch_1 eth1 c_$i --ipaddress=192.188.1.1$i/16 --macaddress=00:00:00:00:00:0$i
done

# Configure Host B IP
sudo ovs-vsctl add-port myswitch_1 vxlan0 -- set interface vxlan0 type=vxlan options:remote_ip=192.168.2.37 options:key=100

# Configure OVS switch IP
sudo ifconfig myswitch_1 192.188.1.1 netmask 255.255.0.0 up 
# Set static route for 192.168.2.0/24 network via gateway 192.168.2.44
sudo route add -net 192.168.2.0 netmask 255.255.255.0 gw 192.168.2.44
# Disable firewall
sudo ufw disable

# Open a new Xfce Terminal window and run interactive bash sessions in different tabs for each container
xfce4-terminal \
--tab --title "Ryu" --command "bash -c 'sudo ryu-manager --ofp-tcp-listen-port=6633 --ofp-listen-host=0.0.0.0 ryu.app.ofctl_rest /home/Desktop/crossHostContainers/get_datapath_idTEST.py'" \
--tab --title "1" --command "bash -c 'docker exec -it c_1 /bin/bash -c \"ip route add default via 192.188.1.1; cd volume_file/; exec bash\"'" \
--tab --title "2" --command "bash -c 'docker exec -it c_2 /bin/bash -c \"ip route add default via 192.188.1.1; cd volume_file/; exec bash\"'" \
--tab --title "3" --command "bash -c 'docker exec -it c_3 /bin/bash -c \"ip route add default via 192.188.1.1; cd volume_file/; exec bash\"'" \
--tab --title "4" --command "bash -c 'docker exec -it c_4 /bin/bash -c \"ip route add default via 192.188.1.1; cd volume_file/; exec bash\"'" \
--tab --title "5" --command "bash -c 'docker exec -it c_5 /bin/bash -c \"ip route add default via 192.188.1.1; cd volume_file/; exec bash\"'" &
```

- ```bash
  sudo ovs-vsctl set-controller myswitch_1 tcp:127.0.0.1:6633
  ```

  This configures the controller for `myswitch_1` to communicate with the Ryu controller on the local host at port 6633.

- ```bash
  sudo ovs-vsctl add-port myswitch_1 vxlan0 -- set interface vxlan0 type=vxlan options:remote_ip=192.168.2.37 options:key=100
  ```

  This adds a new port `vxlan0` to the `myswitch_1` switch, sets the port type to VXLAN tunnel, configures the remote IP address for the VXLAN tunnel to `192.168.2.37`, and sets the VXLAN key to `100` (the VXLAN Network Identifier or VNI used to differentiate between tunnels).

- ```bash
  sudo ryu-manager --ofp-tcp-listen-port=6633 --ofp-listen-host=0.0.0.0 ryu.app.ofctl_rest /home/Desktop/crossHostContainers/get_datapath_idTEST.py
  ```

  `--ofp-listen-host=0.0.0.0`: Configures the Ryu controller to listen on all available network interfaces, ensuring that OpenFlow connections from any interface are accepted.

  `ryu.app.ofctl_rest`: Loads the `ofctl_rest` application, which provides a REST API for interacting with the Ryu controller. This allows remote management and querying of OpenFlow switches and their flow tables.

#### Ryu Script

```bash
import logging
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet

class ChainTopology(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ChainTopology, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = [] # Stores the connected OVS datapaths
        self.bridge_to_datapath_id = {}     # Key-value pair: datapath.id - datapath
        self.datapath_id_to_bridge_name = {}    # Key-value pair: datapath.id - bridge_name
        self.switch_ready = set()   # Datapath IDs of switches that are ready
        self.pending_switch_features = {}   # Stores pending switch_features events
        self.logger.setLevel(logging.INFO)  # Set the logging level to INFO

    # State change handler - Triggered by EventOFPStateChange
    # When the switch enters MAIN_DISPATCHER -> sends Port Description request to get the switch name
    # When the switch enters CONFIG_DISPATCHER -> Removes the corresponding datapath and mappings
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath not in self.datapaths:
                self.datapaths.append(datapath)
                self.bridge_to_datapath_id[datapath.id] = datapath
                self.logger.info("Switch connected: datapath_id=%s", format(datapath.id, "016x"))
                parser = datapath.ofproto_parser
                req = parser.OFPPortDescStatsRequest(datapath)  # Send Port Description request to get switch name
                datapath.send_msg(req)
        elif ev.state == CONFIG_DISPATCHER:
            if datapath in self.datapaths:
                self.datapaths.remove(datapath)
                if datapath.id in self.bridge_to_datapath_id:
                    del self.bridge_to_datapath_id[datapath.id]
                if datapath.id in self.datapath_id_to_bridge_name:
                    del self.datapath_id_to_bridge_name[datapath.id]

    # Port Description Reply handler - Triggered by EventOFPPortDescStatsReply
    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        datapath = ev.msg.datapath
        for p in ev.msg.body:
            if p.name.startswith(b'myswitch_'):     # Check if the port name starts with 'myswitch_'
                bridge_name = p.name.decode('utf-8')    # Decode the port name from bytes to string to get the switch name
                self.datapath_id_to_bridge_name[datapath.id] = bridge_name
                self.logger.info("Switch %s connected with datapath_id=%s", bridge_name, format(datapath.id, "016x"))
                self.switch_ready.add(datapath.id)      # Add to the switch_ready set to indicate the switch is ready
                break
        # Check if both switches are connected
        if len(self.switch_ready) == 2:
            self.logger.info("Both switches connected, sending Features Request")
            for dp in self.datapaths:
                parser = dp.ofproto_parser
                features_req = parser.OFPFeaturesRequest(dp)
                dp.send_msg(features_req)

        # Check if there are any pending switch features events to handle
        if datapath.id in self.pending_switch_features:
            self.switch_features_handler(self.pending_switch_features[datapath.id])

    # Switch Features handler - Triggered by EventOFPSwitchFeatures
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.logger.info("switch_features_handler - Switch features handler called for datapath_id=%s", format(datapath.id, "016x"))

        self.mac_to_port[datapath.id] = {}
        self.clear_flow_table(datapath, ofproto, parser)    # Clear the flow table
        bridge_name = self.datapath_id_to_bridge_name.get(datapath.id, None)
        vxlan_port_1 = 6
        vxlan_port_2 = 6
        if bridge_name:
            if bridge_name == 'myswitch_1':
                self.logger.info("switch_features_handler - do myswitch_1 init_switch_flows")
                self.init_switch_flows_myswitch_1(datapath, ofproto, parser, vxlan_port_1)
            elif bridge_name == 'myswitch_2':
                self.logger.info("switch_features_handler - do myswitch_2 init_switch_flows")
                self.init_switch_flows_myswitch_2(datapath, ofproto, parser, vxlan_port_2)
        else:
            # Store the event in the pending queue
            self.pending_switch_features[datapath.id] = ev

    def init_switch_flows_myswitch_1(self, datapath, ofproto, parser, vxlan_port):
        self.logger.info("Initializing switch flows for myswitch_1")

        # Add local flow rules
        self.add_flow(datapath, 1, "00:00:00:00:00:01", "00:00:00:00:00:02", 1, 2, parser, ofproto)
        self.add_flow(datapath, 1, "00:00:00:00:00:02", "00:00:00:00:00:01", 2, 1, parser, ofproto)
        self.add_flow(datapath, 1, "00:00:00:00:00:02", "00:00:00:00:00:03", 2, 3, parser, ofproto)
        self.add_flow(datapath, 1, "00:00:00:00:00:03", "00:00:00:00:00:02", 3, 2, parser, ofproto)
        self.add_flow(datapath, 1, "00:00:00:00:00:03", "00:00:00:00:00:04", 3, 4, parser, ofproto)
        self.add_flow(datapath, 1, "00:00:00:00:00:04", "00:00:00:00:00:03", 4, 3, parser, ofproto)
        self.add_flow(datapath, 1, "00:00:00:00:00:04", "00:00:00:00:00:05", 4, 5, parser, ofproto)
        self.add_flow(datapath, 1, "00:00:00:00:00:05", "00:00:00:00:00:04", 5, 4, parser, ofproto)

        # Add cross-host flow rules via VXLAN tunnel interface
        self.add_flow(datapath, 1, "00:00:00:00:00:05", "00:00:00:00:00:06", 5, vxlan_port, parser, ofproto)
        self.add_flow(datapath, 1, "00:00:00:00:00:06", "00:00:00:00:00:05", vxlan_port, 5, parser, ofproto)

        # Add local broadcast flow rules
        self.add_broadcast_flow(datapath, 1, [2], parser, ofproto)
        self.add_broadcast_flow(datapath, 2, [1, 3], parser, ofproto)
        self.add_broadcast_flow(datapath, 3, [2, 4], parser, ofproto)
        self.add_broadcast_flow(datapath, 4, [3, 5], parser, ofproto)
        self.add_broadcast_flow(datapath, 5, [4, vxlan_port], parser, ofproto)
        self.add_broadcast_flow(datapath, vxlan_port, [5], parser, ofproto)

    def init_switch_flows_myswitch_2(self, datapath, ofproto, parser, vxlan_port):
        self.logger.info("Initializing switch flows for myswitch_2")

        # Add local flow rules
        self.add_flow(datapath, 1, "00:00:00:00:00:06", "00:00:00:00:00:07", 1, 2, parser, ofproto)
        self.add_flow(datapath, 1, "00:00:00:00:00:07", "00:00:00:00:00:06", 2, 1, parser, ofproto)
        self.add_flow(datapath, 1, "00:00:00:00:00:07", "00:00:00:00:00:08", 2, 3, parser, ofproto)
        self.add_flow(datapath, 1, "00:00:00:00:00:08", "00:00:00:00:00:07", 3, 2, parser, ofproto)
        self.add_flow(datapath, 1, "00:00:00:00:00:08", "00:00:00:00:00:09", 3, 4, parser, ofproto)
        self.add_flow(datapath, 1, "00:00:00:00:00:09", "00:00:00:00:00:08", 4, 3, parser, ofproto)
        self.add_flow(datapath, 1, "00:00:00:00:00:09", "00:00:00:00:00:0A", 4, 5, parser, ofproto)
        self.add_flow(datapath, 1, "00:00:00:00:00:0A", "00:00:00:00:00:09", 5, 4, parser, ofproto)

        # Add cross-host flow rules via VXLAN tunnel interface
        self.add_flow(datapath, 1, "00:00:00:00:00:06", "00:00:00:00:00:05", 1, vxlan_port, parser, ofproto)
        self.add_flow(datapath, 1, "00:00:00:00:00:05", "00:00:00:00:00:06", vxlan_port, 1, parser, ofproto)

        # Add local broadcast flow rules
        self.add_broadcast_flow(datapath, 1, [2, vxlan_port], parser, ofproto)
        self.add_broadcast_flow(datapath, 2, [1, 3], parser, ofproto)
        self.add_broadcast_flow(datapath, 3, [2, 4], parser, ofproto)
        self.add_broadcast_flow(datapath, 4, [3, 5], parser, ofproto)
        self.add_broadcast_flow(datapath, 5, [4], parser, ofproto)
        self.add_broadcast_flow(datapath, vxlan_port, [1], parser, ofproto)

    def add_flow(self, datapath, priority, src_mac, dst_mac, src_port, dst_port, parser, ofproto):
        self.logger.info("Adding flow: %s -> %s (in_port=%d, out_port=%d)", src_mac, dst_mac, src_port, dst_port)
        actions = [parser.OFPActionOutput(dst_port)]
        match = parser.OFPMatch(in_port=src_port, eth_src=src_mac, eth_dst=dst_mac)
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    def add_broadcast_flow(self, datapath, src_port, dst_ports, parser, ofproto):
        self.logger.info("Adding broadcast flow: in_port=%d -> out_ports=%s", src_port, dst_ports)
        actions = [parser.OFPActionOutput(port) for port in dst_ports]
        match = parser.OFPMatch(in_port=src_port, eth_dst='ff:ff:ff:ff:ff:ff')
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=200, match=match, instructions=inst)
        datapath.send_msg(mod)

    def clear_flow_table(self, datapath, ofproto, parser):
        self.logger.info("Clearing flow table for datapath_id=%s", format(datapath.id, "016x"))
        mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE)
        datapath.send_msg(mod)
```

#### **Host B** Script

```bash
#!/bin/bash
# Host B (local machine) - IP: 192.168.2.37

# Create the OVS virtual switch (if it doesn't exist)
sudo ovs-vsctl del-br myswitch_2
sudo ovs-vsctl add-br myswitch_2

# Set the controller for the OVS virtual switch
sudo ovs-vsctl set-controller myswitch_2 tcp:192.168.2.44:6633 

# Create and configure containers
for i in {1..5}
do
   # Remove existing containers with the same name
   if [ $(sudo docker ps -a -q -f name=c_$i) ]; then
       docker rm -f c_$i
   fi

   # Create new containers
   docker run -itd --rm --privileged --name=c_$i --network=none -e DISPLAY=$DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix -v /home/Desktop/crossHostContainers/volume_file:/volume_file ubuntu_htop:18.04 /bin/bash

   # Add OVS ports
   sudo ovs-docker add-port myswitch_2 eth1 c_$i --ipaddress=192.188.1.1$((i+5))/16 --macaddress=00:00:00:00:00:0$((i+5))
done

# Configure the IP for Host A
sudo ovs-vsctl add-port myswitch_2 vxlan0 -- set interface vxlan0 type=vxlan options:remote_ip=192.168.2.44 options:key=100

# Configure the IP for the OVS switch
sudo ifconfig myswitch_2 192.188.1.1 netmask 255.255.0.0 up 

# Set static route for the 192.168.2.0/24 network, through gateway 192.168.2.37
sudo route add -net 192.168.2.0 netmask 255.255.255.0 gw 192.168.2.37

# Disable the firewall
sudo ufw disable

# Open a new Xfce Terminal window and launch interactive Bash sessions for each container in different tabs, running the respective programs
xfce4-terminal \
--tab --title "1" --command "bash -c 'docker exec -it c_1 /bin/bash -c \"ip route add default via 192.188.1.1; cd volume_file/; exec bash\"'" \
--tab --title "2" --command "bash -c 'docker exec -it c_2 /bin/bash -c \"ip route add default via 192.188.1.1; cd volume_file/; exec bash\"'" \
--tab --title "3" --command "bash -c 'docker exec -it c_3 /bin/bash -c \"ip route add default via 192.188.1.1; cd volume_file/; exec bash\"'" \
--tab --title "4" --command "bash -c 'docker exec -it c_4 /bin/bash -c \"ip route add default via 192.188.1.1; cd volume_file/; exec bash\"'" \
--tab --title "5" --command "bash -c 'docker exec -it c_5 /bin/bash -c \"ip route add default via 192.188.1.1; cd volume_file/; exec bash\"'" &
```

- ```
  sudo ovs-vsctl add-port myswitch_2 vxlan0 -- set interface vxlan0 type=vxlan options:remote_ip=192.168.2.44 options:key=100
  ```

  Configures the VXLAN tunnel interface for switch `myswitch_2`, setting the remote IP address of the VXLAN tunnel to `192.168.2.44` and the VXLAN tunnel identifier (VNI) key to `100`. This VNI key must match the one configured on Host A.
