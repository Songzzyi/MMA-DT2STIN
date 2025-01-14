# MMA-DT2STIN
Through this repository, we provide readers with some basic frameworks, tools, and use cases about MMA

### 1、Ubuntu主机A上容器群跨Wondows主机B通信

**已知: **

**Ubuntu宿主机A:**

- 有线网卡enx207bd2bd5ad5 绑定IP：192.168.2.44/24
- ovs虚拟交换机:192.188.1.1/16
- 容器网络:192.188.0.0/16

**Windows主机B**

（有线）以太网绑定IP：192.168.2.37/24

**A与B网线直连**

