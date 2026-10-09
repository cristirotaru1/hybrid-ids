#!/usr/bin/env bash
set -e

read -r -p "Controller IP: " controller_ip
read -r -p "Controller OpenFlow port [6653]: " controller_port
controller_port=${controller_port:-6653}
read -r -p "Interface used to reach the controller: " controller_interface

echo "Testing controller connectivity..."
ping -I "$controller_interface" -c 2 "$controller_ip"

read -r -p "Bridge name [br0]: " bridge
bridge=${bridge:-br0}
read -r -p "OpenFlow version [OpenFlow13]: " openflow_version
openflow_version=${openflow_version:-OpenFlow13}
read -r -p "Bridge data interfaces, separated by spaces: " ports_input
read -r -a ports <<< "$ports_input"

declare -a ofports
for interface in "${ports[@]}"; do
    read -r -p "OpenFlow port number for $interface: " ofport
    ofports+=("$ofport")
done

systemctl enable --now openvswitch-switch
ovs-vsctl --may-exist add-br "$bridge"
ovs-vsctl set bridge "$bridge" "protocols=$openflow_version"
ovs-vsctl set-fail-mode "$bridge" secure
ovs-vsctl set-controller "$bridge" "tcp:$controller_ip:$controller_port"

echo "Adding data ports. Ensure these interfaces do not contain IP addresses and do not include the controller-facing interface."
for index in "${!ports[@]}"; do
    interface=${ports[$index]}
    ip link set "$interface" up
    ovs-vsctl --may-exist add-port "$bridge" "$interface"
    ovs-vsctl set Interface "$interface" "ofport_request=${ofports[$index]}"
done

echo
echo "Switch configuration:"
ovs-vsctl show
echo "DPID: $(ovs-vsctl get bridge "$bridge" datapath_id)"
echo "Controller connected: $(ovs-vsctl get controller "$bridge" is_connected)"
ovs-ofctl -O "$openflow_version" show "$bridge"
