source /opt/intel/sgxsdk/environment
echo $?
echo "Loading kernel module"
/sbin/modprobe openvswitch
echo $?
echo "Starting ovsdb-server"
ovsdb-server --remote=punix:/usr/local/var/run/openvswitch/db.sock \
    --remote=db:Open_vSwitch,Open_vSwitch,manager_options \
    --private-key=db:Open_vSwitch,SSL,private_key \
    --certificate=db:Open_vSwitch,SSL,certificate \
    --bootstrap-ca-cert=db:Open_vSwitch,SSL,ca_cert \
    --pidfile --detach --log-file
echo $?
ovs-vsctl --no-wait init
echo "Starting ovs-vswitch"
ovs-vswitchd --pidfile --detach --log-file

ovs-vsctl set-controller sw1 ssl:192.168.122.209:6633
touch text.txt
ovs-vsctl set-ssl text.txt text.txt text.txt
ovs-vsctl set Bridge sw1 protocols=OpenFlow10
