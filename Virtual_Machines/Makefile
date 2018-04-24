start_vm1:
	sudo taskset -c 2 qemu-system-x86_64 --enable-kvm -cpu host -name vm1 -machine pc,accel=kvm,usb=off -smp 1,sockets=1,cores=1,threads=1 -drive file=/home/trusted-ovs/2016-mtfs_ovs-integrity/trusted_ovs/Virtual_Machines/vm1.qcow2,format=qcow2,if=virtio -m 4096 -net nic,model=virtio,netdev=net0,macaddr=02:10:20:00:01:01 -netdev tap,id=net0,script=qemu-ifup,vhost=on -nographic &
	
shutdown_vm1:
	ps -ef | grep qemu | grep vm1 | awk '{print $$2}' | head -1 | xargs sudo kill -9
	ps -ef | grep qemu | grep vm1 | awk '{print $$2}' | head -1 | xargs sudo kill -9


start_vm2_sgx:
	sudo taskset -c 1,3 /home/trusted-ovs/New_SGX_KVM/qemu-sgx/x86_64-softmmu/qemu-system-x86_64 --enable-kvm -cpu host -sgx epc=32M -name vm2_sgx -machine pc,accel=kvm,usb=off -smp 2,sockets=1,cores=2,threads=1 -drive file=/home/trusted-ovs/2016-mtfs_ovs-integrity/trusted_ovs/Virtual_Machines/vm2_sgx.qcow2,format=qcow2,if=virtio -m 4096 -net nic,model=virtio,netdev=net0,macaddr=02:10:20:00:02:02 -netdev tap,id=net0,script=qemu-ifup,vhost=on &
	
shutdown_vm2:
	ps -ef | grep qemu | grep vm2_sgx | awk '{print $$2}' | head -1 | xargs sudo kill -9
	ps -ef | grep qemu | grep vm2_sgx | awk '{print $$2}' | head -1 | xargs sudo kill -9
	
start_vm2_no_sgx:
	sudo taskset -c 1,3 qemu-system-x86_64 --enable-kvm -cpu host -name vm2_no_sgx -machine pc,accel=kvm,usb=off -smp 2,sockets=1,cores=2,threads=1 -drive file=/home/trusted-ovs/2016-mtfs_ovs-integrity/trusted_ovs/Virtual_Machines/vm2_no_sgx.qcow2,format=qcow2,if=virtio -m 4096 -net nic,model=virtio,netdev=net0,macaddr=02:10:20:00:03:03 -netdev tap,id=net0,script=qemu-ifup,vhost=on -nographic&
	
shutdown_vm2_no_sgx:
	ps -ef | grep qemu | grep vm2_no_sgx | awk '{print $$2}' | head -1 | xargs sudo kill -9
	ps -ef | grep qemu | grep vm2_no_sgx | awk '{print $$2}' | head -1 | xargs sudo kill -9
