current_dir = $(shell pwd)
DATE:=$(shell /bin/date +"%Y%m%d%H%M")
run_controller_learning_switch:
	ryu-manager  --ctl-privkey $(current_dir)/ctl-privkey.pem  --ctl-cert $(current_dir)/ctl-cert.pem --ca-certs $(current_dir)/rootca-cert.pem $(current_dir)/learning_switch.py > sdn_controller_learning-$(DATE).log 2>&1 &

run_controller_not_learning_switch:
	ryu-manager  --ctl-privkey $(current_dir)/ctl-privkey.pem  --ctl-cert $(current_dir)/ctl-cert.pem --ca-certs $(current_dir)/rootca-cert.pem $(current_dir)/not_learning_switch.py > sdn_controller_not_learning-$(DATE).log 2>&1 &


stop_controller:
	pkill ryu-manager
