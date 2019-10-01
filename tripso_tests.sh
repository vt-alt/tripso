#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

PATH=$PATH:/sbin:/usr/sbin

se_prermisive() {
	if getenforce | grep -q Enforcing; then
		setenforce 0
		echo Selinux set to: `getenforce`
	fi
}
show_dmesg() {
	if [ "$LDMESG" ]; then
		dmesg | sed '/'$LDMESG'/,$!d;//d'
	fi
	LDMESG=$(dmesg | tail -1 | awk '{print$1}')
	LDMESG=${LDMESG%]}
	LDMESG=${LDMESG#[}
}

check_harness() {
	if ! tcpdump -D | grep -qw nflog; then
		echo "tcpdump should support nflog interface."
		exit 1
	fi
}
unload_rules_x() {
	for t in raw mangle nat filter security; do
		iptables-save -t $t | grep -q TRIPSO || continue
		iptables-save -t $t | grep TRIPSO \
		| sed "s/-A//" \
		| while read y; do
			iptables -t $t -D $y
		done
	done
}
netns_exec_fn() {
	ip netns exec test bash -c "$(declare -f $1); $1"
}
unload_module() {
	netns_exec_fn unload_rules_x
	unload_rules_x
	lsmod | grep -q xt_TRIPSO && rmmod -v xt_TRIPSO
}
veth_start() {
	ip link show veth0 >/dev/null 2>&1 \
		|| ip link add veth0 type veth peer name veth1
	ifconfig veth0 hw ether 72:aa:5f:da:66:bb 10.99.0.1/24 up
	ip netns add test 2>/dev/null
	ip link  set veth1 netns test
	ip netns exec test \
		ifconfig veth1 hw ether 72:aa:5f:da:66:aa 10.99.0.3/24 up
}
veth_stop() {
	ip link show veth0 >/dev/null 2>&1 && ip link del veth0
	ip netns del test
}
load_module() {
	sysctl kernel.printk=8
	if ! lsmod | grep -q xt_TRIPSO; then
		insmod ./xt_TRIPSO.ko debug=2 || exit 1
	fi
	# check if correct module is loaded
	if ! modinfo ./xt_TRIPSO.ko | grep -qw $(cat /sys/module/xt_TRIPSO/srcversion); then
		echo "Incorrect version of module is loaded."
		exit 1
	fi
}
load_rules_x() {
	iptables -t security -F
	iptables -t security -A INPUT  -s 10.99.0.1 -j TRIPSO --to-astra
	iptables -t security -A INPUT  -s 10.99.0.2 -j TRIPSO --to-cipso
	iptables -t security -A INPUT  -j NFLOG --nflog-group 1

	#iptables -t filter -F
	#iptables -t filter -A INPUT       -j NFLOG --nflog-group 1
}
load_rules() {
	# tcpreplay'ed outgoing packets not visible to iptables
	# but they will be visible on the other side of veth, in veth1
	# in PREROUTING and INPUT chains.
	netns_exec_fn load_rules_x
	iptables -t security -F
	iptables -t security         -A INPUT  -j TRIPSO --to-cipso
	iptables -t security ! -o lo -A OUTPUT -j TRIPSO --to-astra
}
reload() {
	unload_module
	load_module
	load_rules
}
start() {
	veth_start
	load_module
	load_rules
}
stop() {
	unload_module
	veth_stop
}
restart() {
	stop
	start
}
send_pkt() {
	rm -rf recv
	mkdir -p recv
	show_dmesg
	for i in "$@"; do
		j=recv/`basename $i`
		ip netns exec test \
			tcpdump -Z root -qnnp -i nflog:1 -c 1 -w $j >/dev/null 2>&1 &
		TPID=$!
		sleep 0.1
		tcpreplay -i veth0 $i > /dev/null
		wait $TPID
		echo = sent
		tcpdump -tvx -nnp -r $i 2>/dev/null | tee a
		echo = received
		tcpdump -tvx -nnp -r $j 2>/dev/null | tee b
		#echo $i `md5sum a b` >> test-vec.txt
		show_dmesg

	done
}
test_send() {
	start
	send_pkt test/*pkt
	ip netns exec test \
		iptables-save -t security -c
}
retest() {
	stop
	test_send $@
}

check_harness
se_prermisive
for j; do
	case $j in
		restart) restart ;;
		reload)  reload ;;
		start)   start ;;
	        stop)    stop ;;
	        *.pkt)   send_pkt $j ;;
	        test)    test_send ;;
	        retest)  retest ;;
		*)       echo "argument error: $j"; exit 1 ;;
	esac
done
