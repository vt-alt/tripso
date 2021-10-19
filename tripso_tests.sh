#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# PreReq: apt-get install tcpdump tcpreplay iptables net-tools

PATH=$PATH:/sbin:/usr/sbin

se_permissive() {
	if [ -x /usr/sbin/getenforce ] && getenforce | grep -q Enforcing; then
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
unload_rules() {
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
	netns_exec_fn unload_rules
	unload_rules
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
	ip netns del test >/dev/null 2>&1
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
load_rules_ns() {
	# security/INPUT does not receive test CIPSO packets, raw/PREROUTING
	# does. But this is purely artificial, since we don't need to translate
	# input packets from CIPSO.
	iptables -t raw -F
	iptables -t raw -A PREROUTING  -s 10.99.0.1 -j TRIPSO --to-astra
	iptables -t raw -A PREROUTING  -s 10.99.0.2 -j TRIPSO --to-cipso
	iptables -t raw -A PREROUTING  -j NFLOG --nflog-group 1

	#iptables -t filter -F
	#iptables -t filter -A INPUT       -j NFLOG --nflog-group 1
}
load_rules() {
	# tcpreplay'ed outgoing packets not visible to iptables
	# but they will be visible on the other side of veth, in veth1
	# in PREROUTING and INPUT chains.
	netns_exec_fn load_rules_ns
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
		echo
		j=recv/`basename $i`
		ip netns exec test \
			tcpdump -Z root -qnnp -i nflog:1 -c 1 -w $j -y IPV4 icmp >/dev/null 2>&1 &
		TPID=$!
		sleep 0.1
		echo = send $i
		tcpreplay -i veth0 $i > /dev/null
		tcpdump -tv -nnp -r $i 2>/dev/null | tee a
		wait $TPID
		echo = received
		tcpdump -tv -nnp -r $j 2>/dev/null | tee b
		show_dmesg
		if [ -e test-$j ]; then
			tcpdump -tvxnn -r test-$j > .expected 2>/dev/null
			tcpdump -tvxnn -r      $j > .received 2>/dev/null
			if diff -u .expected .received; then
				echo "= Received packet matches expected!"
			else
				echo "! Received packet differs from expected!"
				exit 1
			fi
		fi
		echo
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
se_permissive
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
