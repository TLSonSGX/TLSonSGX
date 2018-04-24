// udpgen.click

// This file is a simple, fast UDP/IP load generator, meant to be used in the
// Linux kernel module. It sends UDP/IP packets from this machine to another
// machine at a given rate. See 'udpcount.click' for a packet counter
// compatible with udpgen.click.

// The relevant address and rate arguments are specified as parameters to a
// compound element UDPGen.

// UDPGen($device, $rate, $limit, $seth, $sip, $sport, $deth, $dip, $dport);
//
//	$device		name of device to generate traffic on
//	$rate		rate to generate traffic (packets/s)
//	$limit		total number of packets to send
//      $size		bytes per packet
//	$seth		source eth addr
//	$sip		source ip addr
//	$sport		source port
//      $deth		destination eth addr
//	$dip		destination ip addr
//	$dport		destination port



elementclass UDPGen {
  $device, $rate, $limit, $size,
  $seth, $sip, $sport, $deth, $dip, $dport |

  source :: FastUDPSource($rate, $limit, $size, $seth, $sip, $sport,
                                                $deth, $dip, $dport, CHECKSUM true);
  //pd :: PollDevice($device) -> ToHost;
  //source -> StoreUDPTimeSeqRecord(OFFSET 14, DELTA false) -> Queue(20000) -> td :: ToDevice($device, METHOD LINUX, BURST 8);

  source -> StoreUDPTimeSeqRecord(OFFSET 14, DELTA false) ->  td :: ToDevice($device, METHOD LINUX, BURST 32);


}

// create a UDPGen

u :: UDPGen(p1, 500, 10000, $size,
	    00:00:00:00:00:01, 10.0.0.1, 1234,
	    00:00:00:00:00:02, 10.0.0.2, 1234);
//->IPPrint("Before", PAYLOAD HEX)
//FromDevice(p1, SNIFFER false)->CheckIPHeader(14, CHECKSUM false)->IPPrint()->StoreUDPTimeSeqRecord(OFFSET 14, DELTA true)->StripIPHeader()->Strip(24)->Truncate(4)->Print(CONTENTS HEX, MAXLENGTH -1)->Discard;
 
//FromDevice(p1, METHOD LINUX, SNIFFER false)->CheckIPHeader(14, CHECKSUM false)->StoreUDPTimeSeqRecord(OFFSET 14, DELTA true)->ToDump(udpecho.pcap);
 
FromDevice(p1, METHOD LINUX, SNIFFER false, BURST 8, SNAPLEN 10000)-> ThreadSafeQueue(10000)->CheckIPHeader(14, CHECKSUM false)->StoreUDPTimeSeqRecord(OFFSET 14, DELTA true)->c::Counter(COUNT_CALL 10000 stop)->td::ToDump(udpecho_$size.pcap);



 
//->Socket(UDP, 10.0.0.1, 1234, CLIENT true);
//->Socket(UDP, 10.0.0.1, 1234);
