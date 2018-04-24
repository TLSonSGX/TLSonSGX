FromDump(udpecho_$size.pcap, STOP true)->CheckIPHeader(14, CHECKSUM false)->StripIPHeader()->Strip(24)->Truncate(4)->Print(CONTENTS HEX, MAXLENGTH -1)->Queue->Discard;

