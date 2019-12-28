# RawSniffer
This program peels back the layers of raw data and displays the important info about each layer and the data in the packet(if the packet has data)


This program has custom made ethernet , ip and tcp header structures that help in reading the data .
This program used pcap library of C and its functions like pcap_lookupdev() and pcap_open_live().

This program used a pcap_loop function which can run till there are packets to capture and uses a function callback to analyse those packets.
