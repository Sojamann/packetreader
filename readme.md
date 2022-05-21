# Pcapreader
A library that helps reading pcap and pcapng files. This is only a learning project for me.
No metadata metadata except of link layer type, packet size and time stamp
are provided depending on if they are available.

## Pcaps
Only pcaps of version 2.4 are supported.
This should be okay, as this is the latest version since 1998
See https://wiki.wireshark.org/Development/LibpcapFileFormat.

## PcapNg
Only pcapngs of version 1.0 and 1.2 are supported.
Read more about version at https://datatracker.ietf.org/doc/html/draft-tuexen-opsawg-pcapng-04#section-4.1 .
A single PcapNg file can contain recordings from different network interfaces
which can be of different link layer types. This is not supported here.
The first network interface that is being read/encountered counts.
Traffic from different interfaces is ignored. This means that every
pcapng file can be processed but only traffic from one network interface is
esentially being read. This should not be an issue for most applications, as reading
the recoding of Wireshark or tcpdump which record one interface is unproblematic.
Franken-PcapNgs have to be processed differently or split before using this
PcapNg reader. If recordings from the same interface are concatenated
both parts will be read normally.

() section                      <br>
A data of interface A           <br>
                                <br>
(A)             -> A            <br>
(A) | (A)       -> A A          <br>
(A) | (B)       -> A            <br>
(A) | (B) | (A) -> A A          <br>
(A,B,A)|(A)|(B) -> A A A        <br>

## Testing
The test runs the pprint.go file against tshark and compares
the of those two for a given pcap(ng) file.

```SH
./test dump.pcap
```

## Conversion
Converting a pcap into a pcapng
```SH
editcap -F pcapng a.pcap b.pcapng
```
