# Imports
import os
from socket import *
import struct
import time
import select

class IcmpHelperLibrary:
    class IcmpPacket:
        def __init__(self, ttl=255):
            self.__header = b''
            self.__dataRaw = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            self.__data = struct.pack("d", time.time()) + self.__dataRaw.encode("utf-8")
            self.__icmpType = 8
            self.__icmpCode = 0
            self.__packetChecksum = 0
            self.__packetIdentifier = os.getpid() & 0xFFFF
            self.__packetSequenceNumber = 1
            self.__ttl = ttl
            self.__DEBUG_IcmpPacket = False

        def buildPacket_echoRequest(self):
            self.__packAndRecalculateChecksum()

        def __packAndRecalculateChecksum(self):
            self.__packHeader()
            self.__encodeData()
            self.__recalculateChecksum()
            self.__packHeader()

        def __packHeader(self):
            # The following header is based on http://www.networksorcery.com/enp/protocol/icmp/msg8.htm
            # Type = 8 bits
            # Code = 8 bits
            # ICMP Header Checksum = 16 bits
            # Identifier = 16 bits
            # Sequence Number = 16 bits
            self.__header = struct.pack("!BBHHH",
                                        self.__icmpType,
                                        self.__icmpCode,
                                        self.__packetChecksum,
                                        self.__packetIdentifier,
                                        self.__packetSequenceNumber)

        def __encodeData(self):
            data_time = struct.pack("d", time.time())
            self.__data = data_time + self.__dataRaw.encode("utf-8")

        def __recalculateChecksum(self):
            packetAsByteData = b''.join([self.__header, self.__data])
            checksum = 0
            countTo = (len(packetAsByteData) // 2) * 2
            count = 0
            while count < countTo:
                thisVal = packetAsByteData[count + 1] * 256 + packetAsByteData[count]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff
                count = count + 2
            if countTo < len(packetAsByteData):
                checksum = checksum + packetAsByteData[len(packetAsByteData) - 1]
                checksum = checksum & 0xffffffff
            checksum = (checksum >> 16) + (checksum & 0xffff)
            checksum = (checksum >> 16) + checksum
            answer = ~checksum
            answer = answer & 0xffff
            answer = answer >> 8 | (answer << 8 & 0xff00)
            self.__packetChecksum = answer

        def sendEchoRequest(self, destination):
            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            mySocket.settimeout(2)
            mySocket.bind(("", 0))
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', self.__ttl))
            try:
                mySocket.sendto(b''.join([self.__header, self.__data]), (destination, 0))
                startTime = time.time()
                whatReady = select.select([mySocket], [], [], 2)
                if whatReady[0] == []:
                    return None, None, None
                recvPacket, addr = mySocket.recvfrom(1024)
                endTime = time.time()
                rtt = (endTime - startTime) * 1000
                icmpType, icmpCode = struct.unpack("!BB", recvPacket[20:22])
                return rtt, addr[0], (icmpType, icmpCode)
            except timeout:
                return None, None, None
            finally:
                mySocket.close()


    def traceRoute(self, host):
        print(f"Tracing route to {host}")
        max_hops = 30
        destination = gethostbyname(host)
        rtts = []
        lost_packets = 0
        for ttl in range(1, max_hops + 1):
            icmpPacket = IcmpHelperLibrary.IcmpPacket(ttl)
            icmpPacket.buildPacket_echoRequest()
            rtt, addr, icmpInfo = icmpPacket.sendEchoRequest(destination)
            if addr:
                rtts.append(rtt)
                icmpType, icmpCode = icmpInfo if icmpInfo else (None, None)
                if icmpType == 11:
                    print(f"Hop {ttl}: {addr} RTT={rtt:.2f}ms (Time Exceeded)")
                elif icmpType == 3:
                    print(f"Hop {ttl}: {addr} RTT={rtt:.2f}ms (Destination Unreachable)")
                elif icmpType is not None:
                    print(f"Hop {ttl}: {addr} RTT={rtt:.2f}ms Type={icmpType} Code={icmpCode}")
                else:
                    print(f"Hop {ttl}: {addr} RTT={rtt:.2f}ms")
                if addr == destination:
                    print("Trace complete.")
                    break
            else:
                lost_packets += 1
                print(f"Hop {ttl}: * Request timed out.")
        print("Trace finished.")

        if rtts:
            print(f"\n--- {host} traceroute statistics ---")
            print(
                f"Hops: {len(rtts)}, Packets Lost: {lost_packets}, Packet Loss Rate: {(lost_packets / max_hops) * 100:.2f}%")
            print(f"RTT: Min = {min(rtts):.2f}ms, Max = {max(rtts):.2f}ms, Avg = {sum(rtts) / len(rtts):.2f}ms")

def main():
    tracer = IcmpHelperLibrary()
    destinations = {
        "North America": "8.8.8.8",  # Google Public DNS (USA)
        "Europe": "1.1.1.1",  # Cloudflare DNS (Europe)
        "Asia": "202.179.183.94",  # Mongolia Telecom (Asia)
        "Australia": "139.130.4.5"  # Telstra (Australia)
    }

    for continent, ip in destinations.items():
        print(f"\nStarting traceroute to {continent}: {ip}\n")
        tracer.traceRoute(ip)

    print("Program execution completed.")


if __name__ == "__main__":
    main()
