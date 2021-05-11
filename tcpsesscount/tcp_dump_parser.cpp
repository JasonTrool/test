#include "tcp_dump_parser.h"

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <iostream>

TcpDumpParser::TcpDumpParser(const std::string &file_path)
    : descr_(nullptr)
    , has_error_(false)
    , fsm_()
{
    char errbuf[PCAP_ERRBUF_SIZE];

    fsm_.add_transition(ConnectionState::Initial, ConnectionState::Establishing);
    fsm_.add_transition(ConnectionState::Establishing, ConnectionState::Reset);
    fsm_.add_transition(ConnectionState::Establishing, ConnectionState::Established);
    fsm_.add_transition(ConnectionState::Established, ConnectionState::Closing);
    fsm_.add_transition(ConnectionState::Established, ConnectionState::Reseting);
    fsm_.add_transition(ConnectionState::Closing, ConnectionState::Closed);
    fsm_.add_transition(ConnectionState::Reseting, ConnectionState::Reset);

    // open capture file for offline processing
    descr_ = pcap_open_offline(file_path.c_str(), errbuf);
    if (descr_ == NULL)
    {
        has_error_ = true;
        std::cout << "pcap_open_offline() failed: " << errbuf << "\n";
    }
}

bool TcpDumpParser::has_error() const
{
    return has_error_;
}

void TcpDumpParser::parse()
{
    // start packet processing loop, just like live capture
    if (pcap_loop(descr_, 0, packet_handler, NULL) < 0)
    {
        has_error_ = true;
        std::cout << "pcap_loop() failed: " << pcap_geterr(descr_) << "\n";
    }
    std::cout << "end\n";
}

void TcpDumpParser::packet_handler(u_char *userData, const pcap_pkthdr *pkthdr, const u_char *packet)
{
    const struct ether_header* ethernetHeader;
    const struct ip* ipHeader;
    const struct tcphdr* tcpHeader;
    char sourceIp[INET_ADDRSTRLEN];
    char destIp[INET_ADDRSTRLEN];
    u_int sourcePort, destPort;
    u_char *data;
    int dataLength = 0;
    std::string dataStr = "";

    ethernetHeader = (struct ether_header*)packet;
    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP)
    {
        ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
        inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIp, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), destIp, INET_ADDRSTRLEN);
        if (ipHeader->ip_p == IPPROTO_TCP)
        {
            tcpHeader = (tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            sourcePort = ntohs(tcpHeader->source);
            destPort = ntohs(tcpHeader->dest);
            data = (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
            dataLength = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));

            // convert non-printable characters, other than carriage return, line feed,
            // or tab into periods when displayed.
            for (int i = 0; i < dataLength; i++)
            {
                if ((data[i] >= 32 && data[i] <= 126) || data[i] == 10 || data[i] == 11 || data[i] == 13)
                {
                    dataStr += (char)data[i];
                }
                else
                {
                    dataStr += ".";
                }
            }

            const auto ack = tcpHeader->ack;
            const auto syn = tcpHeader->syn;
            const auto fin = tcpHeader->fin;
            const auto rst = tcpHeader->rst;

            if (fin && !ack)
            {
                std::cout << sourceIp << ":" << sourcePort << " sent FIN to " << destIp << ":" << destPort << "\n";
            }
            else if (fin && ack)
            {
                std::cout << sourceIp << ":" << sourcePort << " sent ACK FIN to " << destIp << ":" << destPort << "\n";
            }
            else if (rst && !ack)
            {
                std::cout << sourceIp << ":" << sourcePort << " sent RST to " << destIp << ":" << destPort << "\n";
            }
            else if (rst && ack)
            {
                std::cout << sourceIp << ":" << sourcePort << " sent ACK RST to " << destIp << ":" << destPort << "\n";
            }
//          std::cout << sourceIp << ":" << sourcePort << " -> " << destIp << ":" << destPort << " ";
//          std::cout << "[ACK = " << ack << "] [SYN = " << syn << "] [FIN = " << fin << "] [RST =  " << rst << "]\n";
        }
    }
}
