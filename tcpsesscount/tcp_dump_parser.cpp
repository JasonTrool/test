#include "tcp_dump_parser.h"

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <iostream>
#include <sstream>

void TcpDumpParser::packet_handler(u_char *, const pcap_pkthdr *, const u_char *packet)
{
    using tcp_flags = TcpDumpParserHelper::tcp_flags_mask;
    using FlagsFrom = TcpDumpParserHelper::FlagsFrom;

    auto helper = TcpDumpParserHelper::instance();
    auto &connections = helper->connections();

    const struct ether_header* ethernet_header;
    bool is_tcp = false;

    const struct tcphdr* tcp_header;
    uint16_t source_port = 0;
    uint16_t dest_port = 0;

    std::string source_addr;
    std::string dest_addr;

#define ip6   ip6_hdr
#define ip6_p ip6_nxt

#define get_address(ipv, af_inet, addr_str_len) \
    const struct ip##ipv *ip_header = (struct ip##ipv *)(packet + sizeof(struct ether_header)); \
    char source_ip[addr_str_len] = { 0 }; \
    char dest_ip[addr_str_len]   = { 0 }; \
    std::stringstream ss; \
    inet_ntop(af_inet, &(ip_header->ip##ipv##_src), source_ip, addr_str_len); \
    inet_ntop(af_inet, &(ip_header->ip##ipv##_dst), dest_ip, addr_str_len); \
    if (ip_header->ip##ipv##_p == IPPROTO_TCP) \
    { \
        tcp_header = (tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip##ipv)); \
        source_port = ntohs(tcp_header->source); \
        dest_port = ntohs(tcp_header->dest); \
        ss << "[" << source_ip << "]:" << std::to_string(source_port); \
        source_addr = ss.str(); \
        ss.str(""); \
        ss << "[" << dest_ip << "]:" << std::to_string(dest_port); \
        dest_addr = ss.str(); \
        is_tcp = true; \
    }

    ethernet_header = (struct ether_header*)packet;
    if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IP)
    {
        get_address( , AF_INET, INET_ADDRSTRLEN);
    }
    else if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IPV6)
    {
        get_address(6, AF_INET6, INET6_ADDRSTRLEN);
    }

    if (is_tcp)
    {   
        // Пытаемся найти пару [адрес назначения, адрес отправки].
        //   В случае промаха пытаемся создать пару [адрес отправки,
        //   адрес назначения]. Если такая пара уже существует -
        //   считываем состояние найденного соединения и анализируем
        //   TCP-флаги, пришедшие в очердном пакете.
        auto connection = connections.find({ dest_addr, source_addr });

        // Обращаемся только по итератору, чтобы изменять состояние
        //   соединения прямо в хэш-мапе.
        if ( connection == connections.end() )
        {
            connection = connections.emplace(std::make_pair(std::make_pair(source_addr, dest_addr), ConnectionState::Initial)).first;
        }

        const auto &client = connection->first.first;
        const auto &server = connection->first.second;

        FlagsFrom from;

        if (source_addr == client)
        {
            from = FlagsFrom::FromClient;
        }
        else if (source_addr == server)
        {
            from = FlagsFrom::FromServer;
        }

        tcp_flags flags = helper->get_tcp_flags_mask(tcp_header->syn, tcp_header->ack,
                                                     tcp_header->fin, tcp_header->rst, from);

        connection->second = helper->transit(connection->second, flags);
    }

#undef ip6
#undef ip6_p
#undef get_address
}


TcpDumpParser::TcpDumpParser(const std::string &file_path)
    : pcap_descriptor(nullptr)
    , has_error_(false)
    , error_text_("")
{
    char errbuf[PCAP_ERRBUF_SIZE];

    // open capture file for offline processing
    pcap_descriptor = pcap_open_offline(file_path.c_str(), errbuf);
    if (pcap_descriptor == nullptr)
    {
        std::stringstream ss;
        has_error_ = true;
        ss << "pcap_open_offline() failed: " << errbuf << "\n";
        error_text_ = ss.str();
    }
}

TcpDumpParser::~TcpDumpParser()
{
    if (pcap_descriptor)
    {
        pcap_close(pcap_descriptor);
    }
    helper_->destroy();
}

bool TcpDumpParser::has_error() const
{
    return has_error_;
}

const std::string &TcpDumpParser::error_message() const
{
    return error_text_;
}

void TcpDumpParser::parse()
{
    if (pcap_loop(pcap_descriptor, 0, packet_handler, nullptr) < 0)
    {
        std::stringstream ss;
        has_error_ = true;
        ss << "pcap_loop() failed: " << pcap_geterr(pcap_descriptor) << "\n";
        error_text_ = ss.str();
        return;
    }
    print_report();
    std::cout << "Capture finished." << std::endl;
}

void TcpDumpParser::print_report()
{
    auto helper = TcpDumpParserHelper::instance();

    size_t opened = 0u;
    size_t reset  = 0u;
    size_t closed = 0u;
    size_t errors = 0u;

    const auto connections = helper->connections();

    for (const auto &c : connections)
    {
        auto state = c.second;
        if (state == ConnectionState::Established)
        {
            ++opened;
            std::cout << "Connection between " << c.first.first << " and " << c.first.second << " is still opened." << std::endl;
        }
        else if (state == ConnectionState::Reset)
        {
            ++reset;
            std::cout << "Connection between " << c.first.first << " and " << c.first.second << " has been reset." << std::endl;
        }
        else if (state == ConnectionState::Closed || state == ConnectionState::TimeWait)
        {
            ++closed;
            std::cout << "Connection between " << c.first.first << " and " << c.first.second << " has been closed." << std::endl;
        }
        else if (state == ConnectionState::ErrorState)
        {
            ++errors;
        }
    }
    std::cout << "\nTotal amount of connections: " << connections.size() << "\n";
    std::cout << opened << " connections are still opened.\n";
    std::cout << reset  << " connections have been reset.\n";
    std::cout << closed << " connections have been closed.\n";
    std::cout << errors << " parsing errors.\n" << std::endl;
}
