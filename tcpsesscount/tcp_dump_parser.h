#pragma once

#include <pcap.h>

#include <functional>
#include <string>

class TcpDumpParser
{
public:
    TcpDumpParser(const std::string &file_path);
    ~TcpDumpParser();

    bool has_error() const;
    const std::string &error_message() const;
    void parse();

private:
    static void packet_handler(u_char *, const pcap_pkthdr *, const u_char *packet);

private:
    pcap_t *pcap_descriptor;

    bool has_error_;
    std::string error_text_;
};
