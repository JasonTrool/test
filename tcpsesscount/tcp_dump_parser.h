#pragma once

#include <pcap.h>

#include <map>

#include "finite_state_machine.h"

class TcpDumpParser
{
public:
    enum class ConnectionState : int
    {
        Initial,
        Establishing,
        Established,
        Closing,
        Reseting,
        Closed,
        Reset
    };

    TcpDumpParser(const std::string &file_path);

    bool has_error() const;
    void parse();

private:
   static  void packet_handler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);

    pcap_t *descr_;

    bool has_error_;

    FiniteStateMachine<ConnectionState> fsm_;
    std::map<std::string, ConnectionState> connections_;
};
