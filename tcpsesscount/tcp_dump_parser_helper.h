#pragma once

#include "finite_state_machine.h"

#include <string>
#include <functional>
#include <unordered_map>

enum class ConnectionState : int
{
    ErrorState,
    Initial,
    Establishing,
    Established,
    FinWait1,
    FinWait2,
    Closing,
    TimeWait,
    Closed,
    Reset
};

struct hash_fn
{
    template <class T1, class T2>
    std::size_t operator() (const std::pair<T1, T2> &pair) const
    {
        std::size_t h1 = std::hash<T1>()(pair.first);
        std::size_t h2 = std::hash<T2>()(pair.second);
        return h1 ^ h2;
    }
};

class TcpDumpParserHelper
{
public:
    using tcp_flags_mask = uint8_t;
    using connection_t = std::pair<std::string, std::string>;
    using connections_list = std::unordered_map<connection_t, ConnectionState, hash_fn>;

    enum FlagsFrom
    {
        FromClient = 0,
        FromServer
    };

    enum TcpFlags
    {
        cli_syn = 0x1,
        cli_ack = 0x2,
        cli_fin = 0x4,
        cli_rst = 0x8,

        srv_syn = 0x10,
        srv_ack = 0x20,
        srv_fin = 0x40,
        srv_rst = 0x80
    };

    TcpDumpParserHelper(TcpDumpParserHelper &other) = delete;
    void operator=(const TcpDumpParserHelper &) = delete;

    static TcpDumpParserHelper* instance();
    static bool destroy();

    tcp_flags_mask get_tcp_flags_mask(bool syn, bool ack, bool fin, bool rst, FlagsFrom from);
    ConnectionState transit(ConnectionState from, tcp_flags_mask signal);
    connections_list &connections();

private:
    TcpDumpParserHelper();

private:
    static TcpDumpParserHelper *instance_;

    FiniteStateMachine<ConnectionState, uint8_t> fsm_;
    connections_list connections_;
};
