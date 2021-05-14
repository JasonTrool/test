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
    Closing,
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
    using handler_t = std::function<ConnectionState(ConnectionState)>;
    using connection_t = std::pair<std::string, std::string>;
    using connections_list = std::unordered_map<connection_t, ConnectionState, hash_fn>;

    enum TcpFlags
    {
        syn = 1,
        ack = 2,
        fin = 4,
        rst = 8,

        synack = syn | ack,
        finack = fin | ack,
        rstack = rst | ack
    };

    TcpDumpParserHelper(TcpDumpParserHelper &other) = delete;
    void operator=(const TcpDumpParserHelper &) = delete;

    static TcpDumpParserHelper* instance();
    static bool destroy();

    ConnectionState transit(ConnectionState from, TcpFlags signal);
    connections_list &connections();

private:
    TcpDumpParserHelper();

private:
    static TcpDumpParserHelper *instance_;

    std::unordered_map<tcp_flags_mask, handler_t> flag_handlers_;
    FiniteStateMachine<ConnectionState> fsm_;

    connections_list connections_;
};
