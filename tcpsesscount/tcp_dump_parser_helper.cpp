#include "tcp_dump_parser_helper.h"

TcpDumpParserHelper *TcpDumpParserHelper::instance_ = nullptr;

TcpDumpParserHelper::TcpDumpParserHelper()
    : fsm_()
    , connections_()
{
    fsm_.add_transition(ConnectionState::Initial, cli_syn, ConnectionState::Establishing);
    fsm_.add_transition(ConnectionState::Initial, srv_syn, ConnectionState::Establishing);

    // Если дамп начинается не с открытия соединения
    fsm_.add_transition(ConnectionState::Initial, cli_ack, ConnectionState::Established);
    fsm_.add_transition(ConnectionState::Initial, srv_ack, ConnectionState::Established);
    fsm_.add_transition(ConnectionState::Initial, cli_fin, ConnectionState::FinWait1);
    fsm_.add_transition(ConnectionState::Initial, srv_fin, ConnectionState::FinWait1);
    fsm_.add_transition(ConnectionState::Initial, cli_fin | cli_ack, ConnectionState::FinWait1);
    fsm_.add_transition(ConnectionState::Initial, srv_fin | srv_ack, ConnectionState::FinWait1);

    fsm_.add_transition(ConnectionState::Establishing, srv_syn | srv_ack, ConnectionState::Establishing);
    fsm_.add_transition(ConnectionState::Establishing, cli_ack, ConnectionState::Established);
    fsm_.add_transition(ConnectionState::Establishing, srv_fin,  ConnectionState::FinWait1);
    fsm_.add_transition(ConnectionState::Establishing, cli_rst, ConnectionState::Reset);

    fsm_.add_transition(ConnectionState::Established, cli_ack, ConnectionState::Established);
    fsm_.add_transition(ConnectionState::Established, srv_ack, ConnectionState::Established);
    fsm_.add_transition(ConnectionState::Established, srv_syn | srv_ack, ConnectionState::Established);
    fsm_.add_transition(ConnectionState::Established, cli_fin, ConnectionState::FinWait1);
    fsm_.add_transition(ConnectionState::Established, srv_fin, ConnectionState::FinWait1);
    fsm_.add_transition(ConnectionState::Established, cli_fin | cli_ack, ConnectionState::FinWait1);
    fsm_.add_transition(ConnectionState::Established, srv_fin | srv_ack, ConnectionState::FinWait1);

    fsm_.add_transition(ConnectionState::FinWait1, srv_ack, ConnectionState::FinWait2);
    fsm_.add_transition(ConnectionState::FinWait1, srv_fin | srv_ack, ConnectionState::FinWait2);
    fsm_.add_transition(ConnectionState::FinWait1, cli_ack, ConnectionState::TimeWait);
    fsm_.add_transition(ConnectionState::FinWait1, cli_fin | cli_ack, ConnectionState::Closing);

    fsm_.add_transition(ConnectionState::FinWait2, srv_ack, ConnectionState::FinWait2);
    fsm_.add_transition(ConnectionState::FinWait2, cli_ack, ConnectionState::TimeWait);
    fsm_.add_transition(ConnectionState::FinWait2, srv_fin | srv_ack, ConnectionState::TimeWait);

    fsm_.add_transition(ConnectionState::Closing, srv_ack, ConnectionState::TimeWait);

    fsm_.add_transition(ConnectionState::TimeWait, cli_ack, ConnectionState::Closed);
    fsm_.add_transition(ConnectionState::TimeWait, cli_fin | cli_ack, ConnectionState::TimeWait);
    fsm_.add_transition(ConnectionState::TimeWait, srv_ack, ConnectionState::TimeWait);
    fsm_.add_transition(ConnectionState::TimeWait, srv_fin | srv_ack, ConnectionState::TimeWait);

    fsm_.add_transition(ConnectionState::Closed, cli_ack, ConnectionState::Closed);
    fsm_.add_transition(ConnectionState::Closed, cli_fin | cli_ack, ConnectionState::Closed);
    fsm_.add_transition(ConnectionState::Closed, srv_ack, ConnectionState::Closed);
    fsm_.add_transition(ConnectionState::Closed, srv_fin | srv_ack, ConnectionState::Closed);

    // Считаем, что RST может прийти в любой момент, даже в состоянии Initial при "рваном" дампе.
    fsm_.add_transition(ConnectionState::Initial, cli_rst, ConnectionState::Reset);
    fsm_.add_transition(ConnectionState::Initial, cli_rst | cli_ack, ConnectionState::Reset);
    fsm_.add_transition(ConnectionState::Initial, srv_rst, ConnectionState::Reset);
    fsm_.add_transition(ConnectionState::Initial, srv_rst | srv_ack, ConnectionState::Reset);

    fsm_.add_transition(ConnectionState::Established, cli_rst, ConnectionState::Reset);
    fsm_.add_transition(ConnectionState::Established, cli_rst | cli_ack, ConnectionState::Reset);
    fsm_.add_transition(ConnectionState::Established, srv_rst, ConnectionState::Reset);
    fsm_.add_transition(ConnectionState::Established, srv_rst | srv_ack, ConnectionState::Reset);

    fsm_.add_transition(ConnectionState::Established, srv_rst, ConnectionState::Reset);
    fsm_.add_transition(ConnectionState::Established, srv_rst | srv_ack, ConnectionState::Reset);
    fsm_.add_transition(ConnectionState::Established, cli_rst, ConnectionState::Reset);
    fsm_.add_transition(ConnectionState::Established, cli_rst | cli_ack, ConnectionState::Reset);

    fsm_.add_transition(ConnectionState::FinWait1, srv_rst, ConnectionState::Reset);
    fsm_.add_transition(ConnectionState::FinWait1, srv_rst | srv_ack, ConnectionState::Reset);
    fsm_.add_transition(ConnectionState::FinWait1, cli_rst, ConnectionState::Reset);
    fsm_.add_transition(ConnectionState::FinWait1, cli_rst | cli_ack, ConnectionState::Reset);

    fsm_.add_transition(ConnectionState::FinWait2, srv_rst, ConnectionState::Reset);
    fsm_.add_transition(ConnectionState::FinWait2, srv_rst | srv_ack, ConnectionState::Reset);
    fsm_.add_transition(ConnectionState::FinWait2, cli_rst, ConnectionState::Reset);
    fsm_.add_transition(ConnectionState::FinWait2, cli_rst | cli_ack, ConnectionState::Reset);

    fsm_.add_transition(ConnectionState::TimeWait, srv_rst, ConnectionState::Reset);
    fsm_.add_transition(ConnectionState::TimeWait, srv_rst | srv_ack, ConnectionState::Reset);
    fsm_.add_transition(ConnectionState::TimeWait, cli_rst, ConnectionState::Reset);
    fsm_.add_transition(ConnectionState::TimeWait, cli_rst | cli_ack, ConnectionState::Reset);

    fsm_.add_transition(ConnectionState::Closing, srv_rst, ConnectionState::Reset);
    fsm_.add_transition(ConnectionState::Closing, srv_rst | srv_ack, ConnectionState::Reset);
    fsm_.add_transition(ConnectionState::Closing, cli_rst, ConnectionState::Reset);
    fsm_.add_transition(ConnectionState::Closing, cli_rst | cli_ack, ConnectionState::Reset);

    fsm_.add_transition(ConnectionState::Closed, srv_rst, ConnectionState::Reset);
    fsm_.add_transition(ConnectionState::Closed, srv_rst | srv_ack, ConnectionState::Reset);
    fsm_.add_transition(ConnectionState::Closed, cli_rst, ConnectionState::Reset);
    fsm_.add_transition(ConnectionState::Closed, cli_rst | cli_ack, ConnectionState::Reset);

    fsm_.add_transition(ConnectionState::Reset, cli_rst, ConnectionState::Reset);
    fsm_.add_transition(ConnectionState::Reset, cli_rst | cli_ack, ConnectionState::Reset);
    fsm_.add_transition(ConnectionState::Reset, cli_fin | cli_ack, ConnectionState::Reset);
    fsm_.add_transition(ConnectionState::Reset, srv_rst, ConnectionState::Reset);
    fsm_.add_transition(ConnectionState::Reset, srv_rst | srv_ack, ConnectionState::Reset);
    fsm_.add_transition(ConnectionState::Reset, srv_fin | srv_ack, ConnectionState::Reset);
}

TcpDumpParserHelper *TcpDumpParserHelper::instance()
{
    if (instance_ == nullptr)
    {
        instance_ = new TcpDumpParserHelper();
    }
    return instance_;
}

bool TcpDumpParserHelper::destroy()
{
    if(instance_)
    {
        delete instance_;
        instance_ = nullptr;
        return true;
    }
    return false;
}

TcpDumpParserHelper::tcp_flags_mask TcpDumpParserHelper::get_tcp_flags_mask(bool syn, bool ack,
                                                                            bool fin, bool rst, FlagsFrom from)
{
    tcp_flags_mask mask = 0;
    if (from == FromClient)
    {
        if (syn) mask |= TcpFlags::cli_syn;
        if (ack) mask |= TcpFlags::cli_ack;
        if (fin) mask |= TcpFlags::cli_fin;
        if (rst) mask |= TcpFlags::cli_rst;
    }
    else if (from == FromServer)
    {
        if (syn) mask |= TcpFlags::srv_syn;
        if (ack) mask |= TcpFlags::srv_ack;
        if (fin) mask |= TcpFlags::srv_fin;
        if (rst) mask |= TcpFlags::srv_rst;
    }

    return mask;
}

ConnectionState TcpDumpParserHelper::transit(ConnectionState from, tcp_flags_mask signal)
{
    auto transition_result = fsm_.transit(from, signal);
    if (transition_result.second)
    {
        return transition_result.first;
    }
    return ConnectionState::ErrorState;
}

TcpDumpParserHelper::connections_list &TcpDumpParserHelper::connections()
{
    return connections_;
}
