#include "tcp_dump_parser_helper.h"

TcpDumpParserHelper *TcpDumpParserHelper::instance_ = nullptr;

TcpDumpParserHelper::TcpDumpParserHelper()
    : fsm_()
    , connections_()
{
    fsm_.add_transition(ConnectionState::Initial, ConnectionState::Establishing);
    fsm_.add_transition(ConnectionState::Initial, ConnectionState::Established);
    fsm_.add_transition(ConnectionState::Establishing, ConnectionState::Establishing);
    fsm_.add_transition(ConnectionState::Establishing, ConnectionState::Established);
    fsm_.add_transition(ConnectionState::Establishing, ConnectionState::Reset);
    fsm_.add_transition(ConnectionState::Established, ConnectionState::Established);
    fsm_.add_transition(ConnectionState::Established, ConnectionState::Closing);
    fsm_.add_transition(ConnectionState::Established, ConnectionState::Reset);
    fsm_.add_transition(ConnectionState::Closing, ConnectionState::Closing);
    fsm_.add_transition(ConnectionState::Closing, ConnectionState::Closed);
    fsm_.add_transition(ConnectionState::Closing, ConnectionState::Reset);
    fsm_.add_transition(ConnectionState::Closed, ConnectionState::Reset);

    flag_handlers_[TcpFlags::syn] = [&](ConnectionState current_state)
    {
        auto result = fsm_.transit(current_state, ConnectionState::Establishing);
        if (result.second)
        {
            return result.first;
        }
        return ConnectionState::ErrorState;
    };

    flag_handlers_[TcpFlags::ack] = [&](ConnectionState current_state)
    {
        if (current_state == ConnectionState::Reset)
        {
            return current_state;
        }
        if (current_state == ConnectionState::Establishing)
        {
            auto result = fsm_.transit(current_state, ConnectionState::Established);
            if (result.second)
            {
                return result.first;
            }
        }
        else if (current_state == ConnectionState::Closing)
        {
            auto result = fsm_.transit(current_state, ConnectionState::Closed);
            if (result.second)
            {
                return result.first;
            }
        }
        else if (current_state == ConnectionState::Closed)
        {
            return ConnectionState::Closed;
        }
        else if (current_state == ConnectionState::Established)
        {
            return current_state;
        }
        return ConnectionState::Established;
    };

    flag_handlers_[TcpFlags::fin] = [&](ConnectionState current_state)
    {
        if (current_state == ConnectionState::Reset)
        {
            return current_state;
        }
        if (current_state == ConnectionState::Closing)
        {
            auto result = fsm_.transit(current_state, ConnectionState::Closing);
            if (result.second)
            {
                return result.first;
            }
        }
        return ConnectionState::ErrorState;
    };

    flag_handlers_[TcpFlags::rst] = [&](ConnectionState current_state)
    {
        if (current_state == ConnectionState::Reset)
        {
            return current_state;
        }
        auto result = fsm_.transit(current_state, ConnectionState::Reset);
        if (result.second)
        {
            return result.first;
        }
        return ConnectionState::ErrorState;
    };

    flag_handlers_[TcpFlags::synack] = [&](ConnectionState current_state)
    {
        if (current_state == ConnectionState::Reset)
        {
            return current_state;
        }
        if (current_state == ConnectionState::Established)
        {
            return current_state;
        }
        auto result = fsm_.transit(current_state, ConnectionState::Establishing);
        if (result.second)
        {
            return result.first;
        }
        return ConnectionState::ErrorState;
    };

    flag_handlers_[TcpFlags::finack] = [&](ConnectionState current_state)
    {
        if (current_state == ConnectionState::Reset)
        {
            return ConnectionState::Reset;
        }
        else if (current_state == ConnectionState::Closed)
        {
            return ConnectionState::Closed;
        }
        auto result = fsm_.transit(current_state, ConnectionState::Closing);
        if (result.second)
        {
            return result.first;
        }
        return ConnectionState::ErrorState;
    };
    flag_handlers_[TcpFlags::rstack] = [&](ConnectionState current_state)
    {
        return flag_handlers_[TcpFlags::rst](current_state);
    };
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

ConnectionState TcpDumpParserHelper::transit(ConnectionState from, TcpDumpParserHelper::TcpFlags signal)
{
    auto handler = flag_handlers_.find(signal);
    if (handler == std::end(flag_handlers_))
    {
        return ConnectionState::ErrorState;
    }
    return handler->second(from);
}

TcpDumpParserHelper::connections_list &TcpDumpParserHelper::connections()
{
    return connections_;
}
