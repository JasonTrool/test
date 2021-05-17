#pragma once

#include <set>
#include <map>

template <typename StateType, typename SignalType>
class FiniteStateMachine
{
public:
    FiniteStateMachine() = default;
    ~FiniteStateMachine() = default;

    void add_transition(StateType from, SignalType signal, StateType to)
    {
        if (transition_table_.find(from) == transition_table_.end())
        {
            transition_table_.insert({ from, std::map<SignalType, StateType>() });
        }
        transition_table_[from].insert(std::make_pair(signal, to));
    }

    std::pair<StateType, bool> transit(StateType from, SignalType signal)
    {
        auto table_it = transition_table_.find(from);
        if (table_it == transition_table_.end())
        {
            return std::make_pair(StateType(), false);
        }
        auto signal_state_map_it = table_it->second.find(signal);
        if (signal_state_map_it == table_it->second.end())
        {
            return std::make_pair(StateType(), false);
        }
        return std::make_pair(signal_state_map_it->second, true);
    }

private:
    std::map<StateType, std::map<SignalType, StateType>> transition_table_;
};
