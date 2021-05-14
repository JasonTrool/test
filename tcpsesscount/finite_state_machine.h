#pragma once

#include <set>
#include <map>

template <typename StateType>
class FiniteStateMachine
{
public:
    FiniteStateMachine() = default;
    ~FiniteStateMachine() = default;

    void add_transition(StateType from, StateType to)
    {
        if (transition_table_.find(from) == transition_table_.end())
        {
            transition_table_.insert({ from, std::set<StateType>() });
        }
        transition_table_[from].insert(to);
    }

    std::pair<StateType, bool> transit(StateType from, StateType to)
    {
        if (transition_table_.find(from) == transition_table_.end())
        {
            return std::make_pair(StateType(), false);
        }
        auto state = transition_table_[from].find(to);
        if (state != transition_table_[from].end())
        {
            return std::make_pair(*state, true);
        }
        return std::make_pair(StateType(), false);
    }

private:
    std::map<StateType, std::set<StateType>> transition_table_;
};
