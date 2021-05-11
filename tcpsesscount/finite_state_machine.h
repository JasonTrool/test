#pragma once

#include <vector>

template <typename StateType>
class FiniteStateMachine
{
public:
    FiniteStateMachine() = default;
    ~FiniteStateMachine() = default;

    void add_transition(StateType from, StateType to)
    {
        transition_table_.push_back( {from, to} );
    }

    bool transit_to(StateType current, StateType state)
    {
        for (const auto &transition : transition_table_)
        {
            if (transition.from == current && transition.to == state)
            {
                return true;
            }
        }
        return false;
    }

private:
    struct Transition
    {
        StateType  from;
        StateType  to;
    };

    std::vector<Transition> transition_table_;
};
