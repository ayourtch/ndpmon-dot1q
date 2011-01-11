#ifndef _COUNTER_MEASURES_GUARD_H_

/** @file
    Guards for the different countermeasures.
    Do not include this file directly; use coutnermeasures.h instead.
*/

/** Respond to each call by taking action.*/
#define CM_GUARD_STRATEGY_TYPE_RESPOND  3
/** Starts after a given number of calls to respond by taking action.*/
#define CM_GUARD_STRATEGY_TYPE_LAUNCH    2
/** After a given number of call stops to respond to each call.*/
#define CM_GUARD_STRATEGY_TYPE_CEASE    1
/** Never react to a call (counter measure deactivated).*/
#define CM_GUARD_STRATEGY_TYPE_SUPPRESS 0
/** The maximum string size required to store the string
    representation of a countermeasure guard strategy.
*/
#define CM_GUARD_REPRESENTATION_SIZE 20

/** Encodes the rules of engagement and the call history of a counter measures.*/
struct cm_guard {
    /** The number of recent calls to this counter measure.*/
    uint8_t calls;
    /** The strategy used to decide if a reaction to the current call is welcome.*/
    uint8_t strategy_type;
    /** May hold an additional criteria used by the strategy.*/
    uint8_t strategy_criteria;
};

/** Initialises a counter measure guard from a XML configuration string.
    @param guard Pointer to the guard to be initialized.
    @param config The string from which the guards strategy and criteria is initialized.
*/
void cm_guard_init(struct cm_guard* guard, char* config);

/** Initialises the counter measure guards from the XML configuration strings.*/
void cm_guard_init_all(
    char* config_kill_illegitimate_router,
    char* config_kill_wrong_prefix,
    char* config_propagate_router_params,
    char* config_indicate_ndpmon_presence
);

/** Represents the guards configuration as a string.
    The string must have sufficient capacity to store the string
    representation. Use CM_GUARD_REPRESENTATION_SIZE.
    @param guard Pointer to the guard.
    @param config The string to hold the configuration.
*/
void cm_guard_to_representation(struct cm_guard* guard, char* config);

/** Stores the configuration of all guards in the given strings.
    The strings must have sufficient capacity to store the string
    representations. Use CM_GUARD_REPRESENTATION_SIZE.
*/
void cm_guard_all_to_representation(
    char* config_kill_illegitimate_router,
    char* config_kill_wrong_prefix,
    char* config_propagate_router_params,
    char* config_indicate_ndpmon_presence
);

/** Determines wether the given guard expects a call to a counter measure
    to react to an attack or not.
    @param guard The guard used to decide if the counter measure should react or not.
    @return 1 if a reaction is welcome, 0 if not.
*/
int cm_is_welcome(struct cm_guard* guard);

#endif
