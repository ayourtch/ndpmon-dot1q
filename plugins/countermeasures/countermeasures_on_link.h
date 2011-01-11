#ifndef _COUNTER_MEASURES_ON_LINK_H_

/** @file
    Keeps track of the countermeasures on the link.
    Do not include this file directly; use coutnermeasures.h instead.
*/

/** The actual type of the hash used to identify packages.
    Used to keep the actual hash function and its hash size swapable
    (for instance in case of security flaws in the hash function).
*/
typedef uint8_t cm_on_link_hash_t[20];

/** A linked list type for counter measures on the link.

    If NDPMon sents a counter measures to the same interface it is listening
    on, it will as well capture its own counter measures.
    To prevent them from causing counter-counter measures, we keep a list of
    counter-measures that are on the link.
    "on the link" means that those messages have not been captured yet.
    To have constant size types and to reduce memory consumption
    we use SHA-1.
*/
struct cm_on_link_list {
    /** The hash computed for this packet.
    */
    cm_on_link_hash_t hash;
    /** A pointer to the next counter-measure.
    */
    struct cm_on_link_list* next;
};

/** Adds a counter measure to the list of counter measures on link.
    @param packet Pointer to the counter measure packet, including ETHERNET and IP header.
    @param packet_length Length of the packet.
    @return 0 on success, -1 otherwise.
*/
int cm_on_link_add(const uint8_t* packet, int packet_length);

/** Removes a given packet from the on link list if the packet corresponds to a hashed counter measure.
    @param packet Pointer to the captured packet, including ETHERNET and IP header.
    @param packet_length Length of the packet.
    @return 0 if the packet was not found, 1 if it was found and removed.
*/
int cm_on_link_remove(const uint8_t* packet, int packet_length);

/** Computes the hash value for a given packet.
    @param packet Pointer to the packet, including ETHERNET and IP header.
    @param packet_length Length of the packet.
    @return Pointer to the allocated and calculated hash vector.
*/
cm_on_link_hash_t* cm_on_link_create_hash_for_packet(const uint8_t* packet, int packet_length);

/** Frees the list of counter measures on link.
*/
void free_cm_on_link_list();

#endif
