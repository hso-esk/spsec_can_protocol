/*
 * Copyright (c) 2026
 *
 * Hochschule Offenburg, University of Applied Sciences
 * Institute for reliable Embedded Systems
 * and Communications Electronic (ivESK)
 *
 * This file is licensed as described in the "LICENSE" file
 * included within the root folder of this work.
 */

#ifndef COMMUNICATION_INTERFACE_H
#define COMMUNICATION_INTERFACE_H

#include "messages.h"
#include "spsec_protocol_can.h" // CanFrame

typedef struct {
  int socket; // opaque transport handle (a POSIX fd on Linux)
  char *interface_name_ptr;
  int bitrate; /**< stored for diagnostics; not used to configure the interface */
  int data_bitrate; /**< stored for diagnostics; not used to configure the interface */
} CommChannel;

signed char can_channel_init(CommChannel *channel_ptr, const char *interface_name_ptr,
                             int bitrate, int data_bitrate);
void can_channel_destroy(CommChannel *channel_ptr);
SPsecMessage *can_channel_receive(CommChannel *channel_ptr, int timeout);
signed char channel_send_appdata(CommChannel *channel_ptr, AppData *message_ptr);

// Receive one CAN FD frame as a platform-agnostic CanFrame, blocking up to timeout_ms.
// Returns 1 if a frame was received, 0 on timeout/dropped frame, -1 on error.
signed char can_channel_receive_frame(CommChannel *channel_ptr, CanFrame *out_frame_ptr,
                                      int timeout_ms);

// Probe the CAN socket: 0 if healthy, -1 on ENETDOWN/ENODEV or other fatal error.
signed char can_channel_check_link_alive(CommChannel *channel_ptr);

// Tear down and re-open the CAN socket to recover from a link bounce (ENETDOWN/ENODEV)
// without restarting the participant.
// NOTE: any CAN_RAW_FILTER the caller set is lost on recovery and must be re-applied.
signed char can_channel_recover(CommChannel *channel_ptr);

#endif