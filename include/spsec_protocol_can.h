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

#ifndef SPSEC_CAN_PROTOCOL_H
#define SPSEC_CAN_PROTOCOL_H

#include <stdint.h>

#include "messages.h"
#include "spsec_common.h"

// 29-bit extended CAN ID mask (protocol-level, platform-agnostic)
#define CAN_ID_MASK 0x1FFFFFFF

// Platform-agnostic CAN frame used by protocol layer
typedef struct {
  uint32_t can_id;
  uint8_t len;
  uint8_t data[64];
} CanFrame;

// Helpers for padding/timestamp composition
void concatenate_padding(uint8_t padding_size, uint8_t *timestamp_ptr,
                         uint8_t *result_ptr);
void separate_padding(uint8_t *data_ptr, int *padding_ptr, uint8_t *timestamp_ptr);



// Parsing of received CAN frames into SPsecMessage (platform-agnostic)
SPsecMessage *can_protocol_parse_received_frame(uint32_t base_id,
                                                uint8_t *arb_id_bytes_ptr,
                                                const CanFrame *frame_ptr);

#endif
