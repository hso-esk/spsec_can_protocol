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

#ifndef SPSEC_PROTOCOL_INTERNAL_H
#define SPSEC_PROTOCOL_INTERNAL_H

#include "spsec_protocol_can.h"

// Control-plane response arbitration-ID base (29-bit, priority/band bits).
#define SPSEC_RESP_ADDR_BASE 0x1E000000u

// Build a control-plane response arbitration ID: base | (cnt_low8<<16) | (cpmt<<8) | pid.
// Single source of truth for every set_*_response_address.
static inline uint32_t spsec_build_response_address(uint8_t cpmt, uint32_t cnt,
                                                    uint8_t pid) {
  return SPSEC_RESP_ADDR_BASE | ((cnt & 0xFFu) << 16) |
         ((uint32_t)cpmt << 8) | (pid & 0x7Fu);
}

// Handshake Parsers
SPsecMessage *parse_client_hello_frame(uint8_t *arb_id_bytes_ptr,
                                       const CanFrame *frame_ptr);
SPsecMessage *parse_client_finished_frame(uint8_t *arb_id_bytes_ptr,
                                          const CanFrame *frame_ptr);
SPsecMessage *parse_terminate_request_frame(uint8_t *arb_id_bytes_ptr,
                                            const CanFrame *frame_ptr);

// Session Parsers
SPsecMessage *parse_timesync_request_frame(uint8_t *arb_id_bytes_ptr,
                                           const CanFrame *frame_ptr);
SPsecMessage *parse_timesync_response_frame(uint8_t *arb_id_bytes_ptr,
                                            const CanFrame *frame_ptr);
SPsecMessage *parse_sync_broadcast_frame(uint32_t base_id,
                                         const CanFrame *frame_ptr,
                                         int secure_data_len);
SPsecMessage *parse_heartbeat_broadcast_frame(uint32_t base_id,
                                              uint8_t *arb_id_bytes_ptr,
                                              const CanFrame *frame_ptr,
                                              int secure_data_len);
SPsecMessage *parse_default_app_data(uint32_t base_id, const CanFrame *frame_ptr,
                                     int secure_data_len);

// Register Parsers
SPsecMessage *parse_read_initiate_request_frame(uint8_t *arb_id_bytes_ptr,
                                                const CanFrame *frame_ptr);
SPsecMessage *parse_read_segment_request_frame(uint8_t *arb_id_bytes_ptr,
                                               const CanFrame *frame_ptr);
SPsecMessage *parse_write_initiate_request_frame(uint8_t *arb_id_bytes_ptr,
                                                 const CanFrame *frame_ptr);
SPsecMessage *parse_write_segment_request_frame(uint8_t *arb_id_bytes_ptr,
                                                const CanFrame *frame_ptr);

#endif
