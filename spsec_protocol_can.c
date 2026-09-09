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



#include "messages.h"
#include "spsec_common.h"
#include "spsec_protocol_internal.h"

static const char *logger_name_ptr = "can_protocol";

// Pack the padding nibble and timestamp LSBs into the 2-byte CAN trailer.
void concatenate_padding(uint8_t padding_size, uint8_t *timestamp_ptr,
                         uint8_t *result_ptr) {
  uint16_t timestamp_lsbs = (uint16_t)(
      ((uint16_t)timestamp_ptr[0]) | ((uint16_t)timestamp_ptr[1] << 8));
  uint16_t combined =
      (uint16_t)(((uint16_t)padding_size << 12) | (timestamp_lsbs & 0x0FFF));

  LOG_DEBUG(logger_name_ptr,
            "Combining padding: padding_size=%d (0x%x), timestamp_lsbs=0x%03x, "
            "combined=0x%04x",
            padding_size, padding_size, timestamp_lsbs, combined);

  result_ptr[0] = (uint8_t)(combined & 0xFF);
  result_ptr[1] = (uint8_t)((combined >> 8) & 0xFF);
}

// Reverse of concatenate_padding: split the trailer back into padding + timestamp LSBs.
void separate_padding(uint8_t *data_ptr, int *padding_ptr, uint8_t *timestamp_ptr) {
  uint16_t combined =
      (uint16_t)((uint16_t)data_ptr[0] | ((uint16_t)data_ptr[1] << 8));
  *padding_ptr = (combined >> 12) & 0x0F;
  uint16_t timestamp_lsbs = combined & 0x0FFF;

  LOG_DEBUG(logger_name_ptr,
            "Separating padding: combined=0x%04x, padding=%d (0x%x), "
            "timestamp_lsbs=0x%03x",
            combined, *padding_ptr, *padding_ptr, timestamp_lsbs);

  memset(timestamp_ptr, 0, 8);
  timestamp_ptr[0] = (uint8_t)(timestamp_lsbs & 0xFF);
  timestamp_ptr[1] = (uint8_t)((timestamp_lsbs >> 8) & 0xFF);
}

// How many padding bytes to round message_length up to a valid CAN FD frame size; -1 if it doesn't fit.
signed char participant_channel_calculate_padding(int message_length) {
  static const int can_fd_lengths[] = {12, 16, 20, 24, 32, 48, 64};
  int base_len = message_length + 10;
  for (size_t i = 0; i < sizeof(can_fd_lengths) / sizeof(can_fd_lengths[0]);
       i++) {
    if (base_len <= can_fd_lengths[i]) {
      int padding = can_fd_lengths[i] - base_len;
      if (padding < 0 || padding > 15) {
        LOG_ERROR(logger_name_ptr,
                  "Padding must be 0-15, got %d for message_length %d", padding,
                  message_length);
        return -1;
      }
      LOG_DEBUG(
          logger_name_ptr,
          "Padding calculated: message_length=%d, frame_len=%d, padding=%d",
          message_length, can_fd_lengths[i], padding);
      return (signed char)padding;
    }
  }
  LOG_ERROR(logger_name_ptr, "Message length %d exceeds max CAN FD size",
            message_length);
  return -1;
}

// Reconstruct the full timestamp and padding count carried in a received frame's trailer.
signed char participant_channel_restore_timestamp_and_padding(
    uint8_t *original_timestamp_ptr, SPsecAppData *msg_ptr, uint8_t *result_ptr) {
  int padding;
  uint8_t new_lsb[8];
  separate_padding(msg_ptr->timestamp + 0, &padding, new_lsb);

  uint64_t orig_int = 0;
  for (int i = 0; i < 8; i++) {
    orig_int |= ((uint64_t)original_timestamp_ptr[i]) << (i * 8);
  }
  uint16_t frame12 =
      ((uint16_t)new_lsb[0] | ((uint16_t)new_lsb[1] << 8)) & 0x0FFF;
  uint16_t current_lsb = (uint16_t)(orig_int & 0x0FFF);

  LOG_DEBUG(logger_name_ptr, "=== TIMESTAMP RESTORATION DEBUG ===");
  LOG_DEBUG_ARRAY(logger_name_ptr, "Original timestamp (current):",
                  original_timestamp_ptr, 8);
  LOG_DEBUG(logger_name_ptr, "Current timestamp_ptr LSBs: 0x%03x", current_lsb);
  LOG_DEBUG(logger_name_ptr, "Message timestamp_ptr LSBs: 0x%03x", frame12);

  // Pick the full timestamp closest to the local clock: a naive bitmask merge
  // breaks when frame12 sits just across a 4096-tick rollover, so shift by
  // ±4096 to keep |restored - local| <= 2048 ticks.
  int32_t delta = (int32_t)frame12 - (int32_t)current_lsb;
  if (delta > 2048)
    delta -= 4096;
  else if (delta < -2048)
    delta += 4096;
  uint64_t restored_int = (uint64_t)((int64_t)orig_int + delta);

  for (int i = 0; i < 8; i++) {
    result_ptr[i] = restored_int & 0xFF;
    restored_int >>= 8;
  }

  msg_ptr->padding_size = (uint8_t)padding;
  LOG_DEBUG(logger_name_ptr, "Extracted padding: %d, LSB: 0x%03x", padding, frame12);
  LOG_DEBUG_ARRAY(logger_name_ptr, "Original timestamp:",
                  original_timestamp_ptr, 8);
  LOG_DEBUG_ARRAY(logger_name_ptr, "Restored timestamp:",
                  result_ptr, 8);
  LOG_DEBUG(logger_name_ptr, "=== TIMESTAMP RESTORATION DEBUG END ===");

  return 0;
}

// Dispatch a raw CAN frame to the right SPsec parser based on its arbitration ID.
SPsecMessage *can_protocol_parse_received_frame(uint32_t base_id,
                                                uint8_t *arb_id_bytes_ptr,
                                                const CanFrame *frame_ptr) {
  LOG_DEBUG(logger_name_ptr, "arb_id: 0x%08x", (unsigned)base_id);

  if (arb_id_bytes_ptr[3] == 0x1E) {
    if (arb_id_bytes_ptr[1] == CPMT_SESS_HELLO && arb_id_bytes_ptr[2] == 0xFF) {
      if (is_first_bit_set(arb_id_bytes_ptr[0])) {
        return parse_client_hello_frame(arb_id_bytes_ptr, frame_ptr);
      } else {
        LOG_INFO(logger_name_ptr, "Received ServerHello with PID %d",
                 arb_id_bytes_ptr[0] & 0x7F);
        return NULL;
      }
    } else if (arb_id_bytes_ptr[1] == CPMT_SESS_FINISH) {
      if (is_first_bit_set(arb_id_bytes_ptr[0])) {
        return parse_client_finished_frame(arb_id_bytes_ptr, frame_ptr);
      } else if (arb_id_bytes_ptr[2] == 0xFF &&
                 !is_first_bit_set(arb_id_bytes_ptr[0])) {
        LOG_INFO(logger_name_ptr, "Received ServerFinished with PID %d",
                 arb_id_bytes_ptr[0] & 0x7F);
        return NULL;
      }
    } else if (arb_id_bytes_ptr[1] == CPMT_SESS_RDINIT) {
      if (is_first_bit_set(arb_id_bytes_ptr[0])) {
        return parse_read_initiate_request_frame(arb_id_bytes_ptr, frame_ptr);
      } else {
        LOG_INFO(logger_name_ptr, "Received ServerReadInitiateResponse with PID %d",
                 arb_id_bytes_ptr[0] & 0x7F);
        return NULL;
      }
    } else if (arb_id_bytes_ptr[1] == CPMT_SESS_RDSEG) {
      if (is_first_bit_set(arb_id_bytes_ptr[0])) {
        return parse_read_segment_request_frame(arb_id_bytes_ptr, frame_ptr);
      } else {
        LOG_INFO(logger_name_ptr, "Received ServerReadSegmentResponse with PID %d",
                 arb_id_bytes_ptr[0] & 0x7F);
        return NULL;
      }
    } else if (arb_id_bytes_ptr[1] == CPMT_SESS_WRINIT) {
      if (is_first_bit_set(arb_id_bytes_ptr[0])) {
        return parse_write_initiate_request_frame(arb_id_bytes_ptr, frame_ptr);
      } else {
        LOG_INFO(logger_name_ptr,
                 "Received ServerWriteInitiateResponse with PID %d",
                 arb_id_bytes_ptr[0] & 0x7F);
        return NULL;
      }
    } else if (arb_id_bytes_ptr[1] == CPMT_SESS_WRSEG) {
      if (is_first_bit_set(arb_id_bytes_ptr[0])) {
        return parse_write_segment_request_frame(arb_id_bytes_ptr, frame_ptr);
      } else {
        LOG_INFO(logger_name_ptr, "Received ServerWriteSegmentResponse with PID %d",
                 arb_id_bytes_ptr[0] & 0x7F);
        return NULL;
      }
    } else if (arb_id_bytes_ptr[1] == CPMT_SESS_TERMINATE) {
      if (is_first_bit_set(arb_id_bytes_ptr[0])) {
        return parse_terminate_request_frame(arb_id_bytes_ptr, frame_ptr);
      } else {
        LOG_INFO(logger_name_ptr, "Received ServerTerminateResponse with PID %d",
                 arb_id_bytes_ptr[0] & 0x7F);
        return NULL;
      }
    }
  } else if (arb_id_bytes_ptr[3] == 0x0A && arb_id_bytes_ptr[2] == 0xFF &&
             arb_id_bytes_ptr[1] == CPMT_AUTH_TIME &&
             !is_first_bit_set(arb_id_bytes_ptr[0])) {
    return parse_timesync_request_frame(arb_id_bytes_ptr, frame_ptr);
  } else if (arb_id_bytes_ptr[3] == 0x06 && arb_id_bytes_ptr[2] == 0x23 &&
             arb_id_bytes_ptr[1] == CPMT_AUTH_TIME &&
             is_first_bit_set(arb_id_bytes_ptr[0])) {
    return parse_timesync_response_frame(arb_id_bytes_ptr, frame_ptr);
  } else if (arb_id_bytes_ptr[3] == 0x02 && arb_id_bytes_ptr[2] == 0x21 &&
             arb_id_bytes_ptr[1] == CPMT_SYNC && arb_id_bytes_ptr[0] == 0x00) {
    if (frame_ptr->len < 10)
      return NULL;
    int secure_data_len = (int)frame_ptr->len - 10;
    return parse_sync_broadcast_frame(base_id, frame_ptr, secure_data_len);
  } else if (arb_id_bytes_ptr[3] == 0x12 && arb_id_bytes_ptr[1] == CPMT_HB &&
             !is_first_bit_set(arb_id_bytes_ptr[0])) {
    LOG_INFO(logger_name_ptr, "Received Secure Heartbeat Broadcast");
    if (frame_ptr->len < 10)
      return NULL;
    int secure_data_len = (int)frame_ptr->len - 10;
    return parse_heartbeat_broadcast_frame(base_id, arb_id_bytes_ptr, frame_ptr,
                                           secure_data_len);
  }

  if (frame_ptr->len < 10)
    return NULL;
  int secure_data_len = (int)frame_ptr->len - 10;
  return parse_default_app_data(base_id, frame_ptr, secure_data_len);
}
