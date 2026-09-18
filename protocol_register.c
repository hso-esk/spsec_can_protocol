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

static const char *logger_name_ptr = "protocol_register";

void set_read_initiate_response_address(SPsecReadInitiateMessage *msg_ptr) {
  msg_ptr->address = spsec_build_response_address(
      CPMT_SESS_RDINIT, msg_ptr->cnt, msg_ptr->participant_id);
}

void set_read_segment_response_address(
    SPsecServerReadSegmentResponse *msg_ptr) {
  msg_ptr->address = spsec_build_response_address(
      CPMT_SESS_RDSEG, msg_ptr->cnt, msg_ptr->participant_id);
}

void set_write_initiate_response_address(SPsecWriteInitiateMessage *msg_ptr) {
  msg_ptr->address = spsec_build_response_address(
      CPMT_SESS_WRINIT, msg_ptr->cnt, msg_ptr->participant_id);
}

void set_write_segment_response_address(
    SPsecClientWriteSegmentResponse *msg_ptr) {
  msg_ptr->address = spsec_build_response_address(
      CPMT_SESS_WRSEG, msg_ptr->cnt, msg_ptr->participant_id);
}

SPsecMessage *parse_read_initiate_request_frame(uint8_t *arb_id_bytes_ptr,
                                                const CanFrame *frame_ptr) {
  LOG_INFO(logger_name_ptr, "Received ClientReadInitiateRequest with PID %d",
           arb_id_bytes_ptr[0] & 0x7F);
  if (frame_ptr->len < 8 + AUTH_TAG_SIZE) {
    LOG_ERROR(logger_name_ptr,
              "ReadInitiateRequest frame too short: len=%u (need %u)",
              (unsigned)frame_ptr->len, (unsigned)(8 + AUTH_TAG_SIZE));
    return NULL;
  }
  // SPsec302 §2.10: the shared-counter LSB is carried in arbitration byte 2
  // (bits 16-23), not byte 3 (the plane/priority byte).
  uint8_t cnt_lsb = arb_id_bytes_ptr[2] & 0xFF;
  SPsecReadInitiateMessage *read_init_msg_ptr =
      spsecreadinitiatemessage_new(arb_id_bytes_ptr[0] & 0x7F, cnt_lsb, 0, 0);
  if (!read_init_msg_ptr)
    return NULL;
  memcpy(read_init_msg_ptr->ciphertext, frame_ptr->data, 8);
  memcpy(read_init_msg_ptr->auth_tag, frame_ptr->data + 8, AUTH_TAG_SIZE);
  read_init_msg_ptr->address = frame_ptr->can_id & CAN_ID_MASK;
  SPsecMessage *msg_ptr =
      spsecmessage_new(MSGTYPE_CLIENT_READ_INITIATE, read_init_msg_ptr);
  if (!msg_ptr) {
    spsecreadinitiatemessage_free(read_init_msg_ptr);
    return NULL;
  }
  return msg_ptr;
}

SPsecMessage *parse_read_segment_request_frame(uint8_t *arb_id_bytes_ptr,
                                               const CanFrame *frame_ptr) {
  LOG_INFO(logger_name_ptr, "Received ClientReadSegmentRequest with PID %d",
           arb_id_bytes_ptr[0] & 0x7F);
  if (frame_ptr->len < AUTH_TAG_SIZE) {
    LOG_ERROR(logger_name_ptr,
              "ReadSegmentRequest frame too short: len=%u (need %u)",
              (unsigned)frame_ptr->len, (unsigned)AUTH_TAG_SIZE);
    return NULL;
  }
  // SPsec302 §2.10: the shared-counter LSB is carried in arbitration byte 2
  // (bits 16-23), not byte 3 (the plane/priority byte).
  uint8_t cnt_lsb = arb_id_bytes_ptr[2] & 0xFF;
  SPsecClientReadSegmentRequest *read_seg_msg_ptr =
      spsecreadsegmentrequest_new(arb_id_bytes_ptr[0] & 0x7F, cnt_lsb);
  if (!read_seg_msg_ptr)
    return NULL;
  memcpy(read_seg_msg_ptr->auth_tag, frame_ptr->data, AUTH_TAG_SIZE);
  read_seg_msg_ptr->address = frame_ptr->can_id & CAN_ID_MASK;
  SPsecMessage *msg_ptr =
      spsecmessage_new(MSGTYPE_CLIENT_READ_SEGMENT, read_seg_msg_ptr);
  if (!msg_ptr) {
    spsecreadsegmentrequest_free(read_seg_msg_ptr);
    return NULL;
  }
  return msg_ptr;
}

SPsecMessage *parse_write_initiate_request_frame(uint8_t *arb_id_bytes_ptr,
                                                 const CanFrame *frame_ptr) {
  LOG_INFO(logger_name_ptr, "Received ClientWriteInitiateRequest with PID %d",
           arb_id_bytes_ptr[0] & 0x7F);
  if (frame_ptr->len < 8 + AUTH_TAG_SIZE) {
    LOG_ERROR(logger_name_ptr,
              "WriteInitiateRequest frame too short: len=%u (need %u)",
              (unsigned)frame_ptr->len, (unsigned)(8 + AUTH_TAG_SIZE));
    return NULL;
  }
  // SPsec302 §2.10: the shared-counter LSB is carried in arbitration byte 2
  // (bits 16-23), not byte 3 (the plane/priority byte).
  uint8_t cnt_lsb = arb_id_bytes_ptr[2] & 0xFF;
  SPsecWriteInitiateMessage *write_init_msg_ptr =
      spsecwriteinitiatemessage_new(arb_id_bytes_ptr[0] & 0x7F, cnt_lsb, 0, 0);
  if (!write_init_msg_ptr)
    return NULL;
  memcpy(write_init_msg_ptr->ciphertext, frame_ptr->data, 8);
  memcpy(write_init_msg_ptr->auth_tag, frame_ptr->data + 8, AUTH_TAG_SIZE);
  write_init_msg_ptr->address = frame_ptr->can_id & CAN_ID_MASK;
  SPsecMessage *msg_ptr =
      spsecmessage_new(MSGTYPE_CLIENT_WRITE_INITIATE, write_init_msg_ptr);
  if (!msg_ptr) {
    spsecwriteinitiatemessage_free(write_init_msg_ptr);
    return NULL;
  }
  return msg_ptr;
}

SPsecMessage *parse_write_segment_request_frame(uint8_t *arb_id_bytes_ptr,
                                                const CanFrame *frame_ptr) {
  LOG_INFO(logger_name_ptr, "Received ClientWriteSegmentRequest with PID %d",
           arb_id_bytes_ptr[0] & 0x7F);
  // frame_ptr->len may include DLC padding. Determine effective ciphertext_ptr
  // length
  uint8_t payload_without_tag =
      (frame_ptr->len >= AUTH_TAG_SIZE) ? (uint8_t)(frame_ptr->len - AUTH_TAG_SIZE) : 0;
  // Allowed single-segment ciphertext sizes in descending order
  const uint8_t allowed_sizes[] = {KEY_LEN, 16, SALT_LEN, 4, 2, 1};
  uint8_t cipher_len_effective = 0;
  for (size_t i = 0; i < sizeof(allowed_sizes) / sizeof(allowed_sizes[0]);
       i++) {
    if (payload_without_tag >= allowed_sizes[i]) {
      cipher_len_effective = allowed_sizes[i];
      break;
    }
  }

  LOG_DEBUG(
      logger_name_ptr,
      "WriteSegment split: frame_len=%u payload_no_tag=%u chosen_cipher_len=%u",
      (unsigned)frame_ptr->len, (unsigned)payload_without_tag,
      (unsigned)cipher_len_effective);

  if (cipher_len_effective == 0) {
    LOG_ERROR(
        logger_name_ptr,
        "Invalid WriteSegment frame length: len=%u (payload without tag %u)",
        (unsigned)frame_ptr->len, (unsigned)payload_without_tag);
    return NULL;
  }

  // SPsec302 §2.10: the shared-counter LSB is carried in arbitration byte 2
  // (bits 16-23), not byte 3 (the plane/priority byte).
  uint8_t cnt_lsb = arb_id_bytes_ptr[2] & 0xFF;
  uint8_t *data_ptr = malloc(cipher_len_effective);
  if (!data_ptr)
    return NULL;
  SPsecClientWriteSegmentRequest *write_seg_msg_ptr = spsecwritesegmentrequest_new(
      arb_id_bytes_ptr[0] & 0x7F, cnt_lsb, data_ptr, cipher_len_effective);
  // Free temporary scratch buffer after message initialization.
  free(data_ptr);
  if (!write_seg_msg_ptr)
    return NULL;
  memcpy(write_seg_msg_ptr->ciphertext_ptr, frame_ptr->data, cipher_len_effective);
  memcpy(write_seg_msg_ptr->auth_tag, frame_ptr->data + cipher_len_effective,
         AUTH_TAG_SIZE);
  write_seg_msg_ptr->address = frame_ptr->can_id & CAN_ID_MASK;
  SPsecMessage *msg_ptr =
      spsecmessage_new(MSGTYPE_CLIENT_WRITE_SEGMENT, write_seg_msg_ptr);
  if (!msg_ptr) {
    spsecwritesegmentrequest_free(write_seg_msg_ptr);
    return NULL;
  }
  return msg_ptr;
}
