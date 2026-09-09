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

static const char *logger_name_ptr = "protocol_handshake";

void set_server_finished_address(SPsecServerFinishedMessage *msg_ptr) {
  msg_ptr->address = spsec_build_response_address(
      CPMT_SESS_FINISH, msg_ptr->cnt, msg_ptr->participant_id);

  LOG_INFO(logger_name_ptr, "Set Server Finished address: %08x", msg_ptr->address);
}

void set_session_terminate_response_address(
    SPsecSessionTerminateMessage *msg_ptr) {
  msg_ptr->address = spsec_build_response_address(
      CPMT_SESS_TERMINATE, msg_ptr->cnt, msg_ptr->participant_id);
}

SPsecMessage *parse_client_hello_frame(uint8_t *arb_id_bytes_ptr,
                                       const CanFrame *frame_ptr) {
  LOG_INFO(logger_name_ptr, "Received ClientHello with PID %d",
           arb_id_bytes_ptr[0] & 0x7F);
  if (frame_ptr->len < 4 + RANDOM_SIZE) {
    LOG_ERROR(logger_name_ptr, "ClientHello frame too short: len=%u (need %u)",
              (unsigned)frame_ptr->len, (unsigned)(4 + RANDOM_SIZE));
    return NULL;
  }
  SPsecClientHelloMessage *hello_msg_ptr =
      spsecclienthello_new(arb_id_bytes_ptr[0] & 0x7F, frame_ptr->data[0],
                           (const uint8_t *)(frame_ptr->data + 4));
  if (!hello_msg_ptr)
    return NULL;
  SPsecMessage *msg_ptr = spsecmessage_new(MSGTYPE_CLIENT_HELLO, hello_msg_ptr);
  if (!msg_ptr) {
    spsecclienthello_free(hello_msg_ptr);
    return NULL;
  }
  return msg_ptr;
}

SPsecMessage *parse_client_finished_frame(uint8_t *arb_id_bytes_ptr,
                                          const CanFrame *frame_ptr) {
  LOG_INFO(logger_name_ptr, "Received ClientFinish with PID %d",
           arb_id_bytes_ptr[0] & 0x7F);
  if (frame_ptr->len < AUTH_TAG_SIZE) {
    LOG_ERROR(logger_name_ptr, "ClientFinish frame too short: len=%u (need %u)",
              (unsigned)frame_ptr->len, (unsigned)AUTH_TAG_SIZE);
    return NULL;
  }
  SPsecClientFinishedMessage *finish_msg_ptr =
      spsecclientfinished_new(arb_id_bytes_ptr[0] & 0x7F, arb_id_bytes_ptr[2]);
  if (!finish_msg_ptr)
    return NULL;
  memcpy(finish_msg_ptr->auth_tag, frame_ptr->data, AUTH_TAG_SIZE);
  finish_msg_ptr->address = frame_ptr->can_id & CAN_ID_MASK;
  SPsecMessage *msg_ptr = spsecmessage_new(MSGTYPE_CLIENT_FINISHED, finish_msg_ptr);
  if (!msg_ptr) {
    spsecclientfinished_free(finish_msg_ptr);
    return NULL;
  }
  return msg_ptr;
}

SPsecMessage *parse_terminate_request_frame(uint8_t *arb_id_bytes_ptr,
                                            const CanFrame *frame_ptr) {
  LOG_INFO(logger_name_ptr, "Received ClientTerminateRequest with PID %d",
           arb_id_bytes_ptr[0] & 0x7F);
  if (frame_ptr->len < AUTH_TAG_SIZE) {
    LOG_ERROR(logger_name_ptr,
              "ClientTerminateRequest frame too short: len=%u (need %u)",
              (unsigned)frame_ptr->len, (unsigned)AUTH_TAG_SIZE);
    return NULL;
  }
  // Counter LSB is in arbitration byte 2 (bits 16-23), not the plane byte 3.
  SPsecSessionTerminateMessage *terminate_msg_ptr =
      spsecsessionterminatemsg_new(arb_id_bytes_ptr[0] & 0x7F, arb_id_bytes_ptr[2]);
  if (!terminate_msg_ptr)
    return NULL;
  memcpy(terminate_msg_ptr->auth_tag, frame_ptr->data, AUTH_TAG_SIZE);
  terminate_msg_ptr->address = frame_ptr->can_id & CAN_ID_MASK;
  SPsecMessage *msg_ptr =
      spsecmessage_new(MSGTYPE_CLIENT_TERMINATE, terminate_msg_ptr);
  if (!msg_ptr) {
    spsecsessionterminatemsg_free(terminate_msg_ptr);
    return NULL;
  }
  return msg_ptr;
}
