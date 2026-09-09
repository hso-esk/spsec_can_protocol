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

static const char *logger_name_ptr = "protocol_session";

void set_heartbeat_address(SPsecHeartbeatMessage *msg_ptr) {
  msg_ptr->app_data_ptr->address =
      (uint32_t)(0x12000000 | (msg_ptr->status << 16) | (CPMT_HB << 8) |
                 (msg_ptr->participant_id & 0x7F));

  LOG_DEBUG(logger_name_ptr, "Set heartbeat address: %08x for participant_ptr %d",
            msg_ptr->app_data_ptr->address, msg_ptr->participant_id);
}

void set_broadcast_timesync_address(AppData *msg_ptr) {
  msg_ptr->address = 0x02210000 | (CPMT_SYNC << 8);
}

SPsecMessage *parse_timesync_request_frame(uint8_t *arb_id_bytes_ptr,
                                           const CanFrame *frame_ptr) {
  LOG_INFO(logger_name_ptr, "Received Time Sync request for PID %d",
           arb_id_bytes_ptr[0] & 0x7F);
  if (frame_ptr->len < RANDOM_SIZE) {
    LOG_ERROR(logger_name_ptr, "TimeSync request frame too short: len=%u (need %u)",
              (unsigned)frame_ptr->len, (unsigned)RANDOM_SIZE);
    return NULL;
  }
  SPsecTimeSyncRequest *req_ptr =
      timesyncrequest_new(arb_id_bytes_ptr[0], (const uint8_t *)frame_ptr->data);
  if (!req_ptr)
    return NULL;
  SPsecMessage *msg_ptr = spsecmessage_new(CPMT_AUTH_TIME, req_ptr);
  if (!msg_ptr) {
    timesyncrequest_free(req_ptr);
    return NULL;
  }
  return msg_ptr;
}

SPsecMessage *parse_timesync_response_frame(uint8_t *arb_id_bytes_ptr,
                                            const CanFrame *frame_ptr) {
  LOG_INFO(logger_name_ptr, "Received TimeSync response for PID %u",
           arb_id_bytes_ptr[0] & 0x7F);
  // Frame layout: timestamp_ptr (8 bytes) || csalt (4 bytes) || auth_tag_ptr (8
  // bytes)
  if (frame_ptr->len < TIMESTAMP_SIZE + 4 + AUTH_TAG_SIZE) {
    LOG_ERROR(logger_name_ptr,
              "TimeSync response frame too short: len=%u (need %u)",
              (unsigned)frame_ptr->len,
              (unsigned)(TIMESTAMP_SIZE + 4 + AUTH_TAG_SIZE));
    return NULL;
  }
  SPsecTimeSyncResponse *resp_ptr = timesyncresponse_new(
      (uint8_t *)frame_ptr->data, (uint8_t *)(frame_ptr->data + TIMESTAMP_SIZE),
      (uint8_t *)(frame_ptr->data + TIMESTAMP_SIZE + 4), AUTH_TAG_SIZE,
      arb_id_bytes_ptr[0] & 0x7F);
  if (!resp_ptr)
    return NULL;
  SPsecMessage *msg_ptr = spsecmessage_new(MSGTYPE_TIME_SYNC_RESPONSE, resp_ptr);
  if (!msg_ptr) {
    free(resp_ptr->auth_tag_ptr);
    free(resp_ptr);
    return NULL;
  }
  return msg_ptr;
}

SPsecMessage *parse_sync_broadcast_frame(uint32_t base_id,
                                         const CanFrame *frame_ptr,
                                         int secure_data_len) {
  uint8_t dummy_ts[8] = {0};
  SPsecAppData *sad_ptr = spsecappdata_new(
      base_id, (uint8_t *)frame_ptr->data, (size_t)secure_data_len, 0, dummy_ts,
      (uint8_t *)(frame_ptr->data + frame_ptr->len - AUTH_TAG_SIZE), AUTH_TAG_SIZE);
  if (!sad_ptr)
    return NULL;
  memcpy(sad_ptr->timestamp + 0, frame_ptr->data + secure_data_len, 2);
  SPsecSyncTimeBroadcastMessage *tb_msg_ptr = spsecsynctimebroadcast_new(0);
  if (!tb_msg_ptr) {
    spsecappdata_free(sad_ptr);
    return NULL;
  }
  tb_msg_ptr->spsec_app_data_ptr = sad_ptr;
  SPsecMessage *msg_ptr = spsecmessage_new(MSGTYPE_SYNC_TIME_BROADCAST, tb_msg_ptr);
  if (!msg_ptr) {
    tb_msg_ptr->spsec_app_data_ptr = NULL;  // Prevent double-free in spsecsynctimebroadcast_free
    spsecsynctimebroadcast_free(tb_msg_ptr);
    return NULL;
  }
  return msg_ptr;
}

SPsecMessage *parse_heartbeat_broadcast_frame(uint32_t base_id,
                                              uint8_t *arb_id_bytes_ptr,
                                              const CanFrame *frame_ptr,
                                              int secure_data_len) {
  uint8_t dummy_ts[8] = {0};
  SPsecAppData *sad_ptr = spsecappdata_new(
      base_id, (uint8_t *)frame_ptr->data, (size_t)secure_data_len, 0, dummy_ts,
      (uint8_t *)(frame_ptr->data + frame_ptr->len - AUTH_TAG_SIZE), AUTH_TAG_SIZE);
  if (!sad_ptr)
    return NULL;
  memcpy(sad_ptr->timestamp + 0, frame_ptr->data + secure_data_len, 2);
  SPsecHeartbeatMessage *hb_ptr =
      spsecheartbeat_new(arb_id_bytes_ptr[0] & 0x7F, arb_id_bytes_ptr[2]);
  if (!hb_ptr) {
    spsecappdata_free(sad_ptr);
    return NULL;
  }
  hb_ptr->spsec_app_data_ptr = sad_ptr;
  SPsecMessage *msg_ptr = spsecmessage_new(MSGTYPE_HEARTBEAT, hb_ptr);
  if (!msg_ptr) {
    hb_ptr->spsec_app_data_ptr = NULL;  // Prevent double-free in spsecheartbeat_free
    spsecheartbeat_free(hb_ptr);
    return NULL;
  }
  return msg_ptr;
}

SPsecMessage *parse_default_app_data(uint32_t base_id, const CanFrame *frame_ptr,
                                     int secure_data_len) {
  uint8_t dummy_ts[8] = {0};
  SPsecAppData *sad_ptr = spsecappdata_new(
      base_id, (uint8_t *)frame_ptr->data, (size_t)secure_data_len, 0, dummy_ts,
      (uint8_t *)(frame_ptr->data + frame_ptr->len - AUTH_TAG_SIZE), AUTH_TAG_SIZE);
  if (!sad_ptr)
    return NULL;
  memcpy(sad_ptr->timestamp + 0, frame_ptr->data + secure_data_len, 2);
  SPsecMessage *msg_ptr = spsecmessage_new(MSGTYPE_APP_DATA, sad_ptr);
  if (!msg_ptr) {
    spsecappdata_free(sad_ptr);
    return NULL;
  }
  return msg_ptr;
}
