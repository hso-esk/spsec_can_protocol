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
#include "participant_channel.h"
#include "spsec_common.h"

static const char *logger_name_ptr = "participant_channel_can";

// Send a ServerHello frame on the secure channel.
signed char
participant_channel_send_server_hello(SPsecCommChannel *channel_ptr,
                                      SPsecServerHelloMessage *msg_ptr) {
  uint32_t base_id =
      0x1EFF0000 | (CPMT_SESS_HELLO << 8) | (msg_ptr->participant_id & 0x7F);
  uint8_t payload[16];
  memcpy(payload, msg_ptr->random, 16);

  AppData *ad_ptr = appdata_new(base_id, payload, sizeof(payload));
  if (!ad_ptr) {
    LOG_ERROR(logger_name_ptr, "Failed to allocate AppData for ServerHello");
    return -1;
  }
  if (channel_send_appdata(&channel_ptr->channel, ad_ptr) != 0) {
    LOG_ERROR(logger_name_ptr, "Failed to send ServerHello");
    appdata_free(ad_ptr);
    return -1;
  }
  appdata_free(ad_ptr);
  return 0;
}

/**
 * @brief Send a ServerFinished frame including the authentication tag.
 */
signed char
participant_channel_send_server_finished(SPsecCommChannel *channel_ptr,
                                         SPsecServerFinishedMessage *msg_ptr) {
  uint8_t payload[8];
  memcpy(payload, msg_ptr->auth_tag, 8);

  char hex_data[9];
  format_hex_string(hex_data, sizeof(hex_data), payload,
                    sizeof(payload) < 4 ? sizeof(payload) : 4);
  LOG_INFO(logger_name_ptr,
           "Sending Server Finished frame: ID=%08x, Len=%d, Data=%s...",
           msg_ptr->address, (int)sizeof(payload), hex_data);

  AppData *ad_ptr = appdata_new(msg_ptr->address, payload, sizeof(payload));
  if (!ad_ptr) {
    LOG_ERROR(logger_name_ptr, "Failed to allocate AppData for Server Finished");
    return -1;
  }
  if (channel_send_appdata(&channel_ptr->channel, ad_ptr) != 0) {
    LOG_ERROR(logger_name_ptr, "Failed to send Server Finished");
    appdata_free(ad_ptr);
    return -1;
  }
  appdata_free(ad_ptr);

  return 0;
}

/**
 * @brief Transmit a CPMT_AUTH_TIME request carrying the client random_ptr.
 */
signed char
participant_channel_send_timesync_request(SPsecCommChannel *channel_ptr,
                                          SPsecTimeSyncRequest *msg_ptr) {
  uint32_t base_id =
      0x0AFF0000 | (CPMT_AUTH_TIME << 8) | (msg_ptr->participant_id & 0x7F);
  uint8_t payload[16];
  memcpy(payload, msg_ptr->random, 16);

  char hex_data[9];
  format_hex_string(hex_data, sizeof(hex_data), payload,
                    sizeof(payload) < 4 ? sizeof(payload) : 4);
  LOG_DEBUG(logger_name_ptr,
            "Sending frame: ID=%08x, Len=%d, Data=%s...", base_id,
            (int)sizeof(payload), hex_data);
  AppData *ad_ptr = appdata_new(base_id, payload, sizeof(payload));
  if (!ad_ptr) {
    LOG_ERROR(logger_name_ptr, "Failed to allocate AppData for timesync request");
    return -1;
  }
  if (channel_send_appdata(&channel_ptr->channel, ad_ptr) != 0) {
    LOG_ERROR(logger_name_ptr, "Failed to send timesync request");
    appdata_free(ad_ptr);
    return -1;
  }
  appdata_free(ad_ptr);
  LOG_INFO(logger_name_ptr, "Sent CPMT_AUTH_TIME request");
  return 0;
}

// Send encrypted SPsec AppData, packing padding + timestamp trailer bytes first.
signed char participant_channel_send_spapp_data(SPsecCommChannel *channel_ptr,
                                                SPsecAppData *msg_ptr) {
  LOG_DEBUG(logger_name_ptr,
            "Sending app data: padding_size=%d, secure_data_len=%zu",
            msg_ptr->padding_size, msg_ptr->secure_data_len);
  LOG_DEBUG_ARRAY(logger_name_ptr, "Current full timestamp:",
                  msg_ptr->timestamp, TIMESTAMP_SIZE);
  LOG_DEBUG_ARRAY(logger_name_ptr, "Timestamp LSBs for padding combination:",
                  msg_ptr->timestamp, 2);

  // Compute combined padding+timestamp LSBs without heap allocation
  uint16_t timestamp_lsbs = (uint16_t)(((uint16_t)msg_ptr->timestamp[0]) |
                            ((uint16_t)msg_ptr->timestamp[1] << 8));
  uint16_t combined = (uint16_t)(
      ((uint16_t)msg_ptr->padding_size << 12) | (timestamp_lsbs & 0x0FFF));
  LOG_DEBUG("can_protocol",
            "Combining padding: padding_size=%d (0x%x), timestamp_lsbs=0x%03x, "
            "combined=0x%04x",
            msg_ptr->padding_size, msg_ptr->padding_size, timestamp_lsbs,
            combined);
  uint8_t padding_bytes[2];
  padding_bytes[0] = (uint8_t)(combined & 0xFF);
  padding_bytes[1] = (uint8_t)((combined >> 8) & 0xFF);

  LOG_DEBUG_ARRAY(logger_name_ptr, "Combined padding+timestamp bytes:",
                  padding_bytes, sizeof(padding_bytes));

  size_t total_len = msg_ptr->secure_data_len + 2 + msg_ptr->auth_tag_len;
  uint8_t *can_data_ptr = malloc(total_len);
  if (!can_data_ptr) {
    return -1;
  }

  // Copy secure data to the beginning of the frame
  memcpy(can_data_ptr, msg_ptr->secure_data_ptr, msg_ptr->secure_data_len);
  // Copy concatenated padding and least significant 12 bits of timestamp
  // before auth tag
  memcpy(can_data_ptr + msg_ptr->secure_data_len, padding_bytes, 2);
  // Copy auth tag to the end of the frame
  memcpy(can_data_ptr + msg_ptr->secure_data_len + 2, msg_ptr->auth_tag_ptr,
         msg_ptr->auth_tag_len);

  char hex_preview[9];
  format_hex_string(hex_preview, sizeof(hex_preview), can_data_ptr,
                    total_len < 4 ? total_len : 4);
  LOG_DEBUG(logger_name_ptr,
            "Sending frame: ID=%08x, Len=%zu, Data=%s...",
            msg_ptr->address, total_len, hex_preview);

  AppData *ad_ptr = appdata_new(msg_ptr->address, can_data_ptr, total_len);
  if (!ad_ptr) {
    LOG_ERROR(logger_name_ptr, "Failed to allocate AppData for app data_ptr");
    free(can_data_ptr);
    return -1;
  }
  if (channel_send_appdata(&channel_ptr->channel, ad_ptr) != 0) {
    LOG_ERROR(logger_name_ptr, "Failed to send MSGTYPE_APP_DATA");
    appdata_free(ad_ptr);
    free(can_data_ptr);
    return -1;
  }
  appdata_free(ad_ptr);

  LOG_DEBUG(logger_name_ptr, "Sent MSGTYPE_APP_DATA message.");
  free(can_data_ptr);
  return 0;
}

/**
 * @brief Send a ReadInitiate response payload back to the client.
 */
signed char participant_channel_send_read_initiate_response(
    SPsecCommChannel *channel_ptr, SPsecReadInitiateMessage *msg_ptr) {
  uint8_t payload[8 + AUTH_TAG_SIZE];
  memcpy(payload, msg_ptr->ciphertext, 8);
  memcpy(payload + 8, msg_ptr->auth_tag, AUTH_TAG_SIZE);

  LOG_INFO(logger_name_ptr, "Sending Read Initiate response");

  AppData *ad_ptr = appdata_new(msg_ptr->address, payload, sizeof(payload));
  if (!ad_ptr) {
    LOG_ERROR(logger_name_ptr,
              "Failed to allocate AppData for Read Initiate response");
    return -1;
  }
  if (channel_send_appdata(&channel_ptr->channel, ad_ptr) != 0) {
    LOG_ERROR(logger_name_ptr, "Failed to send Read Initiate response");
    appdata_free(ad_ptr);
    return -1;
  }
  appdata_free(ad_ptr);
  return 0;
}

/**
 * @brief Send an encrypted read segment response (data_ptr + tag).
 */
// Round a payload length up to the next valid CAN FD DLC (0-8, then 12, 16, 20,
// 24, 32, 48, 64). Control-plane segment frames must land on a valid DLC so the
// wire length is well-defined; the gap is filled with 0xFF padding.
static size_t next_canfd_dlc(size_t len) {
  static const size_t dlcs[] = {12, 16, 20, 24, 32, 48, 64};
  if (len <= 8)
    return len; // 0..8 are all valid CAN FD lengths
  for (size_t i = 0; i < sizeof(dlcs) / sizeof(dlcs[0]); i++) {
    if (len <= dlcs[i])
      return dlcs[i];
  }
  return len; // > 64: caller-limited; leave as-is
}

signed char participant_channel_send_read_segment_response(
    SPsecCommChannel *channel_ptr, SPsecServerReadSegmentResponse *msg_ptr) {
  // SPsec302 §6.2.4: padding is added behind the auth tag, set to 0xFF, not part
  // of the AEAD, so the frame reaches a valid CAN FD DLC.
  size_t raw_len = msg_ptr->data_len + AUTH_TAG_SIZE;
  size_t payload_len = next_canfd_dlc(raw_len);
  uint8_t *payload_ptr = malloc(payload_len);
  if (!payload_ptr) {
    LOG_ERROR(logger_name_ptr,
              "Failed to allocate payload for read Segment response");
    return -1;
  }
  memcpy(payload_ptr, msg_ptr->ciphertext_ptr, msg_ptr->data_len);
  memcpy(payload_ptr + msg_ptr->data_len, msg_ptr->auth_tag, AUTH_TAG_SIZE);
  if (payload_len > raw_len)
    memset(payload_ptr + raw_len, 0xFF, payload_len - raw_len);

  LOG_INFO(logger_name_ptr, "Sending read Segment response");

  AppData *ad_ptr = appdata_new(msg_ptr->address, payload_ptr, payload_len);
  free(payload_ptr);
  if (!ad_ptr) {
    LOG_ERROR(logger_name_ptr,
              "Failed to allocate AppData for read Segment response");
    return -1;
  }
  if (channel_send_appdata(&channel_ptr->channel, ad_ptr) != 0) {
    LOG_ERROR(logger_name_ptr, "Failed to send read Segment response");
    appdata_free(ad_ptr);
    return -1;
  }
  appdata_free(ad_ptr);

  return 0;
}

/**
 * @brief Send a WriteInitiate response payload.
 */
signed char participant_channel_send_write_initiate_response(
    SPsecCommChannel *channel_ptr, SPsecWriteInitiateMessage *msg_ptr) {
  uint8_t payload[8 + AUTH_TAG_SIZE];
  memcpy(payload, msg_ptr->ciphertext, 8);
  memcpy(payload + 8, msg_ptr->auth_tag, AUTH_TAG_SIZE);

  LOG_INFO(logger_name_ptr, "Sending Write Initiate Response");

  AppData *ad_ptr = appdata_new(msg_ptr->address, payload, sizeof(payload));
  if (!ad_ptr) {
    LOG_ERROR(logger_name_ptr,
              "Failed to allocate AppData for Write Initiate Response");
    return -1;
  }
  if (channel_send_appdata(&channel_ptr->channel, ad_ptr) != 0) {
    LOG_ERROR(logger_name_ptr, "Failed to send Write Initiate Response");
    appdata_free(ad_ptr);
    return -1;
  }
  appdata_free(ad_ptr);

  return 0;
}

/**
 * @brief Send a WriteSegment response payload (ciphertext_ptr + tag).
 */
signed char participant_channel_send_write_segment_response(
    SPsecCommChannel *channel_ptr, SPsecClientWriteSegmentResponse *msg_ptr) {
  uint8_t payload[4 + AUTH_TAG_SIZE];
  memcpy(payload, msg_ptr->ciphertext, 4);
  memcpy(payload + 4, msg_ptr->auth_tag, AUTH_TAG_SIZE);

  LOG_INFO(logger_name_ptr, "Sending Write Segment Response");

  AppData *ad_ptr = appdata_new(msg_ptr->address, payload, sizeof(payload));
  if (!ad_ptr) {
    LOG_ERROR(logger_name_ptr,
              "Failed to allocate AppData for Write Segment Response");
    return -1;
  }
  if (channel_send_appdata(&channel_ptr->channel, ad_ptr) != 0) {
    LOG_ERROR(logger_name_ptr, "Failed to send Write Segment Response");
    appdata_free(ad_ptr);
    return -1;
  }
  appdata_free(ad_ptr);

  return 0;
}

/**
 * @brief Send the SessionTerminate response auth tag.
 */
signed char participant_channel_send_session_terminate_response(
    SPsecCommChannel *channel_ptr, SPsecSessionTerminateMessage *msg_ptr) {
  // Server terminate response includes auth tag (8 bytes)
  uint8_t payload[AUTH_TAG_SIZE];
  memcpy(payload, msg_ptr->auth_tag, AUTH_TAG_SIZE);

  LOG_INFO(logger_name_ptr, "Sending Session Terminate Response");

  AppData *ad_ptr = appdata_new(msg_ptr->address, payload, sizeof(payload));
  if (!ad_ptr) {
    LOG_ERROR(logger_name_ptr,
              "Failed to allocate AppData for Session Terminate Response");
    return -1;
  }
  if (channel_send_appdata(&channel_ptr->channel, ad_ptr) != 0) {
    LOG_ERROR(logger_name_ptr, "Failed to send Session Terminate Response");
    appdata_free(ad_ptr);
    return -1;
  }
  appdata_free(ad_ptr);

  return 0;
}

signed char
participant_channel_send_timesync_response(SPsecCommChannel *channel_ptr,
                                           SPsecTimeSyncResponse *msg_ptr) {
  // 0x1h = 000 001|1|0|
  uint32_t base_id = (0x06230000 | ((CPMT_AUTH_TIME & 0xFF) << 8) |
                      (msg_ptr->participant_id | 0x80));
  // Payload layout: timestamp (8 bytes) || csalt (4 bytes) || auth_tag
  // (8 bytes)
  size_t payload_len = 8 + 4 + msg_ptr->auth_tag_len;
  uint8_t *payload_ptr = malloc(payload_len);
  if (!payload_ptr) {
    LOG_ERROR(logger_name_ptr, "Failed to allocate payload for timesync response");
    return -1;
  }
  memcpy(payload_ptr, msg_ptr->timestamp, 8);
  memcpy(payload_ptr + 8, msg_ptr->csalt, 4);
  memcpy(payload_ptr + 12, msg_ptr->auth_tag_ptr, msg_ptr->auth_tag_len);

  LOG_INFO(logger_name_ptr, "Sending timesync response");

  AppData *ad_ptr = appdata_new(base_id, payload_ptr, payload_len);
  free(payload_ptr);
  if (!ad_ptr) {
    LOG_ERROR(logger_name_ptr, "Failed to allocate AppData for timesync response");
    return -1;
  }
  if (channel_send_appdata(&channel_ptr->channel, ad_ptr) != 0) {
    LOG_ERROR(logger_name_ptr, "Failed to send timesync response");
    appdata_free(ad_ptr);
    return -1;
  }
  appdata_free(ad_ptr);
  return 0;
}
