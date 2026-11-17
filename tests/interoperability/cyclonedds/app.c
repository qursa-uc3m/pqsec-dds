/*
 * Copyright (C) 2023-2026 Javier Blanco-Romero @fj-blanco (UC3M)
 *
 * CycloneDDS participant of the interoperability run: "pub" writes ten
 * samples once a reader matches, "sub" waits for ten. Security comes from
 * CYCLONEDDS_URI.
 */
#include "Interop.h"
#include <dds/dds.h>
#include <stdio.h>
#include <string.h>

#define SAMPLES 10

static int publish(dds_entity_t participant, dds_entity_t topic, const dds_qos_t *qos) {
  dds_entity_t writer = dds_create_writer(participant, topic, qos, NULL);
  dds_publication_matched_status_t status = {0};
  for (int i = 0; i < 600 && status.current_count == 0; ++i) {
    dds_sleepfor(DDS_MSECS(100));
    dds_get_publication_matched_status(writer, &status);
  }
  if (status.current_count == 0) {
    fprintf(stderr, "cyclonedds: no matched reader\n");
    return 1;
  }
  for (int i = 0; i < SAMPLES; ++i) {
    char text[32];
    snprintf(text, sizeof text, "from CycloneDDS %d", i);
    dds_write(writer, &(Interop_Msg){.id = i, .text = text});
    dds_sleepfor(DDS_MSECS(200));
  }
  dds_sleepfor(DDS_SECS(5));
  printf("cyclonedds: wrote %d samples\n", SAMPLES);
  return 0;
}

static int subscribe(dds_entity_t participant, dds_entity_t topic, const dds_qos_t *qos) {
  dds_entity_t reader = dds_create_reader(participant, topic, qos, NULL);
  int received = 0;
  for (int i = 0; i < 600 && received < SAMPLES; ++i) {
    void *samples[1] = {NULL};
    dds_sample_info_t info;
    while (dds_take(reader, samples, &info, 1, 1) > 0) {
      if (info.valid_data) {
        const Interop_Msg *msg = samples[0];
        printf("cyclonedds: received %d '%s'\n", msg->id, msg->text);
        ++received;
      }
      dds_return_loan(reader, samples, 1);
      samples[0] = NULL;
    }
    dds_sleepfor(DDS_MSECS(100));
  }
  printf("cyclonedds: received %d samples\n", received);
  return received == SAMPLES ? 0 : 1;
}

int main(int argc, char **argv) {
  if (argc != 2 || (strcmp(argv[1], "pub") != 0 && strcmp(argv[1], "sub") != 0)) {
    fprintf(stderr, "usage: cyclonedds_app pub|sub\n");
    return 2;
  }
  dds_entity_t participant = dds_create_participant(DDS_DOMAIN_DEFAULT, NULL, NULL);
  if (participant < 0) {
    fprintf(stderr, "cyclonedds: create_participant: %s\n", dds_strretcode(-participant));
    return 2;
  }
  dds_entity_t topic = dds_create_topic(participant, &Interop_Msg_desc, "PQSecInterop", NULL, NULL);
  dds_qos_t *qos = dds_create_qos();
  dds_qset_reliability(qos, DDS_RELIABILITY_RELIABLE, DDS_SECS(1));
  dds_qset_durability(qos, DDS_DURABILITY_TRANSIENT_LOCAL);
  dds_qset_history(qos, DDS_HISTORY_KEEP_ALL, 0);
  const int result = strcmp(argv[1], "pub") == 0 ? publish(participant, topic, qos)
                                                 : subscribe(participant, topic, qos);
  dds_delete_qos(qos);
  dds_delete(participant);
  return result;
}
