#include "ecbm.h"

#include <crc32.h>
#include <byteorder.h>

typedef struct EcbmTransaction {
    EcbmAddr addr;
    EcbmDataId data_id;
    uint16_t tid;
    bool is_read;
    uint8_t* buf; // READ answer payload destination, unused for WRITE
    uint16_t buf_size;
    uint16_t* data_size; // optional out, also filled before ER_ENT_TOO_BIG
} EcbmTransaction;

static uint16_t _alloc_tid(struct Ecbm* ecbm);
static int _answer_state_load(struct Ecbm const* ecbm);
static void _answer_state_store(struct Ecbm* ecbm, int state);
static int _build_frame(struct Ecbm* ecbm, uint8_t pd, EcbmAddr addr, uint16_t tid, EcbmDataId data_id,
    uint8_t const* payload, uint16_t payload_size);
static int _pump_tx(struct Ecbm* ecbm, uint64_t deadline);
static int _send_all(struct Ecbm* ecbm, uint64_t deadline);
static bool _process_answer(struct Ecbm* ecbm, struct EcbmTransaction const* tr, int* result);
static int _wait_answer(struct Ecbm* ecbm, struct EcbmTransaction const* tr, uint64_t deadline);
static int _transaction(struct Ecbm* ecbm, struct EcbmTransaction const* tr, uint8_t pd_type,
    uint8_t const* payload, uint16_t payload_size, EcbmTimeoutMs timeout_ms, uint8_t retries);
static int _mail_answer(struct Ecbm* ecbm, uint8_t const* packet, uint16_t size);
static int _handle_frame(struct Ecbm* ecbm, uint16_t size);

enum {
    ECBM__PD_DIR_MASK = 0x80,
    ECBM__PD_DIR_IS_REQ = 0x80,
    ECBM__PD_TYPE_MASK = 0x0F,
    ECBM__PD_TYPE_WRITE = 0x00,
    ECBM__PD_TYPE_WRITE_NO_ANSW = 0x01,
    ECBM__PD_TYPE_READ = 0x02,
    ECBM__PD_TYPE_PUB_DATA = 0x03,
    ECBM__PD_TYPE_APP_ERR = 0x0E,
    ECBM__PD_TYPE_PROTO_ERR = 0x0F,

    ECBM__PACKET_PD_POS = 0,
    ECBM__PACKET_ADDR_POS = 1,
    ECBM__PACKET_TID_POS = 2,
    ECBM__PACKET_DATA_ID_POS = 4,
    ECBM__PACKET_PAYLOAD_POS = 6,
    ECBM__CRC_SIZE = 4,

    ECBM__READ_CHUNK_SIZE = 32,
    ECBM__SLEEP_MS = 1,
};

enum EcbmAnswerState {
    ECBM__ANSWER_STATE__EMPTY = 0,
    ECBM__ANSWER_STATE__FULL = 1,
};

static uint16_t _alloc_tid(struct Ecbm* const ecbm) {
    ecbm->tid += 1;
    if (0 == ecbm->tid) {
        ecbm->tid = 1;
    }

    return ecbm->tid;
}

static int _answer_state_load(struct Ecbm const* const ecbm) {
    return __atomic_load_n(&ecbm->answer_state, __ATOMIC_ACQUIRE);
}

static void _answer_state_store(struct Ecbm* const ecbm, int const state) {
    __atomic_store_n(&ecbm->answer_state, state, __ATOMIC_RELEASE);
}

/// @brief Build the request packet in tx_buf and 7B encode it in place,
/// the frame is kept for identical retransmissions.
static int _build_frame(struct Ecbm* const ecbm, uint8_t const pd, EcbmAddr const addr, uint16_t const tid,
    EcbmDataId const data_id, uint8_t const* payload, uint16_t const payload_size) {
    int rc = 0;

    uint8_t* const buf = ecbm->tx_buf;
    buf[ECBM__PACKET_PD_POS] = pd;
    buf[ECBM__PACKET_ADDR_POS] = addr;
    u16_to_le(&buf[ECBM__PACKET_TID_POS], tid);
    u16_to_le(&buf[ECBM__PACKET_DATA_ID_POS], data_id);

    if ((NULL != payload) && (0 < payload_size)) {
        memmove(&buf[ECBM__PACKET_PAYLOAD_POS], payload, payload_size);
    }

    uint16_t const crc_pos = ECBM__PACKET_PAYLOAD_POS + payload_size;
    u32_to_le(&buf[crc_pos], crc32__ieee(buf, crc_pos));

    uint16_t const packet_size = crc_pos + ECBM__CRC_SIZE;
    int const frame_size = framer7b__encode_in_place(buf, packet_size, sizeof(ecbm->tx_buf));
    ASSERTf(0 < frame_size, ER_1, "Fail to encode request packet: %i", frame_size);

    ecbm->send_ptr = 0;
    ecbm->send_total = (uint16_t)frame_size;

 finally:

    return rc;
}

/// @brief Push the pending frame bytes to the transport until all of them are accepted.
/// @param[in] deadline - time when the send is considered failed, pass UINT64_MAX
/// to wait indefinitely.
static int _pump_tx(struct Ecbm* const ecbm, uint64_t const deadline) {
    int rc = 0;

    while (ecbm->send_ptr < ecbm->send_total) {
        int const nwritten = ecbm->write(&ecbm->tx_buf[ecbm->send_ptr], ecbm->send_total - ecbm->send_ptr);
        if (0 > nwritten) {
            rc = nwritten;
            LOG_ERRf("Fail to write to transport: %i", nwritten);
            goto finally;
        }
        if (0 == nwritten) {
            if (ecbm->get_time_ms() >= deadline) {
                rc = ER_TIMEDOUT;
                goto finally;
            }
            ecbm->sleep_ms(ECBM__SLEEP_MS);
            continue;
        }
        ASSERTf(nwritten <= (int)(ecbm->send_total - ecbm->send_ptr), ER_PROTO_INTERNAL,
            "Transport reported more bytes written than requested: %i", nwritten);
        ecbm->send_ptr += (uint16_t)nwritten;
    }

 finally:

    return rc;
}

/// @brief Send the pending frame completely, including the asynchronous write
/// completion if get_write_status is set.
static int _send_all(struct Ecbm* const ecbm, uint64_t const deadline) {
    int rc = 0;

    TRY(_pump_tx(ecbm, deadline));

    if (NULL != ecbm->get_write_status) {
        while (true) {
            enum EcbmWriteStatus const status = ecbm->get_write_status();
            switch (status) {
            case ECBM_WRITE_STATUS__COMPLETED:
                goto finally;
            case ECBM_WRITE_STATUS__PROCEEDED:
                if (ecbm->get_time_ms() >= deadline) {
                    rc = ER_TIMEDOUT;
                    goto finally;
                }
                ecbm->sleep_ms(ECBM__SLEEP_MS);
                break;
            case ECBM_WRITE_STATUS__FAILED:
                rc = ER_IO;
                LOG_ERR("Write status: FAILED");
                goto finally;
            default:
                rc = ER_PROTO_INTERNAL;
                LOG_ERRf("Unknown write status: %i", (int)status);
                goto finally;
            }
        }
    }

 finally:

    return rc;
}

/// @brief Match the mailed answer against the request and take the result.
/// Always releases the mailbox, called only by the transaction wait loop.
/// @param[out] result - transaction result, valid if true is returned.
/// @return true if the answer completes the transaction, false if it is dropped.
static bool _process_answer(struct Ecbm* const ecbm, struct EcbmTransaction const* const tr, int* const result) {
    bool is_completed = false;

    uint8_t const* const pkt = ecbm->answer_buf;
    uint16_t const size = ecbm->answer_size;

    *result = 0;

    // Cannot happen, the producer checks the size. A defense against memory corruption.
    if (ECBM__MIN_PACKET_SIZE > size) {
        LOG_ERRf("Malformed answer in the mailbox: size=%u", size);
        *result = ER_PROTO_INTERNAL;
        is_completed = true;
        goto finally;
    }

    uint8_t const type = pkt[ECBM__PACKET_PD_POS] & ECBM__PD_TYPE_MASK;
    EcbmAddr const addr = pkt[ECBM__PACKET_ADDR_POS];
    uint16_t const tid = u16_from_le(&pkt[ECBM__PACKET_TID_POS]);
    EcbmDataId const data_id = u16_from_le(&pkt[ECBM__PACKET_DATA_ID_POS]);
    uint16_t const payload_size = size - ECBM__MIN_PACKET_SIZE;

    if ((addr != tr->addr) || (tid != tr->tid) || (data_id != tr->data_id)) {
        LOG_DBGf("Drop answer, no match with the request: addr=%u tid=%u data_id=%u", addr, tid, data_id);
        goto finally;
    }

    is_completed = true;

    if ((ECBM__PD_TYPE_APP_ERR == type) || (ECBM__PD_TYPE_PROTO_ERR == type)) {
        if (0 == payload_size) {
            LOG_DBGf("Error answer with empty payload: type=%u", type);
            *result = ER_PROTO;
        }
        else {
            // The APP_ERR description tail is not returned, see the API doc.
            *result = pkt[ECBM__PACKET_PAYLOAD_POS];
        }
    }
    else if (((tr->is_read) && (ECBM__PD_TYPE_READ == type)) ||
        ((!tr->is_read) && (ECBM__PD_TYPE_WRITE == type))) {
        if ((!tr->is_read) && (0 < payload_size)) {
            LOG_DBGf("WRITE answer with non-empty payload: %u", payload_size);
            *result = ER_PROTO;
        }
        else {
            if (NULL != tr->data_size) {
                *tr->data_size = payload_size;
            }
            if (payload_size > tr->buf_size) {
                LOG_DBGf("Answer payload too big: %u > %u", payload_size, tr->buf_size);
                *result = ER_ENT_TOO_BIG;
            }
            else if (0 < payload_size) {
                memmove(tr->buf, &pkt[ECBM__PACKET_PAYLOAD_POS], payload_size);
            }
        }
    }
    else {
        LOG_DBGf("Answer with unexpected type: %u", type);
        *result = ER_PROTO;
    }

 finally:

    _answer_state_store(ecbm, ECBM__ANSWER_STATE__EMPTY);

    return is_completed;
}

static int _wait_answer(struct Ecbm* const ecbm, struct EcbmTransaction const* const tr, uint64_t const deadline) {
    int rc = 0;

    while (true) {
        if (ECBM__ANSWER_STATE__FULL == _answer_state_load(ecbm)) {
            if (_process_answer(ecbm, tr, &rc)) {
                goto finally;
            }
            continue;
        }

        if (ecbm->get_time_ms() >= deadline) {
            rc = ER_TIMEDOUT;
            goto finally;
        }

        ecbm->sleep_ms(ECBM__SLEEP_MS);
    }

 finally:

    return rc;
}

static int _transaction(struct Ecbm* const ecbm, struct EcbmTransaction const* const tr, uint8_t const pd_type,
    uint8_t const* payload, uint16_t const payload_size, EcbmTimeoutMs const timeout_ms, uint8_t const retries) {
    int rc = 0;

    ecbm->is_in_transaction = true;

    TRY(_build_frame(ecbm, ECBM__PD_DIR_IS_REQ | pd_type, tr->addr, tr->tid, tr->data_id, payload, payload_size));

    for (int attempt = 0; attempt <= retries; attempt++) {
        uint64_t const deadline = ecbm->get_time_ms() + timeout_ms;

        ecbm->send_ptr = 0;
        rc = _send_all(ecbm, deadline);
        if (0 != rc) {
            if (ER_TIMEDOUT == rc) {
                LOG_DBGf("Send attempt timed out, resend: tid=%u attempt=%i", tr->tid, attempt);
                continue;
            }
            goto finally;
        }

        rc = _wait_answer(ecbm, tr, deadline);
        if (ER_TIMEDOUT != rc) {
            goto finally;
        }

        LOG_DBGf("Answer timeout, retry: tid=%u attempt=%i", tr->tid, attempt);
    }

    rc = ER_TIMEDOUT;

 finally:

    ecbm->is_in_transaction = false;

    return rc;
}

/// @brief Place the answer packet into the mailbox. The mailbox has a single slot with
/// the ownership transfer: the producer writes only in the EMPTY state, the consumer
/// reads only in the FULL state, so the buffer is never accessed from both contexts
/// at once. If the slot is busy, the answer is dropped, such answers are resent by the
/// slaves on the request retry.
static int _mail_answer(struct Ecbm* const ecbm, uint8_t const* const packet, uint16_t const size) {
    int rc = 0;

    if (ECBM__ANSWER_STATE__FULL == _answer_state_load(ecbm)) {
        LOG_DBG("Drop answer, the mailbox is busy");
        goto finally;
    }

    memmove(ecbm->answer_buf, packet, size);
    ecbm->answer_size = size;
    _answer_state_store(ecbm, ECBM__ANSWER_STATE__FULL);

 finally:

    return rc;
}

static int _handle_frame(struct Ecbm* const ecbm, uint16_t const size) {
    int rc = 0;

    uint8_t* const buf = framer7b_receiver__buf(&ecbm->framer);

    if (ECBM__MIN_PACKET_SIZE > size) {
        LOG_DBGf("Drop packet, too small: %u", size);
        goto finally;
    }

    uint16_t const body_size = size - ECBM__CRC_SIZE;
    uint32_t const crc_recv = u32_from_le(&buf[body_size]);
    uint32_t const crc_calc = crc32__ieee(buf, body_size);
    if (crc_recv != crc_calc) {
        LOG_DBGf("Drop packet, crc mismatch: recv=%08X calc=%08X", crc_recv, crc_calc);
        goto finally;
    }

    uint8_t const pd = buf[ECBM__PACKET_PD_POS];
    if (ECBM__PD_DIR_IS_REQ == (pd & ECBM__PD_DIR_MASK)) {
        LOG_DBGf("Drop packet, request direction: pd=%02X", pd);
        goto finally;
    }

    EcbmAddr const addr = buf[ECBM__PACKET_ADDR_POS];
    EcbmDataId const data_id = u16_from_le(&buf[ECBM__PACKET_DATA_ID_POS]);
    uint8_t const type = pd & ECBM__PD_TYPE_MASK;

    if (ECBM__PD_TYPE_PUB_DATA == type) {
        if (NULL != ecbm->pub_handler) {
            ecbm->pub_handler(addr, data_id, &buf[ECBM__PACKET_PAYLOAD_POS], body_size - ECBM__PACKET_PAYLOAD_POS,
                ecbm->pub_user_data);
        }
        else {
            LOG_DBGf("Drop PUB_DATA, no handler: addr=%u data_id=%u", addr, data_id);
        }
        goto finally;
    }

    TRY(_mail_answer(ecbm, buf, size));

 finally:

    return rc;
}

int ecbm__init(struct Ecbm* const ecbm, uint64_t (*const get_time_ms)(void),
    int (*const read)(uint8_t* buf, uint16_t buf_size), int (*const write)(uint8_t const* data, uint16_t ndata),
    enum EcbmWriteStatus (*const get_write_status)(void), void (*const sleep_ms)(uint32_t ms),
    EcbmPubHandler const pub_handler, void* const pub_user_data) {
    int rc = 0;

    memset(ecbm, 0, sizeof(*ecbm));
    ecbm->read = read;
    ecbm->write = write;
    ecbm->get_time_ms = get_time_ms;
    ecbm->get_write_status = get_write_status;
    ecbm->sleep_ms = sleep_ms;
    ecbm->pub_handler = pub_handler;
    ecbm->pub_user_data = pub_user_data;
    ecbm->answer_state = ECBM__ANSWER_STATE__EMPTY;

    TRY(framer7b_receiver__init(&ecbm->framer, ecbm->rx_buf, sizeof(ecbm->rx_buf)));

 finally:

    return rc;
}

int ecbm__read(struct Ecbm* const ecbm, EcbmAddr const addr, EcbmDataId const data_id, uint8_t* const buf,
    uint16_t const buf_size, uint16_t* const data_size, EcbmTimeoutMs const timeout_ms, uint8_t const retries) {
    int rc = 0;

    ASSERT(ECBM__BROADCAST_ADDR != addr, ER_INVAL);
    ASSERT(0 != timeout_ms, ER_INVAL);
    ASSERT(!ecbm->is_in_transaction, ER_BUSY);

    struct EcbmTransaction tr = {
        .addr = addr,
        .data_id = data_id,
        .tid = _alloc_tid(ecbm),
        .is_read = true,
        .buf = buf,
        .buf_size = buf_size,
        .data_size = data_size,
    };

    // Not TRY: a positive rc is the slave error code result, not a local failure.
    rc = _transaction(ecbm, &tr, ECBM__PD_TYPE_READ, NULL, 0, timeout_ms, retries);

 finally:

    return rc;
}

int ecbm__write(struct Ecbm* const ecbm, EcbmAddr const addr, EcbmDataId const data_id, uint8_t const* const data,
    uint16_t const data_size, EcbmTimeoutMs const timeout_ms, uint8_t const retries) {
    int rc = 0;

    ASSERT(ECBM__BROADCAST_ADDR != addr, ER_INVAL);
    ASSERT(0 != timeout_ms, ER_INVAL);
    ASSERT((NULL != data) || (0 == data_size), ER_INVAL);
    ASSERTf(ECBM__MAX_PAYLOAD_SIZE >= data_size, ER_ENT_TOO_BIG, "Payload too big: %u", data_size);
    ASSERT(!ecbm->is_in_transaction, ER_BUSY);

    struct EcbmTransaction tr = {
        .addr = addr,
        .data_id = data_id,
        .tid = _alloc_tid(ecbm),
        .is_read = false,
        .buf = NULL,
        .buf_size = 0,
        .data_size = NULL,
    };

    // Not TRY: a positive rc is the slave error code result, not a local failure.
    rc = _transaction(ecbm, &tr, ECBM__PD_TYPE_WRITE, data, data_size, timeout_ms, retries);

 finally:

    return rc;
}

int ecbm__write_no_answer(struct Ecbm* const ecbm, EcbmAddr const addr, EcbmDataId const data_id,
    uint8_t const* const data, uint16_t const data_size) {
    int rc = 0;

    ASSERT((NULL != data) || (0 == data_size), ER_INVAL);
    ASSERTf(ECBM__MAX_PAYLOAD_SIZE >= data_size, ER_ENT_TOO_BIG, "Payload too big: %u", data_size);
    ASSERT(!ecbm->is_in_transaction, ER_BUSY);

    TRY(_build_frame(ecbm, ECBM__PD_DIR_IS_REQ | ECBM__PD_TYPE_WRITE_NO_ANSW, addr, 0, data_id, data, data_size));

    // No deadline: the call blocks only until the transport accepts the frame bytes.
    TRY(_pump_tx(ecbm, UINT64_MAX));

 finally:

    return rc;
}

int ecbm__poll(struct Ecbm* const ecbm) {
    int rc = 0;
    uint8_t chunk[ECBM__READ_CHUNK_SIZE] = {0};

    while (true) {
        int const nread = ecbm->read(chunk, sizeof(chunk));
        if (0 > nread) {
            rc = nread;
            LOG_ERRf("Fail to read from transport: %i", nread);
            goto finally;
        }
        if (0 == nread) {
            break;
        }
        ASSERTf(nread <= (int)sizeof(chunk), ER_PROTO_INTERNAL, "Transport read overflow: %i", nread);

        for (int i = 0; i < nread; i++) {
            int const frame_size = framer7b_receiver__push(&ecbm->framer, chunk[i]);
            if (0 < frame_size) {
                TRY_PASS(_handle_frame(ecbm, (uint16_t)frame_size));
            }
        }
    }

 finally:

    return rc;
}
