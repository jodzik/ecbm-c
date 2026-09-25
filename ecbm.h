#ifndef _ECBM_H_
#define _ECBM_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <framer7b.h>
#include <safe_c.h>

#include <stdint.h>
#include <stdbool.h>

typedef uint16_t EcbmDataId;
typedef uint8_t EcbmAddr;
typedef uint16_t EcbmTimeoutMs;

/** Handler for the data published by a slave(PUB_DATA packet, transaction_id=0).
 *
 * Called only from ecbm__poll(), i.e. in the RX(poll) context, possibly in parallel
 * with an active ecbm__read()/ecbm__write() call. The data points to an internal buffer
 * and is valid only until the handler returns, copy it if needed. The handler must be
 * fast enough to not block the transport RX and must not call the ecbm API.
 */
typedef void (*EcbmPubHandler)(EcbmAddr addr, EcbmDataId data_id, uint8_t const* data, uint16_t data_size,
    void* user_data);

typedef enum EcbmWriteStatus {
    ECBM_WRITE_STATUS__COMPLETED,
    ECBM_WRITE_STATUS__PROCEEDED,
    ECBM_WRITE_STATUS__FAILED,
} EcbmWriteStatus;

enum {
    ECBM__BROADCAST_ADDR = 0xFF,
    ECBM__MIN_PACKET_SIZE = 10,
    ECBM__MAX_PAYLOAD_SIZE = CONFIG_ECBM_MAX_PAYLOAD_SIZE,
};

typedef struct Ecbm {
    // RX(poll) context fields, touch only from ecbm__poll().

    uint8_t rx_buf[FRAMER7B_FRAME_SIZE(ECBM__MAX_PAYLOAD_SIZE + ECBM__MIN_PACKET_SIZE)];
    Framer7bReceiver framer;

    // Answer mailbox: passes whole answer packets from the RX(poll) context to the
    // transaction wait loop. The ownership of the slot is transferred by answer_state,
    // access it only inside ecbm.c.

    uint8_t answer_buf[ECBM__MAX_PAYLOAD_SIZE + ECBM__MIN_PACKET_SIZE];
    uint16_t answer_size;
    int answer_state;

    // Application context fields, touch only from ecbm__read()/ecbm__write()/
    // ecbm__write_no_answer().

    uint8_t tx_buf[FRAMER7B_FRAME_SIZE(ECBM__MAX_PAYLOAD_SIZE + ECBM__MIN_PACKET_SIZE)];
    uint16_t send_ptr;
    uint16_t send_total; // count of the frame bytes in tx_buf to send
    uint16_t tid; // transaction_id counter, wraps 65535 to 1, value 0 is not used
    bool is_in_transaction;

    // Callbacks.

    EcbmPubHandler pub_handler;
    void* pub_user_data;
    int (*read)(uint8_t* buf, uint16_t buf_size);
    int (*write)(uint8_t const* data, uint16_t ndata);
    uint64_t (*get_time_ms)(void);
    enum EcbmWriteStatus (*get_write_status)(void); // optional, NULL if transport write is synchronous
    void (*sleep_ms)(uint32_t ms);
} Ecbm;

/** @brief Init ecb master instance.
 *
 * Context contract:
 * - ecbm__poll() must be called from a single dedicated RX context(typically driven
 *   by transport RX events), only it calls the read() callback;
 * - ecbm__read()/ecbm__write()/ecbm__write_no_answer() must be serialized by the caller,
 *   only they call the write() callback;
 * - answers received by ecbm__poll() during a transaction are passed to the wait loop
 *   through a lock-free single slot mailbox, no locking is required;
 * - get_time_ms() must be safe to call from both contexts(e.g. a monotonic uptime).
 *
 * @param[in] get_time_ms - get uptime callback, ms.
 * @param[in] read read data received from the transport(e.g. drained from the platform
 *                  RX ring buffer), return 0 if no data available, return negative if
 *                  error, else return the count of read bytes.
 * @param[in] write write data to the transport callback, return negative if error,
 *                   0 if the transport cannot accept data now(retried later), else return
 *                   the count of really written bytes.
 * @param[in] get_write_status optional(may be NULL) callback for transports with
 *                   asynchronous write, polled after all frame bytes are accepted by
 *                   write(), must return the status of that write. If NULL, the send is
 *                   considered complete immediately after write().
 * @param[in] sleep_ms sleep callback used by the library wait loops, the answer pickup
 *                   latency is bounded by its granularity.
 * @param[in] pub_handler optional(may be NULL) handler for the slaves PUB_DATA packets,
 *                   if NULL such packets are dropped.
 * @param[in] pub_user_data - opaque pointer for the pub_handler, may be NULL.
 */
int ecbm__init(
    struct Ecbm* ecbm,
    uint64_t (*get_time_ms)(void),
    int (*read)(uint8_t* buf, uint16_t buf_size),
    int (*write)(uint8_t const* data, uint16_t ndata),
    enum EcbmWriteStatus (*get_write_status)(void),
    void (*sleep_ms)(uint32_t ms),
    EcbmPubHandler pub_handler,
    void* pub_user_data) __nonnull((1, 2, 3, 4, 6));

/** @brief Send a READ request and wait for the answer. Blocking. On timeout the same
 * request(identical transaction_id, data_id and payload) is resent up to retries times.
 *
 * While the call waits, the answers are received by ecbm__poll() in the RX context and
 * passed through the internal mailbox. Answers that do not match the request are dropped.
 *
 * @param[in] addr slave address, cannot be #ECBM__BROADCAST_ADDR.
 * @param[in] data_id - data identifier.
 * @param[out] buf buffer for the answer payload.
 * @param[in] buf_size buf size.
 * @param[out] data_size optional(may be NULL) answer payload size, also filled on
 *                  #ER_ENT_TOO_BIG so the required size can be observed.
 * @param[in] timeout_ms - answer timeout of one attempt, cannot be zero.
 * @param[in] retries - count of the additional attempts after the first one.
 *
 * @return 0 if the answer is received and the payload is copied to buf, else #ErrorCodes:
 *         #ER_TIMEDOUT - no answer after all the attempts,
 *         #ER_ENT_TOO_BIG - the answer payload does not fit in buf,
 *         #ER_INVAL, #ER_BUSY, transport errors;
 *         positive value - error_code from the slave APP_ERR or PROTO_ERR answer.
 */
int ecbm__read(
    struct Ecbm* ecbm,
    EcbmAddr addr,
    EcbmDataId data_id,
    uint8_t* buf,
    uint16_t buf_size,
    uint16_t* data_size,
    EcbmTimeoutMs timeout_ms,
    uint8_t retries) __nonnull((1, 4));

/** @brief Send a WRITE request and wait for the answer. Blocking, see #ecbm__read.
 *
 * @param[in] data may be NULL if data_size is zero.
 * @param[in] data_size payload size, cannot be greater than #ECBM__MAX_PAYLOAD_SIZE.
 *
 * @return 0 if the WRITE answer is received, else #ErrorCodes or a positive slave
 *         error code, see #ecbm__read.
 */
int ecbm__write(
    struct Ecbm* ecbm,
    EcbmAddr addr,
    EcbmDataId data_id,
    uint8_t const* data,
    uint16_t data_size,
    EcbmTimeoutMs timeout_ms,
    uint8_t retries) __nonnull((1));

/** @brief Send data without confirmation(WRITE_NO_ANSW packet, transaction_id=0).
 * Best effort delivery, no transaction is created. #ECBM__BROADCAST_ADDR is allowed.
 * Blocks only until the transport accepts all the frame bytes.
 *
 * @param[in] data may be NULL if data_size is zero.
 * @param[in] data_size payload size, cannot be greater than #ECBM__MAX_PAYLOAD_SIZE.
 *
 * @return 0 if sended, else #ErrorCodes: #ER_INVAL - invalid arguments,
 *         #ER_BUSY - a transaction is in progress, #ER_ENT_TOO_BIG - data_size too big,
 *         transport errors.
 */
int ecbm__write_no_answer(
    struct Ecbm* ecbm,
    EcbmAddr addr,
    EcbmDataId data_id,
    uint8_t const* data,
    uint16_t data_size) __nonnull((1));

/** @brief Drain the transport RX(non blocking) and process the received frames:
 * PUB_DATA packets are passed to the #EcbmPubHandler in the caller context, answer
 * packets are placed into the internal mailbox for the active transaction. If the
 * mailbox slot is busy, the answer is dropped, such answers are resent by the slaves
 * on the request retry.
 *
 * Must be called from a single RX context, may be called while a transaction is in
 * progress. Does not transmit anything.
 *
 * @return 0 or transport #ErrorCodes(negative read result).
 */
int ecbm__poll(struct Ecbm* ecbm) __nonnull((1));

#ifdef __cplusplus
}
#endif

#endif // _ECBM_H_
