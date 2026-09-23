#ifndef _ECBM_H_
#define _ECBM_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <safe_c.h>

#include <stdint.h>

typedef uint16_t EcbmDataId;
typedef uint8_t EcbmAddr;
typedef uint16_t EcbmTimeoutMs;

/** Handler for data published by a slave(PUB_DATA packet, transaction_id=0).
 * Called from ecbm__read()/ecbm__write() wait loops or from ecbm__poll(),
 * i.e. always in the caller's context. The data points to an internal buffer
 * and is valid only until the handler returns, copy it if needed. */
typedef void (*EcbmPubHandler)(EcbmAddr addr, EcbmDataId data_id, uint8_t const* data, uint16_t data_size,
    void* user_data);

enum EcbmWriteStatus {
    ECBM_WRITE_STATUS__COMPLETED,
    ECBM_WRITE_STATUS__PROCEEDED,
    ECBM_WRITE_STATUS__FAILED,
};

enum {
    ECBM__BROADCAST_ADDR = 0xFF,
    ECBM__MIN_PACKET_SIZE = 10,
    ECBM__MAX_PAYLOAD_SIZE = CONFIG_ECBM_MAX_PAYLOAD_SIZE,
};

typedef struct Ecbm {
    uint8_t rx_buf[ECBM__MAX_PAYLOAD_SIZE + ECBM__MIN_PACKET_SIZE];
    uint8_t tx_buf[ECBM__MAX_PAYLOAD_SIZE + ECBM__MIN_PACKET_SIZE];

    EcbmPubHandler pub_handler;
    void* pub_user_data;

    int (*read)(uint8_t* buf, uint16_t buf_size);
    int (*write)(uint8_t const* data, uint16_t ndata);
    uint64_t (*get_time_ms)(void);
    enum EcbmWriteStatus (*get_write_status)(void); // optional, NULL if transport write is synchronous
    void (*sleep_ms)(uint32_t ms); // optional, NULL if read() blocks itself until data or short timeout

    uint16_t read_ptr;
    uint16_t read_total; // count of bytes in rx_buf, 0 if it is not stored
    uint16_t send_ptr;
    uint16_t send_total; // count of bytes in tx_buf to send
    uint16_t tid; // transaction_id counter for confirmed requests, 0 between transactions
} Ecbm;

/** @brief Init ecb master instance.
 *
 * @param[in] get_time_ms - get uptime callback.
 * @param[in] read read data received from the transport by the caller(e.g. drained
 *                  from the platform RX ring buffer), return 0 if no data available,
 *                  return negative if error, else return read bytes count.
 * @param[in] write write data to the transport callback,
 *                   return negative if error, else return count of really written bytes.
 * @param[in] get_write_status optional(may be NULL) callback for transports with asynchronous write,
 *                   polled after all bytes accepted by write(), must return the status of that write.
 *                   If NULL, the send is considered complete immediately after write().
 * @param[in] sleep_ms optional(may be NULL) sleep callback used by ecbm__read()/ecbm__write()
 *                   wait loops between transport polls. If NULL, read() must block itself
 *                   until data arrives or a short internal timeout expires.
 * @param[in] pub_handler optional(may be NULL) handler for slaves PUB_DATA packets,
 *                   if NULL such packets are dropped.
 * @param[in] pub_user_data - opaque pointer for the pub_handler, may be NULL.
 *
 * @warning All callbacks and API functions must be called from a single context,
 * the library is not thread safe.
 */
int ecbm__init(
    struct Ecbm* ecbm,
    uint64_t (*get_time_ms)(void),
    int (*read)(uint8_t* buf, uint16_t buf_size),
    int (*write)(uint8_t const* data, uint16_t ndata),
    enum EcbmWriteStatus (*get_write_status)(void),
    void (*sleep_ms)(uint32_t ms),
    EcbmPubHandler pub_handler,
    void* pub_user_data) __nonnull((1, 2, 3, 4));

/** @brief Read data from the slave endpoint. Blocking: sends the READ request,
 * waits for the answer, retries the same request(transaction_id, data_id and payload
 * are identical) until the answer is received or retries are exhausted.
 *
 * While waiting, also processes other frames: PUB_DATA packets are dispatched
 * to the #EcbmPubHandler, other packets are dropped.
 *
 * @param[in] addr slave address, cannot be #ECBM__BROADCAST_ADDR.
 * @param[in] data_id - data identifier.
 * @param[out] buf buffer for the answer payload, may be NULL if buf_size is zero.
 * @param[in] buf_size buf size.
 * @param[out] data_size optional(may be NULL) written answer payload size.
 * @param[in] timeout_ms - answer timeout for one attempt.
 * @param[in] retries - count of additional attempts after the first one.
 *
 * @return 0 if the answer is received(payload copied to buf), else #ErrorCodes:
 *         #ER_TIMEDOUT - no answer after retries,
 *         #ER_ENT_TOO_BIG - the answer payload does not fit in buf,
 *         #ER_IO and others - transport/local errors;
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

/** @brief Write data to the slave endpoint. Blocking, see #ecbm__read.
 *
 * @param[in] data may be NULL if data_size is zero.
 * @param[in] data_size payload size, cannot be greater than #ECBM__MAX_PAYLOAD_SIZE.
 *
 * @return 0 if the WRITE answer is received, else #ErrorCodes or positive
 *         slave error code, see #ecbm__read.
 */
int ecbm__write(
    struct Ecbm* ecbm,
    EcbmAddr addr,
    EcbmDataId data_id,
    uint8_t const* data,
    uint16_t data_size,
    EcbmTimeoutMs timeout_ms,
    uint8_t retries) __nonnull((1, 5));

/** @brief Write data without confirmation(WRITE_NO_ANSW packet, transaction_id=0).
 * Non transactional, best effort delivery. Blocking only until the transport
 * accepts the frame bytes.
 *
 * @param[in] addr slave address, #ECBM__BROADCAST_ADDR is allowed.
 *
 * @return 0 if sended, else #ErrorCodes: #ER_INVAL - invalid arguments,
 *         #ER_ENT_TOO_BIG - data_size too big, transport errors.
 */
int ecbm__write_no_answer(
    struct Ecbm* ecbm,
    EcbmAddr addr,
    EcbmDataId data_id,
    uint8_t const* data,
    uint16_t data_size) __nonnull((1, 4));

/** @brief Drain the transport RX(non blocking) and dispatch received frames:
 * PUB_DATA packets are passed to the #EcbmPubHandler, all other packets are dropped.
 * Intended to be called by the platform while no transaction is in progress,
 * e.g. from an event handler, timer or main loop tick. Does not start a transaction.
 *
 * @return 0 or transport #ErrorCodes(negative read result).
 */
int ecbm__poll(struct Ecbm* ecbm) __nonnull((1));

#ifdef __cplusplus
}
#endif

#endif // _ECBM_H_
