#pragma once

#include "esp_err.h"

typedef struct {
  bool is_ch;
} comm_sec_t;

#ifdef __cplusplus
extern "C" {
#endif /**< _cplusplus */

/**
 * @brief start security task
 *
 * @return esp_err_t
 */
esp_err_t nw_security_start();



/**
 * @brief start security eve task
 *
 * @return esp_err_t
 */
esp_err_t nw_security_eve_start();


/**
 * @brief change device type to ch
 *
 * @param is_ch whether it is ch or not
 * @return esp_err_t
 */
esp_err_t nw_security_assign_ch(bool is_ch);

// NOTE: just for debug
void reading_logs();

#ifdef __cplusplus
}
#endif /**< _cplusplus */
