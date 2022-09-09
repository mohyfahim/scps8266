idf_component_register(SRCS "comm_core.cpp" "comm_sec.cpp" "comm_utils.cpp"
                    INCLUDE_DIRS "include"
                    REQUIRES "esp-bch" "app_update" "bootloader_support" "spi_flash" "spiffs" "espnow_core" "espnow_ota" "driver" "mcommon" "mwifi" "mqtt_handler" "http_handler")