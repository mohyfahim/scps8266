#ifndef PRUEBA_H
#define PRUEBA_H

#include <stdint.h>

typedef union {
  float float_;
  uint8_t uint8_[sizeof(float)];
} __attribute__((packed)) Float;

typedef enum {
  Fancoil = 0x00,
  Split = 0x01
} __attribute__((packed)) HVACType_e;

typedef enum {
  Heating = 0x00,
  Cooling = 0x01
} __attribute__((packed)) HVACMode_e;

typedef enum {
  Sleep = 0x00,
  Optimization = 0x01,
  Maintenance = 0x02,
  Manual = 0x03,
  Classical = 0x04,
} __attribute__((packed)) WorkMode_e;

typedef enum {
  Deny = 0x00,
  Accept = 0x01
} __attribute__((packed)) Permission_e;

typedef struct {
  WorkMode_e WorkMode;
  HVACMode_e HVACMode;
  HVACType_e HVACType;

  uint16_t NumberOfHVAC;
  uint16_t NumberOfFanAir;

  uint8_t User_Setpoint;
  Float HVAC1_Setpoint;
  Float HVAC2_Setpoint;
  Float HVAC3_Setpoint;

  Float Area_Temperature;
  Float HVAC1_Temperature;
  Float HVAC2_Temperature;
  Float HVAC3_Temperature;

  uint16_t AnalogSensor_1;
  uint16_t AnalogSensor_2;

  Float AreaLight;
  uint8_t AreaHumidity;

  uint16_t Last_Occupancy;

  unsigned HVAC1_Status : 1;
  unsigned HVAC2_Status : 1;
  unsigned HVAC3_Status : 1;
  unsigned FanAir1_Status : 1;
  unsigned FanAir2_Status : 1;

  unsigned Area_TempSensor_Error : 1;
  unsigned HVAC1_TempSensor_Error : 1;
  unsigned HVAC2_TempSensor_Error : 1;
  unsigned HVAC3_TempSensor_Error : 1;
  unsigned Light_Sensor_Error : 1;
  unsigned PIR_Sensor_Error : 1;
} __attribute__((packed)) Data_Transmitter;

typedef struct {
  HVACMode_e HVACMode;
  WorkMode_e WorkMode;
  Permission_e Permission;

  uint8_t User_Setpoint;

  uint8_t HVAC1_Setpoint;
  uint8_t HVAC2_Setpoint;
  uint8_t HVAC3_Setpoint;

  Float Outside_Temperature;
  Float OtherRoom_Temperature;
  Float EngineRoom_Temperature;

  unsigned HVAC1_Command : 1;
  unsigned HVAC2_Command : 1;
  unsigned HVAC3_Command : 1;
  unsigned FanAir1_Command : 1;
  unsigned FanAir2_Command : 1;
} __attribute__((packed)) Data_Receiver;

#endif
