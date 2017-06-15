/*
 * measurement.h
 *
 *  Created on: 12 Jun 2017
 *      Author: Michael Morscher, morscher@hm.edu
 */

#ifndef EXAMPLES_COAPS_MEASUREMENT_H_
#define EXAMPLES_COAPS_MEASUREMENT_H_

#include <stdint.h>

#ifdef __cplusplus
 extern "C" {
#endif

// Signal naming oscilloscope for documentation purposes only
// CC2538DK
// D0  = LED 0		= PC0
// D1  = LED 1		= PC1
// D2  = LED 2		= PC2
// D3  = LED 3		= PC3
// D4  = KEY LEFT	= PC4
// D5  = KEY RIGHT	= PC5
// D6  = KEY UP		= PC6
// D7  = KEY DOWN	= PC7
// D8  = KEY SELECT	= PA3
// D9  = LCD_RESET  = PB3
// D10 = LCD_MODE   = PB2
// D11 = LCD_CS     = PB5

// OpenMote
// D0 = DIO1 = PD2
// D1 = DIO2 = PD1
// D2 = DIO3 = PD0
// D3 = DIO4 = PA2
// D4 = DIO5 = PA4
// D5 = DIO6 = PA5
// D6 = DIO7 = PA3
// LED0 = PC4 (red)
// LED1 = PC6 (yellow)
// LED2 = PC7 (green)
// LED3 = PC5 (orange)

 // configures GPIO as software controlled outputs
void measurement_init_gpio(void);

// Basics for all OS platforms
// Addresses
#define M_GPIO_A_BASE 0x400D9000 /**< GPIO_A */
#define M_GPIO_B_BASE 0x400DA000 /**< GPIO_A */
#define M_GPIO_C_BASE 0x400DB000 /**< GPIO_C */
#define M_GPIO_D_BASE 0x400DC000 /**< GPIO_A */
#define M_GPIO_DATA   0x00000000
#define M_GPIO_DIR    0x00000400
#define M_GPIO_AFSEL  0x00000420

// GPIO Macros
#define M_HWREG(x)                          (*((volatile uint32_t *)(x)))
#define M_GPIO_PIN_MASK(n)                 	( 1 << (n) )
#define M_GPIO_PORT_TO_DEV(port)           	( M_GPIO_A_BASE + ((port) << 12) )
#define M_GPIO_CONTROL_SOFTWARE(port, pin)  ( M_HWREG(port + M_GPIO_AFSEL) &= ~pin )
#define M_GPIO_SET_OUTPUT(port, pin)       	( M_HWREG(port + M_GPIO_DIR)   |=  pin )
#define M_GPIO_SET_INPUT(port, pin)        	( M_HWREG(port + M_GPIO_DIR)   &= ~pin )
#define M_GPIO_SET_PIN(port, pin)          	( M_HWREG(port + M_GPIO_DATA   +  (pin << 2)) = 0xFF )
#define M_GPIO_CLEAR_PIN(port, pin)        	( M_HWREG(port + M_GPIO_DATA   +  (pin << 2)) = 0x00 )

// undefine possible already existing LED defines
#undef LED0_ON
#undef LED0_OFF
#undef LED1_ON
#undef LED1_OFF
#undef LED2_ON
#undef LED2_OFF
#undef LED3_ON
#undef LED3_OFF

// bit masks for GPIOs
#ifdef HARDWARE_OPENMOTE
#define LED0_MASK       M_GPIO_PIN_MASK(4) 	// red
#define LED1_MASK       M_GPIO_PIN_MASK(6) 	// yellow
#define LED2_MASK       M_GPIO_PIN_MASK(7) 	// green
#define LED3_MASK       M_GPIO_PIN_MASK(5) 	// orange
#define LED_MASK_ALL    LED0_MASK + LED1_MASK + LED2_MASK + LED3_MASK
#define DIO1_MASK       M_GPIO_PIN_MASK(2)
#define DIO2_MASK       M_GPIO_PIN_MASK(1)
#define DIO3_MASK       M_GPIO_PIN_MASK(0)
#define DIO_D_MASK_ALL  DIO1_MASK + DIO2_MASK + DIO3_MASK
#define DIO4_MASK       M_GPIO_PIN_MASK(2)
#define DIO5_MASK       M_GPIO_PIN_MASK(4)
#define DIO6_MASK       M_GPIO_PIN_MASK(5)
#define DIO7_MASK       M_GPIO_PIN_MASK(3)
#define DIO_A_MASK_ALL  DIO4_MASK + DIO5_MASK + DIO6_MASK + DIO7_MASK
#else
#define LED0_MASK       M_GPIO_PIN_MASK(0) 	// red
#define LED1_MASK       M_GPIO_PIN_MASK(1) 	// yellow
#define LED2_MASK       M_GPIO_PIN_MASK(2) 	// green
#define LED3_MASK       M_GPIO_PIN_MASK(3) 	// blue
#define LED_MASK_ALL    LED0_MASK + LED1_MASK + LED2_MASK + LED3_MASK
#define KEY_LEFT_MASK   M_GPIO_PIN_MASK(4)
#define KEY_RIGHT_MASK  M_GPIO_PIN_MASK(5)
#define KEY_UP_MASK     M_GPIO_PIN_MASK(6)
#define KEY_DOWN_MASK   M_GPIO_PIN_MASK(7)
#define KEY_SELECT_MASK M_GPIO_PIN_MASK(3)
#define KEY_MASK_C_ALL  KEY_LEFT_MASK + KEY_RIGHT_MASK + KEY_UP_MASK + KEY_DOWN_MASK
#define LCD_MODE_MASK   M_GPIO_PIN_MASK(2)
#define LCD_RESET_MASK  M_GPIO_PIN_MASK(3)
#define LCD_CS_MASK     M_GPIO_PIN_MASK(5)
#define LCD_MASK_ALL    LCD_RESET_MASK + LCD_MODE_MASK + LCD_CS_MASK
#endif

// Enable or disable GPIO outputs
#if GPIO_OUTPUT_ENABLE
#define LED0_ON         M_GPIO_SET_PIN(M_GPIO_C_BASE, LED0_MASK)
#define LED0_OFF        M_GPIO_CLEAR_PIN(M_GPIO_C_BASE, LED0_MASK)
#define LED1_ON         M_GPIO_SET_PIN(M_GPIO_C_BASE, LED1_MASK)
#define LED1_OFF        M_GPIO_CLEAR_PIN(M_GPIO_C_BASE, LED1_MASK)
#define LED2_ON         M_GPIO_SET_PIN(M_GPIO_C_BASE, LED2_MASK)
#define LED2_OFF        M_GPIO_CLEAR_PIN(M_GPIO_C_BASE, LED2_MASK)
#define LED3_ON         M_GPIO_SET_PIN(M_GPIO_C_BASE, LED3_MASK)
#define LED3_OFF        M_GPIO_CLEAR_PIN(M_GPIO_C_BASE, LED3_MASK)
#ifdef HARDWARE_OPENMOTE
#define DIO1_ON         M_GPIO_SET_PIN(M_GPIO_D_BASE, DIO1_MASK)
#define DIO1_OFF        M_GPIO_CLEAR_PIN(M_GPIO_D_BASE, DIO1_MASK)
#define KEY_LEFT_ON
#define KEY_LEFT_OFF
#define KEY_RIGHT_ON
#define KEY_RIGHT_OFF
#define KEY_UP_ON
#define KEY_UP_OFF
#define KEY_DOWN_ON
#define KEY_DOWN_OFF
#define KEY_SELECT_ON
#define KEY_SELECT_OFF
#define LCD_RESET_ON
#define LCD_RESET_OFF
#define LCD_MODE_ON
#define LCD_MODE_OFF
#define LCD_CS_ON
#define LCD_CS_OFF
#else
#define DIO1_ON
#define DIO1_OFF
#define KEY_LEFT_ON     M_GPIO_SET_PIN(M_GPIO_C_BASE, KEY_LEFT_MASK)
#define KEY_LEFT_OFF    M_GPIO_CLEAR_PIN(M_GPIO_C_BASE, KEY_LEFT_MASK)
#define KEY_RIGHT_ON    M_GPIO_SET_PIN(M_GPIO_C_BASE, KEY_RIGHT_MASK)
#define KEY_RIGHT_OFF   M_GPIO_CLEAR_PIN(M_GPIO_C_BASE, KEY_RIGHT_MASK)
#define KEY_UP_ON       M_GPIO_SET_PIN(M_GPIO_C_BASE, KEY_UP_MASK)
#define KEY_UP_OFF      M_GPIO_CLEAR_PIN(M_GPIO_C_BASE, KEY_UP_MASK)
#define KEY_DOWN_ON     M_GPIO_SET_PIN(M_GPIO_C_BASE, KEY_DOWN_MASK)
#define KEY_DOWN_OFF    M_GPIO_CLEAR_PIN(M_GPIO_C_BASE, KEY_DOWN_MASK)
#define KEY_SELECT_ON   M_GPIO_SET_PIN(M_GPIO_A_BASE, KEY_SELECT_MASK)
#define KEY_SELECT_OFF  M_GPIO_CLEAR_PIN(M_GPIO_A_BASE, KEY_SELECT_MASK)
#define LCD_RESET_ON    M_GPIO_SET_PIN(M_GPIO_B_BASE, LCD_RESET_MASK)
#define LCD_RESET_OFF   M_GPIO_CLEAR_PIN(M_GPIO_B_BASE, LCD_RESET_MASK)
#define LCD_MODE_ON     M_GPIO_SET_PIN(M_GPIO_B_BASE, LCD_MODE_MASK)
#define LCD_MODE_OFF    M_GPIO_CLEAR_PIN(M_GPIO_B_BASE, LCD_MODE_MASK)
#define LCD_CS_ON       M_GPIO_SET_PIN(M_GPIO_B_BASE, LCD_CS_MASK)
#define LCD_CS_OFF      M_GPIO_CLEAR_PIN(M_GPIO_B_BASE, LCD_CS_MASK)
#endif
#else
#define LED0_ON
#define LED0_OFF
#define LED1_ON
#define LED1_OFF
#define LED2_ON
#define LED2_OFF
#define LED3_ON
#define LED3_OFF
#define DIO1_ON
#define DIO1_OFF
#define KEY_LEFT_ON
#define KEY_LEFT_OFF
#define KEY_RIGHT_ON
#define KEY_RIGHT_OFF
#define KEY_UP_ON
#define KEY_UP_OFF
#define KEY_DOWN_ON
#define KEY_DOWN_OFF
#define KEY_SELECT_ON
#define KEY_SELECT_OFF
#define LCD_RESET_ON
#define LCD_RESET_OFF
#define LCD_MODE_ON
#define LCD_MODE_OFF
#define LCD_CS_ON
#define LCD_CS_OFF
#endif

// #1: Define RF measurements
#define MEASUREMENT_DTLS_TOTAL_ON   LED3_ON
#define MEASUREMENT_DTLS_TOTAL_OFF  LED3_OFF
#define MEASUREMENT_DTLS_WRITE_ON   KEY_LEFT_ON
#define MEASUREMENT_DTLS_WRITE_OFF  KEY_LEFT_OFF
#define MEASUREMENT_DTLS_READ_ON    LCD_RESET_ON
#define MEASUREMENT_DTLS_READ_OFF   LCD_RESET_OFF
#define MEASUREMENT_RX_ON           LED0_ON
#define MEASUREMENT_RX_OFF          LED0_OFF
#define MEASUREMENT_CCA_ON 	        LED1_ON
#define MEASUREMENT_CCA_OFF         LED1_OFF
#define MEASUREMENT_TX_ON           LED2_ON
#define MEASUREMENT_TX_OFF          LED2_OFF
#define MEASUREMENT_PREPARE_ON      KEY_RIGHT_ON
#define MEASUREMENT_PREPARE_OFF     KEY_RIGHT_OFF
#define MEASUREMENT_RECEIVING_ON    KEY_UP_ON
#define MEASUREMENT_RECEIVING_OFF   KEY_UP_OFF
#define MEASUREMENT_TRANSMIT_ON     KEY_DOWN_ON
#define MEASUREMENT_TRANSMIT_OFF    KEY_DOWN_OFF
#define MEASUREMENT_READ_ON         KEY_SELECT_ON
#define MEASUREMENT_READ_OFF        KEY_SELECT_OFF



#ifdef __cplusplus
} // end extern "C"
#endif

#endif /* EXAMPLES_COAPS_MEASUREMENT_H_ */
