/*
 * measurement.c
 *
 *  Created on: 12 Jun 2017
 *      Author: Michael Morscher, morscher@hm.edu
 */

#include "measurement.h"

void measurement_init_gpio(void) {
	M_GPIO_CONTROL_SOFTWARE(M_GPIO_C_BASE, LED_MASK_ALL);
	M_GPIO_CONTROL_SOFTWARE(M_GPIO_C_BASE, KEY_MASK_C_ALL);
	M_GPIO_CONTROL_SOFTWARE(M_GPIO_A_BASE, KEY_SELECT_MASK);
	M_GPIO_SET_OUTPUT(M_GPIO_C_BASE, LED_MASK_ALL);
	M_GPIO_SET_OUTPUT(M_GPIO_C_BASE, KEY_MASK_C_ALL);
	M_GPIO_SET_OUTPUT(M_GPIO_A_BASE, KEY_SELECT_MASK);
}
