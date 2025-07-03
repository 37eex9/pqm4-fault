#include "hal.h"

uint16_t serial_get_len(void)
{
	uint16_t len;

	len = getch();
	len += (getch() << 8);

	return len;
}

uint8_t nibble_to_hex(uint8_t nib)
{
	nib &= 0x0f;
	if (nib < 0x0a) {
		return nib + 0x30;
	}
	else {
		return nib + 0x61 - 0x0a;
	}
}

void serial_send_hex(uint8_t * send, uint16_t length)
{
	uint8_t * ptr = send, current, cur_l, cur_h;
	uint16_t len = length;

	while (len) {
		current = *ptr;
		cur_l = current & ((1 << 4) -1);
  		cur_h = current >> 4;

		cur_l = nibble_to_hex(cur_l);
		cur_h = nibble_to_hex(cur_h);
		putch(cur_h);
		putch(cur_l);
		ptr++;
		len--;
	}
}
