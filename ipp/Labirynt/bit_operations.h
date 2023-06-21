#ifndef BIT_OPERATIONS_H
#define BIT_OPERATIONS_H

#define CheckBit(array, bit) (array[(bit / 32)] & (1 << (bit % 32)))
#define ClearBit(array, bit) (array[(bit / 32)] &= ~(1 << (bit % 32)))
#define SetBit(array, bit) (array[(bit / 32)] |= (1 << (bit % 32)))

#endif
