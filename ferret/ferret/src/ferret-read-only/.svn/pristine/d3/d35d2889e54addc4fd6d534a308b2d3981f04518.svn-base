/* Copyright (c) 2008 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
/*
	SOME NOTES ABOUT TCP CHECKSUM CALCULATION

  The checksum can be calculated in any order:

  [A,B] + [C,D] = [X,Y]
  [C,D] + [A,B] = [X,Y]

  The checksum can be calculated using either byte order:

  [A,B] + [C,D] = [X,Y]
  [B,A] + [D,C] = [Y,X]

  Because the checksum can be calculated in any order,
  we can simply cast *(unsigned short*) to the bytes
  in order to extract the integers, and only byte-swap
  the result at the end for little-endian architectures
  like the x86. However, if the memory is not evenly
  aligned, this will crash RISC processors and may
  perform more slowly on x86 processors.

  If we are validating a checksum, then we include the
  TCP 'checksum' field itself, and the result should come
  out to 0xFFFF. If we are calculating a checksum, then
  we need to skip the checksum field.

  We cannot change the packet contents. The way a lot of
  code skips the checksum field is by writing 0x0000 into
  the field before the calculation, then restoring it
  afterword.

  An especially bad technique is to write a padding byte 
  of 0x00 on the end of odd packets. While there is usually
  a spare byte at the end of the packet, this can't
  be guaranteed to always be the case.

  We could write a much faster algorithm using assembly
  language. If we used the ADC (add with carry) instruction,
  we could add 4-bytes at a time. 

*/

unsigned
validate_tcp_checksum(	const unsigned char *px,
						unsigned length,
						unsigned pseudo_ip_src,
						unsigned pseudo_ip_dst)
{
	unsigned sum = 0;
	unsigned i;
	
	/* Calculate the pseudo-header sum */
	sum += (pseudo_ip_src>>16) & 0xFFff;
	sum += (pseudo_ip_src>> 0) & 0xFFff;
	sum += (pseudo_ip_dst>>16) & 0xFFff;
	sum += (pseudo_ip_dst>> 0) & 0xFFff;
	sum += 6; /* protocol field */
	sum += length & 0xFFff;

	/* If the data is an odd number of bytes long, then we have to
	 * do special processing on the last byte. Remember that the
	 * checksum can be calculated in any order. Therefore, we can
	 * add the final byte to the sum before the rest of the bytes */
	if (length&1) {
		length--;
		sum += (px[length]<<8);
	}


	/* Run through the entire packet */
	for (i=0; i<length; i += 2)
		sum += (px[i]<<8) | px[i+1];

	
	/* Now roll the upper bits back into the sum */
	while (sum & 0xFFFF0000)
		sum = (sum>>16) + (sum&0xFFff);

	return sum==0xFFFF;
}

unsigned
validate_udp_checksum(	const unsigned char *px,
						unsigned length,
						unsigned pseudo_ip_src,
						unsigned pseudo_ip_dst)
{
	unsigned sum = 0;
	unsigned i;
	
	/* Calculate the pseudo-header sum */
	sum += (pseudo_ip_src>>16) & 0xFFff;
	sum += (pseudo_ip_src>> 0) & 0xFFff;
	sum += (pseudo_ip_dst>>16) & 0xFFff;
	sum += (pseudo_ip_dst>> 0) & 0xFFff;
	sum += 17; /* protocol field */
	sum += length & 0xFFff;

	/* If the data is an odd number of bytes long, then we have to
	 * do special processing on the last byte. Remember that the
	 * checksum can be calculated in any order. Therefore, we can
	 * add the final byte to the sum before the rest of the bytes */
	if (length&1) {
		length--;
		sum += (px[length]<<8);
	}


	/* Run through the entire packet */
	for (i=0; i<length; i += 2)
		sum += (px[i]<<8) | px[i+1];

	
	/* Now roll the upper bits back into the sum */
	while (sum & 0xFFFF0000)
		sum = (sum>>16) + (sum&0xFFff);

	return sum==0xFFFF;
}
