import sys

def dns_match(name, length):
	name = '.' + name
	if not name.endswith('.'):
		name += '.'
	def fill(x):
	    if  len(x) < 8:
		x = '0' * (8 - len(x)) + x

	    return x

	section_length = 0
	section_lengths = []
	names = []

	for character in name:
		binary_character = fill(format(ord(character), 'b'))

		# Compute the section lengths also.
		if binary_character == "00101110":
			section_lengths.append(section_length)
			section_length = 0
		else:
			section_length += 1

		names.append(binary_character)
	section_lengths.append(section_length)
	del section_lengths[0]

	# Label count starts at one because we do not match on the first
	# length field.
	label_count = 0
	for index in range(len(names)):
		if names[index] == "00101110":
			names[index] = fill(format(section_lengths[label_count], 'b'))
			label_count += 1

	binary_name = ''.join(names)

	if len(name) < length:
	    binary_name += '00000000' * (length - len(name))
	if len(name) > length:
	    print "Error: name is longer than ", length, "bytes long"
	    raise Exception(1)

	for index in range(0, len(binary_name), 8):
	    char = chr(int(binary_name[index:index + 8], 2))
	    print char

	return '0b' + binary_name


if __name__ == "__main__":
	if len(sys.argv) != 3:
	    print "Usage: <script> <dns name> <length (in bytes)>"
	    sys.exit(1)

	name = sys.argv[1]
	length = int(sys.argv[2])

	print dns_match(name, length)
