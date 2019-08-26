import sys
import matplotlib
import numpy as np
# Avoid errors when running on headless servers.
matplotlib.use('Agg')
import matplotlib.pyplot as plt

if len(sys.argv) != 6:
    print "Usage plot.py <data file port 1> <min size> <step size> <max size> <num packets sent>"
    sys.exit(1)

width = 20

data_file = sys.argv[1]
min_rate = int(sys.argv[2])
step_size = int(sys.argv[3])
max_rate = int(sys.argv[4])
num_packets_sent = int(sys.argv[5])

x_data = np.arange(min_rate, max_rate + step_size, step_size)
y_data = []
error = []
with open(data_file, 'r') as f:
    for data in f.readlines():
        if len(data.split(' ')) == 1:
            y_data.append(int(data))
            error = None
        else:
            values = []
            for value in data.split(' '):
                values.append(int(value))
            y_data.append(np.mean(values))
            error.append(np.std(values))

dropped_counts = []
for data in y_data:
    dropped_counts.append(num_packets_sent - data)


plt.title('Number of drops by one port with different sized packets')
plt.xlabel('Packet size (Bytes)')
plt.ylabel('Packets')
plt.bar(x_data, y_data, width, color='blue', label="Number Captured", y_err=error)
plt.bar(x_data, dropped_counts, width, color='red', bottom=y_data, label="Number Dropped")
plt.legend()
plt.savefig('dropped_packets.eps', format='eps')
