from decimal import Decimal
import sys
import numpy

def extract_latency(filename, threshold=None):
    all_timestamps = []
    all_timestamp_deltas = []
    with open(filename) as f:
        lines = f.readlines()
        if len(lines[0].split(',')) < 9:
            lines = lines[1:]
        for line in lines:
            values = line.split(',')
            if 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' in values[8]:
                continue
            if values[8][24:28] != '0800':
                print values[8][24:28]
                print "Found arp: omitting"
                continue
            all_timestamps.append(Decimal(values[2]) * 1000000)  # Multiply by 1000000 to turn this into us.
    all_timestamps = sorted(all_timestamps)


    for i in range(0, len(all_timestamps) - 1, 2):
        all_timestamp_deltas.append(float((all_timestamps[i + 1] - all_timestamps[i])))

    if threshold:
        all_timestamp_deltas = [x for x in all_timestamp_deltas if x < threshold]
    return all_timestamps, all_timestamp_deltas


if __name__ == "__main__":
    INPUT_FILE_NAME=sys.argv[1]
    all_timestamps, all_timestamp_deltas = extract_latency(INPUT_FILE_NAME)
    print "i have obtained timestamp deltas from timestamps", len(all_timestamp_deltas), len(all_timestamps)

    print "this is median: ", numpy.median(all_timestamp_deltas)
    print "this is iqr: ", numpy.percentile(all_timestamp_deltas, [25,75])
    print "this is 99th percentile: ", numpy.percentile(all_timestamp_deltas, [99])
    print "this is the max: ", max(all_timestamp_deltas)
    print "this is the min: ", min(all_timestamp_deltas)
