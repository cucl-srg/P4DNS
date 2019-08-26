alphabet=abcdefghijklmnopqrstuvwxyz
for (( i=0; i<26; i ++ )); do
	for (( j=0; j<26; j++ )); do
		python generate_dns_request.py ${alphabet:$i:1}${alphabet:$j:1}.uk
	done
done