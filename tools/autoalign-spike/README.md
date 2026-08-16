# AutoStream output alignment — capability check

This is a throwaway diagnostic page (`index.html` + `goertzel-processor.js`) used to
confirm, on a real phone, whether a browser supports the measurements needed for
AutoStream's automatic output alignment feature: secure-context microphone access with
raw (unprocessed) audio, detection of short test tones at 1000 Hz / 1250 Hz, repeatable
timing of tone bursts using the audio clock rather than the system clock, and navigating
back to another page with a result attached via the URL. It reports PASS/FAIL/value for
each check directly in the page — there is nothing to install and no data is sent
anywhere except when the "Test handoff" button is used to navigate to a URL you supply.

To deploy, copy the whole `autoalign-spike/` folder as-is to any path served over HTTPS
(microphone access requires a secure context, so plain HTTP will not work) and open
`index.html` on the phone. Run the checks in order: grant microphone access first, then
start tone detection and play a steady 1000 Hz or 1250 Hz tone from another device's
speaker near the phone, then start onset capture and play a repeating 1000 Hz burst
(e.g. a short beep on a fixed period) from another device — once at least 10 onsets are
captured the page shows the mean and standard deviation of the intervals between them.
Check 4 can be exercised by opening the page with a URL fragment such as
`#return=https://example.com/align&x=42`.
