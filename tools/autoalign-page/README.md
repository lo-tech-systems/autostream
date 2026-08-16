# AutoStream output alignment

This page is used by AutoStream's automatic output alignment feature. An audio
appliance opens it on a phone and plays a short test tone through one output
at a time; the page listens with the phone's microphone, times when each
output's tone arrives, and reports the timing differences back to the
appliance so it can correct them. Nothing is recorded or leaves the device
except the final result, which is sent by navigating back to the appliance
when the measurement finishes (or can be typed in manually if that doesn't
work).

To deploy, copy this whole folder (`index.html` and
`goertzel-bank-processor.js`) as-is to a path served over HTTPS — microphone
access requires a secure context, so plain HTTP will not work. The appliance
links to `index.html` with the measurement parameters attached after a `#` in
the URL; opening the page without those parameters shows a message explaining
that it was opened incorrectly.
