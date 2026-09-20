# Factory Reset

## Reaching the page

Open **Setup** and expand the **Factory Reset** card, at the bottom of the Setup page.

## What it does

Factory Reset returns the appliance to first-run Wi-Fi setup mode. All settings are erased,
and the appliance reboots into the same state it was in out of the box, broadcasting its own
Wi-Fi access point (named `autostream_XXXX`, using the last four hex digits of its Wi-Fi MAC
address) so you can reconnect and reconfigure it from scratch.

## Running it

Press the red **Factory Reset** button. A confirmation dialog explains that all settings,
including Wi-Fi settings, will be erased and the appliance will reboot, and that you'll need
to reconnect to the appliance's Wi-Fi network afterwards using the factory-configured PIN
(the dialog shows the PIN directly if it can still be read from the boot partition).

Choose **Continue** to proceed, or **Cancel** to back out without changing anything.
Confirming disables both buttons and sends the reset request; on success, the browser is
taken to a "resetting" placeholder page while the appliance reboots. If the request can't be
scheduled, an inline error appears ("Reset could not be scheduled. Please try again.") and
the buttons re-enable so you can try again; if the request fails because the appliance has
already gone offline to reset, the browser is taken to the same placeholder page.

## Gaps

- [gap: how long the reset/reboot cycle takes before the Wi-Fi access point reappears was
  not found in this code path]
