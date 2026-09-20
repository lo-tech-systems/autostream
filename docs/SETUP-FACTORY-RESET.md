# Factory Reset

## Reaching the page

Open **Setup** and expand the **Factory Reset** card, at the bottom of the Setup page.

## What it does

Factory Reset returns the appliance to first-run Wi-Fi setup mode. All settings are erased,
and the appliance reboots into the same state it was in out of the box, broadcasting its own
Wi-Fi access point (named `autostream_XXXX`) so you can reconnect and reconfigure it from
scratch.

## Running it

Press the red **Factory Reset** button. A confirmation dialog explains that all settings,
including Wi-Fi settings, will be erased and the appliance will reboot, and that you'll need
to reconnect to the appliance's Wi-Fi network afterwards using the factory-configured PIN
(the dialog shows the PIN directly if it can still be read from the boot partition).

Choose **Continue** to proceed, or **Cancel** to back out without changing anything.
Confirming disables both buttons and sends the reset request; on success, the browser is
taken to a "resetting" placeholder page while the appliance reboots. If the request fails,
an inline error appears and the buttons re-enable so you can try again.
