// Words the browser pages show, in one place so every page says the same thing.

export const START_FAILURE = {
  refused: 'The speaker turned down the request to play. Check that it is switched on and not in use by another app, then try again.',
  failed: 'The speaker did not start. autostream keeps trying while the music plays.',
  timed_out: 'The speaker did not answer in time. Check that it is switched on and connected to the network.',
  encoder_capacity: 'The appliance cannot encode another stream at the chosen quality. Turn another speaker off or choose a lighter audio mode.',
  other: 'The speaker did not start.',
};

// What a refused intent says: { title, text }, or the sentence alone.
export const REFUSAL = {
  encoder_capacity: (name) => ({
    title: 'CPU limit reached',
    text: 'Unable to enable ' + (name || 'this output') + ': the appliance\'s CPU cannot encode another stream at the selected quality. Disable another output or choose a lighter audio mode.',
  }),
  pin_invalid: 'That PIN was not accepted. Try again.',
  nothing_selected: 'Turn on at least one speaker first.',
  settings_unavailable: 'The speakers could not be saved just now. Try again in a moment.',
};

// What the relay says when it cannot take a person to another appliance.
const CANT_REACH = "Can't reach this appliance";
export const RELAY = {
  control_disabled: 'Control of other appliances is turned off',
  unknown_appliance: 'Appliance not found',
  bound_appliance: 'Appliance not found',
  appliance_conflict: 'Two appliances share this name',
  appliance_unconfigured: 'This appliance is not set up yet',
  unconfigured: 'This appliance is not set up yet',
  protocol_mismatch: 'This appliance needs an update',
  peer_unreachable: CANT_REACH,
  unreachable: CANT_REACH,
  timeout: CANT_REACH,
  bad_reply: CANT_REACH,
  backoff: CANT_REACH + ', retrying',
};
export const SELECTOR_NOTE = { update: 'needs an update', setup: 'not set up' };

export const CHIP = {
  on: 'On',
  off: 'Off',
  paused: 'Paused',
  inUse: (by) => 'In Use by ' + (by || 'another appliance'),
  autoStart: 'Auto-Start',
  connecting: ' (Connecting)',
  offline: ' (offline)',
};

// Input words: the type word, and the shorter prefix while a track is identified.
export const INPUT_TYPE_LABELS = { turntable: 'Turntable', cd: 'CD', line: 'Line' };
export const TYPE_WORD = { turntable: 'Turntable', bluetooth: 'Bluetooth', cd: 'CD', line: 'Line Level' };
export const PREFIX_WORD = { turntable: 'Vinyl', bluetooth: 'Bluetooth', cd: 'CD', line: 'Line In' };

export const moreSuffix = (n) => ' +' + n + ' more';
export const moreCards = (n) => n + ' more';

export const AUTO_START_PILL = 'Auto-Start';
export const AUTO_START_CONFIRM = 'Auto-Start playing for future sessions with the current playing devices?';
