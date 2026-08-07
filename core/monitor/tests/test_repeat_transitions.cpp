// =============================================================================
// test_repeat_transitions.cpp
//
// Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.
//
// Unit tests for decide_repeat_transition() -- the pure decision core of
// RepeatController's state machine. See the state x event matrix comment
// above decide_repeat_transition() in autostream_monitor.h for the
// authoritative table this test drives, cell by cell.
//
// Why a free function rather than a real RepeatController: RepeatController
// pulls in libtwolame/libmpg123 (Mp2Encoder/Mp2Decoder), spins up two real
// worker threads (RepeatRecorder, ReplayEngine), and does actual /proc/
// meminfo file I/O in perform_pending_start() -- none of that is available
// or desirable in a unit test. The (state, armed, enabled_cfg,
// pending_action, pending_restorable, event, ctx) -> RepeatDecision decision
// lives in decide_repeat_transition(), a pure function with no shared state,
// no I/O, and no blocking, and defined it `inline` directly in
// autostream_monitor.h precisely so it stays link-independent of libtwolame/
// libmpg123 -- this test includes only the header, no autostream_repeat.cpp,
// so it builds with the same bare `g++ -I core/monitor` every other
// zero-dependency monitor test uses (autostream_repeat_buffer.h/
// autostream_spsc_ring.h's pattern). RepeatController::handle_event_locked()
// (autostream_repeat.cpp) is the only production caller of this function;
// it is exercised indirectly by the D-suite / repeat_test_driver.py
// scenarios, not here.
//
// Coverage: every (RepeatState, RepeatEvent) cell in the matrix, including
// the PendingAction/armed/enabled_cfg/pending_restorable sub-branches that
// make some cells fan out into more than one outcome, and the two
// IMPOSSIBLE cells (PendingStartSucceeded/Failed outside Pending).
//
// Build (on Linux/WSL, from repo root):
//   g++ -std=c++17 -Wall -Wextra -O2 -I core/monitor \
//       core/monitor/tests/test_repeat_transitions.cpp \
//       -o /tmp/test_repeat_transitions && /tmp/test_repeat_transitions
// =============================================================================

#include "autostream_monitor.h"

#include <cstdio>
#include <array>

// ---------------------------------------------------------------------------
// Minimal assertion harness (matches test_repeat_buffer.cpp / test_spsc_ring.cpp)
// ---------------------------------------------------------------------------

static int g_tests  = 0;
static int g_failed = 0;

#define CHECK(cond, msg) do { \
    ++g_tests; \
    if (!(cond)) { \
        ++g_failed; \
        std::fprintf(stderr, "FAIL [%s:%d] %s -- %s\n", \
                     __FILE__, __LINE__, #cond, (msg)); \
    } \
} while (0)

static const std::array<RepeatState, 6> kAllStates = {
    RepeatState::Idle, RepeatState::Recording, RepeatState::Hold,
    RepeatState::Replaying, RepeatState::FadingOut, RepeatState::Pending,
};

static const char* state_name(RepeatState s)
{
    switch (s)
    {
        case RepeatState::Idle:       return "Idle";
        case RepeatState::Recording:  return "Recording";
        case RepeatState::Hold:       return "Hold";
        case RepeatState::Replaying:  return "Replaying";
        case RepeatState::FadingOut:  return "FadingOut";
        case RepeatState::Pending:    return "Pending";
    }
    return "?";
}

// ---------------------------------------------------------------------------
// EnabledOn / EnabledOff
// ---------------------------------------------------------------------------

static void test_enabled_on_off()
{
    for (RepeatState s : kAllStates)
    {
        // EnabledOff: Idle -> NoOp; everything else -> Apply.
        RepeatDecision off_default = decide_repeat_transition(
            s, /*armed=*/false, /*enabled_cfg=*/false, PendingAction::None,
            /*pending_restorable=*/false, RepeatEvent::EnabledOff, RepeatEventCtx{});
        if (s == RepeatState::Idle)
        {
            CHECK(off_default.kind == RepeatDecision::Kind::NoOp, state_name(s));
        }
        else
        {
            CHECK(off_default.kind == RepeatDecision::Kind::Apply, state_name(s));
            CHECK(off_default.log_tag == RepeatLogTag::DisabledMidState, state_name(s));
            if (s == RepeatState::Replaying || s == RepeatState::FadingOut)
            {
                CHECK(off_default.do_request_abort, state_name(s));
                CHECK(!off_default.do_free_recording, state_name(s));
                CHECK(off_default.set_pending_action &&
                      off_default.pending_action == PendingAction::Discard, state_name(s));
            }
            else
            {
                CHECK(off_default.do_free_recording, state_name(s));
                CHECK(!off_default.do_request_abort, state_name(s));
            }
        }

        // EnabledOff while Replaying/FadingOut: pending_restorable snapshot
        // mirrors (pending_action == LiveInterrupt) at call time.
        if (s == RepeatState::Replaying || s == RepeatState::FadingOut)
        {
            RepeatDecision off_li = decide_repeat_transition(
                s, false, false, PendingAction::LiveInterrupt, false,
                RepeatEvent::EnabledOff, RepeatEventCtx{});
            CHECK(off_li.set_pending_restorable && off_li.pending_restorable, state_name(s));

            RepeatDecision off_none = decide_repeat_transition(
                s, false, false, PendingAction::None, false,
                RepeatEvent::EnabledOff, RepeatEventCtx{});
            CHECK(off_none.set_pending_restorable && !off_none.pending_restorable, state_name(s));
        }

        // EnabledOn: only Replaying/FadingOut with Discard+restorable applies.
        RepeatDecision on_noop = decide_repeat_transition(
            s, false, false, PendingAction::None, false,
            RepeatEvent::EnabledOn, RepeatEventCtx{});
        CHECK(on_noop.kind == RepeatDecision::Kind::NoOp, state_name(s));

        if (s == RepeatState::Replaying || s == RepeatState::FadingOut)
        {
            RepeatDecision on_restore = decide_repeat_transition(
                s, false, false, PendingAction::Discard, /*pending_restorable=*/true,
                RepeatEvent::EnabledOn, RepeatEventCtx{});
            CHECK(on_restore.kind == RepeatDecision::Kind::Apply, state_name(s));
            CHECK(on_restore.set_pending_action &&
                  on_restore.pending_action == PendingAction::LiveInterrupt, state_name(s));
            CHECK(on_restore.set_pending_restorable && !on_restore.pending_restorable, state_name(s));
            CHECK(on_restore.log_tag == RepeatLogTag::ReenabledRestoringLiveInterrupt, state_name(s));

            // Discard but NOT restorable -> still NoOp.
            RepeatDecision on_not_restorable = decide_repeat_transition(
                s, false, false, PendingAction::Discard, /*pending_restorable=*/false,
                RepeatEvent::EnabledOn, RepeatEventCtx{});
            CHECK(on_not_restorable.kind == RepeatDecision::Kind::NoOp, state_name(s));

            // LiveInterrupt already (nothing to restore) -> NoOp.
            RepeatDecision on_live = decide_repeat_transition(
                s, false, false, PendingAction::LiveInterrupt, true,
                RepeatEvent::EnabledOn, RepeatEventCtx{});
            CHECK(on_live.kind == RepeatDecision::Kind::NoOp, state_name(s));
        }
    }
}

// ---------------------------------------------------------------------------
// CaptureStarted
// ---------------------------------------------------------------------------

static void test_capture_started()
{
    RepeatEventCtx ctx;
    ctx.input_index = 1;

    // Global !enabled_cfg guard: NoOp for every state.
    for (RepeatState s : kAllStates)
    {
        RepeatDecision d = decide_repeat_transition(
            s, false, /*enabled_cfg=*/false, PendingAction::None, false,
            RepeatEvent::CaptureStarted, ctx);
        CHECK(d.kind == RepeatDecision::Kind::NoOp, state_name(s));
    }

    // Recording/Pending: defensive NoOp regardless of enabled_cfg.
    for (RepeatState s : {RepeatState::Recording, RepeatState::Pending})
    {
        RepeatDecision d = decide_repeat_transition(
            s, false, true, PendingAction::None, false, RepeatEvent::CaptureStarted, ctx);
        CHECK(d.kind == RepeatDecision::Kind::NoOp, state_name(s));
    }

    // Idle: new Pending session.
    {
        RepeatDecision d = decide_repeat_transition(
            RepeatState::Idle, false, true, PendingAction::None, false,
            RepeatEvent::CaptureStarted, ctx);
        CHECK(d.kind == RepeatDecision::Kind::Apply, "Idle");
        CHECK(!d.do_free_recording, "Idle");
        CHECK(d.change_state && d.next_state == RepeatState::Pending, "Idle");
        CHECK(d.set_origin && d.origin_input == 1, "Idle");
        CHECK(d.do_request_pending_start, "Idle");
    }

    // Hold: frees the stale recording too.
    {
        RepeatDecision d = decide_repeat_transition(
            RepeatState::Hold, false, true, PendingAction::None, false,
            RepeatEvent::CaptureStarted, ctx);
        CHECK(d.kind == RepeatDecision::Kind::Apply, "Hold");
        CHECK(d.do_free_recording, "Hold");
        CHECK(d.change_state && d.next_state == RepeatState::Pending, "Hold");
        CHECK(d.set_origin && d.origin_input == 1, "Hold");
        CHECK(d.do_request_pending_start, "Hold");
    }

    // Replaying/FadingOut: the four sub-branches (Ignored x3 + the state-
    // dependent outcome: Replaying arms probation, FadingOut still upgrades
    // immediately -- see decide_repeat_transition()'s CaptureStarted cell).
    for (RepeatState s : {RepeatState::Replaying, RepeatState::FadingOut})
    {
        RepeatDecision ignored_li = decide_repeat_transition(
            s, false, true, PendingAction::LiveInterrupt, false,
            RepeatEvent::CaptureStarted, ctx);
        CHECK(ignored_li.kind == RepeatDecision::Kind::Ignored, state_name(s));
        CHECK(ignored_li.log_tag == RepeatLogTag::CaptureStartIgnoredFadeInProgress, state_name(s));

        RepeatDecision ignored_discard = decide_repeat_transition(
            s, false, true, PendingAction::Discard, false,
            RepeatEvent::CaptureStarted, ctx);
        CHECK(ignored_discard.kind == RepeatDecision::Kind::Ignored, state_name(s));
        CHECK(ignored_discard.log_tag == RepeatLogTag::CaptureStartIgnoredDiscardPending, state_name(s));

        RepeatDecision ignored_probation = decide_repeat_transition(
            s, false, true, PendingAction::InterruptProbation, false,
            RepeatEvent::CaptureStarted, ctx);
        CHECK(ignored_probation.kind == RepeatDecision::Kind::Ignored, state_name(s));
        CHECK(ignored_probation.log_tag == RepeatLogTag::CaptureStartIgnoredProbationInProgress,
              state_name(s));

        RepeatDecision trigger = decide_repeat_transition(
            s, false, true, PendingAction::None, false, RepeatEvent::CaptureStarted, ctx);
        CHECK(trigger.kind == RepeatDecision::Kind::Apply, state_name(s));

        if (s == RepeatState::Replaying)
        {
            // Interrupt probation: no fade, no state change yet -- only
            // arms the gate. pending_restorable is untouched (still belongs
            // to the eventual confirmed/timed-out outcome).
            CHECK(trigger.set_pending_action &&
                  trigger.pending_action == PendingAction::InterruptProbation, "Replaying");
            CHECK(trigger.set_pending_interrupt_input &&
                  trigger.pending_interrupt_input == 1, "Replaying");
            CHECK(!trigger.set_pending_restorable, "Replaying: probation arm doesn't touch restorable");
            CHECK(!trigger.change_state, "Replaying: probation arm doesn't change state");
            CHECK(!trigger.do_request_fade_out, "Replaying: probation arm doesn't fade");
            CHECK(trigger.log_tag == RepeatLogTag::CaptureStartArmsProbation, "Replaying");
        }
        else
        {
            // FadingOut: unprobated, immediate upgrade -- unchanged from
            // before probation existed.
            CHECK(trigger.set_pending_action &&
                  trigger.pending_action == PendingAction::LiveInterrupt, "FadingOut");
            CHECK(trigger.set_pending_interrupt_input &&
                  trigger.pending_interrupt_input == 1, "FadingOut");
            CHECK(trigger.set_pending_restorable && !trigger.pending_restorable, "FadingOut");
            CHECK(!trigger.change_state, "FadingOut upgrade: no state change");
            CHECK(!trigger.do_request_fade_out, "FadingOut upgrade: fade already running");
            CHECK(trigger.log_tag == RepeatLogTag::LiveInterruptUpgradingDisarmFade, "FadingOut");
        }
    }
}

// ---------------------------------------------------------------------------
// ProbationConfirmed / ProbationTimedOut
// ---------------------------------------------------------------------------

static void test_probation_confirmed_and_timed_out()
{
    // ProbationConfirmed, Replaying, armed: promotes to LiveInterrupt and
    // starts the fade-out, reproducing exactly what an unprobated
    // CaptureStarted used to do directly.
    {
        RepeatDecision d = decide_repeat_transition(
            RepeatState::Replaying, false, true, PendingAction::InterruptProbation, false,
            RepeatEvent::ProbationConfirmed, RepeatEventCtx{});
        CHECK(d.kind == RepeatDecision::Kind::Apply, "Replaying confirmed");
        CHECK(d.set_pending_action && d.pending_action == PendingAction::LiveInterrupt,
              "Replaying confirmed");
        CHECK(d.set_pending_restorable && !d.pending_restorable, "Replaying confirmed");
        CHECK(d.change_state && d.next_state == RepeatState::FadingOut, "Replaying confirmed");
        CHECK(d.do_request_fade_out, "Replaying confirmed");
        CHECK(d.log_tag == RepeatLogTag::LiveInterruptFadingOutReplay, "Replaying confirmed");
    }

    // ProbationConfirmed, FadingOut, armed: a disarm-fade started while
    // probation was still armed -- upgrade in place, no new state change,
    // no new fade request (one already running).
    {
        RepeatDecision d = decide_repeat_transition(
            RepeatState::FadingOut, false, true, PendingAction::InterruptProbation, false,
            RepeatEvent::ProbationConfirmed, RepeatEventCtx{});
        CHECK(d.kind == RepeatDecision::Kind::Apply, "FadingOut confirmed");
        CHECK(d.set_pending_action && d.pending_action == PendingAction::LiveInterrupt,
              "FadingOut confirmed");
        CHECK(!d.change_state, "FadingOut confirmed: no state change");
        CHECK(!d.do_request_fade_out, "FadingOut confirmed: fade already running");
        CHECK(d.log_tag == RepeatLogTag::LiveInterruptUpgradingDisarmFade, "FadingOut confirmed");
    }

    // ProbationConfirmed but stale/superseded: pending_action already moved
    // on (Discard won, or already LiveInterrupt), or the replay already
    // ended (state outside Replaying/FadingOut) -- moot, NoOp.
    {
        RepeatDecision superseded_discard = decide_repeat_transition(
            RepeatState::Replaying, false, true, PendingAction::Discard, false,
            RepeatEvent::ProbationConfirmed, RepeatEventCtx{});
        CHECK(superseded_discard.kind == RepeatDecision::Kind::NoOp, "confirmed, Discard won");

        RepeatDecision superseded_none = decide_repeat_transition(
            RepeatState::Replaying, false, true, PendingAction::None, false,
            RepeatEvent::ProbationConfirmed, RepeatEventCtx{});
        CHECK(superseded_none.kind == RepeatDecision::Kind::NoOp, "confirmed, already resolved");

        for (RepeatState s : {RepeatState::Idle, RepeatState::Recording,
                               RepeatState::Hold, RepeatState::Pending})
        {
            RepeatDecision superseded_state = decide_repeat_transition(
                s, false, true, PendingAction::InterruptProbation, false,
                RepeatEvent::ProbationConfirmed, RepeatEventCtx{});
            CHECK(superseded_state.kind == RepeatDecision::Kind::NoOp, state_name(s));
        }
    }

    // ProbationTimedOut: silent reset back to None, no state change --
    // replay continues untouched. The WARN-level log line is the only
    // operator-visible signal (this test only checks the decision, not the
    // actual LOG_WARN call, which lives in handle_event_locked()).
    {
        RepeatDecision d = decide_repeat_transition(
            RepeatState::Replaying, false, true, PendingAction::InterruptProbation, false,
            RepeatEvent::ProbationTimedOut, RepeatEventCtx{});
        CHECK(d.kind == RepeatDecision::Kind::Apply, "timed out");
        CHECK(d.set_pending_action && d.pending_action == PendingAction::None, "timed out");
        CHECK(!d.change_state, "timed out: replay continues, no state change");
        CHECK(d.log_tag == RepeatLogTag::ProbationTimedOutReplayContinues, "timed out");
    }

    // ProbationTimedOut but stale (already resolved another way): NoOp.
    {
        RepeatDecision d = decide_repeat_transition(
            RepeatState::Replaying, false, true, PendingAction::LiveInterrupt, false,
            RepeatEvent::ProbationTimedOut, RepeatEventCtx{});
        CHECK(d.kind == RepeatDecision::Kind::NoOp, "timed out, already confirmed");
    }
}

// ---------------------------------------------------------------------------
// CaptureStarted -- minimum playback hold (replay-takeover suppression)
//
// ctx.replay_hold_active gates ONLY the Replaying/FadingOut takeover cells.
// Every other (state, event) cell in the matrix never reads this field, so
// leaving it at its default (false) -- which every other test function in
// this file does, via RepeatEventCtx{} -- reproduces today's behaviour
// exactly. That default-false coverage across the whole rest of the suite
// IS the "minimum_playback_seconds=0 => identical to today" regression
// check for this cell; the cases below additionally pin down the "hold
// active" behaviour itself.
// ---------------------------------------------------------------------------

static void test_capture_started_replay_hold()
{
    RepeatEventCtx ctx;
    ctx.input_index = 1;
    ctx.replay_hold_active = true;

    for (RepeatState s : {RepeatState::Replaying, RepeatState::FadingOut})
    {
        // Hold active, no fade/discard already pending: ignored outright,
        // no state change, no pending-interrupt latch.
        RepeatDecision held = decide_repeat_transition(
            s, false, true, PendingAction::None, false,
            RepeatEvent::CaptureStarted, ctx);
        CHECK(held.kind == RepeatDecision::Kind::Ignored, state_name(s));
        CHECK(held.log_tag == RepeatLogTag::CaptureStartIgnoredReplayHoldActive, state_name(s));
        CHECK(!held.change_state, state_name(s));
        CHECK(!held.set_pending_action, state_name(s));
        CHECK(!held.set_pending_interrupt_input, state_name(s));
        CHECK(!held.set_pending_restorable, state_name(s));

        // Hold active but a fade/discard is already in flight: those cells
        // are checked first and still win (unaffected by the hold).
        RepeatDecision held_over_fade = decide_repeat_transition(
            s, false, true, PendingAction::LiveInterrupt, false,
            RepeatEvent::CaptureStarted, ctx);
        CHECK(held_over_fade.kind == RepeatDecision::Kind::Ignored, state_name(s));
        CHECK(held_over_fade.log_tag == RepeatLogTag::CaptureStartIgnoredFadeInProgress, state_name(s));

        RepeatDecision held_over_discard = decide_repeat_transition(
            s, false, true, PendingAction::Discard, false,
            RepeatEvent::CaptureStarted, ctx);
        CHECK(held_over_discard.kind == RepeatDecision::Kind::Ignored, state_name(s));
        CHECK(held_over_discard.log_tag == RepeatLogTag::CaptureStartIgnoredDiscardPending, state_name(s));

        // Delivery-mechanism simulation: InputChannel's bounded re-notify
        // (compute_should_renotify_capture_started()) calls
        // notify_capture_started() -> this same CaptureStarted event
        // repeatedly, roughly once a second, for as long as the input keeps
        // capturing unrecorded. Simulate several such calls while the hold
        // is still active: every one must independently land on the exact
        // same Ignored/no-mutation outcome (this function is pure and
        // stateless, so "repeated calls" is "the same inputs produce the
        // same output" -- which is exactly the property that makes the
        // real re-notify loop safe to fire unconditionally at that cadence).
        for (int repeat = 0; repeat < 5; ++repeat)
        {
            RepeatDecision r = decide_repeat_transition(
                s, false, true, PendingAction::None, false,
                RepeatEvent::CaptureStarted, ctx);
            CHECK(r.kind == RepeatDecision::Kind::Ignored, state_name(s));
            CHECK(r.log_tag == RepeatLogTag::CaptureStartIgnoredReplayHoldActive, state_name(s));
            CHECK(!r.change_state, state_name(s));
            CHECK(!r.set_pending_action, state_name(s));
        }

        // Hold expired (replay_hold_active=false): the very next re-notify
        // call after expiry is what actually applies the takeover --
        // identical to test_capture_started()'s "trigger" case above
        // (probation-arm for Replaying, immediate upgrade for FadingOut).
        RepeatEventCtx ctx_expired = ctx;
        ctx_expired.replay_hold_active = false;
        RepeatDecision expired = decide_repeat_transition(
            s, false, true, PendingAction::None, false,
            RepeatEvent::CaptureStarted, ctx_expired);
        CHECK(expired.kind == RepeatDecision::Kind::Apply, state_name(s));
        CHECK(expired.set_pending_action, state_name(s));
        if (s == RepeatState::Replaying)
            CHECK(expired.pending_action == PendingAction::InterruptProbation, state_name(s));
        else
            CHECK(expired.pending_action == PendingAction::LiveInterrupt, state_name(s));
    }

    // Idle/Hold/Recording/Pending never consult replay_hold_active at all --
    // spot-check Idle behaves exactly as the non-hold test above with the
    // field simply set to true.
    RepeatDecision idle = decide_repeat_transition(
        RepeatState::Idle, false, true, PendingAction::None, false,
        RepeatEvent::CaptureStarted, ctx);
    CHECK(idle.kind == RepeatDecision::Kind::Apply, "Idle unaffected by replay_hold_active");
    CHECK(idle.change_state && idle.next_state == RepeatState::Pending, "Idle unaffected by replay_hold_active");
}

// ---------------------------------------------------------------------------
// CaptureStopped
// ---------------------------------------------------------------------------

static void test_capture_stopped()
{
    for (RepeatState s : {RepeatState::Idle, RepeatState::Hold,
                           RepeatState::Replaying, RepeatState::FadingOut})
    {
        RepeatDecision d = decide_repeat_transition(
            s, false, true, PendingAction::None, false, RepeatEvent::CaptureStopped, RepeatEventCtx{});
        CHECK(d.kind == RepeatDecision::Kind::NoOp, state_name(s));
    }

    RepeatDecision pending = decide_repeat_transition(
        RepeatState::Pending, false, true, PendingAction::None, false,
        RepeatEvent::CaptureStopped, RepeatEventCtx{});
    CHECK(pending.kind == RepeatDecision::Kind::Apply, "Pending");
    CHECK(pending.change_state && pending.next_state == RepeatState::Idle, "Pending");
    CHECK(pending.set_origin && pending.origin_input == 0, "Pending");
    CHECK(pending.log_tag == RepeatLogTag::CaptureStoppedPendingCancelled, "Pending");

    RepeatDecision recording = decide_repeat_transition(
        RepeatState::Recording, false, true, PendingAction::None, false,
        RepeatEvent::CaptureStopped, RepeatEventCtx{});
    CHECK(recording.kind == RepeatDecision::Kind::Apply, "Recording");
    CHECK(recording.change_state && recording.next_state == RepeatState::Hold, "Recording");
    CHECK(!recording.do_free_recording, "Recording -> Hold, not freed");
}

// ---------------------------------------------------------------------------
// Armed / Disarmed
// ---------------------------------------------------------------------------

static void test_armed_disarmed()
{
    for (RepeatState s : kAllStates)
    {
        RepeatDecision armed = decide_repeat_transition(
            s, false, true, PendingAction::None, false, RepeatEvent::Armed, RepeatEventCtx{});
        if (s == RepeatState::Hold)
        {
            CHECK(armed.kind == RepeatDecision::Kind::Apply, "Hold armed");
            CHECK(armed.do_begin_replay, "Hold armed -> BeginReplay");
            CHECK(!armed.change_state, "begin_replay_locked() owns the state write");
        }
        else
        {
            CHECK(armed.kind == RepeatDecision::Kind::NoOp, state_name(s));
        }

        RepeatDecision disarmed = decide_repeat_transition(
            s, true, true, PendingAction::None, false, RepeatEvent::Disarmed, RepeatEventCtx{});
        if (s == RepeatState::Replaying)
        {
            CHECK(disarmed.kind == RepeatDecision::Kind::Apply, "Replaying disarmed");
            CHECK(disarmed.change_state && disarmed.next_state == RepeatState::FadingOut, "Replaying disarmed");
            CHECK(disarmed.do_request_fade_out, "Replaying disarmed");
            CHECK(disarmed.log_tag == RepeatLogTag::DisarmDuringReplayFadingOut, "Replaying disarmed");
        }
        else
        {
            // Includes FadingOut: a disarm during an in-flight fade is
            // a deliberate no-op -- the fade already running continues
            // untouched, matching "No-op; fade completes".
            CHECK(disarmed.kind == RepeatDecision::Kind::NoOp, state_name(s));
        }
    }
}

// ---------------------------------------------------------------------------
// InputStopped
// ---------------------------------------------------------------------------

static void test_input_stopped()
{
    for (RepeatState s : {RepeatState::Idle, RepeatState::Recording,
                           RepeatState::Hold, RepeatState::Pending})
    {
        RepeatDecision d = decide_repeat_transition(
            s, false, true, PendingAction::None, false, RepeatEvent::InputStopped, RepeatEventCtx{});
        CHECK(d.kind == RepeatDecision::Kind::Apply, state_name(s));
        CHECK(d.do_free_recording, state_name(s));
        CHECK(!d.do_request_abort, state_name(s));
    }

    for (RepeatState s : {RepeatState::Replaying, RepeatState::FadingOut})
    {
        RepeatDecision d = decide_repeat_transition(
            s, false, true, PendingAction::None, false, RepeatEvent::InputStopped, RepeatEventCtx{});
        CHECK(d.kind == RepeatDecision::Kind::Apply, state_name(s));
        CHECK(!d.do_free_recording, state_name(s));
        CHECK(d.do_request_abort, state_name(s));
        CHECK(d.set_pending_action && d.pending_action == PendingAction::Discard, state_name(s));
        // Never restorable: this cell must NOT touch pending_restorable.
        CHECK(!d.set_pending_restorable, state_name(s));
    }
}

// ---------------------------------------------------------------------------
// ReplaySessionEnded
// ---------------------------------------------------------------------------

static void test_replay_session_ended()
{
    for (RepeatState s : {RepeatState::Idle, RepeatState::Recording,
                           RepeatState::Hold, RepeatState::Pending})
    {
        RepeatDecision d = decide_repeat_transition(
            s, false, true, PendingAction::None, false,
            RepeatEvent::ReplaySessionEnded, RepeatEventCtx{});
        CHECK(d.kind == RepeatDecision::Kind::NoOp, state_name(s));
    }

    for (RepeatState s : {RepeatState::Replaying, RepeatState::FadingOut})
    {
        RepeatEventCtx ctx;
        ctx.interrupting_input = 2;

        // Discard wins.
        RepeatDecision discard = decide_repeat_transition(
            s, true, true, PendingAction::Discard, false,
            RepeatEvent::ReplaySessionEnded, ctx);
        CHECK(discard.kind == RepeatDecision::Kind::Apply, state_name(s));
        CHECK(discard.do_free_recording, state_name(s));
        CHECK(!discard.change_state, state_name(s));
        CHECK(discard.set_pending_action && discard.pending_action == PendingAction::None, state_name(s));
        CHECK(discard.set_pending_restorable && !discard.pending_restorable, state_name(s));
        CHECK(discard.log_tag == RepeatLogTag::ReplaySessionEndedDiscarded, state_name(s));

        // LiveInterrupt, enabled -> admit-before-free (change 5): the old
        // recording is NOT freed here any more -- it stays intact in
        // _buffer until perform_pending_start() actually decides admission
        // (steals it on success, leaves it alone on refusal). Only the new
        // Pending session is started here.
        RepeatDecision li_enabled = decide_repeat_transition(
            s, true, /*enabled_cfg=*/true, PendingAction::LiveInterrupt, false,
            RepeatEvent::ReplaySessionEnded, ctx);
        CHECK(li_enabled.kind == RepeatDecision::Kind::Apply, state_name(s));
        CHECK(!li_enabled.do_free_recording, state_name(s));
        CHECK(li_enabled.change_state && li_enabled.next_state == RepeatState::Pending, state_name(s));
        CHECK(li_enabled.set_origin && li_enabled.origin_input == 2, state_name(s));
        CHECK(li_enabled.do_request_pending_start, state_name(s));
        CHECK(li_enabled.log_tag == RepeatLogTag::ReplaySessionEndedLiveInterruptPending, state_name(s));

        // LiveInterrupt, disabled before the fade finished -> nowhere to
        // record into, so this falls back to freeing immediately (the
        // deferred-free contract only applies to a genuine Pending attempt).
        RepeatDecision li_disabled = decide_repeat_transition(
            s, true, /*enabled_cfg=*/false, PendingAction::LiveInterrupt, false,
            RepeatEvent::ReplaySessionEnded, ctx);
        CHECK(li_disabled.kind == RepeatDecision::Kind::Apply, state_name(s));
        CHECK(li_disabled.do_free_recording, state_name(s));
        CHECK(!li_disabled.change_state, state_name(s));
        CHECK(!li_disabled.do_request_pending_start, state_name(s));
        CHECK(li_disabled.log_tag == RepeatLogTag::ReplaySessionEndedLiveInterruptDisabledFreed,
              state_name(s));

        // InterruptProbation, never confirmed (e.g. a hard write error hit
        // the replay while probation was still armed) -> treated the same
        // as None: retain Hold, nothing to promote.
        RepeatDecision probation_unconfirmed = decide_repeat_transition(
            s, true, /*enabled_cfg=*/true, PendingAction::InterruptProbation, false,
            RepeatEvent::ReplaySessionEnded, ctx);
        CHECK(probation_unconfirmed.kind == RepeatDecision::Kind::Apply, state_name(s));
        CHECK(!probation_unconfirmed.do_free_recording, state_name(s));
        CHECK(probation_unconfirmed.change_state &&
              probation_unconfirmed.next_state == RepeatState::Hold, state_name(s));
        CHECK(probation_unconfirmed.log_tag == RepeatLogTag::ReplaySessionEndedRetainedHold,
              state_name(s));

        // None, armed+enabled+bytes -> Hold + BeginReplay (restart).
        RepeatEventCtx ctx_bytes;
        ctx_bytes.has_hold_bytes = true;
        RepeatDecision none_restart = decide_repeat_transition(
            s, /*armed=*/true, /*enabled_cfg=*/true, PendingAction::None, false,
            RepeatEvent::ReplaySessionEnded, ctx_bytes);
        CHECK(none_restart.kind == RepeatDecision::Kind::Apply, state_name(s));
        CHECK(none_restart.change_state && none_restart.next_state == RepeatState::Hold, state_name(s));
        CHECK(none_restart.do_begin_replay, state_name(s));
        CHECK(none_restart.log_tag == RepeatLogTag::ReplaySessionEndedRetainedHold, state_name(s));

        // None, but not armed -> Hold, no restart.
        RepeatDecision none_no_restart = decide_repeat_transition(
            s, /*armed=*/false, /*enabled_cfg=*/true, PendingAction::None, false,
            RepeatEvent::ReplaySessionEnded, ctx_bytes);
        CHECK(none_no_restart.kind == RepeatDecision::Kind::Apply, state_name(s));
        CHECK(none_no_restart.change_state && none_no_restart.next_state == RepeatState::Hold, state_name(s));
        CHECK(!none_no_restart.do_begin_replay, state_name(s));

        // None, armed+enabled but no bytes -> Hold, no restart.
        RepeatEventCtx ctx_no_bytes;
        ctx_no_bytes.has_hold_bytes = false;
        RepeatDecision none_no_bytes = decide_repeat_transition(
            s, /*armed=*/true, /*enabled_cfg=*/true, PendingAction::None, false,
            RepeatEvent::ReplaySessionEnded, ctx_no_bytes);
        CHECK(!none_no_bytes.do_begin_replay, state_name(s));
    }
}

// ---------------------------------------------------------------------------
// PendingStartSucceeded / PendingStartFailed
// ---------------------------------------------------------------------------

static void test_pending_start_outcomes()
{
    RepeatDecision ok = decide_repeat_transition(
        RepeatState::Pending, false, true, PendingAction::None, false,
        RepeatEvent::PendingStartSucceeded, RepeatEventCtx{});
    CHECK(ok.kind == RepeatDecision::Kind::Apply, "Pending PendingStartSucceeded");
    CHECK(ok.change_state && ok.next_state == RepeatState::Recording, "Pending PendingStartSucceeded");
    CHECK(!ok.set_origin, "origin untouched on success");

    // PendingStartFailed, has_hold_bytes == false: plain Idle/Hold -> Pending
    // attempt with no held recording in play -- unchanged from before this
    // fix.
    RepeatDecision failed = decide_repeat_transition(
        RepeatState::Pending, false, true, PendingAction::None, false,
        RepeatEvent::PendingStartFailed, RepeatEventCtx{});
    CHECK(failed.kind == RepeatDecision::Kind::Apply, "Pending PendingStartFailed");
    CHECK(failed.change_state && failed.next_state == RepeatState::Idle, "Pending PendingStartFailed");
    CHECK(failed.set_origin && failed.origin_input == 0, "Pending PendingStartFailed");
    CHECK(failed.log_tag != RepeatLogTag::PendingStartFailedRevertedToHold, "Pending PendingStartFailed");

    // PendingStartFailed, has_hold_bytes == true: a LiveInterrupt promotion
    // deferred freeing the old recording (change 5) and admission was
    // refused -- revert to Hold with the ORIGINAL origin restored (NOT
    // origin_input=0, and NOT the interrupting input), so the surviving
    // recording is attributed correctly and can be replayed again.
    {
        RepeatEventCtx ctx;
        ctx.has_hold_bytes = true;
        ctx.revert_origin_input = 3;

        RepeatDecision reverted = decide_repeat_transition(
            RepeatState::Pending, /*armed=*/true, /*enabled_cfg=*/true, PendingAction::None, false,
            RepeatEvent::PendingStartFailed, ctx);
        CHECK(reverted.kind == RepeatDecision::Kind::Apply, "PendingStartFailed reverted");
        CHECK(reverted.change_state && reverted.next_state == RepeatState::Hold,
              "PendingStartFailed reverted");
        CHECK(reverted.set_origin && reverted.origin_input == 3, "PendingStartFailed reverted");
        CHECK(reverted.log_tag == RepeatLogTag::PendingStartFailedRevertedToHold,
              "PendingStartFailed reverted");
        CHECK(reverted.do_begin_replay, "PendingStartFailed reverted: armed+enabled resumes replay");

        // Same has_hold_bytes but not armed/enabled: reverts to Hold, no
        // auto-resume -- mirrors ReplaySessionEnded's own None -> Hold cell.
        RepeatDecision reverted_not_armed = decide_repeat_transition(
            RepeatState::Pending, /*armed=*/false, /*enabled_cfg=*/true, PendingAction::None, false,
            RepeatEvent::PendingStartFailed, ctx);
        CHECK(!reverted_not_armed.do_begin_replay, "PendingStartFailed reverted, not armed");
        CHECK(reverted_not_armed.next_state == RepeatState::Hold, "PendingStartFailed reverted, not armed");
    }

    // Impossible cells: every state other than Pending, both events.
    for (RepeatState s : kAllStates)
    {
        if (s == RepeatState::Pending)
            continue;
        RepeatDecision succ_bad = decide_repeat_transition(
            s, false, true, PendingAction::None, false,
            RepeatEvent::PendingStartSucceeded, RepeatEventCtx{});
        CHECK(succ_bad.kind == RepeatDecision::Kind::Impossible, state_name(s));

        RepeatDecision fail_bad = decide_repeat_transition(
            s, false, true, PendingAction::None, false,
            RepeatEvent::PendingStartFailed, RepeatEventCtx{});
        CHECK(fail_bad.kind == RepeatDecision::Kind::Impossible, state_name(s));
    }
}

// ---------------------------------------------------------------------------
// Constant derivations: kMinAvailableMibForStart == kFreeRamFloorMib +
// kSessionAdmissionMarginMib (78 == 64 + 14) and kFadeSeconds == 1.0 -- both
// changes 3 and 4. Compile-time checks so a future edit to either input
// constant without updating the derivation comment fails the build, not
// just this test binary.
// ---------------------------------------------------------------------------

static_assert(kFreeRamFloorMib == 64, "kFreeRamFloorMib moved -- re-check the admission gate derivation");
static_assert(RepeatController::kSessionAdmissionMarginMib == 14,
              "margin constant changed -- re-check the 110 -> 78 derivation comment");
static_assert(RepeatController::kMinAvailableMibForStart ==
                  kFreeRamFloorMib + RepeatController::kSessionAdmissionMarginMib,
              "admission gate must stay derived from the floor + margin");
static_assert(RepeatController::kMinAvailableMibForStart == 78,
              "expected 64 + 14 == 78");
static_assert(ReplayEngine::kFadeSeconds == 1.0, "expected fade shortened to 1.0 s");

// ---------------------------------------------------------------------------
// Full-matrix smoke pass: every (state, event) combination must return a
// well-defined Kind (nothing falls through to a garbage/default value) --
// catches an event enumerator added later without a matching switch arm.
// ---------------------------------------------------------------------------

static void test_full_matrix_smoke()
{
    static const std::array<RepeatEvent, 12> kAllEvents = {
        RepeatEvent::EnabledOn, RepeatEvent::EnabledOff, RepeatEvent::CaptureStarted,
        RepeatEvent::CaptureStopped, RepeatEvent::Armed, RepeatEvent::Disarmed,
        RepeatEvent::InputStopped, RepeatEvent::ReplaySessionEnded,
        RepeatEvent::PendingStartSucceeded, RepeatEvent::PendingStartFailed,
        RepeatEvent::ProbationConfirmed, RepeatEvent::ProbationTimedOut,
    };

    for (RepeatState s : kAllStates)
    {
        for (RepeatEvent e : kAllEvents)
        {
            for (bool armed : {false, true})
            {
                for (bool enabled_cfg : {false, true})
                {
                    for (PendingAction pa : {PendingAction::None, PendingAction::Discard,
                                              PendingAction::InterruptProbation,
                                              PendingAction::LiveInterrupt})
                    {
                        for (bool replay_hold_active : {false, true})
                        {
                            RepeatEventCtx ctx;
                            ctx.replay_hold_active = replay_hold_active;
                            RepeatDecision d = decide_repeat_transition(
                                s, armed, enabled_cfg, pa, false, e, ctx);
                            CHECK(d.kind == RepeatDecision::Kind::Apply ||
                                  d.kind == RepeatDecision::Kind::Ignored ||
                                  d.kind == RepeatDecision::Kind::NoOp ||
                                  d.kind == RepeatDecision::Kind::Impossible,
                                  "every cell returns a well-defined Kind");
                        }
                    }
                }
            }
        }
    }
}

int main()
{
    test_enabled_on_off();
    test_capture_started();
    test_capture_started_replay_hold();
    test_probation_confirmed_and_timed_out();
    test_capture_stopped();
    test_armed_disarmed();
    test_input_stopped();
    test_replay_session_ended();
    test_pending_start_outcomes();
    test_full_matrix_smoke();

    std::printf("%d/%d tests passed\n", g_tests - g_failed, g_tests);
    return g_failed == 0 ? 0 : 1;
}
