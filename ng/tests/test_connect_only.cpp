// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
//
// Unit tests for -T, the connect-only mode.
//
// Two properties define it. Nothing is ever sent -- not at connect, not on a
// timer, not in answer to anything the far end says -- because the first byte
// is the thing withheld. And the run's one measurement, how long the far end
// tolerated the silence, has to credit the far end only with the closes it
// actually made: the engine closes every connection itself when the attack
// phase stops, and counting those would report a timeout that never fired.
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>

#include "slowhttp/attacks/connect_only.hpp"
#include "slowhttp/config.hpp"

using slowhttp::Action;
using slowhttp::Config;
using slowhttp::ConnectOnly;

static int failures = 0;

static void check(bool cond, const char* what) {
  if (!cond) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
  }
}

static bool contains(const std::string& s, const char* needle) {
  return s.find(needle) != std::string::npos;
}

static Config make_config(int connections = 4) {
  Config cfg;
  cfg.connections = connections;
  cfg.mode = slowhttp::Mode::ConnectOnly;
  cfg.target.host = "example.test";
  return cfg;
}

// A clock the test moves by hand.
struct FakeClock {
  ConnectOnly::Clock::time_point t{};
  void advance(double secs) {
    t += std::chrono::duration_cast<ConnectOnly::Clock::duration>(
        std::chrono::duration<double>(secs));
  }
};

static void use(ConnectOnly& a, FakeClock& clock) {
  a.set_clock([&clock] { return clock.t; });
}

// Opens connection `id` the way the engine does.
static Action open_conn(ConnectOnly& a, int id) {
  a.on_open(id);
  return a.on_connect(id);
}

static void test_nothing_is_ever_sent() {
  Config cfg = make_config();
  ConnectOnly attack(cfg);
  Action a = open_conn(attack, 0);
  check(a.kind == Action::Kind::Idle, "on_connect asks for nothing");
  check(a.bytes.empty(), "and sends no bytes");
  check(!a.rearm, "and arms no timer: there is nothing to send later either");
  check(a.read_bytes == 0, "and asks for no explicit read");

  Action t = attack.on_timer(0);
  check(t.kind == Action::Kind::Idle && t.bytes.empty(),
        "a stray timer sends nothing");
  check(attack.started() == 1, "the connection is counted as held");
}

static void test_a_reply_does_not_end_the_hold() {
  Config cfg = make_config();
  ConnectOnly attack(cfg);
  open_conn(attack, 0);

  const std::string banner = "SSH-2.0-OpenSSH_9.6\r\n";
  Action a = attack.on_readable(0, banner.data(), banner.size());
  check(a.kind == Action::Kind::Idle,
        "a server that speaks first and then waits is still holding the "
        "connection, so this side keeps holding it too");
  check(a.bytes.empty(), "and still sends nothing in answer");
  check(attack.spoke() == 1, "the reply is counted");
  check(attack.first_reply() == "SSH-2.0-OpenSSH_9.6",
        "and its first line kept, without the line ending");

  attack.on_readable(0, "more", 4);
  check(attack.spoke() == 1, "a connection is counted once, however much it says");
}

static void test_the_first_reply_is_made_safe_to_print() {
  {
    Config cfg = make_config();
    ConnectOnly attack(cfg);
    open_conn(attack, 0);
    // A peer chooses these bytes, and a terminal acts on escape sequences.
    const std::string hostile = "HTTP/1.1 408 \x1b]0;pwned\x07Request Time-out\r\n";
    attack.on_readable(0, hostile.data(), hostile.size());
    check(attack.first_reply().find('\x1b') == std::string::npos &&
              attack.first_reply().find('\x07') == std::string::npos,
          "control bytes from the peer never reach the terminal");
    check(attack.first_reply().rfind("HTTP/1.1 408 ", 0) == 0,
          "the readable part is kept");
  }
  {
    Config cfg = make_config();
    ConnectOnly attack(cfg);
    open_conn(attack, 0);
    // A TLS alert record: binary, and a row of dots would describe nothing.
    const char alert[] = {0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28};
    attack.on_readable(0, alert, sizeof(alert));
    check(attack.spoke() == 1, "binary replies are still counted");
    check(attack.first_reply().empty(), "but not quoted");
    check(contains(attack.summary(), "not as text"),
          "and the summary says why there is no quote");
  }
}

static void test_the_far_end_ending_it_is_timed() {
  Config cfg = make_config();
  ConnectOnly attack(cfg);
  FakeClock clock;
  use(attack, clock);

  open_conn(attack, 0);
  clock.advance(2.0);
  attack.on_peer_close(0);
  attack.on_close(0);  // the engine always follows with this

  check(attack.ended_by_peer() == 1, "the far end's close is counted");
  const std::string s = attack.summary();
  check(contains(s, "ended by the far end (closed or reset): 1, after 2.0s"),
        "with how long the silence was tolerated");
  check(contains(s, "still open when the attack stopped: none"),
        "and the on_close that follows is not counted a second time");
}

static void test_the_engines_close_is_not_credited_to_the_target() {
  Config cfg = make_config();
  ConnectOnly attack(cfg);
  FakeClock clock;
  use(attack, clock);

  open_conn(attack, 0);
  clock.advance(30.0);
  // The attack phase stopping: on_close with no on_peer_close before it.
  attack.on_close(0);

  check(attack.ended_by_peer() == 0,
        "closing everything at the end of the attack is not the target's doing");
  const std::string s = attack.summary();
  check(contains(s, "ended by the far end (closed or reset): none"),
        "so no timeout is reported");
  check(contains(s, "still open when the attack stopped: 1, the oldest after 30.0s"),
        "the connection outlasted the attack instead");
}

static void test_connections_still_open_are_counted_at_summary_time() {
  // Without a probe the engine closes nothing before the summary is printed.
  Config cfg = make_config();
  ConnectOnly attack(cfg);
  FakeClock clock;
  use(attack, clock);

  open_conn(attack, 0);
  clock.advance(4.0);
  open_conn(attack, 1);
  clock.advance(6.0);
  const std::string s = attack.summary();
  check(contains(s, "still open when the attack stopped: 2, the oldest after 10.0s"),
        "open connections count as having outlasted the attack, oldest first");
}

static void test_median_and_range() {
  Config cfg = make_config();
  ConnectOnly attack(cfg);
  FakeClock clock;
  use(attack, clock);

  // Lifetimes of 1, 2 and 9 seconds, ended by the far end.
  open_conn(attack, 0);
  open_conn(attack, 1);
  open_conn(attack, 2);
  clock.advance(1.0);
  attack.on_peer_close(0);
  attack.on_close(0);
  clock.advance(1.0);
  attack.on_peer_close(1);
  attack.on_close(1);
  clock.advance(7.0);
  attack.on_peer_close(2);
  attack.on_close(2);

  check(contains(attack.summary(),
                 "ended by the far end (closed or reset): 3, after 2.0s of "
                 "silence (median; 1.0-9.0s)"),
        "the median and the range are both reported");
}

static void test_a_slot_is_reused_cleanly() {
  Config cfg = make_config(1);
  ConnectOnly attack(cfg);
  FakeClock clock;
  use(attack, clock);

  open_conn(attack, 0);
  attack.on_readable(0, "hi\r\n", 4);
  clock.advance(3.0);
  attack.on_peer_close(0);
  attack.on_close(0);

  // The engine reconnects the same slot.
  open_conn(attack, 0);
  attack.on_readable(0, "hi\r\n", 4);
  clock.advance(5.0);
  attack.on_close(0);  // end of the attack

  check(attack.started() == 2, "both connections are counted");
  check(attack.spoke() == 2, "each connection's reply is counted on its own");
  const std::string s = attack.summary();
  check(contains(s, "ended by the far end (closed or reset): 1, after 3.0s"),
        "the first connection's lifetime is the far end's");
  check(contains(s, "still open when the attack stopped: 1, the oldest after 5.0s"),
        "the second is timed from its own connect, not the slot's first");
}

static void test_a_zero_length_read_is_a_close() {
  Config cfg = make_config();
  ConnectOnly attack(cfg);
  FakeClock clock;
  use(attack, clock);

  open_conn(attack, 0);
  clock.advance(1.5);
  Action a = attack.on_readable(0, nullptr, 0);
  check(a.kind == Action::Kind::Reconnect, "EOF signalled as a read recycles the slot");
  attack.on_close(0);
  check(attack.ended_by_peer() == 1, "and is the far end ending the connection");
  check(contains(attack.summary(), "still open when the attack stopped: none"),
        "not a connection that outlasted the attack");
}

static void test_summary_says_nothing_without_a_connection() {
  Config cfg = make_config();
  ConnectOnly attack(cfg);
  check(attack.summary().empty(),
        "nothing reached the target, so there is nothing to say about it");
  check(attack.verdict_caveat().empty(), "and no caveat to attach");
}

static void test_tunnel_is_named() {
  Config cfg = make_config();
  cfg.target.scheme = "https";
  cfg.proxy.host = "127.0.0.1";
  cfg.proxy.port = "3128";
  ConnectOnly attack(cfg);
  open_conn(attack, 0);
  check(contains(attack.summary(), "nothing was sent through the tunnel"),
        "through -d, the CONNECT exchange is traffic and the summary says the "
        "silence is what went through the tunnel");
}

static void test_caveat_when_nothing_was_held() {
  {
    Config cfg = make_config();
    ConnectOnly attack(cfg);
    FakeClock clock;
    use(attack, clock);
    for (int i = 0; i < 4; ++i) {
      open_conn(attack, i);
      clock.advance(0.1);
      attack.on_peer_close(i);
      attack.on_close(i);
    }
    const std::string c = attack.verdict_caveat();
    check(contains(c, "No connection was held for even a second"),
          "a target dropping every connection at once held nothing, and a "
          "denial under it was not caused by held connections");
    check(contains(c, "4 of the 4 opened"), "the caveat says how many");
  }
  {
    Config cfg = make_config();
    ConnectOnly attack(cfg);
    FakeClock clock;
    use(attack, clock);
    open_conn(attack, 0);
    clock.advance(0.1);
    attack.on_peer_close(0);
    attack.on_close(0);
    open_conn(attack, 1);
    clock.advance(5.0);
    check(attack.verdict_caveat().empty(),
          "one connection held for seconds is enough to have held something");
  }
  {
    Config cfg = make_config();
    ConnectOnly attack(cfg);
    FakeClock clock;
    use(attack, clock);
    open_conn(attack, 0);
    clock.advance(0.5);
    check(attack.verdict_caveat().empty(),
          "a short run the far end never interrupted is not the far end "
          "refusing to hold anything");
  }
}

static void test_many_lifetimes_stay_bounded_and_representative() {
  // A target that drops everything turns the run into a stream of new
  // connections; the lifetimes kept for the median must not grow with it, and
  // must not describe only the start of the run either.
  Config cfg = make_config(1);
  ConnectOnly attack(cfg);
  FakeClock clock;
  use(attack, clock);
  const int n = 100000;
  for (int i = 0; i < n; ++i) {
    open_conn(attack, 0);
    // Lifetimes grow through the run, 0.0s to just under 10.0s.
    clock.advance(10.0 * i / n);
    attack.on_peer_close(0);
    attack.on_close(0);
  }
  check(attack.ended_by_peer() == n, "every close is counted");
  const std::string s = attack.summary();
  // The true median is 5.0s. A sample of only the first lifetimes would put
  // it near 3.3s; a uniform one lands within a few tenths of the truth.
  const std::size_t at = s.find(", after ");
  check(at != std::string::npos, "the summary reports a median");
  if (at != std::string::npos) {
    const double median = std::atof(s.c_str() + at + 8);
    check(median > 4.7 && median < 5.3,
          "the median is drawn from the whole run, not its beginning");
  }
  check(contains(s, "(median; 0.0-10.0s)"), "min and max are exact");
}

static void test_out_of_range_ids_are_refused_not_indexed() {
  Config cfg = make_config(2);
  ConnectOnly attack(cfg);
  attack.on_open(-1);
  attack.on_open(2);
  check(attack.on_connect(-1).kind == Action::Kind::Idle, "negative id ignored");
  check(attack.on_connect(2).kind == Action::Kind::Idle, "id past the end ignored");
  attack.on_readable(5, "x", 1);
  attack.on_peer_close(7);
  attack.on_close(-3);
  check(attack.started() == 0 && attack.spoke() == 0 &&
            attack.ended_by_peer() == 0,
        "and none of them is counted");
}

int main() {
  test_nothing_is_ever_sent();
  test_a_reply_does_not_end_the_hold();
  test_the_first_reply_is_made_safe_to_print();
  test_the_far_end_ending_it_is_timed();
  test_the_engines_close_is_not_credited_to_the_target();
  test_connections_still_open_are_counted_at_summary_time();
  test_median_and_range();
  test_a_slot_is_reused_cleanly();
  test_a_zero_length_read_is_a_close();
  test_summary_says_nothing_without_a_connection();
  test_tunnel_is_named();
  test_caveat_when_nothing_was_held();
  test_many_lifetimes_stay_bounded_and_representative();
  test_out_of_range_ids_are_refused_not_indexed();
  if (failures) {
    std::fprintf(stderr, "%d check(s) failed\n", failures);
    return 1;
  }
  std::printf("connect only: all checks passed\n");
  return 0;
}
