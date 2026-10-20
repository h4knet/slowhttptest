// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#ifndef SLOWHTTP_ATTACKS_CONNECT_ONLY_HPP_
#define SLOWHTTP_ATTACKS_CONNECT_ONLY_HPP_

#include <chrono>
#include <cstddef>
#include <functional>
#include <random>
#include <string>
#include <vector>

#include "slowhttp/attack.hpp"
#include "slowhttp/config.hpp"

namespace slowhttp {

// A TCP connection that never sends anything.
//
// Every other mode puts bytes on the wire the moment a connection is up -- a
// request line, a ClientHello, a connection preface -- so none of them ever
// exercises what a server does with a connection that has said nothing at all:
// the clock that runs from accept() to the first byte. This mode is that clock
// and nothing else. Connect, then silence, held until the far end gives up or
// the run ends. Not even TLS is started on an https:// URL, since a ClientHello
// is a first byte like any other; the availability probe still does a real
// handshake.
//
// It is the floor of the slow family. Anything that bounds silence defeats it,
// including a per-read inactivity timeout that slow headers can outlast by
// sending a byte per interval -- so a target that holds these connections
// indefinitely has no timeout before the first byte at all. What that costs it
// depends on what owns a silent connection: a thread-per-connection server
// spends a worker on each, an event-driven one a few hundred bytes, and a
// kernel deferring accept until the first byte (TCP_DEFER_ACCEPT on Linux)
// keeps it from the server process until its defer period runs out. The
// probe, not the socket count, says which of those happened.
//
// How long the far end tolerated the silence is the measurement, so every
// connection's lifetime is recorded: those the far end ended, and those still
// open when the attack stopped. Two limits are inherent rather than missing:
//
//   - Nothing is sent, so nothing reveals a path that forgets the flow without
//     saying so, such as a NAT or firewall idle timeout that drops state with
//     no reset. Such a connection stays counted as held; only the probe is
//     unaffected.
//   - There is no request to carry a User-Agent, so these connections are
//     anonymous in the target's logs. The probe's requests still name the
//     tool, and they are how the run shows up on the receiving end.
class ConnectOnly : public Attack {
 public:
  using Clock = std::chrono::steady_clock;

  explicit ConnectOnly(const Config& cfg);

  const char* name() const override { return "connect only (nothing sent)"; }

  // Silence is the attack, but reading is how the far end's half of it is
  // seen: a close or a reset ends a hold, and some servers answer the silence
  // -- a 408, a protocol banner -- before they hang up, or instead of it.
  bool wants_read_events() const override { return true; }

  void on_open(ConnId id) override;
  Action on_connect(ConnId id) override;
  Action on_timer(ConnId id) override;
  Action on_readable(ConnId id, const char* data, std::size_t len) override;
  void on_peer_close(ConnId id) override;
  void on_close(ConnId id) override;

  std::string summary() const override;
  std::string verdict_caveat() const override;

  // Connections that got as far as on_connect(), i.e. that were held at all.
  long started() const { return started_; }
  // Of those, the ones the far end closed or reset.
  long ended_by_peer() const { return ended_by_peer_; }
  // Connections the far end sent anything on, counted once each.
  long spoke() const { return spoke_; }
  // The first line the far end sent on any connection, made printable; empty
  // if it sent nothing, or nothing that reads as text.
  const std::string& first_reply() const { return first_reply_; }

  // Replaces the clock. Hold times are intervals of real time, and a test
  // that had to sleep through them would be slow and still flaky.
  void set_clock(std::function<Clock::time_point()> now) {
    now_ = std::move(now);
  }

 private:
  enum class Slot : unsigned char { Idle, Holding, Ended };

  bool valid(ConnId id) const {
    return id >= 0 && static_cast<std::size_t>(id) < slot_.size();
  }
  double age_s(ConnId id) const;
  void record_peer_end(double secs);

  bool tunnelled_;
  std::function<Clock::time_point()> now_;

  std::vector<Slot> slot_;
  std::vector<Clock::time_point> connected_at_;
  std::vector<bool> spoke_on_;

  long started_ = 0;
  long ended_by_peer_ = 0;
  long spoke_ = 0;
  std::string first_reply_;

  // Lifetimes of the connections the far end ended. Bounded by reservoir
  // sampling: a target that drops every connection at once turns the run into
  // -r new connections a second, and an unbounded list of their lifetimes
  // would grow for as long as the run did. A uniform sample keeps the median
  // honest where keeping only the first N would describe the start of the run.
  std::vector<double> ended_sample_;
  double ended_min_ = 0;
  double ended_max_ = 0;
  std::mt19937 rng_;

  // Connections still open when the engine closed them at the end of the
  // attack. Those still open at summary time are counted there instead.
  long outlasted_ = 0;
  double outlasted_max_ = 0;
};

}  // namespace slowhttp

#endif  // SLOWHTTP_ATTACKS_CONNECT_ONLY_HPP_
