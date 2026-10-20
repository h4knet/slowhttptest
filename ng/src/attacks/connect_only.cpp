// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#include "slowhttp/attacks/connect_only.hpp"

#include <algorithm>
#include <cstdio>

namespace slowhttp {
namespace {

// Lifetimes kept for the median. Far more than one summary line needs, and
// small enough that the worst case -- a target dropping connections as fast as
// -r opens them, for the whole run -- costs half a megabyte.
constexpr std::size_t kMaxEndedSample = 65536;

// How much of the far end's first reply is shown: enough for a status line or
// a protocol banner. The summary describes the reply, it does not capture it.
constexpr std::size_t kMaxReplyShown = 64;

// A connection that did not last this long was not held in any sense worth
// crediting to the attack.
constexpr double kHeldFloorSeconds = 1.0;

// The first line of what the far end sent, safe to print. The peer chooses
// these bytes and a terminal interprets escape sequences in whatever it is
// given, so anything outside printable ASCII is replaced. A reply that is
// mostly unprintable is a binary protocol, and a row of dots says nothing.
std::string printable_line(const char* data, std::size_t len) {
  std::string out;
  std::size_t odd = 0;
  for (std::size_t i = 0; i < len && out.size() < kMaxReplyShown; ++i) {
    const unsigned char ch = static_cast<unsigned char>(data[i]);
    if (ch == '\r' || ch == '\n') break;
    if (ch >= 0x20 && ch < 0x7f) {
      out.push_back(static_cast<char>(ch));
    } else {
      out.push_back('.');
      ++odd;
    }
  }
  if (out.empty() || odd * 2 > out.size()) return std::string();
  return out;
}

double median_of(std::vector<double> v) {
  if (v.empty()) return 0;
  std::sort(v.begin(), v.end());
  const std::size_t mid = v.size() / 2;
  return v.size() % 2 ? v[mid] : (v[mid - 1] + v[mid]) / 2;
}

}  // namespace

ConnectOnly::ConnectOnly(const Config& cfg)
    // -d with an http:// URL is refused by the CLI, so a proxy here means a
    // CONNECT tunnel: the proxy was spoken to, the origin never was.
    : tunnelled_(cfg.proxy.enabled() && cfg.target.tls()),
      now_([] { return Clock::now(); }),
      slot_(static_cast<std::size_t>(cfg.connections), Slot::Idle),
      connected_at_(static_cast<std::size_t>(cfg.connections)),
      spoke_on_(static_cast<std::size_t>(cfg.connections), false),
      rng_(std::random_device{}()) {}

double ConnectOnly::age_s(ConnId id) const {
  return std::chrono::duration<double>(now_() - connected_at_[id]).count();
}

void ConnectOnly::on_open(ConnId id) {
  if (valid(id)) spoke_on_[id] = false;
}

Action ConnectOnly::on_connect(ConnId id) {
  if (!valid(id)) return Action::idle();
  ++started_;
  slot_[id] = Slot::Holding;
  connected_at_[id] = now_();
  spoke_on_[id] = false;
  // Nothing to send, now or later, so no timer either: a held connection
  // costs the event loop nothing until the far end does something.
  return Action::idle();
}

Action ConnectOnly::on_timer(ConnId /*id*/) {
  // Never armed. Were one to fire, sending anything would end the mode.
  return Action::idle();
}

Action ConnectOnly::on_readable(ConnId id, const char* data, std::size_t len) {
  if (!valid(id)) return Action::idle();
  if (len == 0) {
    // The engine reports a close through on_peer_close() and never gets here;
    // this is for a driver that signals one the way the interface describes.
    on_peer_close(id);
    return Action::reconnect();
  }
  if (!spoke_on_[id]) {
    spoke_on_[id] = true;
    if (++spoke_ == 1) first_reply_ = printable_line(data, len);
  }
  // Keep holding. A server that answers the silence and then waits -- a
  // greeting, a banner -- still has the connection, and hanging up here would
  // end the hold from this side and credit the target with it.
  return Action::idle();
}

void ConnectOnly::record_peer_end(double secs) {
  ++ended_by_peer_;
  if (ended_by_peer_ == 1) {
    ended_min_ = ended_max_ = secs;
  } else {
    ended_min_ = std::min(ended_min_, secs);
    ended_max_ = std::max(ended_max_, secs);
  }
  if (ended_sample_.size() < kMaxEndedSample) {
    ended_sample_.push_back(secs);
    return;
  }
  // Reservoir sampling (Algorithm R): the n-th lifetime replaces a random
  // entry with probability size/n, which leaves every lifetime equally likely
  // to be in the sample whenever it is read.
  std::uniform_int_distribution<long> pick(0, ended_by_peer_ - 1);
  const long j = pick(rng_);
  if (j < static_cast<long>(ended_sample_.size()))
    ended_sample_[static_cast<std::size_t>(j)] = secs;
}

void ConnectOnly::on_peer_close(ConnId id) {
  if (!valid(id) || slot_[id] != Slot::Holding) return;
  slot_[id] = Slot::Ended;
  record_peer_end(age_s(id));
}

void ConnectOnly::on_close(ConnId id) {
  if (!valid(id)) return;
  if (slot_[id] == Slot::Holding) {
    // Still held, and not ended by the far end: the engine closed it, which
    // it does to every connection when the attack phase stops. It outlasted
    // the attack.
    ++outlasted_;
    outlasted_max_ = std::max(outlasted_max_, age_s(id));
  }
  slot_[id] = Slot::Idle;
}

std::string ConnectOnly::summary() const {
  // Nothing reached the target, so there is nothing to say about it; the
  // engine already says that, louder.
  if (started_ == 0) return std::string();

  // Connections still open now count with those the engine closed at the end
  // of the attack. Without a probe it closes nothing before this is printed.
  long outlasted = outlasted_;
  double oldest = outlasted_max_;
  for (std::size_t i = 0; i < slot_.size(); ++i) {
    if (slot_[i] != Slot::Holding) continue;
    ++outlasted;
    oldest = std::max(oldest, age_s(static_cast<ConnId>(i)));
  }

  std::string out;
  char buf[256];
  std::snprintf(buf, sizeof(buf),
                "connect only: nothing was sent%s on any of %ld connection(s)",
                tunnelled_ ? " through the tunnel" : "", started_);
  out += buf;

  if (ended_by_peer_ > 0)
    std::snprintf(buf, sizeof(buf),
                  "\n  ended by the far end (closed or reset): %ld, after"
                  " %.1fs of silence (median; %.1f-%.1fs)",
                  ended_by_peer_, median_of(ended_sample_), ended_min_,
                  ended_max_);
  else
    std::snprintf(buf, sizeof(buf),
                  "\n  ended by the far end (closed or reset): none");
  out += buf;

  if (outlasted > 0)
    std::snprintf(buf, sizeof(buf),
                  "\n  still open when the attack stopped: %ld, the oldest"
                  " after %.1fs of silence",
                  outlasted, oldest);
  else
    std::snprintf(buf, sizeof(buf), "\n  still open when the attack stopped: none");
  out += buf;

  // Anything the far end said is unprompted, since nothing was ever sent to
  // it. Often it is the reason the connection ended -- a 408 -- and for a port
  // that is not HTTP at all it is the clearest sign of that.
  if (spoke_ > 0) {
    if (!first_reply_.empty())
      std::snprintf(buf, sizeof(buf),
                    "\n  the far end sent data unprompted on %ld of them; the"
                    " first began \"%s\"",
                    spoke_, first_reply_.c_str());
    else
      std::snprintf(buf, sizeof(buf),
                    "\n  the far end sent data unprompted on %ld of them, not"
                    " as text",
                    spoke_);
    out += buf;
  }
  return out;
}

std::string ConnectOnly::verdict_caveat() const {
  if (started_ == 0 || ended_by_peer_ == 0) return std::string();
  double longest = std::max(ended_max_, outlasted_max_);
  for (std::size_t i = 0; i < slot_.size(); ++i)
    if (slot_[i] == Slot::Holding)
      longest = std::max(longest, age_s(static_cast<ConnId>(i)));
  if (longest >= kHeldFloorSeconds) return std::string();
  // Everything was dropped about as fast as it was opened, so nothing was
  // ever held. The only load this run applied was the stream of new
  // connections replacing the dropped ones, and a denial seen under it says
  // nothing about how many silent connections the target can afford.
  char buf[320];
  std::snprintf(buf, sizeof(buf),
                "No connection was held for even a second: the far end closed"
                " or reset %ld of the %ld opened, none later than %.1fs after"
                " it opened. Whatever the probe saw was not caused by"
                " connections held open -- at most by the rate of new ones"
                " (-r).",
                ended_by_peer_, started_, ended_max_);
  return std::string(buf);
}

}  // namespace slowhttp
