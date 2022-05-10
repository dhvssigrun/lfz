#include "libfilezilla/event_loop.hpp"
#include "libfilezilla/event_handler.hpp"
#include "libfilezilla/thread_pool.hpp"
#include "libfilezilla/util.hpp"

#include <algorithm>

#ifdef LFZ_EVENT_DEBUG
#include <assert.h>
#define event_assert(pred) assert((pred))
#else
#define event_assert(pred)
#endif

namespace fz {

event_loop::event_loop()
	: sync_(false)
	, thread_(std::make_unique<thread>())
{
	thread_->run([this] { entry(); });
}

event_loop::event_loop(thread_pool & pool)
	: sync_(false)
{
	task_ = std::make_unique<async_task>(pool.spawn([this] { entry(); }));
}

event_loop::event_loop(event_loop::loop_option)
	: sync_(false)
{
}

event_loop::~event_loop()
{
	stop(true);
}

void event_loop::send_event(event_handler* handler, event_base* evt)
{
	event_assert(handler);
	event_assert(evt);

	{
		scoped_lock lock(sync_);
		if (!handler->removing_) {
			if (pending_events_.empty()) {
				cond_.signal(lock);
			}
			pending_events_.emplace_back(handler, evt);
			return;
		}
	}

	delete evt;
}

void event_loop::remove_handler(event_handler* handler)
{
	scoped_lock l(sync_);

	handler->removing_ = true;

	pending_events_.erase(
		std::remove_if(pending_events_.begin(), pending_events_.end(),
			[&](Events::value_type const& v) {
				if (v.first == handler) {
					delete v.second;
				}
				return v.first == handler;
			}
		),
		pending_events_.end()
	);

	timers_.erase(
		std::remove_if(timers_.begin(), timers_.end(),
			[&](timer_data const& v) {
				return v.handler_ == handler;
			}
		),
		timers_.end()
	);
	if (timers_.empty()) {
		deadline_ = monotonic_clock();
	}

	if (active_handler_ == handler) {
		if (thread::own_id() != thread_id_) {
			while (active_handler_ == handler) {
				l.unlock();
				yield();
				l.lock();
			}
		}
	}
}

void event_loop::filter_events(std::function<bool(Events::value_type &)> const& filter)
{
	scoped_lock l(sync_);

	pending_events_.erase(
		std::remove_if(pending_events_.begin(), pending_events_.end(),
			[&](Events::value_type & v) {
				bool const remove = filter(v);
				if (remove) {
					delete v.second;
				}
				return remove;
			}
		),
		pending_events_.end()
	);
}

timer_id event_loop::add_timer(event_handler* handler, duration const& interval, bool one_shot)
{
	timer_data d;
	d.handler_ = handler;
	if (!one_shot) {
		d.interval_ = interval;
	}
	d.deadline_ = monotonic_clock::now() + interval;

	scoped_lock lock(sync_);
	if (!handler->removing_) {
		d.id_ = ++next_timer_id_; // 64bit, can this really ever overflow?

		timers_.emplace_back(d);
		if (!deadline_ || d.deadline_ < deadline_) {
			// Our new time is the next timer to trigger
			deadline_ = d.deadline_;
			cond_.signal(lock);
		}
	}
	return d.id_;
}

void event_loop::stop_timer(timer_id id)
{
	if (id) {
		scoped_lock lock(sync_);
		for (auto it = timers_.begin(); it != timers_.end(); ++it) {
			if (it->id_ == id) {
				if (&*it != &timers_.back()) {
					*it = std::move(timers_.back());
				}
				timers_.pop_back();

				if (timers_.empty()) {
					deadline_ = monotonic_clock();
				}
				break;
			}
		}
	}
}

bool event_loop::process_event(scoped_lock & l)
{
	Events::value_type ev{};

	if (pending_events_.empty()) {
		return false;
	}
	ev = pending_events_.front();
	pending_events_.pop_front();

	event_assert(ev.first);
	event_assert(ev.second);
	event_assert(!ev.first->removing_);

	active_handler_ = ev.first;

	l.unlock();
	(*ev.first)(*ev.second);
	delete ev.second;
	l.lock();

	active_handler_ = nullptr;

	return true;
}

void event_loop::run()
{
	if (task_ || thread_ || thread_id_ != thread::id()) {
		return;
	}

	entry();
}

void event_loop::entry()
{
	thread_id_ = thread::own_id();

	monotonic_clock now;

	scoped_lock l(sync_);
	while (!quit_) {
		if (process_timers(l, now)) {
			continue;
		}
		if (process_event(l)) {
			continue;
		}

		// Nothing to do, now we wait
		if (deadline_) {
			cond_.wait(l, deadline_ - now);
		}
		else {
			cond_.wait(l);
		}
	}
}

bool event_loop::process_timers(scoped_lock & l, monotonic_clock & now)
{
	if (!deadline_) {
		// There's no deadline
		return false;
	}

	now = monotonic_clock::now();
	if (now < deadline_) {
		// Deadline has not yet expired
		return false;
	}

	// Update deadline_, stop at first expired timer
	deadline_ = monotonic_clock();
	auto it = timers_.begin();
	for (; it != timers_.end(); ++it) {
		if (!deadline_ || it->deadline_ < deadline_) {
			if (it->deadline_ <= now) {
				break;
			}
			deadline_ = it->deadline_;
		}
	}

	if (it != timers_.end()) {
		// 'it' is now expired
		// deadline_ has been updated with prior timers
		// go through remaining elements to update deadline_
		for (auto it2 = std::next(it); it2 != timers_.end(); ++it2) {
			if (!deadline_ || it2->deadline_ < deadline_) {
				deadline_ = it2->deadline_;
			}
		}

		event_handler *const handler = it->handler_;
		auto const id = it->id_;

		// Update the expired timer
		if (!it->interval_) {
			// Remove one-shot timer
			if (&*it != &timers_.back()) {
				*it = std::move(timers_.back());
			}
			timers_.pop_back();
		}
		else {
			it->deadline_ = now + it->interval_;
			if (!deadline_ || it->deadline_ < deadline_) {
				deadline_ = it->deadline_;
			}
		}

		// Call event handler
		event_assert(!handler->removing_);

		active_handler_ = handler;

		l.unlock();
		(*handler)(timer_event(id));
		l.lock();

		active_handler_ = nullptr;

		return true;
	}

	return false;
}

void event_loop::stop(bool join)
{
	{
		scoped_lock l(sync_);
		quit_ = true;
		cond_.signal(l);
	}

	if (join) {
		thread_.reset();
		task_.reset();

		scoped_lock lock(sync_);
		for (auto & v : pending_events_) {
			delete v.second;
		}
		pending_events_.clear();

		timers_.clear();
		deadline_ = monotonic_clock();
	}
}

}
