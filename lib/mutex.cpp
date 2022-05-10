#include "libfilezilla/mutex.hpp"

#ifndef FZ_WINDOWS
#include <errno.h>
#include <sys/time.h>

#endif

#ifdef LFZ_DEBUG_MUTEXES
#include <assert.h>
#include <execinfo.h>
#include <stdlib.h>
#include <cstddef>
#include <memory>
#include <tuple>
#include <iostream>
#include "libfilezilla/format.hpp"

namespace fz {
namespace debug {
static mutex m_;
thread_local std::vector<std::weak_ptr<mutex_debug>> lock_stack;
thread_local size_t waitcounter{};
static std::ptrdiff_t mutex_offset{};

void record_order(mutex* m, bool from_try)
{
	if (m == &debug::m_) {
		return;
	}
	scoped_lock l(debug::m_);

	auto & mdata = *m->h_.get();
	for (auto const& wsm : lock_stack) {
		auto sm = wsm.lock();
		if (!sm || sm->mtx_ == m) {
			continue;
		}

		size_t i = 0;
		while (i < sm->order_.size()) {
			auto & o = sm->order_[i];
			auto so = std::get<0>(o).lock();
			if (!so) {
				// Remove stale pointer
				if (i + 1 != sm->order_.size()) {
					o = std::move(sm->order_.back());
				}
				sm->order_.pop_back();
				continue;
			}

			if (so->mtx_ == m) {
				if (from_try) {
					return;
				}

#if FZ_UNIX
				std::cerr << fz::sprintf("Locking order violation. fz::mutex %p locked after %p. Reverse order was established at:\n", m, sm->mtx_);
				auto & v = std::get<1>(o);
				auto symbols = backtrace_symbols(v.data(), v.size());
				if (symbols) {
					for (size_t i = 0; i < v.size(); ++i) {
						if (symbols[i]) {
							std::cerr << symbols[i] << "\n";
						}
						else {
							std::cerr << "unknown\n";
						}
					}
				}
				else {
					std::cerr << "Stacktrace unavailable\n";
				}
#else
				std::cerr << fz::sprintf("Locking order violation. fz::mutex %p locked after %p\n");
#endif
				abort();
			}
			++i;
		}

		i = 0;
		while (i < mdata.order_.size()) {
			auto & o = mdata.order_[i];
			auto so = std::get<0>(o).lock();
			if (!so) {
				if (i + 1 != mdata.order_.size()) {
					o = std::move(mdata.order_.back());
				}
				mdata.order_.pop_back();
				continue;
			}
			if (so->mtx_ == sm->mtx_) {
				break;
			}
			++i;
		}
		if (i == mdata.order_.size()) {
			std::vector<void*> v;
#if FZ_UNIX
			v.resize(100);
			v.resize(backtrace(v.data(), 100));
#endif
			mdata.order_.push_back(std::make_tuple(sm, v));
		}
	}
}

void lock(mutex* m, bool from_try) {
	if (m == &debug::m_) {
		return;
	}

	if (!m->h_->count_++) {
		lock_stack.push_back(m->h_);

		if (!from_try) {
			record_order(m, from_try);
		}
	}
}

void unlock(mutex* m) {
	if (m == &debug::m_) {
		return;
	}

	size_t count = m->h_->count_--;
	assert(count);
	if (count != 1) {
		return;
	}

	for (auto it = lock_stack.rbegin(); it != lock_stack.rend(); ++it) {
		auto sm = it->lock();
		if (sm && sm->mtx_ == m) {
			it->reset();
			while (!lock_stack.empty() && lock_stack.back().expired()) {
				lock_stack.pop_back();
			}
			return;
		}
	}
	abort();
}
}

void mutex_debug::record_lock(void* m)
{
	debug::lock(reinterpret_cast<mutex*>(reinterpret_cast<unsigned char*>(m) - debug::mutex_offset), false);
}

void mutex_debug::record_unlock(void* m)
{
	debug::unlock(reinterpret_cast<mutex*>(reinterpret_cast<unsigned char*>(m) - debug::mutex_offset));
}

void debug_prepare_wait(void* p)
{
	auto m = reinterpret_cast<mutex*>(reinterpret_cast<unsigned char*>(p) - debug::mutex_offset);
	debug::waitcounter = m->h_->count_;
	assert(debug::waitcounter);
	m->h_->count_ = 0;
}

void debug_post_wait(void* p)
{
	auto m = reinterpret_cast<mutex*>(reinterpret_cast<unsigned char*>(p) - debug::mutex_offset);
	assert(!m->h_->count_);
	m->h_->count_ = debug::waitcounter;
}
}
#else
constexpr void debug_prepare_wait(void*) {}
constexpr void debug_post_wait(void*) {}
#endif

#ifndef FZ_WINDOWS
namespace {
// Static initializers for mutex and condition attributes
template<int type>
pthread_mutexattr_t* init_mutexattr()
{
	static pthread_mutexattr_t attr;
	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, type);

	return &attr;
}

pthread_mutexattr_t* get_mutex_attributes(bool recursive)
{
	if (recursive) {
		static pthread_mutexattr_t *attr = init_mutexattr<PTHREAD_MUTEX_RECURSIVE>();
		return attr;
	}
	else {
		static pthread_mutexattr_t *attr = init_mutexattr<PTHREAD_MUTEX_NORMAL>();
		return attr;
	}
}

pthread_condattr_t* init_condattr()
{
#if HAVE_CLOCK_GETTIME && HAVE_DECL_PTHREAD_CONDATTR_SETCLOCK
	static pthread_condattr_t attr;
	pthread_condattr_init(&attr);
	pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
	return &attr;
#else
	return 0;
#endif
}
}
#endif

namespace fz {

mutex::mutex(bool recursive)
{
#ifdef FZ_WINDOWS
	(void)recursive; // Critical sections are always recursive
	InitializeCriticalSectionEx(&m_, 0, CRITICAL_SECTION_NO_DEBUG_INFO);
#else
	pthread_mutex_init(&m_, get_mutex_attributes(recursive));
#endif
#ifdef LFZ_DEBUG_MUTEXES
	[[maybe_unused]] static bool init = [this]() {
		debug::mutex_offset = reinterpret_cast<unsigned char*>(&m_) - reinterpret_cast<unsigned char*>(this);
		return true;
	}();
	h_ = std::make_shared<mutex_debug>(this);
#endif
}

mutex::~mutex()
{
#ifdef FZ_WINDOWS
	DeleteCriticalSection(&m_);
#else
	pthread_mutex_destroy(&m_);
#endif
}

void mutex::lock()
{
#ifdef FZ_WINDOWS
	EnterCriticalSection(&m_);
#else
	pthread_mutex_lock(&m_);
#endif

#ifdef LFZ_DEBUG_MUTEXES
	debug::lock(this, false);
#endif
}

void mutex::unlock()
{
#ifdef LFZ_DEBUG_MUTEXES
	debug::unlock(this);
#endif
#ifdef FZ_WINDOWS
	LeaveCriticalSection(&m_);
#else
	pthread_mutex_unlock(&m_);
#endif
}

bool mutex::try_lock()
{
#ifdef FZ_WINDOWS
	bool locked = TryEnterCriticalSection(&m_) != 0;
#else
	bool locked = pthread_mutex_trylock(&m_) == 0;
#endif
#ifdef LFZ_DEBUG_MUTEXES
	if (locked) {
		debug::lock(this, true);
	}
#endif
	return locked;
}


condition::condition()
{
#ifdef FZ_WINDOWS
	InitializeConditionVariable(&cond_);
#else

	static pthread_condattr_t *attr = init_condattr();
	pthread_cond_init(&cond_, attr);
#endif
}


condition::~condition()
{
#ifdef FZ_WINDOWS
#else
	pthread_cond_destroy(&cond_);
#endif
}

void condition::wait(scoped_lock& l)
{
	while (!signalled_) {
		debug_prepare_wait(l.m_);
#ifdef FZ_WINDOWS
		SleepConditionVariableCS(&cond_, l.m_, INFINITE);
#else
		pthread_cond_wait(&cond_, l.m_);
#endif
		debug_post_wait(l.m_);
	}
	signalled_ = false;
}

bool condition::wait(scoped_lock& l, duration const& timeout)
{
	if (signalled_) {
		signalled_ = false;
		return true;
	}
#ifdef FZ_WINDOWS
	auto ms = timeout.get_milliseconds();
	if (ms < 0) {
		ms = 0;
	}
	debug_prepare_wait(l.m_);
	bool const success = SleepConditionVariableCS(&cond_, l.m_, static_cast<DWORD>(ms)) != 0;
	debug_post_wait(l.m_);
#else
	int res;
	timespec ts;
#if HAVE_CLOCK_GETTIME && HAVE_DECL_PTHREAD_CONDATTR_SETCLOCK
	clock_gettime(CLOCK_MONOTONIC, &ts);
#else
	timeval tv{};
	gettimeofday(&tv, 0);
	ts.tv_sec = tv.tv_sec;
	ts.tv_nsec = tv.tv_usec * 1000;
#endif

	ts.tv_sec += timeout.get_milliseconds() / 1000;
	ts.tv_nsec += (timeout.get_milliseconds() % 1000) * 1000 * 1000;
	if (ts.tv_nsec > 1000000000ll) {
		++ts.tv_sec;
		ts.tv_nsec -= 1000000000ll;
	}

	do {
		debug_prepare_wait(l.m_);
		res = pthread_cond_timedwait(&cond_, l.m_, &ts);
		debug_post_wait(l.m_);
	}
	while (res == EINTR);
	bool const success = res == 0;
#endif
	if (success) {
		signalled_ = false;
	}

	return success;
}


void condition::signal(scoped_lock &)
{
	if (!signalled_) {
		signalled_ = true;
#ifdef FZ_WINDOWS
		WakeConditionVariable(&cond_);
#else
		pthread_cond_signal(&cond_);
#endif
	}
}

}
