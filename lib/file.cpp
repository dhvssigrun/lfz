#include "libfilezilla/libfilezilla.hpp"
#include "libfilezilla/file.hpp"

#ifdef FZ_WINDOWS
#include "windows/security_descriptor_builder.hpp"
#else
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace fz {

file::file(native_string const& f, mode m, creation_flags d)
{
	open(f, m, d);
}

file::file(file::file_t fd)
	: fd_(fd)
{
}

file::~file()
{
	close();
}

#ifdef FZ_WINDOWS
file::file(file && op) noexcept
	: fd_{op.fd_}
{
	op.fd_ = INVALID_HANDLE_VALUE;
}

file& file::operator=(file && op) noexcept
{
	if (this != &op) {
		close();
		fd_ = op.fd_;
		op.fd_ = INVALID_HANDLE_VALUE;
	}
	return *this;
}

result file::open(native_string const& f, mode m, creation_flags d)
{
	close();

	if (f.empty()) {
		return {result::invalid};
	}

	DWORD dispositionFlags;
	if (m == writing) {
		if (d & empty) {
			dispositionFlags = CREATE_ALWAYS;
		}
		else {
			dispositionFlags = OPEN_ALWAYS;
		}
	}
	else {
		dispositionFlags = OPEN_EXISTING;
	}

	DWORD shareMode = FILE_SHARE_READ;
	if (m == reading) {
		shareMode |= FILE_SHARE_WRITE;
	}

	SECURITY_ATTRIBUTES attr{};
	attr.nLength = sizeof(SECURITY_ATTRIBUTES);

	security_descriptor_builder sdb;
	if (d & (current_user_only | current_user_and_admins_only)) {
		sdb.add(security_descriptor_builder::self);
		if ((d & current_user_and_admins_only) == current_user_and_admins_only) {
			sdb.add(security_descriptor_builder::administrators);
		}

		auto sd = sdb.get_sd();
		if (!sd) {
			return {result::other};
		}
		attr.lpSecurityDescriptor = sd;
	}
	fd_ = CreateFile(f.c_str(), (m == reading) ? GENERIC_READ : GENERIC_WRITE, shareMode, &attr, dispositionFlags, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);

	if (fd_ == INVALID_HANDLE_VALUE) {
		auto const err = GetLastError();
		switch (err) {
		case ERROR_ACCESS_DENIED:
			return {result::noperm, err};
		case ERROR_DISK_FULL:
			return {result::nospace, err};
		default:
			return {result::other, err};
		}
	}

	return {result::ok};
}

void file::close()
{
	if (fd_ != INVALID_HANDLE_VALUE) {
		CloseHandle(fd_);
		fd_ = INVALID_HANDLE_VALUE;
	}
}

file::file_t file::detach()
{
	file_t fd = fd_;
	fd_ = INVALID_HANDLE_VALUE;
	return fd;
}

int64_t file::size() const
{
	int64_t ret = -1;

	LARGE_INTEGER size{};
	if (GetFileSizeEx(fd_, &size)) {
		ret = static_cast<int64_t>(size.QuadPart);
	}
	return ret;
}

int64_t file::seek(int64_t offset, seek_mode m)
{
	int64_t ret = -1;

	LARGE_INTEGER dist{};
	dist.QuadPart = offset;

	DWORD method = FILE_BEGIN;
	if (m == current) {
		method = FILE_CURRENT;
	}
	else if (m == end) {
		method = FILE_END;
	}

	LARGE_INTEGER newPos{};
	if (SetFilePointerEx(fd_, dist, &newPos, method)) {
		ret = newPos.QuadPart;
	}
	return ret;
}

bool file::truncate()
{
	return !!SetEndOfFile(fd_);
}

int64_t file::read(void *buf, int64_t count)
{
	int64_t ret = -1;

	DWORD read = 0;
	if (ReadFile(fd_, buf, static_cast<DWORD>(count), &read, nullptr)) {
		ret = static_cast<int64_t>(read);
	}

	return ret;
}

int64_t file::write(void const* buf, int64_t count)
{
	int64_t ret = -1;

	DWORD written = 0;
	if (WriteFile(fd_, buf, static_cast<DWORD>(count), &written, nullptr)) {
		ret = static_cast<int64_t>(written);
	}

	return ret;
}

bool file::opened() const
{
	return fd_ != INVALID_HANDLE_VALUE;
}

bool remove_file(native_string const& name)
{
	bool ret = DeleteFileW(name.c_str()) != 0;
	if (!ret && GetLastError() == ERROR_FILE_NOT_FOUND) {
		ret = true;
	}

	return ret;
}

bool file::fsync()
{
	return FlushFileBuffers(fd_) != 0;
}

#else

file::file(file && op) noexcept
	: fd_{op.fd_}
{
	op.fd_ = -1;
}

file& file::operator=(file && op) noexcept
{
	if (this != &op) {
		close();
		fd_ = op.fd_;
		op.fd_ = -1;
	}
	return *this;
}

result file::open(native_string const& f, mode m, creation_flags d)
{
	close();

	if (f.empty()) {
		return {result::invalid};
	}

	int flags = O_CLOEXEC;
	if (m == reading) {
		flags |= O_RDONLY;
	}
	else {
		flags |= O_WRONLY | O_CREAT;
		if (d & empty) {
			flags |= O_TRUNC;
		}
	}
	int mode = S_IRUSR | S_IWUSR;
	if (!(d & (current_user_only | current_user_and_admins_only))) {
		mode |= S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
	}
	fd_ = ::open(f.c_str(), flags, mode);
	if (fd_ == -1) {
		int const err = errno;
		switch (err) {
		case EACCES:
			return {result::noperm, err};
		case EDQUOT:
		case ENOSPC:
			return {result::nospace, err};
		default:
			return {result::other, err};
		}
	}

#if HAVE_POSIX_FADVISE
	(void)posix_fadvise(fd_, 0, 0, POSIX_FADV_SEQUENTIAL | POSIX_FADV_NOREUSE);
#endif

	return {result::ok};
}

void file::close()
{
	if (fd_ != -1) {
		::close(fd_);
		fd_ = -1;
	}
}

file::file_t file::detach()
{
	file_t fd = fd_;
	fd_ = -1;
	return fd;
}

int64_t file::size() const
{
	int64_t ret = -1;

	struct stat buf;
	if (!fstat(fd_, &buf)) {
		ret = buf.st_size;
	}

	return ret;
}

int64_t file::seek(int64_t offset, seek_mode m)
{
	int64_t ret = -1;

	int whence = SEEK_SET;
	if (m == current) {
		whence = SEEK_CUR;
	}
	else if (m == end) {
		whence = SEEK_END;
	}

	auto newPos = lseek(fd_, offset, whence);
	if (newPos != static_cast<off_t>(-1)) {
		ret = newPos;
	}

	return ret;
}

bool file::truncate()
{
	bool ret = false;

	auto length = lseek(fd_, 0, SEEK_CUR);
	if (length != static_cast<off_t>(-1)) {
		do {
			ret = !ftruncate(fd_, length);
		} while (!ret && (errno == EAGAIN || errno == EINTR));
	}

	return ret;
}

int64_t file::read(void *buf, int64_t count)
{
	int64_t ret;
	do {
		ret = ::read(fd_, buf, count);
	} while (ret == -1 && (errno == EAGAIN || errno == EINTR));

	return ret;
}

int64_t file::write(void const* buf, int64_t count)
{
	int64_t ret;
	do {
		ret = ::write(fd_, buf, count);
	} while (ret == -1 && (errno == EAGAIN || errno == EINTR));

	return ret;
}

bool file::opened() const
{
	return fd_ != -1;
}

bool remove_file(native_string const& name)
{
	bool ret = unlink(name.c_str()) == 0;
	if (!ret && errno == ENOENT) {
		ret = true;
	}
	return ret;
}

bool file::fsync()
{
#if defined(_POSIX_SYNCHRONIZED_IO) && _POSIX_SYNCHRONIZED_IO > 0
	return fdatasync(fd_) == 0;
#else
	return ::fsync(fd_) == 0;
#endif
}

#endif

}
