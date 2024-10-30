
class win_handle {
public:
	win_handle() noexcept = default;

	// implicit
	win_handle(std::nullptr_t) noexcept {}

	// implicit
	win_handle(HANDLE h)
		: handle_(h) {}

	explicit operator bool() const noexcept {
		return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
	}

	// implicit
	operator HANDLE() const noexcept {
		return handle_;
	}

	friend bool operator==(win_handle lhs, win_handle rhs) noexcept {
		return lhs.handle_ == rhs.handle_;
	}

	friend bool operator!=(win_handle lhs, win_handle rhs) noexcept {
		return !(lhs == rhs);
	}

private:
	friend struct win_handle_deleter;
	HANDLE handle_ = nullptr;
};

struct win_handle_deleter {
	using pointer = win_handle;

	void operator()(pointer ptr) const {
		dbg("destroying handle!");
		CloseHandle(ptr.handle_);
	}
};

static_assert(std::is_empty_v<win_handle_deleter>);

using scoped_win_handle_unique = std::unique_ptr<win_handle, win_handle_deleter>;
using scoped_win_handle = std::shared_ptr<scoped_win_handle_unique>;
